use ::pulp_sdk_rust::*;
use core::ops::{Deref, DerefMut};

/// A managed buffer in L1 cache with automatic DMA transfers in and out based on
/// rounds
/// DMA triple buffer
/// Since we need to transfer back the modified data, we divide the L1 allocation
/// in 3 buffers: work, pre-fetch and commit
///
///  round: 0
///    work         dma in(pre-fetch)
///         |              |
/// |--------------|--------------|---------------|
///
///  round: 1
/// dma out (commit)      work      dma in(pre-fetch)
///         |              |              |
/// |--------------|--------------|---------------|
///
///  round: 2
///   dma in (pre-fetch) dma out (commit) work
///         |              |              |
/// |--------------|--------------|---------------|
pub struct DmaBuf<const CORES: usize> {
    // data in external memory
    source: *mut u8,
    source_len: usize,
    // allocation in L1 cache
    // Ideally the blocks are layed out in memory so that each core's block lays entirely on a different l1 bank so that we minimize contention
    // on the same bank. Probably we could force this knowing the memory addresses layout
    // DMA should also operate on separate banks
    l1_alloc: *mut u8,
    // how many rounds have been completed till now
    rounds: usize,
    pre_fetch_dma: DmaTransfer,
    commit_dma: DmaTransfer,
    buf_size: usize,
    counters: [usize; 3],
    last_transfer: usize,
    work_buf_len: usize,
}

// todo implement unpin
enum DmaTransfer {
    Ram {
        req: PiClRamReq,
        device: *mut PiDevice,
    },
    L2(PiClDmaCmd),
}

impl DmaTransfer {
    unsafe fn transfer_in(&mut self, remote: *mut u8, l1: *mut u8, len: usize) {
        match self {
            Self::Ram { ref mut req, device } => {
                pi_cl_ram_read(
                    *device,
                    remote,
                    l1,
                    len,
                    req,
                );
            }
            Self::L2(ref mut cmd) => {
                pi_cl_dma_cmd(
                    remote,
                    l1,
                    len,
                    PiClDmaDirE::PI_CL_DMA_DIR_EXT2LOC,
                    cmd,
                );
            }
        }
    }

    unsafe fn transfer_out(&mut self, remote: *mut u8, l1: *mut u8, len: usize) {
        match self {
            Self::Ram { ref mut req, device } => {
                pi_cl_ram_write(
                    *device,
                    remote,
                    l1,
                    len,
                    req,
                );
            }
            Self::L2(ref mut cmd) => {
                pi_cl_dma_cmd(
                    remote,
                    l1,
                    len,
                    PiClDmaDirE::PI_CL_DMA_DIR_LOC2EXT,
                    cmd,
                );
            }
        }
    }

    fn wait(&mut self) {
        match self {
            Self::Ram { ref mut req, .. } if req.is_in_transfer() => pi_cl_ram_read_wait(req),
            Self::Ram { ref mut req, .. } => pi_cl_ram_write_wait(req),
            Self::L2(ref mut cmd) => pi_cl_dma_wait(cmd),
        }
    }

    
}

impl<const CORES: usize> DmaBuf<CORES> {
    fn common(
        source: *mut u8,
        source_len: usize,
        l1_alloc: *mut u8,
        l1_alloc_len: usize,
        mut pre_fetch_dma: DmaTransfer,
        commit_dma: DmaTransfer,
    ) -> Self {
        assert_eq!(l1_alloc_len % 3, 0);
        let buf_size = l1_alloc_len / 3;
        assert_eq!(buf_size % CORES, 0);
        unsafe {
            let size = core::cmp::min(buf_size * 2, source_len);
            // initialize first buffer
            if pi_core_id() == 0 {
                pre_fetch_dma.transfer_in(source, l1_alloc, size);
                pre_fetch_dma.wait();
            }
            pi_cl_team_barrier();
        }

        Self {
            source,
            source_len,
            l1_alloc,
            pre_fetch_dma,
            commit_dma,
            buf_size,
            rounds: 0,
            counters: [0, buf_size, buf_size * 2],
            last_transfer: core::cmp::min(
                buf_size,
                source_len.checked_sub(buf_size).unwrap_or_default(),
            ),
            work_buf_len: core::cmp::min(buf_size, source_len),
        }
    }

    pub fn new_from_ram(
        source: *mut u8,
        source_len: usize,
        l1_alloc: *mut u8,
        l1_alloc_len: usize,
        device: *mut PiDevice
    ) -> Self {
        Self::common(source, source_len, l1_alloc, l1_alloc_len, DmaTransfer::Ram{device, req: PiClRamReq::new(device)}, DmaTransfer::Ram{device, req: PiClRamReq::new(device)})
    }

    pub fn new_from_l2(
        source: *mut u8,
        source_len: usize,
        l1_alloc: *mut u8,
        l1_alloc_len: usize,
    ) -> Self {
        Self::common(source, source_len, l1_alloc, l1_alloc_len, DmaTransfer::L2(PiClDmaCmd::new()), DmaTransfer::L2(PiClDmaCmd::new()))
    }

    pub fn work_buf_len(&self) -> usize {
        self.buf_size
    }

    /// Signal that work has completed on the current 'work' buffer
    #[inline(never)]
    pub fn advance(&mut self) {
        pi_cl_team_barrier();
        self.rounds += 1;
        let a = self.counters[0];
        self.counters[0] = self.counters[1];
        self.counters[1] = self.counters[2];
        self.counters[2] = a;
        // Only core 0 interacts with the dma
        // (this is unsafe only because those are FFI calls)
        unsafe {
            let offset = (self.rounds + 1) * self.buf_size;
            let size = core::cmp::min(
                self.source_len.checked_sub(offset).unwrap_or_default(),
                self.buf_size,
            );
            if pi_core_id() == 0 {
                if self.rounds > 1 {
                    // wait dma completed on commit buf before using it as pre-fetch (should not actually wait in practice)
                    self.commit_dma.wait();
                    // wait dma completed on current work buf
                    self.pre_fetch_dma.wait();
                }

                // start dma out (commit)
                let commit_buf_ptr = self.get_commit_buf_ptr();
                self.commit_dma.transfer_out(self.source.add((self.rounds - 1) * self.buf_size), commit_buf_ptr, self.work_buf_len);

                if offset < self.source_len {
                    // start dma in (pre-fetch)
                    let pre_fetch_buf_ptr = self.get_pre_fetch_buf_ptr();
                    self.pre_fetch_dma.transfer_in(self.source.add(offset), pre_fetch_buf_ptr, size);
                    
                }
            }
            self.work_buf_len = self.last_transfer;
            self.last_transfer = size;
            // everyone has to wait for transfers to be finished
            pi_cl_team_barrier();
        }
    }

    /// Finalize by flushing all local cached data upstream
    pub fn flush(&mut self) {
        unsafe {
            if pi_core_id() == 0 {
                self.commit_dma.wait();
            }
            pi_cl_team_barrier();
        }
    }

    /// TODO: this is wildly unsound and aliased in every core
    /// # Safety
    /// For this to be safe we need:
    ///     * sharding based on cores, but that's a bit too much domain knowledge for a simple buffer
    ///     * lifetime of the returned buffer should never exceed any other invocation of `advance` by other cores
    #[inline(never)]
    pub unsafe fn get_work_buf(&mut self) -> SmartBuf {
        SmartBuf {
            buf: self.l1_alloc.add(self.counters[0]),
            core_buf_size: self.buf_size / CORES,
            len: self.work_buf_len,
            _lifetime: core::marker::PhantomData,
        }
    }

    #[inline(never)]
    fn get_pre_fetch_buf_ptr(&mut self) -> *mut u8 {
        unsafe { self.l1_alloc.add(self.counters[1]) }
    }

    #[inline(never)]
    fn get_commit_buf_ptr(&mut self) -> *mut u8 {
        unsafe { self.l1_alloc.add(self.counters[2]) }
    }
}

// A smart pointer that automatically derefs to a different portion of the slice in each core
// in the pulp cluster to avoid aliasing
pub struct SmartBuf<'a> {
    buf: *mut u8,
    pub len: usize,
    pub core_buf_size: usize,
    // limit the lifetime of this buffer
    _lifetime: core::marker::PhantomData<&'a u8>,
}

impl<'a> Deref for SmartBuf<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        let core_id = unsafe { pi_core_id() };
        let base = core_id * self.core_buf_size;
        let len = core::cmp::min(
            self.core_buf_size,
            self.len.checked_sub(base).unwrap_or_default(),
        );
        unsafe { core::slice::from_raw_parts::<'a, _>(self.buf.add(base), len) }
    }
}
impl<'a> DerefMut for SmartBuf<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let core_id = unsafe { pi_core_id() };
        let base = core_id * self.core_buf_size;
        let len = core::cmp::min(
            self.core_buf_size,
            self.len.checked_sub(base).unwrap_or_default(),
        );
        unsafe { core::slice::from_raw_parts_mut::<'a, _>(self.buf.add(base), len) }
    }
}
