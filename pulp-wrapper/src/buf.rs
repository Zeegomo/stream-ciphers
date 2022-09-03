use ::pulp_sdk_rust::*;
use cipher::inout::InOutBuf;
use core::marker::PhantomPinned;
use core::ops::{Deref, DerefMut};

/// A managed buffer in L1 cache with automatic DMA transfers in and out based on
/// rounds
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

enum DmaTransfer {
    Ram {
        req: PiClRamReq,
        _pin: PhantomPinned,
    },
    L2 {
        cmd: PiClDmaCmd,
        _pin: PhantomPinned,
    },
}

// TODO: ensure can't be unpinned
// It's safe for now as it's a private struct and we know that we never move it,
// but it will be necessary to make [DmaBuf] a public struct.
impl DmaTransfer {
    pub fn new_l2() -> Self {
        Self::L2 {
            cmd: PiClDmaCmd::new(),
            _pin: PhantomPinned,
        }
    }

    pub fn new_ram(ram: *mut PiDevice) -> Self {
        Self::Ram {
            req: PiClRamReq::new(ram),
            _pin: PhantomPinned,
        }
    }

    unsafe fn transfer_in(&mut self, remote: *mut u8, l1: *mut u8, len: usize) {
        match self {
            Self::Ram { ref mut req, .. } => {
                pi_cl_ram_read(req.device(), remote, l1, len, req);
            }
            Self::L2 { ref mut cmd, .. } => {
                pi_cl_dma_cmd(remote, l1, len, PiClDmaDirE::PI_CL_DMA_DIR_EXT2LOC, cmd);
            }
        }
    }

    unsafe fn transfer_out(&mut self, remote: *mut u8, l1: *mut u8, len: usize) {
        match self {
            Self::Ram { ref mut req, .. } => {
                pi_cl_ram_write(req.device(), remote, l1, len, req);
            }
            Self::L2 { ref mut cmd, .. } => {
                pi_cl_dma_cmd(remote, l1, len, PiClDmaDirE::PI_CL_DMA_DIR_LOC2EXT, cmd);
            }
        }
    }

    // TODO typestate
    // Safety: do not call on uninitialized requests
    unsafe fn wait(&mut self) {
        match self {
            Self::Ram { ref mut req, .. } if req.is_in_transfer() => pi_cl_ram_read_wait(req),
            Self::Ram { ref mut req, .. } => pi_cl_ram_write_wait(req),
            Self::L2 { ref mut cmd, .. } => pi_cl_dma_wait(cmd),
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

    /// Build a new managed L1 cluster buffer backing a ram memory allocation
    ///
    /// Safety:
    /// * source must be valid to read for source_len bytes
    /// * l1_alloc must be valid to read / write for l1_alloc_len bytes
    /// * should only be called from within a PULP cluster
    pub fn new_from_ram(
        source: *mut u8,
        source_len: usize,
        l1_alloc: *mut u8,
        l1_alloc_len: usize,
        device: *mut PiDevice,
    ) -> Self {
        Self::common(
            source,
            source_len,
            l1_alloc,
            l1_alloc_len,
            DmaTransfer::new_ram(device),
            DmaTransfer::new_ram(device),
        )
    }

    /// Build a new managed L1 cluster buffer backing a L2 memory allocation
    ///
    /// Safety:
    /// * source must be valid to read for source_len bytes
    /// * l1_alloc must be valid to read / write for l1_alloc_len bytes
    /// * should only be called from within a PULP cluster
    pub fn new_from_l2(
        source: *mut u8,
        source_len: usize,
        l1_alloc: *mut u8,
        l1_alloc_len: usize,
    ) -> Self {
        Self::common(
            source,
            source_len,
            l1_alloc,
            l1_alloc_len,
            DmaTransfer::new_l2(),
            DmaTransfer::new_l2(),
        )
    }

    pub fn work_buf_len(&self) -> usize {
        self.buf_size
    }

    /// Signal that work has completed on the current 'work' buffer
    ///
    /// Safety:
    /// * source must be valid to read / write for source_len bytes
    /// * l1_alloc must be valid to read / write for l1_alloc_len bytes
    /// * should only be called from within a PULP cluster
    #[inline]
    pub fn advance(&mut self) {
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
                self.source_len.saturating_sub(offset),
                self.buf_size,
            );
            if pi_core_id() == 0 {
                if self.rounds > 1 {
                    // wait dma completed on commit buf before using it as pre-fetch (should not actually wait in practice)
                    self.commit_dma.wait();
                    // wait dma completed on current work buf
                    self.pre_fetch_dma.wait();
                }

                pi_cl_team_barrier();

                // start dma out (commit)
                let commit_buf_ptr = self.get_commit_buf_ptr();
                self.commit_dma.transfer_out(
                    self.source.add((self.rounds - 1) * self.buf_size),
                    commit_buf_ptr,
                    self.work_buf_len,
                );

                if offset < self.source_len {
                    // start dma in (pre-fetch)
                    let pre_fetch_buf_ptr = self.get_pre_fetch_buf_ptr();
                    self.pre_fetch_dma.transfer_in(
                        self.source.add(offset),
                        pre_fetch_buf_ptr,
                        size,
                    );
                }
            } else {
                // everyone has to wait for transfers to be finished
                pi_cl_team_barrier();
            }

            self.work_buf_len = self.last_transfer;
            self.last_transfer = size;
            
        }
    }

    /// Finalize by flushing all local cached data upstream
    ///
    /// Safety:
    /// * must be called in the PULP cluster
    /// * must be called after having called advance() at least once
    pub unsafe fn flush(&mut self) {
        if pi_core_id() == 0 {
            self.commit_dma.wait();
        }
        pi_cl_team_barrier();
    }

    /// Get mutable pointers to working core buffer
    #[inline(always)]
    pub fn get_work_buf<'a>(&'a mut self) -> InOutBuf<'a, 'a, u8> {
        let core_buf_len = self.buf_size / CORES;
        let base = core_buf_len * unsafe { pi_core_id() };
        let len = core::cmp::min(core_buf_len, self.work_buf_len.saturating_sub(base));
        unsafe {
            let ptr = self.l1_alloc.add(base);
            InOutBuf::from_raw(ptr as *const u8, ptr, len)
        }
    }

    #[inline(always)]
    fn get_pre_fetch_buf_ptr(&mut self) -> *mut u8 {
        unsafe { self.l1_alloc.add(self.counters[1]) }
    }

    #[inline(always)]
    fn get_commit_buf_ptr(&mut self) -> *mut u8 {
        unsafe { self.l1_alloc.add(self.counters[2]) }
    }
}
