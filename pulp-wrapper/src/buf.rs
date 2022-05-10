use ::pulp_sdk_rust::*;
use core::ops::{DerefMut, Deref};
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
pub struct DmaBuf {
    // data in external memory
    source: *mut u8,
    source_len: usize,
    // allocation in L1 cache
    l1_alloc: *mut u8,
    // how many rounds has been completed till now
    rounds: usize,
    pre_fetch_dma: PiClDmaCmd,
    commit_dma: PiClDmaCmd,
    buf_size: usize,
    counters: [usize; 3],
    cores: usize,
    last_transfer: usize,
    work_buf_len: usize,
}

impl DmaBuf {
    pub fn new(source: *mut u8, source_len: usize, l1_alloc: *mut u8, l1_alloc_len: usize, cores: usize) -> Self {
        assert_eq!(l1_alloc_len % 3, 0);
        let buf_size = l1_alloc_len / 3;
        assert_eq!(buf_size % cores, 0);
        unsafe {
            let mut tmp = PiClDmaCmd::new();
            let size = core::cmp::min(buf_size * 2, source_len);
            // initialize first buffer
            if pi_core_id() == 0 {
                pi_cl_dma_cmd(
                    source as cty::uint32_t,
                    l1_alloc as cty::uint32_t,
                    size as cty::uint32_t,
                    PiClDmaDirE::PI_CL_DMA_DIR_EXT2LOC,
                    &mut tmp,
                );
                pi_cl_dma_wait(&mut tmp);
            }
            pi_cl_team_barrier();
        }

        Self {
            source,
            source_len,
            l1_alloc,
            pre_fetch_dma: Default::default(),
            commit_dma: Default::default(),
            buf_size,
            rounds: 0,
            counters: [0, buf_size, buf_size * 2],
            cores,
            last_transfer: core::cmp::min(buf_size, source_len.checked_sub(buf_size).unwrap_or_default()),
            work_buf_len: core::cmp::min(buf_size, source_len),
        }
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
            let size = core::cmp::min(self.source_len.checked_sub(offset).unwrap_or_default(), self.buf_size);
            if pi_core_id() == 0 {
                if self.rounds > 1 {
                    // wait dma completed on commit buf before using it as pre-fetch (should not actually wait in practice)
                    pi_cl_dma_wait(&mut self.commit_dma);
                    // wait dma completed on current work buf
                    pi_cl_dma_wait(&mut self.pre_fetch_dma);
                }

                // start dma out (commit)
                pi_cl_dma_cmd(
                    self.source.add((self.rounds - 1) * self.buf_size) as cty::uint32_t,
                    self.get_commit_buf_ptr() as cty::uint32_t,
                    self.work_buf_len as cty::uint32_t,
                    PiClDmaDirE::PI_CL_DMA_DIR_LOC2EXT,
                    &mut self.commit_dma,
                );
                
                if offset < self.source_len {
                    // start dma in (pre-fetch)
                    pi_cl_dma_cmd(
                        self.source.add(offset) as cty::uint32_t,
                        self.get_pre_fetch_buf_ptr() as cty::uint32_t,
                        size as cty::uint32_t,
                        PiClDmaDirE::PI_CL_DMA_DIR_EXT2LOC,
                        &mut self.pre_fetch_dma,
                    );
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
                pi_cl_dma_wait(&mut self.commit_dma);
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
            core_buf_size: self.buf_size / self.cores,
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
pub struct SmartBuf<'a>{
    buf: *mut u8,
    pub len: usize,
    pub core_buf_size: usize,
    // limit the lifetime of this buffer
    _lifetime: core::marker::PhantomData<&'a u8>,
}

impl<'a> Deref for SmartBuf<'a>{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        let core_id = unsafe { pi_core_id() };
        let base = core_id * self.core_buf_size;
        let len = core::cmp::min(self.core_buf_size, self.len.checked_sub(base).unwrap_or_default());
        unsafe { core::slice::from_raw_parts::<'a, _>(self.buf.add(base), len)}
    }
}
impl<'a> DerefMut for SmartBuf<'a>{
    fn deref_mut(&mut self) -> &mut Self::Target {
        let core_id = unsafe { pi_core_id() };
        let base = core_id * self.core_buf_size;
        let len = core::cmp::min(self.core_buf_size, self.len.checked_sub(base).unwrap_or_default());
        unsafe { core::slice::from_raw_parts_mut::<'a, _>(self.buf.add(base), len)}
    }
}
