use ::pulp_sdk_rust::*;
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
}

impl DmaBuf {
    pub fn new(source: *mut u8, source_len: usize, l1_alloc: *mut u8, l1_alloc_len: usize) -> Self {
        assert_eq!(l1_alloc_len % 3, 0);
        let buf_size = l1_alloc_len / 3;
        unsafe {
            let mut tmp = PiClDmaCmd::new();
            // initialize first buffer
            if pi_core_id() == 0 {
                pi_cl_dma_cmd(
                    source as cty::uint32_t,
                    l1_alloc as cty::uint32_t,
                    (buf_size * 2) as cty::uint32_t,
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
        }
    }

    /// Signal that work has completed on the current 'work' buffer
    #[inline(never)]
    pub fn advance(&mut self) {
        self.rounds += 1;
        let a = self.counters[0];
        self.counters[0] = self.counters[1];
        self.counters[1] = self.counters[2];
        self.counters[2] = a;
        // Only core 0 interacts with the dma
        // (this is unsafe only because those are FFI calls)
        unsafe {
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
                    self.get_commit_buf().as_mut_ptr() as cty::uint32_t,
                    self.buf_size as cty::uint32_t,
                    PiClDmaDirE::PI_CL_DMA_DIR_LOC2EXT,
                    &mut self.commit_dma,
                );
                let offset = (self.rounds + 1) * self.buf_size;
                if offset + self.buf_size <= self.source_len {
                    // start dma in (pre-fetch)
                    pi_cl_dma_cmd(
                        self.source.add(offset) as cty::uint32_t,
                        self.get_pre_fetch_buf().as_mut_ptr() as cty::uint32_t,
                        self.buf_size as cty::uint32_t,
                        PiClDmaDirE::PI_CL_DMA_DIR_EXT2LOC,
                        &mut self.pre_fetch_dma,
                    );
                }
            }
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
    pub unsafe fn get_work_buf(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.l1_alloc.add(self.counters[0]), self.buf_size)
    }

    #[inline(never)]
    fn get_pre_fetch_buf(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self.l1_alloc.add(self.counters[1]), self.buf_size)
        }
    }

    #[inline(never)]
    fn get_commit_buf(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self.l1_alloc.add(self.counters[2]), self.buf_size)
        }
    }
}
