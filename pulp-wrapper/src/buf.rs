use crate::Cluster;
use ::pulp_sdk_rust::*;
use alloc::boxed::Box;
use cipher::inout::InOutBuf;
use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::ptr::NonNull;

// newtype around naked pointer to guarantee proper allocation and handling
pub(crate) struct BufAlloc<const BUF_LEN: usize> {
    buf: *mut u8,
    allocator: ClusterAllocator,
}

// Newtype around naked pointer to guarantee proper handling
//
// Conceptually a mutable slice but with aliasing in different cores
pub(crate) struct SourcePtr<'a> {
    ptr: *mut u8,
    len: usize,
    _lifetime: PhantomData<&'a u8>,
}

impl<const BUF_LEN: usize> BufAlloc<BUF_LEN> {
    pub fn new(cluster: &mut Cluster) -> Self {
        let device_ptr = unsafe { Pin::get_unchecked_mut(cluster.device_mut()) as *mut PiDevice };
        let allocator = ClusterAllocator::new(device_ptr);
        // SAFETY: u8 are always valid, and this will be overwritten before actual use by DMA
        let buf =
            unsafe { Box::leak(Box::new_uninit_slice_in(BUF_LEN * 3, allocator).assume_init()) };

        Self {
            buf: buf.as_mut_ptr(),
            allocator,
        }
    }
}

impl<const BUF_LEN: usize> Drop for BufAlloc<BUF_LEN> {
    fn drop(&mut self) {
        let _ = unsafe {
            Box::from_raw_in(
                core::slice::from_raw_parts_mut(self.buf, BUF_LEN),
                self.allocator,
            )
        };
    }
}

impl<'a> SourcePtr<'a> {
    /// # Safety
    /// The memory referenced by the slice must not be accessed through any
    /// other pointer (including the original slice) for the duration of
    /// lifetime 'a. Both read and write accesses are forbidden.
    #[allow(unused)]
    pub unsafe fn from_mut_slice(slice: &'a mut [u8]) -> Self {
        SourcePtr {
            ptr: slice.as_mut_ptr(),
            len: slice.len(),
            _lifetime: PhantomData,
        }
    }

    /// # Safety
    /// Behavior is undefined if any of the following conditions are violated:
    /// - `ptr` must point to a properly initialized value of type `T` and
    /// must be valid for reads.
    /// - `in_ptr` and `out_ptr` must be either equal or non-overlapping.
    /// - The memory referenced by ptr must not be accessed through any other pointer
    /// (not derived from the return value) for the duration of lifetime 'a.
    /// Both read and write accesses are forbidden.
    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize) -> Self {
        SourcePtr {
            ptr,
            len,
            _lifetime: PhantomData,
        }
    }
}

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
pub(crate) struct DmaBuf<'buf, 'source, const CORES: usize, const BUF_LEN: usize> {
    // data in external memory
    source: SourcePtr<'source>,
    // allocation in L1 cache
    // Ideally the blocks are layed out in memory so that each core's block lays entirely on a different l1 bank so that we minimize contention
    // on the same bank. Probably we could force this knowing the memory addresses layout
    // DMA should also operate on separate banks
    l1_alloc: &'buf BufAlloc<BUF_LEN>,
    // how many rounds have been completed till now
    rounds: usize,
    pre_fetch_dma: DmaTransfer,
    commit_dma: DmaTransfer,
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

    pub fn new_ram(ram: NonNull<PiDevice>) -> Self {
        Self::Ram {
            req: PiClRamReq::new(ram.as_ptr()),
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

impl<'buf, 'source, const CORES: usize, const BUF_LEN: usize>
    DmaBuf<'buf, 'source, CORES, BUF_LEN>
{
    pub const FULL_WORK_BUF_LEN: usize = BUF_LEN;

    fn common(
        source: SourcePtr<'source>,
        l1_alloc: &'buf BufAlloc<BUF_LEN>,
        mut pre_fetch_dma: DmaTransfer,
        commit_dma: DmaTransfer,
    ) -> Self {
        assert_eq!(BUF_LEN % CORES, 0);
        unsafe {
            let size = core::cmp::min(BUF_LEN * 2, source.len);
            // initialize first buffer
            if pi_core_id() == 0 {
                pre_fetch_dma.transfer_in(source.ptr, l1_alloc.buf, size);
                pre_fetch_dma.wait();
            }
            pi_cl_team_barrier();
        }

        Self {
            l1_alloc,
            pre_fetch_dma,
            commit_dma,
            rounds: 0,
            counters: [0, BUF_LEN, BUF_LEN * 2],
            last_transfer: core::cmp::min(
                BUF_LEN,
                source.len.checked_sub(BUF_LEN).unwrap_or_default(),
            ),
            work_buf_len: core::cmp::min(BUF_LEN, source.len),
            source,
        }
    }

    /// Build a new managed L1 cluster buffer backing a ram memory allocation
    ///
    /// Safety:
    /// * should only be called from within a PULP cluster
    pub fn new_from_ram(
        source: SourcePtr<'source>,
        l1_alloc: &'buf BufAlloc<BUF_LEN>,
        device: NonNull<PiDevice>,
    ) -> Self {
        Self::common(
            source,
            l1_alloc,
            DmaTransfer::new_ram(device),
            DmaTransfer::new_ram(device),
        )
    }

    /// Build a new managed L1 cluster buffer backing a L2 memory allocation
    ///
    /// Safety:
    /// * should only be called from within a PULP cluster
    pub fn new_from_l2(source: SourcePtr<'source>, l1_alloc: &'buf BufAlloc<BUF_LEN>) -> Self {
        Self::common(
            source,
            l1_alloc,
            DmaTransfer::new_l2(),
            DmaTransfer::new_l2(),
        )
    }

    /// Signal that work has completed on the current 'work' buffer
    ///
    /// Safety:
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
            let offset = (self.rounds + 1) * BUF_LEN;
            let size = core::cmp::min(self.source.len.saturating_sub(offset), BUF_LEN);
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
                    self.source.ptr.add((self.rounds - 1) * BUF_LEN),
                    commit_buf_ptr,
                    self.work_buf_len,
                );

                if offset < self.source.len {
                    // start dma in (pre-fetch)
                    let pre_fetch_buf_ptr = self.get_pre_fetch_buf_ptr();
                    self.pre_fetch_dma.transfer_in(
                        self.source.ptr.add(offset),
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
    pub fn get_work_buf(&mut self) -> InOutBuf<'_, '_, u8> {
        let core_buf_len = BUF_LEN / CORES;
        let base = core_buf_len * unsafe { pi_core_id() };
        let len = core::cmp::min(core_buf_len, self.work_buf_len.saturating_sub(base));
        unsafe {
            let ptr = self.l1_alloc.buf.add(base);
            InOutBuf::from_raw(ptr as *const u8, ptr, len)
        }
    }

    #[inline(always)]
    fn get_pre_fetch_buf_ptr(&mut self) -> *mut u8 {
        unsafe { self.l1_alloc.buf.add(self.counters[1]) }
    }

    #[inline(always)]
    fn get_commit_buf_ptr(&mut self) -> *mut u8 {
        unsafe { self.l1_alloc.buf.add(self.counters[2]) }
    }
}
