#![no_std]

use chacha20::{ChaCha20, Key, Nonce};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use core::ops::Fn;

#[cfg(not(target_arch = "riscv32"))]
extern crate std;

#[cfg(target_arch = "riscv32")]
extern "C" {
    pub fn pi_cl_team_fork_tmp(
        num_cores: usize,
        cluster_fn: extern "C" fn(*mut cty::c_void),
        args: *mut cty::c_void,
    );

    pub fn pi_cl_team_barrier_tmp();
}

#[cfg(target_arch = "riscv32")]
extern "C" {
    pub fn pi_l2_malloc_align(size: cty::c_int, align: cty::c_int) -> *mut cty::c_void;
}

#[cfg(target_arch = "riscv32")]
extern "C" {
    pub fn bsp_init();
}

#[cfg(target_arch = "riscv32")]
extern "C" {
    pub fn pi_l2_malloc(size: cty::c_int) -> *mut cty::c_int;

    pub fn pi_cl_l1_malloc(size: cty::c_int) -> *mut cty::c_int;
}
#[cfg(not(target_arch = "riscv32"))]
fn pi_l2_malloc(size: cty::c_int) -> *mut cty::c_int {
    use core::alloc::*;
    unsafe { std::alloc::alloc(Layout::array::<u8>(size as usize).unwrap()) as *mut cty::c_int }
}

#[repr(C)]
pub struct pi_cl_dma_cmd_t {
    id: cty::c_int,
    next: *mut Self,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum pi_cl_dma_dir_e {
    PI_CL_DMA_DIR_LOC2EXT = 0,
    PI_CL_DMA_DIR_EXT2LOC = 1,
}

#[cfg(target_arch = "riscv32")]
extern "C" {

    pub fn pi_cl_dma_cmd_tmp(
        ext: cty::uint32_t,
        loc: cty::uint32_t,
        size: cty::uint32_t,
        dir: pi_cl_dma_dir_e,
        cmd: *mut pi_cl_dma_cmd_t,
    );

    pub fn pi_cl_dma_wait_tmp(copy: *mut cty::c_void);

    pub fn abort_all();
}

fn pi_core_id() -> usize {
    #[cfg(not(target_arch = "riscv32"))]
    {
        1
    }
    #[cfg(target_arch = "riscv32")]
    {
        let core_id: usize;
        unsafe {
            core::arch::asm!("csrr {core_id}, 0x014", core_id = out(reg) core_id,);
        }
        core_id & 0x01f
    }
}

struct PulpWrapper<C, F: Fn() -> C> {
    data: *mut CoreData<C, F>,
}

use core::panic::PanicInfo;

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    unsafe {
        abort_all();
    }
    loop {}
}

const fn parse_u8(s: &str) -> usize {
    if s.len() != 1 {
        //    compile_error!("unsupported value");
    }

    (s.as_bytes()[0] - b'0') as usize
}

const CORES: usize = parse_u8(core::env!("CORES"));

/// A managed buffer in L1 cache with automatic DMA transfers in and out based on
/// rounds
/// DMA triple buffer
/// Since we need to transfer back the modified data, we use divide the L1 allocation
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
pub struct DmaBuf<'a> {
    // data in external memory
    source: *mut u8,
    source_len: usize,
    // allocation in L1 cache
    l1_alloc: &'a mut [u8],
    // how many rounds has been completed till now
    rounds: usize,
    pre_fetch_dma: pi_cl_dma_cmd_t,
    commit_dma: pi_cl_dma_cmd_t,
    buf_size: usize,
    pi_core_id: usize,
    // some bit hacks
    // we save here current and pre-fetch as byte positions, then each turn we rotate right by 8 bits
    // commit can be retrieved as 2 - 
    
}

impl<'a> DmaBuf<'a> {
    pub fn new(source: *mut u8, source_len: usize, l1_alloc: *mut u8, l1_alloc_len: usize) -> Self {
        assert_eq!(l1_alloc_len % 3, 0);
        let buf_size = l1_alloc_len / 3;
        let pi_core_id = pi_core_id();
        unsafe {
            let mut tmp =  pi_cl_dma_cmd_t {
                id: 0,
                next: core::ptr::null_mut(),
            };
            // initialize first buffer
            if pi_core_id == 0 {
                pi_cl_dma_cmd_tmp(
                    source as cty::uint32_t,
                    l1_alloc as cty::uint32_t,
                    (buf_size * 2) as cty::uint32_t,
                    pi_cl_dma_dir_e::PI_CL_DMA_DIR_EXT2LOC,
                    &mut tmp as *mut pi_cl_dma_cmd_t,
                );
                pi_cl_dma_wait_tmp(&mut tmp as *mut pi_cl_dma_cmd_t as *mut cty::c_void);
            }
            pi_cl_team_barrier_tmp();
        }
        
        
        Self {
            source,
            source_len,
            l1_alloc: unsafe { core::slice::from_raw_parts_mut(l1_alloc, l1_alloc_len) },
            pre_fetch_dma: pi_cl_dma_cmd_t {
                id: 0,
                next: core::ptr::null_mut(),
            },
            commit_dma: pi_cl_dma_cmd_t {
                id: 0,
                next: core::ptr::null_mut(),
            },
            pi_core_id ,
            buf_size,
            rounds: 0,
        }
    }

    /// Signal that work has completed on the current 'work' buffer

    #[inline(always)]
    pub fn advance(&mut self) {
        self.rounds += 1;
        // Only core 0 interacts with the dma
        // (this is unsafe only because those are FFI calls)
        unsafe {
            if self.pi_core_id == 0 {
                if self.rounds > 1 {
                    // wait dma completed on commit buf before using it as pre-fetch (should not actually wait in practice)
                    pi_cl_dma_wait_tmp(
                        &mut self.commit_dma as *mut pi_cl_dma_cmd_t as *mut cty::c_void,
                    );
                    // wait dma completed on current work buf
                    pi_cl_dma_wait_tmp(
                        &mut self.pre_fetch_dma as *mut pi_cl_dma_cmd_t as *mut cty::c_void,
                    );
                }

                // start dma out (commit)
                pi_cl_dma_cmd_tmp(
                    self.source.add((self.rounds - 1) * self.buf_size) as cty::uint32_t,
                    self.get_commit_buf().as_mut_ptr() as cty::uint32_t,
                    self.buf_size as cty::uint32_t,
                    pi_cl_dma_dir_e::PI_CL_DMA_DIR_LOC2EXT,
                    &mut self.commit_dma as *mut pi_cl_dma_cmd_t,
                );
                let offset = (self.rounds + 1) * self.buf_size;
                if offset + self.buf_size <= self.source_len {
                    // start dma in (pre-fetch)
                    pi_cl_dma_cmd_tmp(
                        self.source.add(offset) as cty::uint32_t,
                        self.get_pre_fetch_buf().as_mut_ptr() as cty::uint32_t,
                        self.buf_size as cty::uint32_t,
                        pi_cl_dma_dir_e::PI_CL_DMA_DIR_EXT2LOC,
                        &mut self.pre_fetch_dma as *mut pi_cl_dma_cmd_t,
                    );
                }
            }
            // everyone has to wait for transfers to be finished
            pi_cl_team_barrier_tmp();
        }
    }

    /// Finalize by flushing all local cached data upstream
    pub fn flush(&mut self) {
        unsafe {
            if self.pi_core_id == 0 {
                // pi_cl_dma_cmd_tmp(
                //     self.source.add(self.rounds * self.buf_size) as cty::uint32_t,
                //     self.get_work_buf().as_mut_ptr() as cty::uint32_t,
                //     self.buf_size as cty::uint32_t,
                //     pi_cl_dma_dir_e::PI_CL_DMA_DIR_LOC2EXT,
                //     &mut self.commit_dma as *mut pi_cl_dma_cmd_t,
                // );
                pi_cl_dma_wait_tmp(
                    &mut self.commit_dma as *mut pi_cl_dma_cmd_t as *mut cty::c_void,
                );
            }
            pi_cl_team_barrier_tmp();
        }
    }

    
    #[inline(always)]
    pub fn get_work_buf(&mut self) -> &mut [u8] {
        // TODO: optimize remainder
        let counter = self.rounds % 3;
        let base = counter * self.buf_size;
        &mut self.l1_alloc[base..base + self.buf_size]
    }

    
    #[inline(always)]
    fn get_commit_buf(&mut self) -> &mut [u8] {
        // TODO: optimize remainder
        let counter = (self.rounds + 2) % 3;
        let base = counter * self.buf_size;
        &mut self.l1_alloc[base..base + self.buf_size]
    }

    #[inline(always)]
    fn get_pre_fetch_buf(&mut self) -> &mut [u8] {
        // TODO: optimize remainder
        let counter = (self.rounds + 1) % 3;
        let base = counter * self.buf_size;
        &mut self.l1_alloc[base..base + self.buf_size]
    }
}

impl<C: StreamCipher + StreamCipherSeek, F: Fn() -> C> PulpWrapper<C, F> {
    fn new(data: CoreData<C, F>) -> Self {
        let align = core::mem::align_of::<CoreData<C, F>>();
        let size = core::mem::size_of::<CoreData<C, F>>();
        //const L1_BUFFER_SIZE: usize = BLOCK_SIZE * BLOCKS_PER_ROUND * 8;
        core::assert_eq!(align, 4);
        let ptr = unsafe {
            // TODO: we need pi_l2_malloc_align();
            let raw_ptr = pi_l2_malloc(size as cty::c_int);
            let data_ptr = &mut *(raw_ptr as *mut CoreData<C, F>);
            // Do not call drop on uninitialized memory
            core::ptr::write(data_ptr, data);
            data_ptr
        };

        Self { data: ptr }
    }

    pub fn run(self) {
        #[cfg(target_arch = "riscv32")]
        unsafe {
            pi_cl_team_fork_tmp(CORES, Self::entry_point, self.data as *mut cty::c_void)
        };
        #[cfg(not(target_arch = "riscv32"))]
        Self::entry_point(self.data as *mut cty::c_void)
    }

    extern "C" fn entry_point(data: *mut cty::c_void) {
        let data: &mut CoreData<C, F> = unsafe { &mut *(data as *mut CoreData<C, F>) };
        let CoreData {
            ref mut cipher,
            source,
            len,
            l1_alloc,
            l1_alloc_len,
        } = *data;
        //TODO: shoud use malloc_align
        let mut cipher = cipher();
        let core_id = pi_core_id();
        // Ideally the blocks are layed out in memory so that each core's block lays entirely on a different l1 bank so that we minimize contention
        // on the same bank. Probably we could force this knowing the memory addresses layout
        // DMA should also operate on separate banks
        
        
        // To fit all data in L1 cache, we split input in rounds.
        // Each core will process BLOCKS_PER_ROUND blocks per round. Accounting for DMA triple buffering,
        // this means that we have to fit BLOCKS_PER_ROUND * BLOCK_SIZE * CORES * 3 bytes in L1 cache.
        // Since ChaCha20 operates on 512 byte blocks and assuming all 8 cores active and 64KiB of L1 cache,
        // BLOCKS_PER_ROUND have to be at most 5, leaving some space for core stacks;
        let mut buf = <DmaBuf<'_>>::new(source, len, l1_alloc, l1_alloc_len);
        let round_buf_len = buf.get_work_buf().len();
        let rounds = len / round_buf_len;
        assert_eq!(round_buf_len % (BLOCK_SIZE * CORES), 0);
        assert_eq!(len % round_buf_len, 0);
        let core_buf_size = round_buf_len / CORES;
        assert_eq!(core_buf_size % BLOCK_SIZE, 0);
        assert_eq!(rounds, 5);
        for round in 0..rounds {
            let round_buf = buf.get_work_buf();
            let base = core_id * core_buf_size;
            let buffer = &mut round_buf[base..base + core_buf_size];
            let past = round * round_buf_len;
            cipher.seek(base + past);
            cipher.apply_keystream(buffer);

            buf.advance();
        }
        
        buf.flush();
    }
}

const BLOCK_SIZE: usize = 512;

struct CoreData<C, F: Fn() -> C> {
    source: *mut u8,
    len: usize,
    cipher: F,
    l1_alloc: *mut u8,
    l1_alloc_len: usize,
}

impl<'a, C, F: Fn() -> C> CoreData<C, F> {
    pub fn new(source: *mut u8, len: usize, l1_alloc: *mut u8, l1_alloc_len: usize, cipher: F) -> Self {
        Self {
            source,
            len,
            cipher,
            l1_alloc,
            l1_alloc_len
        }
    }
}

/// ChaCha20 encrypt function
#[no_mangle]
pub extern "C" fn encrypt(
    data: *mut u8,
    len: usize,
    key: *const u8,
    l1_alloc: *mut u8,
    l1_alloc_len: usize,
) {
    let key = Key::from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
    let core_data = CoreData::new(data, len, l1_alloc, l1_alloc_len, move || {
        ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]))
    });
    let wrapper = PulpWrapper::new(core_data);
    wrapper.run();
}

#[no_mangle]
pub extern "C" fn encrypt_serial(data: *mut u8, len: usize, key: *const u8) {
    let data = unsafe { core::slice::from_raw_parts_mut(data, len) };
    let key = Key::from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
    let mut chacha = ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]));
    chacha.apply_keystream(data);
}

#[no_mangle]
pub extern "C" fn encrypt_serial_orig(data: *mut u8, len: usize, key: *const u8) {
    let data = unsafe { core::slice::from_raw_parts_mut(data, len) };
    let key = Key::from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
    let mut chacha = chacha20_orig::ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]));
    chacha.apply_keystream(data);
}

#[cfg(target_arch = "x86_64")]
mod test {
    use super::*;

    #[test]
    fn test_1_core() {
        let mut data = [0; 7168];
        let mut data2 = [0; 7168];

        let key = Key::from_slice(&[0; 32]);

        let core_data = CoreData::new(&mut data, move || {
            ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]))
        });
        PulpWrapper::new(core_data).run();

        ChaCha20::new(key, Nonce::from_slice(&[0u8; 12])).apply_keystream(&mut data2);
        assert_eq!(data, data2);
    }
}
