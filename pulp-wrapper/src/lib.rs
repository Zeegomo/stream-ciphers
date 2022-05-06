#![no_std]

use cipher::{StreamCipher, StreamCipherSeek};
use core::ops::Fn;
use pulp_sdk_rust::*;

mod buf;
pub use buf::DmaBuf;

const fn parse_u8(s: &str) -> usize {
    (s.as_bytes()[0] - b'0') as usize
}

const CORES: usize = parse_u8(core::env!("CORES"));

pub struct PulpWrapper<C, F: Fn() -> C> {
    data: *mut CoreData<C, F>,
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic_handler(_info: &PanicInfo) -> ! {
    loop {}
}

impl<C: StreamCipher + StreamCipherSeek, F: Fn() -> C> PulpWrapper<C, F> {
    pub fn new(
        source: *mut u8,
        len: usize,
        l1_alloc: *mut u8,
        l1_alloc_len: usize,
        cipher: F,
    ) -> Self {
        let data = CoreData::new(source, len, l1_alloc, l1_alloc_len, cipher);
        let align = core::mem::align_of::<CoreData<C, F>>();
        let size = core::mem::size_of::<CoreData<C, F>>();
        core::assert_eq!(align, 4);
        let ptr = unsafe {
            let raw_ptr = pi_l2_malloc(size as cty::c_int);
            let data_ptr = &mut *(raw_ptr as *mut CoreData<C, F>);
            assert_eq!(raw_ptr.align_offset(align), 0);
            // Do not call drop on uninitialized memory
            core::ptr::write(data_ptr, data);
            data_ptr
        };

        Self { data: ptr }
    }

    pub fn run(self) {
        #[cfg(target_arch = "riscv32")]
        unsafe {
            pi_cl_team_fork(CORES, Self::entry_point, self.data as *mut cty::c_void)
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
        let mut cipher = cipher();
        let core_id = unsafe { pi_core_id() };
        // Ideally the blocks are layed out in memory so that each core's block lays entirely on a different l1 bank so that we minimize contention
        // on the same bank. Probably we could force this knowing the memory addresses layout
        // DMA should also operate on separate banks

        // To fit all data in L1 cache, we split input in rounds.
        // Each core will process BLOCKS_PER_ROUND blocks per round. Accounting for DMA triple buffering,
        // this means that we have to fit BLOCKS_PER_ROUND * BLOCK_SIZE * CORES * 3 bytes in L1 cache.
        // Since ChaCha20 operates on 512 byte blocks and assuming all 8 cores active and 64KiB of L1 cache,
        // BLOCKS_PER_ROUND have to be at most 5, leaving some space for core stacks;
        let mut buf = DmaBuf::new(source, len, l1_alloc, l1_alloc_len);
        let round_buf_len = unsafe { buf.get_work_buf().len() };
        let rounds = len / round_buf_len;
        assert_eq!(round_buf_len % (BLOCK_SIZE * CORES), 0);
        assert_eq!(len % round_buf_len, 0);
        let core_buf_size = round_buf_len / CORES;
        assert_eq!(core_buf_size % BLOCK_SIZE, 0);
        assert_eq!(rounds, 5);
        for round in 0..rounds {
            let round_buf = unsafe { buf.get_work_buf() };
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
    fn new(source: *mut u8, len: usize, l1_alloc: *mut u8, l1_alloc_len: usize, cipher: F) -> Self {
        Self {
            source,
            len,
            cipher,
            l1_alloc,
            l1_alloc_len,
        }
    }
}

// /// ChaCha20 encrypt function
// #[no_mangle]
// pub extern "C" fn encrypt(
//     data: *mut u8,
//     len: usize,
//     key: *const u8,
//     l1_alloc: *mut u8,
//     l1_alloc_len: usize,
// ) {
//     let key = Key::from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
//     let core_data = CoreData::new(data, len, l1_alloc, l1_alloc_len, move || {
//         ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]))
//     });
//     let wrapper = PulpWrapper::new(core_data);
//     wrapper.run();
// }

// #[no_mangle]
// pub extern "C" fn encrypt_serial(data: *mut u8, len: usize, key: *const u8) {
//     let data = unsafe { core::slice::from_raw_parts_mut(data, len) };
//     let key = Key::from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
//     let mut chacha = ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]));
//     chacha.apply_keystream(data);
// }

// #[no_mangle]
// pub extern "C" fn encrypt_serial_orig(data: *mut u8, len: usize, key: *const u8) {
//     let data = unsafe { core::slice::from_raw_parts_mut(data, len) };
//     let key = Key::from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
//     let mut chacha = chacha20_orig::ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]));
//     chacha.apply_keystream(data);
// }

// #[cfg(target_arch = "x86_64")]
// mod test {
//     use super::*;

//     #[test]
//     fn test_1_core() {
//         let mut data = [0; 7168];
//         let mut data2 = [0; 7168];

//         let key = Key::from_slice(&[0; 32]);

//         let core_data = CoreData::new(&mut data, move || {
//             ChaCha20::new(key, Nonce::from_slice(&[0u8; 12]))
//         });
//         PulpWrapper::new(core_data).run();

//         ChaCha20::new(key, Nonce::from_slice(&[0u8; 12])).apply_keystream(&mut data2);
//         assert_eq!(data, data2);
//     }
// }
