#![no_std]
#![feature(allocator_api)]
#![feature(default_alloc_error_handler)]
#![feature(new_uninit)]
extern crate alloc;

use alloc::boxed::Box;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, Unsigned};
use core::ptr::NonNull;
use pulp_sdk_rust::*;

use generic_array::GenericArray;

mod buf;
use buf::DmaBuf;

// This should not actually be used, as it's not clear from the context what the default allocation is
#[global_allocator]
static DEFAULT_ALLOCATOR: GlobalAllocator = GlobalAllocator;

const fn parse_cores_u8(s: &str) -> usize {
    let cores = (s.as_bytes()[0] - b'0') as usize;

    if cores.count_ones() != 1 {
        panic!("Unsupported number of cores. Please use a power of 2");
    }
    cores
}

const CORES: usize = parse_cores_u8(core::env!("CORES"));
const CLUSTER_L1_BUFFER_LEN: usize = 2048 * 3;

/// Convenience struct for stream encryption / decryption using the PULP cluster.
/// Supports encryption / decryption directly from ram or L2 memory and manages
/// dma in/out autonomously.
pub struct PulpWrapper<C: StreamCipher + StreamCipherSeek + KeyIvInit> {
    device: *mut PiDevice,
    cluster_buffer: Box<[u8], ClusterAllocator>,
    core_data: NonNull<CoreData<C>>,
    _l1_allocator: ClusterAllocator,
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic_handler(_info: &PanicInfo) -> ! {
    unsafe { abort_all() };
    loop {}
}

#[derive(Clone, Copy)]
pub enum SourceLocation {
    L1,
    L2,
    Ram(*mut PiDevice),
}

impl<C: StreamCipher + StreamCipherSeek + KeyIvInit> PulpWrapper<C> {
    /// Initialize the wrapper and allocates necessary buffers in the cluster.
    /// This enables to reuse allocations across calls to [run].
    ///
    /// Safety:
    ///  * device must be a valid pointer pointing to a correctly initialized PULP cluster
    pub fn new(device: *mut PiDevice) -> Self {
        let l1_allocator = ClusterAllocator::new(device);
        Self {
            cluster_buffer: {
                let buf = Box::new_uninit_slice_in(CLUSTER_L1_BUFFER_LEN, l1_allocator);
                // SAFETY: u8 are always valid, and this will be overwritten before actual use by DMA
                unsafe { buf.assume_init() }
            },
            core_data: NonNull::new(unsafe {
                pi_cl_l1_malloc(device, core::mem::size_of::<CoreData<C>>() as i32)
            } as *mut CoreData<C>)
            .unwrap(),
            _l1_allocator: ClusterAllocator::new(device),
            device,
        }
    }

    /// Encrypt / decrypt data in [source] with given key and iv
    ///
    /// Safety:
    /// * source, key and iv must be valid pointers.
    /// * source must be valid to read / write for len bytes
    /// * source location must be correctly specified in [loc]
    /// * if present, ram device pointer must be valid to read
    /// * key and iv must be located in either L2 or L1 memory and should be valid to read for 32 and 12 bytes respectively
    pub unsafe fn run(
        &mut self,
        source: *mut u8,
        len: usize,
        key: *const u8,
        iv: *const u8,
        loc: SourceLocation,
    ) {
        let key = core::slice::from_raw_parts(key, C::KeySize::USIZE);
        let iv = core::slice::from_raw_parts(iv, C::IvSize::USIZE);
        let arr = <GenericArray<u8, C::KeySize>>::from_slice(key);
        let ivv = <GenericArray<u8, C::IvSize>>::from_slice(iv);
        let data = CoreData::new(
            source,
            len,
            self.cluster_buffer.as_mut_ptr(),
            self.cluster_buffer.len(),
            arr,
            ivv,
            loc,
        );
        // Use ptr::write() not to drop possibly uninitialized memory
        core::ptr::write(self.core_data.as_ptr(), data);

        pi_cl_team_fork(
            CORES,
            Self::entry_point,
            self.core_data.as_ptr() as *mut cty::c_void,
        );
    }

    extern "C" fn entry_point(data: *mut cty::c_void) {
        unsafe {
            let data: &CoreData<C> = &*(data as *const CoreData<C>);
            let CoreData {
                key,
                iv,
                source,
                len,
                l1_alloc,
                l1_alloc_len,
                loc,
            } = *data;
            let key = &*key;
            let iv = &*iv;
            let mut cipher = C::new(key, iv);
            let core_id = pi_core_id();

            // To fit all data in L1 cache, we split input in rounds.
            let mut buf = match loc {
                SourceLocation::L2 => {
                    <DmaBuf<CORES>>::new_from_l2(source, len, l1_alloc, l1_alloc_len)
                }
                SourceLocation::Ram(device) => {
                    <DmaBuf<CORES>>::new_from_ram(source, len, l1_alloc, l1_alloc_len, device)
                }
                _ => panic!("unsupported"),
            };
            let round_buf_len = buf.work_buf_len();
            let full_rounds = len / round_buf_len;
            let base = core_id * (round_buf_len / CORES);
            assert_eq!(round_buf_len % (BLOCK_SIZE * CORES), 0);
            let mut past = 0;

            for _ in 0..full_rounds {
                let mut core_round_buf = buf.get_work_buf();
                cipher.seek(base + past);
                cipher.apply_keystream(&mut core_round_buf);
                past += round_buf_len;
                buf.advance();
            }

            // handle remaining buffer
            if len > past {
                let mut core_round_buf = buf.get_work_buf();
                cipher.seek(base + past);
                cipher.apply_keystream(&mut core_round_buf);
                buf.advance();
            }

            buf.flush();
        }
    }
}

impl<C: StreamCipher + StreamCipherSeek + KeyIvInit> Drop for PulpWrapper<C> {
    fn drop(&mut self) {
        unsafe {
            pi_cl_l1_free(
                self.device,
                self.core_data.as_ptr() as *mut cty::c_void,
                core::mem::size_of::<CoreData<C>>() as i32,
            );
        }
    }
}

const BLOCK_SIZE: usize = 64;

struct CoreData<C: StreamCipher + StreamCipherSeek + KeyIvInit> {
    source: *mut u8,
    len: usize,
    l1_alloc: *mut u8,
    l1_alloc_len: usize,
    key: *const GenericArray<u8, C::KeySize>,
    iv: *const GenericArray<u8, C::IvSize>,
    loc: SourceLocation,
}

impl<C: StreamCipher + StreamCipherSeek + KeyIvInit> CoreData<C> {
    fn new(
        source: *mut u8,
        len: usize,
        l1_alloc: *mut u8,
        l1_alloc_len: usize,
        key: *const GenericArray<u8, C::KeySize>,
        iv: *const GenericArray<u8, C::IvSize>,
        loc: SourceLocation,
    ) -> Self {
        Self {
            source,
            len,
            l1_alloc,
            l1_alloc_len,
            key,
            iv,
            loc,
        }
    }
}
