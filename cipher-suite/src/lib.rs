#![no_std]
#![feature(allocator_api)]
#![feature(default_alloc_error_handler)]
#![feature(new_uninit)]
extern crate alloc;

use crate::alloc::string::ToString;
use alloc::boxed::Box;
use chacha20::ChaCha20;
use cipher::{IvSizeUser, KeySizeUser, Unsigned};
use core::pin::Pin;
use core::ptr::NonNull;
use generic_array::GenericArray;
use pulp_sdk_rust::{abort_all, print, GlobalAllocator, PiDevice};
use pulp_wrapper::{Cluster, PulpWrapper, SourceLocation};
// This should not actually be used, as it's not clear from the context what the default allocation is
#[global_allocator]
static DEFAULT_ALLOCATOR: GlobalAllocator = GlobalAllocator;

use core::panic::PanicInfo;

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    print(info.to_string());
    unsafe { abort_all() };
    loop {}
}

#[repr(C)]
pub enum Cipher {
    ChaCha20,
    Rc4,
    Rabbit,
}

/// Initialize the cluster wrapper in L2 memory
///
/// Safety:
/// * device must be a valid pointer to a correctly initialized PULP cluster
#[no_mangle]
pub extern "C" fn cluster_init(cluster_loc: *mut *mut PiDevice) -> *mut cty::c_void {
    let mut cluster = Cluster::new().unwrap();
    unsafe {
        *cluster_loc = Pin::get_unchecked_mut(cluster.device_mut());
    }
    let wrapper = Box::new_in(<PulpWrapper>::new(cluster), pulp_sdk_rust::L2Allocator);
    Box::into_raw(wrapper) as *mut cty::c_void
}

/// Encrypt / decrypt using the provided cipher
///
/// Safety:
/// * data must be valid to read / write for len bytes and must be in L2 memory
/// * key must be valid to read for: 32 bytes
/// * iv must be valid to read for 12 bytes
/// * wrapper must be a valid pointer to an initialized PULP Wrapper allocated by this library
#[no_mangle]
pub unsafe extern "C" fn encrypt(
    data: *mut u8,
    len: usize,
    key: *const u8,
    iv: *const u8,
    wrapper: *mut cty::c_void,
    ram_device: *mut PiDevice,
    cipher: Cipher,
) {
    let wrapper = (wrapper as *mut PulpWrapper).as_mut().unwrap();
    let data = core::slice::from_raw_parts_mut(data, len);
    let location = if let Some(device) = NonNull::new(ram_device) {
        SourceLocation::Ram(device)
    } else {
        SourceLocation::L2
    };
    let (key_size, iv_size) = match cipher {
        Cipher::ChaCha20 => (
            <ChaCha20 as KeySizeUser>::KeySize::USIZE,
            <ChaCha20 as IvSizeUser>::IvSize::USIZE,
        ),
        _ => unimplemented!(),
    };
    let key = GenericArray::from_slice(core::slice::from_raw_parts(key, key_size));
    let iv = GenericArray::from_slice(core::slice::from_raw_parts(iv, iv_size));
    match cipher {
        Cipher::ChaCha20 => wrapper.run::<chacha20::ChaCha20>(data, key, iv, location),
        _ => unimplemented!(),
    }
}

/// Clean up resources used by the PULP wrapper
///
/// Safety: wrapper must be a valid pointer to an initialized PULP wrapper
#[no_mangle]
pub unsafe extern "C" fn cluster_close(wrapper: *mut cty::c_void) {
    let _wrapper = Box::from_raw_in(wrapper, pulp_sdk_rust::L2Allocator);
}

/// Encrypt data serially using the unmodified version of this library
///
/// Safety:
/// * data must be valid to read / write for len bytes and must be in L2 memory
/// * key must be valid to read for 32 bytes
/// * iv must be valid to read for 12 bytes
#[no_mangle]
pub extern "C" fn encrypt_serial_orig(data: *mut u8, len: usize, key: *const u8, iv: *const u8) {
    use chacha20_orig::cipher::StreamCipher;
    use chacha20_orig::*;
    use cipher::KeyIvInit;
    let data = unsafe { core::slice::from_raw_parts_mut(data, len) };
    let key = Key::from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
    let iv = Nonce::from_slice(unsafe { core::slice::from_raw_parts(iv, 12) });
    let mut chacha = chacha20_orig::ChaCha20::new(key, iv);
    chacha.apply_keystream(data);
}
