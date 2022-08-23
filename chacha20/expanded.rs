#![feature(prelude_import)]
#![doc = " Implementation of the [ChaCha] family of stream ciphers."]
#![doc = ""]
#![doc = " Cipher functionality is accessed using traits from re-exported [`cipher`] crate."]
#![doc = ""]
#![doc = " ChaCha stream ciphers are lightweight and amenable to fast, constant-time"]
#![doc = " implementations in software. It improves upon the previous [Salsa] design,"]
#![doc = " providing increased per-round diffusion with no cost to performance."]
#![doc = ""]
#![doc = " This crate contains the following variants of the ChaCha20 core algorithm:"]
#![doc = ""]
#![doc = " - [`ChaCha20`]: standard IETF variant with 96-bit nonce"]
#![doc = " - [`ChaCha8`] / [`ChaCha12`]: reduced round variants of ChaCha20"]
#![doc = " - [`XChaCha20`]: 192-bit extended nonce variant"]
#![doc = " - [`XChaCha8`] / [`XChaCha12`]: reduced round variants of XChaCha20"]
#![doc = " - [`ChaCha20Legacy`]: \"djb\" variant with 64-bit nonce."]
#![doc = " **WARNING:** This implementation internally uses 32-bit counter,"]
#![doc = " while the original implementation uses 64-bit coutner. In other words,"]
#![doc = " it does not allow encryption of more than 256 GiB of data."]
#![doc = ""]
#![doc = " # ⚠\u{fe0f} Security Warning: Hazmat!"]
#![doc = ""]
#![doc = " This crate does not ensure ciphertexts are authentic, which can lead to"]
#![doc = " serious vulnerabilities if used incorrectly!"]
#![doc = ""]
#![doc = " If in doubt, use the [`chacha20poly1305`] crate instead, which provides"]
#![doc = " an authenticated mode on top of ChaCha20."]
#![doc = ""]
#![doc = " **USE AT YOUR OWN RISK!**"]
#![doc = ""]
#![doc = " # Diagram"]
#![doc = ""]
#![doc = " This diagram illustrates the ChaCha quarter round function."]
#![doc = " Each round consists of four quarter-rounds:"]
#![doc = ""]
#![doc = " <img src=\"https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/img/stream-ciphers/chacha20.png\" width=\"300px\">"]
#![doc = ""]
#![doc = " Legend:"]
#![doc = ""]
#![doc = " - ⊞ add"]
#![doc = " - ‹‹‹ rotate"]
#![doc = " - ⊕ xor"]
#![doc = ""]
#![doc = " # Example"]
#![doc = " ```"]
#![doc = " use chacha20::ChaCha20;"]
#![doc = " // Import relevant traits"]
#![doc = " use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};"]
#![doc = " use hex_literal::hex;"]
#![doc = ""]
#![doc = " let key = [0x42; 32];"]
#![doc = " let nonce = [0x24; 12];"]
#![doc = " let plaintext = hex!(\"00010203 04050607 08090A0B 0C0D0E0F\");"]
#![doc = " let ciphertext = hex!(\"e405626e 4f1236b3 670ee428 332ea20e\");"]
#![doc = ""]
#![doc = " // Key and IV must be references to the `GenericArray` type."]
#![doc = " // Here we use the `Into` trait to convert arrays into it."]
#![doc = " let mut cipher = ChaCha20::new(&key.into(), &nonce.into());"]
#![doc = ""]
#![doc = " let mut buffer = plaintext.clone();"]
#![doc = ""]
#![doc = " // apply keystream (encrypt)"]
#![doc = " cipher.apply_keystream(&mut buffer);"]
#![doc = " assert_eq!(buffer, ciphertext);"]
#![doc = ""]
#![doc = " let ciphertext = buffer.clone();"]
#![doc = ""]
#![doc = " // ChaCha ciphers support seeking"]
#![doc = " cipher.seek(0u32);"]
#![doc = ""]
#![doc = " // decrypt ciphertext by applying keystream again"]
#![doc = " cipher.apply_keystream(&mut buffer);"]
#![doc = " assert_eq!(buffer, plaintext);"]
#![doc = ""]
#![doc = " // stream ciphers can be used with streaming messages"]
#![doc = " cipher.seek(0u32);"]
#![doc = " for chunk in buffer.chunks_mut(3) {"]
#![doc = "     cipher.apply_keystream(chunk);"]
#![doc = " }"]
#![doc = " assert_eq!(buffer, ciphertext);"]
#![doc = " ```"]
#![doc = ""]
#![doc = " # Configuration Flags"]
#![doc = ""]
#![doc = " You can modify crate using the following configuration flags:"]
#![doc = ""]
#![doc = " - `chacha20_force_soft`: force software backend."]
#![doc = " - `chacha20_force_sse2`: force SSE2 backend. Requires enabled SSE2 target feature,"]
#![doc = " ignored on non-x86(-64) targets."]
#![doc = " - `chacha20_force_avx2`: force AVX2 backend. Requires enabled AVX2 target feature,"]
#![doc = " ignored on non-x86(-64) targets."]
#![doc = ""]
#![doc = " The flags can be enabled using `RUSTFLAGS` enviromental variable"]
#![doc = " (e.g. `RUSTFLAGS=\"--cfg chacha20_force_avx2\"`) or by modifying `.cargo/config`."]
#![doc = ""]
#![doc = " You SHOULD NOT enable several `force` flags simultaneously."]
#![doc = ""]
#![doc = " [ChaCha]: https://tools.ietf.org/html/rfc8439"]
#![doc = " [Salsa]: https://en.wikipedia.org/wiki/Salsa20"]
#![doc = " [`chacha20poly1305`]: https://docs.rs/chacha20poly1305"]
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/chacha20/0.9.0"
)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]
#![allow(clippy::needless_range_loop)]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
#[macro_use]
extern crate compiler_builtins;
pub use cipher;
use cfg_if::cfg_if;
use cipher::{
    consts::{U10, U12, U32, U4, U6, U64},
    generic_array::{typenum::Unsigned, GenericArray},
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};
use core::marker::PhantomData;
mod backends {
    use cfg_if::cfg_if;
    pub(crate) mod pulp {
        #![doc = " Portable implementation which does not rely on architecture-specific"]
        #![doc = " intrinsics."]
        use crate::{Block, ChaChaCore, Unsigned, STATE_WORDS};
        use cipher::{
            consts::{U1, U64},
            BlockSizeUser, ParBlocksSizeUser, StreamBackend,
        };
        pub(crate) struct Backend<'a, R: Unsigned>(pub(crate) &'a mut ChaChaCore<R>);
        impl<'a, R: Unsigned> BlockSizeUser for Backend<'a, R> {
            type BlockSize = U64;
        }
        impl<'a, R: Unsigned> ParBlocksSizeUser for Backend<'a, R> {
            type ParBlocksSize = U1;
        }
        impl<'a, R: Unsigned> StreamBackend for Backend<'a, R> {
            #[inline(always)]
            fn gen_ks_block(&mut self, block: &mut Block) {
                let res = run_rounds::<R>(self.0.state);
                self.0.state[12] = self.0.state[12].wrapping_add(1);
                for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
                    let chunk = chunk.as_mut_ptr() as *mut u32;
                    unsafe {
                        core::ptr::write(chunk, *val);
                    }
                }
            }
        }
        const S1: u8 = 17;
        const S2: u8 = 16;
        const S3: u8 = 15;
        const S4: u8 = 14;
        use asm_macros::{xor, add, ror};
        #[inline(always)]
        fn run_rounds<R: Unsigned>(state: [u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
            let mut res = state;
            for _ in 0..R::USIZE {
                unsafe {
                    asm ! ("add x16, x16, x20\nxor x28, x28, x16\n.4byte 0x91E5E33\nadd x24, x24, x28\nxor x20, x20, x24\n.4byte 0x90A5A33\nadd x16, x16, x20\nxor x28, x28, x16\n.4byte 0x8FE5E33\nadd x24, x24, x28\nxor x20, x20, x24\n.4byte 0x8EA5A33\n\nadd x17, x17, x21\nxor x29, x29, x17\n.4byte 0x91EDEB3\nadd x25, x25, x29\nxor x21, x21, x25\n.4byte 0x90ADAB3\nadd x17, x17, x21\nxor x29, x29, x17\n.4byte 0x8FEDEB3\nadd x25, x25, x29\nxor x21, x21, x25\n.4byte 0x8EADAB3\n\nadd x18, x18, x22\nxor x30, x30, x18\n.4byte 0x91F5F33\nadd x26, x26, x30\nxor x22, x22, x26\n.4byte 0x90B5B33\nadd x18, x18, x22\nxor x30, x30, x18\n.4byte 0x8FF5F33\nadd x26, x26, x30\nxor x22, x22, x26\n.4byte 0x8EB5B33\n\nadd x19, x19, x23\nxor x31, x31, x19\n.4byte 0x91FDFB3\nadd x27, x27, x31\nxor x23, x23, x27\n.4byte 0x90BDBB3\nadd x19, x19, x23\nxor x31, x31, x19\n.4byte 0x8FFDFB3\nadd x27, x27, x31\nxor x23, x23, x27\n.4byte 0x8EBDBB3\n\nadd x16, x16, x21\nxor x31, x31, x16\n.4byte 0x91FDFB3\nadd x26, x26, x31\nxor x21, x21, x26\n.4byte 0x90ADAB3\nadd x16, x16, x21\nxor x31, x31, x16\n.4byte 0x8FFDFB3\nadd x26, x26, x31\nxor x21, x21, x26\n.4byte 0x8EADAB3\n\nadd x17, x17, x22\nxor x12, x12, x17\n.4byte 0x9165633\nadd x27, x27, x12\nxor x22, x22, x27\n.4byte 0x90B5B33\nadd x17, x17, x22\nxor x12, x12, x17\n.4byte 0x8F65633\nadd x27, x27, x12\nxor x22, x22, x27\n.4byte 0x8EB5B33\n\nadd x18, x18, x23\nxor x13, x13, x18\n.4byte 0x916D6B3\nadd x24, x24, x13\nxor x23, x23, x24\n.4byte 0x90BDBB3\nadd x18, x18, x23\nxor x13, x13, x18\n.4byte 0x8F6D6B3\nadd x24, x24, x13\nxor x23, x23, x24\n.4byte 0x8EBDBB3\n\nadd x19, x19, x20\nxor x14, x14, x19\n.4byte 0x9175733\nadd x25, x25, x14\nxor x20, x20, x25\n.4byte 0x90A5A33\nadd x19, x19, x20\nxor x14, x14, x19\n.4byte 0x8F75733\nadd x25, x25, x14\nxor x20, x20, x25\n.4byte 0x8EA5A33\n" , inout ("x16") res [0] , inout ("x17") res [1] , inout ("x18") res [2] , inout ("x19") res [3] , inout ("x20") res [4] , inout ("x21") res [5] , inout ("x22") res [6] , inout ("x23") res [7] , inout ("x24") res [8] , inout ("x25") res [9] , inout ("x26") res [10] , inout ("x27") res [11] , inout ("x28") res [12] , inout ("x29") res [13] , inout ("x30") res [14] , inout ("x31") res [15] , options (pure , nomem))
                };
            }
            for (s1, s0) in res.iter_mut().zip(state.iter()) {
                *s1 = s1.wrapping_add(*s0);
            }
            res
        }
        #[inline(always)]
        fn quarter_round(
            a: usize,
            b: usize,
            c: usize,
            d: usize,
            state: &mut [u32; STATE_WORDS],
            s1: u32,
            s2: u32,
            s3: u32,
            s4: u32,
        ) {
            unsafe {
                asm ! ("add {0}, {0}, {1}\nxor t0, {3}, {0}\n.4byte 0x922d2b3\nadd {2}, {2}, t0\nxor t1, {1}, {2}\n.4byte 0x9335333\nadd {0}, t1, {0}\nxor t0, t0, {0}\n.4byte 0x942d2b3\nadd {2}, t0, {2}\nxor t1, {2}, t1\n.4byte 0x9535333" , inout (reg) state [a] , in (reg) state [b] , inout (reg) state [c] , in (reg) state [d] , out ("t0") state [d] , out ("t2") state [c] , in ("s2") s1 , in ("s3") s2 , in ("s4") s3 , in ("s5") s4 , options (nomem))
            }
        }
    }
}
mod legacy {
    #![doc = " Legacy version of ChaCha20 with a 64-bit nonce"]
    use super::{ChaChaCore, Key, Nonce};
    use cipher::{
        consts::{U10, U32, U64, U8},
        generic_array::GenericArray,
        BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore,
        StreamCipherCoreWrapper, StreamCipherSeekCore, StreamClosure,
    };
    #[doc = " Nonce type used by [`ChaCha20Legacy`]."]
    pub type LegacyNonce = GenericArray<u8, U8>;
    #[doc = " The ChaCha20 stream cipher (legacy \"djb\" construction with 64-bit nonce)."]
    #[doc = ""]
    #[doc = " **WARNING:** this implementation uses 32-bit counter, while the original"]
    #[doc = " implementation uses 64-bit counter. In other words, it does"]
    #[doc = " not allow encrypting of more than 256 GiB of data."]
    pub type ChaCha20Legacy = StreamCipherCoreWrapper<ChaCha20LegacyCore>;
    #[doc = " The ChaCha20 stream cipher (legacy \"djb\" construction with 64-bit nonce)."]
    pub struct ChaCha20LegacyCore(ChaChaCore<U10>);
    impl KeySizeUser for ChaCha20LegacyCore {
        type KeySize = U32;
    }
    impl IvSizeUser for ChaCha20LegacyCore {
        type IvSize = U8;
    }
    impl BlockSizeUser for ChaCha20LegacyCore {
        type BlockSize = U64;
    }
    impl KeyIvInit for ChaCha20LegacyCore {
        #[inline(always)]
        fn new(key: &Key, iv: &LegacyNonce) -> Self {
            let mut padded_iv = Nonce::default();
            padded_iv[4..].copy_from_slice(iv);
            ChaCha20LegacyCore(ChaChaCore::new(key, &padded_iv))
        }
    }
    impl StreamCipherCore for ChaCha20LegacyCore {
        #[inline(always)]
        fn remaining_blocks(&self) -> Option<usize> {
            self.0.remaining_blocks()
        }
        #[inline(always)]
        fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
            self.0.process_with_backend(f);
        }
    }
    impl StreamCipherSeekCore for ChaCha20LegacyCore {
        type Counter = u32;
        #[inline(always)]
        fn get_block_pos(&self) -> u32 {
            self.0.get_block_pos()
        }
        #[inline(always)]
        fn set_block_pos(&mut self, pos: u32) {
            self.0.set_block_pos(pos);
        }
    }
}
mod xchacha {
    #![doc = " XChaCha is an extended nonce variant of ChaCha"]
    use super::{ChaChaCore, Key, Nonce, CONSTANTS, STATE_WORDS};
    use cipher::{
        consts::{U10, U16, U24, U32, U4, U6, U64},
        generic_array::{typenum::Unsigned, GenericArray},
        BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore,
        StreamCipherCoreWrapper, StreamCipherSeekCore, StreamClosure,
    };
    #[doc = " Nonce type used by XChaCha variants."]
    pub type XNonce = GenericArray<u8, U24>;
    #[doc = " XChaCha is a ChaCha20 variant with an extended 192-bit (24-byte) nonce."]
    #[doc = ""]
    #[doc = " The construction is an adaptation of the same techniques used by"]
    #[doc = " XChaCha as described in the paper \"Extending the Salsa20 Nonce\","]
    #[doc = " applied to the 96-bit nonce variant of ChaCha20, and derive a"]
    #[doc = " separate subkey/nonce for each extended nonce:"]
    #[doc = ""]
    #[doc = " <https://cr.yp.to/snuffle/xsalsa-20081128.pdf>"]
    #[doc = ""]
    #[doc = " No authoritative specification exists for XChaCha20, however the"]
    #[doc = " construction has \"rough consensus and running code\" in the form of"]
    #[doc = " several interoperable libraries and protocols (e.g. libsodium, WireGuard)"]
    #[doc = " and is documented in an (expired) IETF draft:"]
    #[doc = ""]
    #[doc = " <https://tools.ietf.org/html/draft-arciszewski-xchacha-03>"]
    pub type XChaCha20 = StreamCipherCoreWrapper<XChaChaCore<U10>>;
    #[doc = " XChaCha12 stream cipher (reduced-round variant of [`XChaCha20`] with 12 rounds)"]
    pub type XChaCha12 = StreamCipherCoreWrapper<XChaChaCore<U6>>;
    #[doc = " XChaCha8 stream cipher (reduced-round variant of [`XChaCha20`] with 8 rounds)"]
    pub type XChaCha8 = StreamCipherCoreWrapper<XChaChaCore<U4>>;
    #[doc = " The XChaCha core function."]
    pub struct XChaChaCore<R: Unsigned>(ChaChaCore<R>);
    impl<R: Unsigned> KeySizeUser for XChaChaCore<R> {
        type KeySize = U32;
    }
    impl<R: Unsigned> IvSizeUser for XChaChaCore<R> {
        type IvSize = U24;
    }
    impl<R: Unsigned> BlockSizeUser for XChaChaCore<R> {
        type BlockSize = U64;
    }
    impl<R: Unsigned> KeyIvInit for XChaChaCore<R> {
        fn new(key: &Key, iv: &XNonce) -> Self {
            let subkey = hchacha::<R>(key, iv[..16].as_ref().into());
            let mut padded_iv = Nonce::default();
            padded_iv[4..].copy_from_slice(&iv[16..]);
            XChaChaCore(ChaChaCore::new(&subkey, &padded_iv))
        }
    }
    impl<R: Unsigned> StreamCipherCore for XChaChaCore<R> {
        #[inline(always)]
        fn remaining_blocks(&self) -> Option<usize> {
            self.0.remaining_blocks()
        }
        #[inline(always)]
        fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
            self.0.process_with_backend(f);
        }
    }
    impl<R: Unsigned> StreamCipherSeekCore for XChaChaCore<R> {
        type Counter = u32;
        #[inline(always)]
        fn get_block_pos(&self) -> u32 {
            self.0.get_block_pos()
        }
        #[inline(always)]
        fn set_block_pos(&mut self, pos: u32) {
            self.0.set_block_pos(pos);
        }
    }
    #[doc = " The HChaCha function: adapts the ChaCha core function in the same"]
    #[doc = " manner that HSalsa adapts the Salsa function."]
    #[doc = ""]
    #[doc = " HChaCha takes 512-bits of input:"]
    #[doc = ""]
    #[doc = " - Constants: `u32` x 4"]
    #[doc = " - Key: `u32` x 8"]
    #[doc = " - Nonce: `u32` x 4"]
    #[doc = ""]
    #[doc = " It produces 256-bits of output suitable for use as a ChaCha key"]
    #[doc = ""]
    #[doc = " For more information on HSalsa on which HChaCha is based, see:"]
    #[doc = ""]
    #[doc = " <http://cr.yp.to/snuffle/xsalsa-20110204.pdf>"]
    pub fn hchacha<R: Unsigned>(key: &Key, input: &GenericArray<u8, U16>) -> GenericArray<u8, U32> {
        let mut state = [0u32; STATE_WORDS];
        state[..4].copy_from_slice(&CONSTANTS);
        let key_chunks = key.chunks_exact(4);
        for (v, chunk) in state[4..12].iter_mut().zip(key_chunks) {
            *v = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let input_chunks = input.chunks_exact(4);
        for (v, chunk) in state[12..16].iter_mut().zip(input_chunks) {
            *v = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        for _ in 0..R::USIZE {
            quarter_round(0, 4, 8, 12, &mut state);
            quarter_round(1, 5, 9, 13, &mut state);
            quarter_round(2, 6, 10, 14, &mut state);
            quarter_round(3, 7, 11, 15, &mut state);
            quarter_round(0, 5, 10, 15, &mut state);
            quarter_round(1, 6, 11, 12, &mut state);
            quarter_round(2, 7, 8, 13, &mut state);
            quarter_round(3, 4, 9, 14, &mut state);
        }
        let mut output = GenericArray::default();
        for (chunk, val) in output[..16].chunks_exact_mut(4).zip(&state[..4]) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        for (chunk, val) in output[16..].chunks_exact_mut(4).zip(&state[12..]) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        output
    }
    #[doc = " The ChaCha20 quarter round function"]
    fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; STATE_WORDS]) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
}
pub use legacy::{ChaCha20Legacy, ChaCha20LegacyCore, LegacyNonce};
pub use xchacha::{hchacha, XChaCha12, XChaCha20, XChaCha8, XChaChaCore, XNonce};
#[doc = " State initialization constant (\"expand 32-byte k\")"]
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
#[doc = " Number of 32-bit words in the ChaCha state"]
const STATE_WORDS: usize = 16;
#[doc = " Block type used by all ChaCha variants."]
type Block = GenericArray<u8, U64>;
#[doc = " Key type used by all ChaCha variants."]
pub type Key = GenericArray<u8, U32>;
#[doc = " Nonce type used by ChaCha variants."]
pub type Nonce = GenericArray<u8, U12>;
#[doc = " ChaCha8 stream cipher (reduced-round variant of [`ChaCha20`] with 8 rounds)"]
pub type ChaCha8 = StreamCipherCoreWrapper<ChaChaCore<U4>>;
#[doc = " ChaCha12 stream cipher (reduced-round variant of [`ChaCha20`] with 12 rounds)"]
pub type ChaCha12 = StreamCipherCoreWrapper<ChaChaCore<U6>>;
#[doc = " ChaCha20 stream cipher (RFC 8439 version with 96-bit nonce)"]
pub type ChaCha20 = StreamCipherCoreWrapper<ChaChaCore<U10>>;
type Tokens = ();
#[doc = " The ChaCha core function."]
pub struct ChaChaCore<R: Unsigned> {
    #[doc = " Internal state of the core function"]
    state: [u32; STATE_WORDS],
    #[doc = " CPU target feature tokens"]
    #[allow(dead_code)]
    tokens: Tokens,
    #[doc = " Number of rounds to perform"]
    rounds: PhantomData<R>,
}
impl<R: Unsigned> KeySizeUser for ChaChaCore<R> {
    type KeySize = U32;
}
impl<R: Unsigned> IvSizeUser for ChaChaCore<R> {
    type IvSize = U12;
}
impl<R: Unsigned> BlockSizeUser for ChaChaCore<R> {
    type BlockSize = U64;
}
impl<R: Unsigned> KeyIvInit for ChaChaCore<R> {
    #[inline]
    fn new(key: &Key, iv: &Nonce) -> Self {
        let mut state = [0u32; STATE_WORDS];
        state[0..4].copy_from_slice(&CONSTANTS);
        let key_chunks = key.chunks_exact(4);
        for (val, chunk) in state[4..12].iter_mut().zip(key_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let iv_chunks = iv.chunks_exact(4);
        for (val, chunk) in state[13..16].iter_mut().zip(iv_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let tokens = ();
        Self {
            state,
            tokens,
            rounds: PhantomData,
        }
    }
}
impl<R: Unsigned> StreamCipherCore for ChaChaCore<R> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        let rem = u32::MAX - self.get_block_pos();
        rem.try_into().ok()
    }
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut backends::pulp::Backend(self));
    }
}
impl<R: Unsigned> StreamCipherSeekCore for ChaChaCore<R> {
    type Counter = u32;
    #[inline(always)]
    fn get_block_pos(&self) -> u32 {
        self.state[12]
    }
    #[inline(always)]
    fn set_block_pos(&mut self, pos: u32) {
        self.state[12] = pos;
    }
}
