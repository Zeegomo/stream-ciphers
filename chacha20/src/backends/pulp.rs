//! Portable implementation which does not rely on architecture-specific
//! intrinsics.

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
            // is this little endian?
            let chunk = chunk.as_mut_ptr() as *mut u32;
            unsafe {
                core::ptr::write(chunk, *val);
            }
        }
    }
}

macro_rules! qr {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        concat!(
            asm_macros::add!($a, $a, $b), "\n",
            asm_macros::xor!($d, $d, $a), "\n",
            asm_macros::ror!($d, $d, 5),  "\n",
            asm_macros::add!($c, $c, $d), "\n",
            asm_macros::xor!($b, $b, $c), "\n",
            asm_macros::ror!($b, $b, 6),  "\n",
            asm_macros::add!($a, $a, $b), "\n",
            asm_macros::xor!($d, $d, $a), "\n",
            asm_macros::ror!($d, $d, 7),  "\n",
            asm_macros::add!($c, $c, $d), "\n",
            asm_macros::xor!($b, $b, $c), "\n",
            asm_macros::ror!($b, $b, 15), "\n",
        )
    };
}

macro_rules! full_round {
    ($iter:expr, $state:expr) => {
        unsafe {
            core::arch::asm!(
                qr!(16, 20, 24, 28),
                qr!(17, 21, 25, 29),
                qr!(18, 22, 26, 30),
                qr!(19, 23, 27, 31),
                qr!(16, 21, 26, 31),
                qr!(17, 22, 27, 28),
                qr!(18, 23, 24, 29),
                qr!(19, 20, 25, 30),
                inout("x16") $state[0],
                inout("x17") $state[1],
                inout("x18") $state[2],
                inout("x19") $state[3],
                inout("x20") $state[4],
                inout("x21") $state[5],
                inout("x22") $state[6],
                inout("x23") $state[7],
                inout("x24") $state[8],
                inout("x25") $state[9],
                inout("x26") $state[10],
                inout("x27") $state[11],
                inout("x28") $state[12],
                inout("x29") $state[13],
                inout("x30") $state[14],
                inout("x31") $state[15],
                in("x5") 16,
                in("x6") 20,
                in("x7") 24,
                in("x15") 25,
                options(pure, nomem)
            )
        }
        
    };
}

#[inline(always)]
fn run_rounds<R: Unsigned>(state: [u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = state;
    for _ in 0..R::USIZE {
        full_round!(TODO, res);
    }

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
    }
    res
}

// // /// The ChaCha20 quarter round function
// #[inline(always)]
// fn quarter_round(
//     a: usize,
//     b: usize,
//     c: usize,
//     d: usize,
//     state: &mut [u32; STATE_WORDS],
// ) {
//     unsafe {
//         core::arch::asm!(
//             "add {sa}, {sa}, {sb}",
//             "xor t0, {sd}, {sa}",
//             ".4byte 0x922d2b3", // ror t0, t0, s2
//             "add {sc}, {sc}, t0", // sc = sc + sd
//             "xor t1, {sb}, {sc}",
//             ".4byte 0x9335333", // TODO ror t1, t1, s3
//             "add {sa}, t1, {sa}",
//             "xor t0, t0, {sa}",
//             ".4byte 0x942d2b3", // TODO ror t0, t0, s4
//             "add {sc}, t0, {sc}",
//             "xor t1, {sc}, t1",
//             ".4byte 0x9535333", // TODO ror t1, t1, s5,
//             sa = inout(reg) state[a],
//             sb = in(reg) state[b],
//             sc =  inout(reg) state[c],
//             sd = in(reg) state[d],
//             out("t0") state[d],
//             out("t2") state[c],
//             in("s2") 16,
//             in("s3") 20,
//             in("s4") 24,
//             in("s5") 25,
//             options(nomem)
//         )
//     }
// }
