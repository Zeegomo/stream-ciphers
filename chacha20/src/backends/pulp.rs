//! Portable implementation which does not rely on architecture-specific
//! intrinsics.

use crate::{Block, ChaChaCore, Unsigned, STATE_WORDS};
use cipher::{
    consts::{U1, U64},
    inout::InOut,
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

        for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        self.0.state[12] = self.0.state[12].wrapping_add(1);
    }
}

macro_rules! qr {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        concat!(
            asm_macros::add!($a, $a, $b),
            "\n",
            asm_macros::xor!($d, $d, $a),
            "\n",
            asm_macros::ror!($d, $d, 5),
            "\n",
            asm_macros::add!($c, $c, $d),
            "\n",
            asm_macros::xor!($b, $b, $c),
            "\n",
            asm_macros::ror!($b, $b, 6),
            "\n",
            asm_macros::add!($a, $a, $b),
            "\n",
            asm_macros::xor!($d, $d, $a),
            "\n",
            asm_macros::ror!($d, $d, 7),
            "\n",
            asm_macros::add!($c, $c, $d),
            "\n",
            asm_macros::xor!($b, $b, $c),
            "\n",
            asm_macros::ror!($b, $b, 15),
            "\n",
        )
    };
}

macro_rules! out_reg {
    ($a:expr) => {
        concat!(
            asm_macros::lw_pi!(t1, 4(10!)), "\n", // state
            asm_macros::lw_pi!(t0, 4(a2!)), "\n", // block
            asm_macros::add!($a, t1, $a),   "\n",
            asm_macros::xor!($a, t0, $a),   "\n",
        )
    };
}

impl<'a, R: Unsigned> Backend<'a, R> {
    #[inline(always)]
    pub fn _apply_keystream_block_inout(&mut self, mut block: InOut<'_, '_, Block>) {
        let block_slice: &mut [u32] = unsafe {
            core::slice::from_raw_parts_mut(block.get_out().as_mut_ptr() as *mut u32, 16)
        };
        unsafe {
            core::arch::asm!(
                asm_macros::lp_setup!(0, 14, 160),
                qr!(16, 20, 24, 28),
                qr!(17, 21, 25, 29),
                qr!(18, 22, 26, 30),
                qr!(19, 23, 27, 31),
                qr!(16, 21, 26, 31),
                qr!(17, 22, 27, 28),
                qr!(18, 23, 24, 29),
                qr!(19, 20, 25, 30),
                out_reg!(16),
                out_reg!(17),
                out_reg!(18),
                out_reg!(19),
                out_reg!(20),
                out_reg!(21),
                out_reg!(22),
                out_reg!(23),
                out_reg!(24),
                out_reg!(25),
                out_reg!(26),
                out_reg!(27),
                out_reg!(28),
                out_reg!(29),
                out_reg!(30),
                out_reg!(31),
                inout("x16") self.0.state[0] => block_slice[0],
                inout("x17") self.0.state[1] => block_slice[1],
                inout("x18") self.0.state[2] => block_slice[2],
                inout("x19") self.0.state[3] => block_slice[3],
                inout("x20") self.0.state[4] => block_slice[4],
                inout("x21") self.0.state[5] => block_slice[5],
                inout("x22") self.0.state[6] => block_slice[6],
                inout("x23") self.0.state[7] => block_slice[7],
                inout("x24") self.0.state[8] => block_slice[8],
                inout("x25") self.0.state[9] => block_slice[9],
                inout("x26") self.0.state[10] => block_slice[10],
                inout("x27") self.0.state[11] => block_slice[11],
                inout("x28") self.0.state[12] => block_slice[12],
                inout("x29") self.0.state[13] => block_slice[13],
                inout("x30") self.0.state[14] => block_slice[14],
                inout("x31") self.0.state[15] => block_slice[15],
                inout("x5") 16 => _,
                inout("x6") 20 => _,
                in("x7") 24,
                in("x15") 25,
                in("x14") 10,
                inout("x10") &self.0.state as *const u32 => _,
                inout("x12") block.get_in().as_ptr() as *const u32 => _,
                options(readonly)
            );
        }

        self.0.state[12] = self.0.state[12].wrapping_add(1);
    }
}

macro_rules! full_round {
    ($state:expr) => {
        unsafe {
            core::arch::asm!(
                asm_macros::lp_setup!(0, 14, 160),
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
                in("x14") 10,
                options(pure, nomem)
            )
        }

    };
}

#[inline(always)]
fn run_rounds<R: Unsigned>(state: [u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = state;

    full_round!(res);

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
    }
    res
}
