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
        

        // unsafe { 
        //     core::arch::asm!(
        //         asm_macros::lp_setupi!(0, 8, 8),
        //         asm_macros::lw_pi!(t0, 4(a0!)),
        //         asm_macros::lw_pi!(t1, 4(a0!)),
        //         asm_macros::sw_pi!(t0, 4(a1!)),
        //         asm_macros::sw_pi!(t1, 4(a1!)),
        //         in("a0") block.as_mut_ptr() as *mut u32,
        //         in("a1") &res as *const u32,
        //     );
        // }

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
    
    
    
    res[0] = res[0].wrapping_add(state[0]);
    res[1] = res[1].wrapping_add(state[1]);
    res[2] = res[2].wrapping_add(state[2]);
    res[3] = res[3].wrapping_add(state[3]);
    res[4] = res[4].wrapping_add(state[4]);
    res[5] = res[5].wrapping_add(state[5]);
    res[6] = res[6].wrapping_add(state[6]);
    res[7] = res[7].wrapping_add(state[7]);
    res[8] = res[8].wrapping_add(state[8]);
    res[9] = res[9].wrapping_add(state[9]);
    res[10] = res[10].wrapping_add(state[10]);
    res[11] = res[11].wrapping_add(state[11]);
    res[12] = res[12].wrapping_add(state[12]);
    res[13] = res[13].wrapping_add(state[13]);
    res[14] = res[14].wrapping_add(state[14]);
    res[15] = res[15].wrapping_add(state[15]);
    res
}
