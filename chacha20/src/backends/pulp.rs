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

#[inline(always)]
fn run_rounds<R: Unsigned>(state: [u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = state;
    for _ in 0..R::USIZE {
        
        // column rounds
        quarter_round(0, 4, 8, 12, &mut res);
        quarter_round(1, 5, 9, 13, &mut res);
        quarter_round(2, 6, 10, 14, &mut res);
        quarter_round(3, 7, 11, 15, &mut res);

        // diagonal rounds
        quarter_round(0, 5, 10, 15, &mut res);
        quarter_round(1, 6, 11, 12, &mut res);
        quarter_round(2, 7, 8, 13, &mut res);
        quarter_round(3, 4, 9, 14, &mut res);
    }

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
    }
    res
}

// /// The ChaCha20 quarter round function
#[inline(always)]
fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; STATE_WORDS], s1: u32, s2: u32, s3: u32) {
  
    unsafe {
        core::arch::asm!(
            "add {sa}, {sa}, {sb}",
            "xor t0, {sd}, {sa}",
            ".4byte 0x922d2b3", // ror t0, t0, s2
            "add {sc}, {sc}, t0", // sc = sc + sd
            "xor t1, {sb}, {sc}",
            ".4byte 0x9335333", // TODO ror t1, t1, s3
            "add {sa}, t1, {sa}",
            "xor t0, t0, {sa}",
            ".4byte 0x942d2b3", // TODO ror t0, t0, s4
            "add {sc}, t0, {sc}",
            "xor t1, {sc}, t1",
            ".4byte 0x9535333", // TODO ror t1, t1, s5,
            sa = inout(reg) state[a],
            sb = in(reg) state[b],
            sc =  inout(reg) state[c],
            sd = in(reg) state[d],
            out("t0") state[d],
            out("t2") state[c],
            in("s2") s1,
            in("s3") s2,
            in("s4") s3,
            in("s5") s3,
            options(nomem)
        )
    }
}