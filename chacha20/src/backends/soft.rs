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
        let res = run_rounds::<R>(&self.0.state);
        self.0.state[12] = self.0.state[12].wrapping_add(1);

        for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
    }
}

#[inline(always)]
fn run_rounds<R: Unsigned>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = *state;

    for _ in 0..R::USIZE {
        // column rounds
        quarter_round(0, 4, 8, 12, 1, 5, 9, 13, &mut res);
        quarter_round(2, 6, 10, 14, 3, 7, 11, 15, &mut res);

        // diagonal rounds
        quarter_round(0, 5, 10, 15, 1, 6, 11, 12, &mut res);
        quarter_round(2, 7, 8, 13, 3, 4, 9, 14, &mut res);
    }

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
    }
    res
}

/// The ChaCha20 quarter round function
#[inline(always)]
fn quarter_round(a: usize, b: usize, c: usize, d: usize, aa: usize, bb: usize, cc: usize, dd: usize, state: &mut [u32; STATE_WORDS]) {
    let mut sa = state[a];
    let mut sb = state[b];
    let mut sc = state[c];
    let mut sd = state[d];
    let mut saa = state[aa];
    let mut sbb = state[bb];
    let mut scc = state[cc];
    let mut sdd = state[dd];

    sa = sa.wrapping_add(sb);
    saa = saa.wrapping_add(sbb);
    sd ^= sa;
    sdd ^= saa;
    sd = sd.rotate_left(16);
    sdd = sdd.rotate_left(16);

    sc = sc.wrapping_add(sd);
    scc = scc.wrapping_add(sdd);
    sb ^= sc;
    sbb ^= scc;
    sb = sb.rotate_left(12);
    sbb = sbb.rotate_left(12);

    sa = sa.wrapping_add(sb);
    saa = saa.wrapping_add(sbb);
    sd ^= sa;
    sdd ^= saa;
    sd = sd.rotate_left(8);
    sdd = sdd.rotate_left(8);

    sc = sc.wrapping_add(sd);
    scc = scc.wrapping_add(sdd);
    sb ^= sc;
    sbb ^= scc;
    sb = sb.rotate_left(7);
    sbb = sbb.rotate_left(7);

    state[a] = sa;
    state[b] = sb;
    state[c] = sc;
    state[d] = sd;

    state[a] = saa;
    state[b] = sbb;
    state[c] = scc;
    state[d] = sdd;
}
