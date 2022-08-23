use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(chacha20_force_soft)] {
        pub(crate) mod soft;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        cfg_if! {
            if #[cfg(chacha20_force_avx2)] {
                pub(crate) mod avx2;
            } else if #[cfg(chacha20_force_sse2)] {
                pub(crate) mod sse2;
            } else {
                pub(crate) mod soft;
                pub(crate) mod avx2;
                pub(crate) mod sse2;
            }
        }
    } else if #[cfg(target_arch = "riscv32")] {
        // TODO: introduce some more specific notion of pulp (requires compiler mod)
        pub(crate) mod pulp;
    } else {
        pub(crate) mod soft;
    }
}
