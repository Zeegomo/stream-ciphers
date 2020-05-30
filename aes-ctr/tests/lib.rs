#![no_std]

use aes_ctr::{Aes128Ctr, Aes256Ctr};
use stream_cipher::{new_seek_test, new_sync_test};

new_sync_test!(aes128_ctr_core, Aes128Ctr, "aes128-ctr");
new_seek_test!(aes128_ctr_seek, Aes128Ctr, "aes128-ctr");
new_sync_test!(aes256_ctr_core, Aes256Ctr, "aes256-ctr");
new_seek_test!(aes256_ctr_seek, Aes256Ctr, "aes256-ctr");