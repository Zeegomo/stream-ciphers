use alloc::boxed::Box;
use core::pin::Pin;
use pulp_sdk_rust::{
    pi_cluster_conf_init, pi_cluster_open, pi_open_from_conf, L2Allocator, PiClusterConf, PiDevice,
};

pub struct Cluster {
    inner: Pin<Box<Inner, L2Allocator>>,
}

// The whole C interface is built around pointers, it would be a shame
// for us to move them by accident.
struct Inner {
    _marker: core::marker::PhantomPinned,
    device: PiDevice,
    conf: PiClusterConf,
}

impl Cluster {
    pub fn new() -> Result<Self, ()> {
        let inner = Inner {
            _marker: core::marker::PhantomPinned,
            device: PiDevice::uninit(),
            conf: PiClusterConf::uninit(),
        };
        let mut inner = Box::new_in(inner, L2Allocator);

        unsafe {
            pi_cluster_conf_init(&mut inner.conf as *mut PiClusterConf);
            pi_open_from_conf(
                &mut inner.device as *mut PiDevice,
                &mut inner.conf as *mut PiClusterConf as *mut cty::c_void,
            );
            if pi_cluster_open(&mut inner.device as *mut PiDevice) != 0 {
                return Err(());
            }

            Ok(Self {
                inner: Pin::new_unchecked(inner),
            })
        }
    }

    pub fn device_mut(&mut self) -> Pin<&mut PiDevice> {
        // This is okay because `device` is always pinned
        unsafe { self.inner.as_mut().map_unchecked_mut(|s| &mut s.device) }
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        // TODO
    }
}
