use lief_ffi as ffi;

use super::{Properties, Property};
use crate::common::into_optional;

/// This structure exposes Android-specific API for the current process.
pub struct Process {}

impl Process {
    /// Return the content of `/proc/cmdline`
    pub fn cmdline() -> Option<String> {
        let cmdline = ffi::runtime_android_Process::cmdline().to_string();
        if cmdline.is_empty() {
            None
        } else {
            Some(cmdline)
        }
    }

    /// Return the Android system property with the given `name`
    /// (e.g. `ro.build.version.sdk`) or `None` if the property does not exist.
    pub fn get_system_property(name: &str) -> Option<Property> {
        cxx::let_cxx_string!(s = name);
        into_optional(ffi::runtime_android_Process::get_system_property(&s))
    }

    /// Return an iterator over all the Android system properties.
    pub fn properties() -> Properties {
        Properties::new(ffi::runtime_android_Process::properties())
    }
}
