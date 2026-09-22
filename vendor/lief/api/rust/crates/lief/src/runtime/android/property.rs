use std::fmt;

use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::declare_standalone_fwd_iterator;

/// This structure represents an Android system property such as
/// `ro.boot.hardware`.
pub struct Property {
    ptr: cxx::UniquePtr<ffi::runtime_android_Property>,
}

impl FromFFI<ffi::runtime_android_Property> for Property {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_android_Property>) -> Self {
        Self { ptr }
    }
}

impl Property {
    /// Name of the property (e.g. `ro.boot.hardware`).
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Value associated with the property.
    pub fn value(&self) -> String {
        self.ptr.value().to_string()
    }

    /// Serial number of the property.
    pub fn serial(&self) -> u32 {
        self.ptr.serial()
    }
}

impl fmt::Debug for Property {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Property")
            .field("name", &self.name())
            .field("value", &self.value())
            .field("serial", &self.serial())
            .finish()
    }
}

impl fmt::Display for Property {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

declare_standalone_fwd_iterator!(
    Properties,
    Property,
    ffi::runtime_android_Property,
    ffi::runtime_android_it_properties
);
