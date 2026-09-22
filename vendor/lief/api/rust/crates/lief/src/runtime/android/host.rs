use lief_ffi as ffi;

/// This structure exposes Android-specific host information.
pub struct Host {}

impl Host {
    /// Return the Android SDK/API level of the device (e.g. `34` for Android
    /// 14).
    pub fn sdk_version() -> Option<u32> {
        let version = ffi::runtime_android_Host::sdk_version();
        if version < 0 {
            None
        } else {
            Some(version as u32)
        }
    }
}
