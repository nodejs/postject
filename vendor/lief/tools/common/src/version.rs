use std::sync::LazyLock;

pub fn get_lief_version() -> &'static str {
    static LIEF_VERSION: LazyLock<String> = LazyLock::new(|| lief::version().to_string());
    LIEF_VERSION.as_str()
}
