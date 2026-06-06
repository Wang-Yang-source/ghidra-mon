use crate::adapter::schema::{AdapterCapability, OutputFormat};

pub mod binwalk;
pub mod checksec;
pub mod rizin;
pub mod rop;

pub fn native_rust_capability(name: &str) -> AdapterCapability {
    AdapterCapability {
        name: name.to_string(),
        formats: vec![OutputFormat::NativeRust],
        read_only: true,
        parser_version: Some("native-rust-v1".to_string()),
    }
}
