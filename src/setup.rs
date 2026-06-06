// Ghidra setup and discovery utilities.
// Handles automatic download, extraction, and locating the analyzeHeadless script.

use crate::error::{GhidraMonError, Result};

use std::io::Write;

/// Find the Ghidra headless analyzer binary.
///
/// Search order:
/// 1. `GHIDRA_HEADLESS` environment variable
/// 2. `~/.ghidra-mon/ghidra/support/analyzeHeadless` (auto-installed location)
pub fn find_ghidra_headless() -> Option<String> {
    if let Ok(val) = std::env::var("GHIDRA_HEADLESS")
        && std::path::Path::new(&val).exists() {
            return Some(val);
        }

    let script_name = if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    };

    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let auto_path = std::path::PathBuf::from(home)
            .join(".ghidra-mon/ghidra/support")
            .join(script_name);
        if auto_path.exists() {
            return Some(auto_path.to_string_lossy().to_string());
        }
    }

    None
}

/// Download and install Ghidra to `~/.ghidra-mon/ghidra`.
pub async fn setup_ghidra() -> Result<()> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    let install_dir = std::path::PathBuf::from(home).join(".ghidra-mon");
    std::fs::create_dir_all(&install_dir)
        .map_err(|e| GhidraMonError::io("create install directory", e))?;

    // We will use Ghidra 11.2_PUBLIC as an example
    let ghidra_url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip";
    let zip_path = install_dir.join("ghidra.zip");

    println!("🚀 Downloading Ghidra 11.2 (this might take a while depending on your connection)...");
    let response = reqwest::get(ghidra_url).await?;
    let mut file = std::fs::File::create(&zip_path)
        .map_err(|e| GhidraMonError::io("create ghidra.zip", e))?;

    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)
            .map_err(|e| GhidraMonError::io("write download chunk", e))?;
    }

    println!("📦 Extracting Ghidra...");
    let file = std::fs::File::open(&zip_path)
        .map_err(|e| GhidraMonError::io("open ghidra.zip for extraction", e))?;
    let mut archive = zip::ZipArchive::new(file)?;
    archive.extract(&install_dir)?;

    // Rename extracted dir to "ghidra"
    for entry in std::fs::read_dir(&install_dir)
        .map_err(|e| GhidraMonError::io("read install directory", e))?
    {
        let entry = entry.map_err(|e| GhidraMonError::io("read directory entry", e))?;
        if entry
            .file_type()
            .map_err(|e| GhidraMonError::io("check file type", e))?
            .is_dir()
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("ghidra_") {
                let final_dir = install_dir.join("ghidra");
                if final_dir.exists() {
                    std::fs::remove_dir_all(&final_dir)
                        .map_err(|e| GhidraMonError::io("remove old ghidra dir", e))?;
                }
                std::fs::rename(entry.path(), &final_dir)
                    .map_err(|e| GhidraMonError::io("rename ghidra directory", e))?;
                break;
            }
        }
    }

    println!("✅ Setup Complete! Ghidra is installed to ~/.ghidra-mon/ghidra");
    let _ = std::fs::remove_file(zip_path);

    // Set execution permissions on Linux/macOS
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let analyze_headless = install_dir.join("ghidra/support/analyzeHeadless");
        if analyze_headless.exists() {
            let mut perms = std::fs::metadata(&analyze_headless)
                .map_err(|e| GhidraMonError::io("read headless permissions", e))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&analyze_headless, perms)
                .map_err(|e| GhidraMonError::io("set headless permissions", e))?;
        }
    }

    Ok(())
}
