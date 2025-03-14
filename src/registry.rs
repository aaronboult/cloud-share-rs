use std::fmt;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use tokio::fs::File as TokioFile;
use tokio::io::AsyncReadExt;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistryEntry {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub hash: String,
}

impl fmt::Display for RegistryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<RegistryEntry id={} name={} path={} hash={}>",
            self.id,
            self.name,
            self.path.to_str().unwrap_or(String::from("None").as_ref()),
            self.hash
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExclusionRule {
    pub path: String,
    pub filename_pattern: Option<String>,
}

impl fmt::Display for ExclusionRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<ExclusionRule path={} filename_pattern={}>",
            &self.path,
            self.filename_pattern.as_ref().unwrap_or(&String::from("None"))
        )
    }
}

pub async fn compute_file_md5(file_path: &Path) -> Result<String, std::io::Error> {
    let mut file = TokioFile::open(file_path).await?;
    let mut hasher = md5::Context::new();
    let mut buffer = [0; 4096]; // 4KB buffer

    loop {
        let bytes_read = file.read(&mut buffer).await?;

        if bytes_read == 0 {
            break;
        }

        hasher.consume(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.compute()))
}