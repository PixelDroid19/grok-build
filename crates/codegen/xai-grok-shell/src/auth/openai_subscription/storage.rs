use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;

use super::model::StoredOpenAiAuth;

const AUTH_FILE_NAME: &str = "openai-auth.json";
const LOCK_FILE_NAME: &str = "openai-auth.json.lock";

pub struct OpenAiAuthStorage {
    path: PathBuf,
}

impl OpenAiAuthStorage {
    pub fn new(grok_home: &Path) -> Self {
        Self {
            path: grok_home.join(AUTH_FILE_NAME),
        }
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(&self) -> std::io::Result<Option<StoredOpenAiAuth>> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        tighten_owner_only(&self.path);
        if contents.trim().is_empty() {
            return Ok(None);
        }
        serde_json::from_str(&contents)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn write(&self, auth: &StoredOpenAiAuth) -> std::io::Result<()> {
        let _lock = self.lock()?;
        self.write_locked(auth)
    }

    pub fn clear(&self) -> std::io::Result<()> {
        let _lock = self.lock()?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn lock(&self) -> std::io::Result<OpenAiAuthFileLock> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = self.path.with_file_name(LOCK_FILE_NAME);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(lock_path)?;
        file.lock_exclusive()?;
        Ok(OpenAiAuthFileLock { _file: file })
    }

    pub(crate) fn write_locked(&self, auth: &StoredOpenAiAuth) -> std::io::Result<()> {
        let contents = serde_json::to_string_pretty(auth)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_atomically_owner_only(&self.path, contents.as_bytes())
    }

    pub(crate) fn read_locked(&self) -> std::io::Result<Option<StoredOpenAiAuth>> {
        self.read()
    }
}

pub(crate) struct OpenAiAuthFileLock {
    _file: File,
}

fn write_atomically_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    static WRITE_NONCE: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let nonce = WRITE_NONCE.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("json.{}.{nonce}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    #[cfg(windows)]
    {
        let _ = std::fs::remove_file(path);
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => {
            tighten_owner_only(path);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn tighten_owner_only(path: &Path) {
    let _ = crate::util::secure_file::ensure_owner_only_permissions(path);
}
