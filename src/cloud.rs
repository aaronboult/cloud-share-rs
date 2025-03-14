extern crate hyper;
extern crate hyper_rustls;
extern crate google_drive3 as drive3;

use crate::{println_verbose};
use crate::config::Config;
use crate::registry::RegistryEntry;

use std::pin::Pin;
use std::task::{Context, Poll};
use std::path::{Path, PathBuf};
use std::collections::VecDeque;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::str::FromStr;
use bytes::Bytes;
use mime_guess::from_path;
use thiserror::Error;
use path_clean::PathClean;
use tokio::fs::{self, File as TokioFile};
use tokio::io::{AsyncRead, AsyncWriteExt};
use hyper::body::{Body, Frame};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use google_drive3::api::{Scope, File as DriveFile};
use drive3::Error as DriveError;
use drive3::{DriveHub, hyper_util, yup_oauth2};
use http_body_util::BodyExt;
use mime::Mime;

struct BytesAsyncRead {
    inner: Cursor<Bytes>,
}

impl Seek for BytesAsyncRead {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl Read for BytesAsyncRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.inner, buf)
    }
}

impl AsyncRead for BytesAsyncRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pos = self.inner.position() as usize;
        let len = self.inner.get_ref().len();

        if pos >= len {
            return Poll::Ready(Ok(()));
        }

        let remaining = &self.inner.get_ref()[pos..];
        let to_copy = std::cmp::min(remaining.len(), buf.remaining());
        buf.put_slice(&remaining[..to_copy]);
        self.inner.set_position((pos + to_copy) as u64);

        Poll::Ready(Ok(()))
    }
}

impl Body for BytesAsyncRead {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut buf = [0u8; 8192];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);

        match self.poll_read(_cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    Poll::Ready(None)
                } else {
                    let bytes = Bytes::copy_from_slice(&buf[..n]);
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Error)]
pub enum CloudError {
    #[error("Authentication error")]
    AuthError,

    #[error("I/O error at {path}: {source}")]
    IoError {
        #[source]
        source: std::io::Error,
        path: PathBuf,
    },

    #[error("Google Drive API error: {0}")]
    DriveApiError(#[from] DriveError),

    #[error("Download error: {0}")]
    DownloadError(#[from] hyper::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Thread synchronization error: {0}")]
    SyncError(String),

    #[error("Path error: {0}")]
    PathError(String),

    #[error("MIME type error: {0}")]
    MimeError(#[from] mime::FromStrError),
}

impl CloudError {
    pub fn config_error(msg: impl Into<String>) -> Self {
        Self::ConfigError(msg.into())
    }
}

pub fn init_crypto() {
    match rustls::crypto::aws_lc_rs::default_provider()
        .install_default() {
        Ok(_) => (),
        Err(e) => eprintln!("Failed to initialize AWS LC: {:?}", e),
    }
}

#[derive(Clone)]
pub struct CloudService {
    hub: DriveHub<HttpsConnector<HttpConnector>>,
}

impl CloudService {
    pub fn get_tokens_filename() -> &'static str {
        "tokens.json"
    }

    pub async fn new(verbose: bool) -> Result<Self, CloudError> {
        println_verbose!(verbose, "Initializing Google Drive API...");

        // Embed secret using the json file at ./assets/client_secret.json
        let secret = yup_oauth2::parse_application_secret(
            include_bytes!("../assets/client_secret.json")
        );

        if let Err(e) = secret {
            eprintln!("Failed to load client credentials: {}", e);
            return Err(CloudError::AuthError);
        }

        println_verbose!(verbose, "Building authenticator...");

        let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
                secret.unwrap(),
                yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
            )
            .persist_tokens_to_disk(CloudService::get_tokens_filename())
            .build()
            .await;

        if let Err(e) = auth {
            eprintln!("Failed to create authenticator: {}", e);
            return Err(CloudError::AuthError);
        }
        let auth = auth.unwrap();

        println_verbose!(verbose, "Building HTTP client...");

        let http_client = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots();

        if http_client.is_err() {
            eprintln!("Failed to create HTTPS connector: {}", http_client.err().unwrap());
            return Err(CloudError::AuthError);
        }
        let http_client = http_client.unwrap()
            .https_or_http()
            .enable_http1()
            .build();

        let client = hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new()
            )
            .build(http_client);

        println_verbose!(verbose, "Creating DriveHub...");

        Ok(Self { hub: DriveHub::new(client, auth) })
    }

    pub async fn get_remote_files(&self, config: &Config, verbose: bool) -> Result<Vec<RegistryEntry>, DriveError> {
        let root_folder_id = Self::extract_folder_id(&config.remote_url)
            .ok_or_else(|| DriveError::Cancelled)?;

        let mut files = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back((root_folder_id.to_string(), String::from("/")));

        while let Some((folder_id, folder_path)) = queue.pop_front() {
            let mut page_token: Option<String> = None;

            loop {

                let mut query = self.hub.files().list()
                    .q(&format!("'{}' in parents and trashed = false", folder_id))
                    .param("fields", "files(id,name,md5Checksum,mimeType),nextPageToken")
                    .add_scope(Scope::Full);

                if let Some(token) = &page_token {
                    query = query.page_token(token);
                }

                let (_, response) = query.doit().await?;

                let file_list = response.files.unwrap_or_default();

                println_verbose!(verbose, "Found {} files/folders in {}", file_list.len(), folder_path);

                for file in file_list {
                    let is_folder = file.mime_type.as_deref() == Some("application/vnd.google-apps.folder");

                    if let (Some(id), Some(name)) = (file.id, file.name) {
                        if is_folder {
                            // Add folder to processing queue with updated path
                            let new_path = format!("{}{}/", folder_path, name);

                            println_verbose!(verbose, "Found folder: {}", new_path);

                            queue.push_back((id, new_path));
                        } else {
                            // Add file with its full path
                            println_verbose!(verbose, "Found file: {}", name);

                            files.push(RegistryEntry {
                                id,
                                name: name.clone(),
                                path: PathBuf::from(&folder_path).join(name),
                                hash: file.md5_checksum.unwrap_or_default(),
                            });
                        }
                    }
                }

                page_token = response.next_page_token;
                if page_token.is_none() {
                    break;
                }
            }

        }

        Ok(files)
    }

    pub async fn download_file(
        &self,
        registry_entry: &RegistryEntry,
        local_base_path: &Path,
        verbose: bool,
    ) -> Result<(), CloudError> {
        let relative_path = Path::new(&registry_entry.path)
            .strip_prefix("/")  // Remove leading slash
            .unwrap_or_else(|_| Path::new(&registry_entry.path));

        // Create platform-correct path components
        let mut full_path = local_base_path.to_path_buf();
        for component in relative_path.components() {
            full_path.push(component);
        }

        let path_abs = full_path.clean();

        println_verbose!(verbose, "Downloading file:\n\tID: {}\n\tBase path: {}\n\tFull path: {:?}",
            registry_entry.id,
            local_base_path.display(),
            path_abs
        );

        // Create parent directories
        if !path_abs.exists() {
            if let Some(parent) = path_abs.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|e| CloudError::IoError {
                        source: e,
                        path: parent.to_path_buf()
                    })?;
            }
        }

        println_verbose!(verbose, "Downloaded file metadata...");

        let (_, meta) = self.hub.files().get(&registry_entry.id)
            .param("fields", "trashed")
            .add_scope(Scope::Full)
            .doit()
            .await
            .map_err(CloudError::DriveApiError)?;

        println_verbose!(verbose, "Downloaded file metadata: {:?}", meta);

        if meta.trashed == Some(true) {
            // Remove file from filesystem
            if path_abs.exists() {
                println_verbose!(verbose, "Removing trashed file: {:?}", path_abs);

                fs::remove_file(&path_abs)
                    .await
                    .map_err(|e| CloudError::IoError {
                        source: e,
                        path: path_abs.clone()
                    })?;
            }
        } else {
            println_verbose!(verbose, "Downloading file from cloud...");

            let (response, _) = self.hub.files().get(&registry_entry.id)
                .param("alt", "media")
                .add_scope(Scope::Full)
                .doit()
                .await
                .map_err(CloudError::DriveApiError)?;

            println_verbose!(verbose, "Writing file to disk...");

            // Read entire body to bytes
            let bytes = BodyExt::collect(response.into_body())
                .await
                .map_err(CloudError::DownloadError)?
                .to_bytes();

            // Write to file
            let mut file = TokioFile::create(&path_abs)
                .await
                .map_err(|e| CloudError::IoError {
                    source: e,
                    path: path_abs.clone()
                })?;

            file.write_all(&bytes)
                .await
                .map_err(|e| CloudError::IoError {
                    source: e,
                    path: path_abs.clone()
                })?;
        }

        Ok(())
    }

    pub async fn upload_file(
        &self,
        id: Option<String>,
        file_path: &Path,
        remote_url: &String,
        remote_path: &Path,
        verbose: bool,
    ) -> Result<(String, Option<String>), CloudError> {
        // Get relative path from config's local_path
        let relative_path = file_path
            .strip_prefix(&remote_path)
            .map_err(|_| CloudError::PathError(
                format!(
                    "File not in base directory:\n\tFile: `{}`\n\tBase directory: {}",
                    file_path.to_str().unwrap_or(""),
                    remote_path.to_str().unwrap_or("")
                ),
            ))?;

        // Split into components (without root)
        let path_components: Vec<&str> = relative_path
            .iter()
            .map(|c| c.to_str().ok_or_else(|| CloudError::PathError("Invalid unicode in path".into())))
            .collect::<Result<_, _>>()?;

        // Get/create folder hierarchy
        let root_folder_id = Self::extract_folder_id(&remote_url)
            .ok_or_else(|| CloudError::ConfigError("Invalid remote URL".into()))?;

        let parent_id = self.ensure_folder_structure(
            root_folder_id,
            &path_components[..path_components.len() - 1],
            verbose
        ).await?;

        // Get filename
        let file_name = path_components.last()
            .ok_or_else(|| CloudError::PathError("Empty path components".into()))?
            .to_string();

        println_verbose!(
            verbose,
            "Does file ({}) exist? {}",
            file_path.to_str().unwrap_or(""),
            file_path.exists()
        );

        let local_path = Config::make_path_local(&file_path.to_path_buf());

        // Are we deleting the file or uploading it
        if local_path.exists() {
            println_verbose!(verbose, "Creating or Uploading file: {}", file_name);
            self.create_or_update_file(id, &local_path, &file_name, parent_id, verbose).await
        } else {
            println_verbose!(verbose, "Removing file: {}", file_name);
            self.remove_file(id, verbose).await
        }
    }

    async fn ensure_folder_structure(
        &self,
        root_id: &str,
        components: &[&str],
        verbose: bool,
    ) -> Result<String, CloudError> {
        println_verbose!(verbose, "Verifying directory structure...");

        let mut current_id = root_id.to_string();

        for component in components {
            current_id = self.get_or_create_folder(component, &current_id, verbose).await?;
        }

        Ok(current_id)
    }

    async fn get_or_create_folder(
        &self,
        folder_name: &str,
        parent_id: &str,
        verbose: bool,
    ) -> Result<String, CloudError> {
        // Check if folder exists
        let query = format!("name = '{}' and '{}' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false",
                            folder_name, parent_id);

        // Execute list request directly with await
        let (_, data) = self.hub.files().list()
            .q(&query)
            .param("fields", "files(id)")
            .add_scope(Scope::Full)
            .doit()
            .await?;

        if let Some(files) = data.files {
            if !files.is_empty() {
                return Ok(files[0].id.clone().unwrap());
            }
        }

        println_verbose!(verbose, "Creating folder: {}", folder_name);

        // Create new folder
        let new_folder = DriveFile {
            name: Some(folder_name.to_string()),
            parents: Some(vec![parent_id.to_string()]),
            mime_type: Some("application/vnd.google-apps.folder".into()),
            ..Default::default()
        };

        let body = BytesAsyncRead {
            inner: Cursor::new(Bytes::new()),
        };

        // Execute create request directly with await
        let created = self.hub.files().create(new_folder)
            .upload(body, Mime::from_str("application/vnd.google-apps.folder").unwrap())
            .await?;

        Ok(created.1.id.unwrap())
    }

    /// Created or updates a file. Returns the file id and its hash
    async fn create_or_update_file(
        &self,
        id: Option<String>,
        file_path: &Path,
        file_name: &str,
        parent_id: String,
        verbose: bool,
    ) -> Result<(String, Option<String>), CloudError> {
        // Read file content
        let content = tokio::fs::read(file_path)
            .await
            .map_err(|e| CloudError::IoError {
                source: e,
                path: file_path.to_path_buf(),
            })?;

        // Upload or update file
        if let Some(file_id) = id {
            self.update_file(file_id, &file_name, content, verbose).await
        } else {
            self.create_file(&file_name, parent_id, content, verbose).await
        }
    }

    async fn create_file(
        &self,
        name: &str,
        parent_id: String,
        content: Vec<u8>,
        verbose: bool,
    ) -> Result<(String, Option<String>), CloudError> {
        let mime_type = from_path(name).first_or_octet_stream();

        let new_file = DriveFile {
            name: Some(name.to_string()),
            parents: Some(vec![parent_id]),
            ..Default::default()
        };

        let bytes = Bytes::from(content);
        let body = BytesAsyncRead {
            inner: Cursor::new(bytes),
        };

        println_verbose!(verbose, "[{}] Creating file", name);

        let (_, data) = self.hub.files().create(new_file)
            .param("uploadType", "multipart")
            .param("fields", "id,md5Checksum")
            .add_scope(Scope::Full)
            .upload(body, mime_type)
            .await?;

        if let Some(id) = data.id {
            Ok((id, data.md5_checksum))
        } else {
            Err(CloudError::DriveApiError(DriveError::Cancelled))
        }
    }

    /// Updates or removes a file. Returns the file id and its hash or none if deleted
    async fn update_file(
        &self,
        file_id: String,
        name: &str,
        content: Vec<u8>,
        verbose: bool,
    ) -> Result<(String, Option<String>), CloudError> {
        let mime_type = from_path(name).first_or_octet_stream();

        let bytes = Bytes::from(content);
        let body = BytesAsyncRead {
            inner: Cursor::new(bytes),
        };

        println_verbose!(verbose, "[{}] Updating file", name);

        let (_, data) = self.hub.files().update(Default::default(), &file_id)
            .param("uploadType", "multipart")
            .param("fields", "id,md5Checksum")
            .add_scope(Scope::Full)
            .upload(body, mime_type)
            .await?;

        if let Some(id) = data.id {
            Ok((id, data.md5_checksum))
        } else {
            Err(CloudError::DriveApiError(DriveError::Cancelled))
        }
    }

    async fn remove_file(
        &self,
        file_id: Option<String>,
        verbose: bool,
    ) -> Result<(String, Option<String>), CloudError> {
        if let Some(id) = file_id {
            println_verbose!(verbose, "Deleting file: {}", id);

            self.hub.files().delete(&id)
                .add_scope(Scope::Full)
                .doit()
                .await?;

            Ok((id, None))
        } else {
            Err(CloudError::ConfigError("No file ID provided".into()))
        }
    }

    fn extract_folder_id(url: &str) -> Option<&str> {
        url.split('/')
            .find(|s| s.starts_with("folders/"))
            .and_then(|s| s.splitn(2, '/').nth(1))
            .or_else(|| url.split('/').last())
            .and_then(|s| s.splitn(2, '?').next())
    }
}