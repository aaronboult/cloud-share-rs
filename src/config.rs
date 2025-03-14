use crate::registry::{RegistryEntry, ExclusionRule};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::{Path, PathBuf, StripPrefixError};
use toml;
use crate::println_verbose;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(skip)]
    pub filename: String,

    local_path: PathBuf,
    pub remote_url: String,
    pub registry: Vec<RegistryEntry>,
    pub exclusions: Vec<ExclusionRule>,
}

unsafe impl Send for Config {}
unsafe impl Sync for Config {}

impl Config {
    pub fn set_filename(&mut self, filename: String) -> &mut Self {
        self.filename = filename;

        self
    }

    pub fn get_filename(&self) -> &String {
        &self.filename
    }

    pub fn load(filename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(filename)?;

        let mut config: Config = toml::from_str(&content)?;

        config.set_filename(filename.to_string());

        Ok(config)
    }

    pub fn new(remote_url: String, local_path: PathBuf, filename: &str) -> Self {
        Self {
            filename: filename.to_string(),
            remote_url,
            local_path: Config::format_path(&local_path),
            registry: Vec::new(),
            exclusions: Vec::new(),
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string(self)?;

        fs::write(&self.filename, content)?;

        Ok(())
    }

    pub fn get_system_local_path(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let local_path = self.local_path.to_str();

        if let Some(local_path) = local_path {
            Ok(PathBuf::from(format!(".{}", local_path)))
        } else {
            Err("Local path is not a valid UTF-8 string".into())
        }
    }

    pub fn format_path(in_path: &PathBuf) -> PathBuf {
        let path = in_path.to_str().unwrap().to_string();

        let out_path_string = path.replace("\\", "/")
            .replace("//", "/")
            .replace("./", "/");

        if out_path_string.starts_with("/") {
            return PathBuf::from(out_path_string);
        }

        PathBuf::from(format!("/{}", out_path_string))
    }

    pub fn make_path_local(in_path: &PathBuf) -> PathBuf {
        let formatted_in_path = Config::format_path(in_path);

        if formatted_in_path.starts_with("/") {
            PathBuf::from(format!(".{}", formatted_in_path.to_str().unwrap_or("")))
        }
        else if !formatted_in_path.starts_with("./") {
            PathBuf::from(format!("./{}", formatted_in_path.to_str().unwrap_or("")))
        }
        else {
            formatted_in_path
        }
    }

    pub fn make_path_remote(in_path: &PathBuf) -> PathBuf {
        let formatted_in_path = Config::format_path(in_path);

        if formatted_in_path.starts_with("/") {
            formatted_in_path
        }
        else if !formatted_in_path.starts_with("./") {
            PathBuf::from(format!(
                "/{}",
                formatted_in_path.strip_prefix("./").unwrap().to_str().unwrap_or("")
            ))
        }
        else {
            PathBuf::from(format!("/{}", formatted_in_path.to_str().unwrap_or("")))
        }
    }

    pub fn resolve_abs_path(&self, in_path: &PathBuf) -> PathBuf {
        let formatted_in_path = Config::format_path(in_path);

        let path = if formatted_in_path.starts_with("/") {
            formatted_in_path.strip_prefix("/").unwrap()
        } else {
            &formatted_in_path
        };

        Config::format_path(&self.local_path.join(path))
    }

    pub fn set_remote(&mut self, url: String) -> &mut Self {
        self.remote_url = url;

        self
    }

    pub fn clear_registry(&mut self) -> &mut Self {
        self.registry.clear();

        self
    }

    pub fn contains_registry_entry(&self, id: String) -> bool {
        self.registry.iter().any(|entry| entry.id == id)
    }

    pub fn add_registry_entry(&mut self, entry: &RegistryEntry) -> &mut Self {
        self.registry.push(RegistryEntry {
            id: entry.id.clone(),
            name: entry.name.clone(),
            path: Config::format_path(&entry.path),
            hash: entry.hash.clone(),
        });

        self
    }

    pub fn remove_registry_entry(&mut self, path: PathBuf) -> &mut Self {
        let path = Config::format_path(&path);

        self.registry.retain(|entry| entry.path != path && !entry.path.starts_with(&path));

        self
    }

    pub fn find_registry_entry_by_id(&self, id: String) -> Option<&RegistryEntry> {
        self.registry.iter().find(|entry| entry.id == id)
    }

    pub fn find_registry_entry_by_path(&self, path: PathBuf) -> Option<&RegistryEntry> {
        let path = Config::format_path(&path);


        self.registry.iter().find(|entry| entry.path == path)
    }

    pub fn update_entry_hash(&mut self, id: String, hash: String) -> &mut Self {
        if let Some(entry) = self.registry.iter_mut().find(|entry| entry.id == id) {
            entry.hash = hash;
        }

        self
    }

    pub fn clear_exclusions(&mut self) -> &mut Self {
        self.exclusions.clear();

        self
    }

    pub fn add_exclusion_rule(&mut self, path: String, filename_pattern: Option<String>) -> &mut Self {
        let path = Config::format_path(&PathBuf::from(path)).to_str().unwrap().to_string();

        self.exclusions.push(ExclusionRule {
            path,
            filename_pattern
        });

        self
    }

    pub fn remove_exclusion_rule(&mut self, path: String, filename_pattern: Option<String>) -> &mut Self {
        let path = Config::format_path(&PathBuf::from(path)).to_str().unwrap().to_string();

        if filename_pattern.is_some() {
            self.exclusions.retain(|rule| rule.path != path || rule.filename_pattern != filename_pattern);
        } else {
            self.exclusions.retain(|rule| rule.path != path);
        }

        self
    }

    pub fn is_path_excluded(&self, path: &Path, verbose: bool) -> bool {
        let path = Config::format_path(&PathBuf::from(path));
        let stripped_path = path.strip_prefix(&self.local_path);

        if let Err(_) = stripped_path {
            return false;
        }
        // strip prefix removed our leading slash :(
        let stripped_path = Path::new("/").join(stripped_path.unwrap());

        println_verbose!(
            verbose,
            "Determining if path excluded...\n\tStripped path: `{}`\n\tGiven path: `{}`\n\tStripped part: `{}`\n\tIs directory: {}",
            stripped_path.display(),
            path.display(),
            self.local_path.display(),
            path.is_dir()
        );

        if stripped_path.is_dir() {
            self.exclusions.iter().any(|rule| {
                println_verbose!(verbose, "Checking exclusion rule: {}", rule);

                stripped_path.starts_with(&Path::new(&rule.path))
            })
        }
        else {
            self.exclusions.iter().any(|rule| {
                println_verbose!(verbose, "Checking exclusion rule: {}", rule);

                if stripped_path.starts_with(&Path::new(&rule.path)) {
                    if let Some(pattern) = &rule.filename_pattern {
                        if pattern == "*" {
                            return true;
                        }

                        let filename = stripped_path.file_name().unwrap().to_str().unwrap();

                        return filename.contains(pattern);
                    }

                    return true;
                }

                false
            })
        }
    }
}