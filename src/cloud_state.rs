use crate::cloud::CloudService;
use crate::config::Config;
use crate::registry::{compute_file_md5, RegistryEntry};
use std::path::PathBuf;
use std::collections::HashMap;
use walkdir::WalkDir;
use crate::println_verbose;

/// |-------------------------------------------------|
/// | Local | Registry | Remote | Can Pull | Can Push |
/// |-------------------------------------------------|
/// |  None |   None   |  None  |   No     |   No     | No files
/// |   1   |   None   |  None  |   No     |   Yes    | New local file
/// |  None |    1     |  None  |   No     |   No     | Deleted local file, Deleted remote file
/// |  None |   None   |   1    |   Yes    |   No     | New remote file
/// |   1   |    1     |  None  |   Yes    |   Yes    | Deleted remote file
/// |  None |    1     |   1    |   Yes    |   Yes    | Deleted local file
/// |   1   |   None   |   1    |   No     |   No     | New local file, New remote file
/// |   1   |    1     |   1    |   No     |   No     | Nothing changed
/// |   2   |    1     |   1    |   No     |   Yes    | Changed local file
/// |   1   |    2     |   1    |   No     |   No     | Changed local file, Changed remote file
/// |   1   |    1     |   2    |   Yes    |   No     | Changed remote file
/// |-------------------------------------------------|

#[derive(Debug)]
pub enum StateError {
    NotLoaded,
    RemoteError,
    IOError,
    ParseError
}

#[derive(Debug)]
pub struct StateRule {
    conditions: &'static [StateRuleCondition],
    action: StateRuleAction,
}

impl std::fmt::Display for StateRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State Rule Actioning ({:?})", self.action)?;

        for condition in self.conditions {
            write!(f, "\n\t{}", condition)?;
        }

        Ok(())
    }
}

impl StateRule {
    pub fn applies(&self, file_state: &FileState) -> bool {
        for condition in self.conditions {
            if !condition.applies(file_state) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug)]
pub enum StateRuleCondition {
    Exists(StateRuleTarget),
    NotExists(StateRuleTarget),
    Equal(StateRuleTarget, StateRuleTarget),
    NotEqual(StateRuleTarget, StateRuleTarget),
}

impl std::fmt::Display for StateRuleCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateRuleCondition::Exists(target) => write!(f, "Target ({:?}) Exists", target),
            StateRuleCondition::NotExists(target) => write!(f, "Target ({:?}) Does Not Exists", target),
            StateRuleCondition::Equal(target1, target2) => write!(f, "Target ({:?}) Equals Target ({:?})", target1, target2),
            StateRuleCondition::NotEqual(target1, target2) => write!(f, "Target ({:?}) Does Not Equal Target ({:?})", target1, target2),
        }
    }
}

impl StateRuleCondition {
    pub fn applies(&self, file_state: &FileState) -> bool {
        match self {
            StateRuleCondition::Exists(target) => {
                match target {
                    StateRuleTarget::Local => file_state.local_md5.is_some(),
                    StateRuleTarget::Registry => file_state.registry_md5.is_some(),
                    StateRuleTarget::Remote => file_state.remote_md5.is_some(),
                }
            },
            StateRuleCondition::NotExists(target) => {
                match target {
                    StateRuleTarget::Local => file_state.local_md5.is_none(),
                    StateRuleTarget::Registry => file_state.registry_md5.is_none(),
                    StateRuleTarget::Remote => file_state.remote_md5.is_none(),
                }
            },
            StateRuleCondition::Equal(target1, target2) => {
                match (target1, target2) {
                    (StateRuleTarget::Local, StateRuleTarget::Registry) => file_state.local_md5 == file_state.registry_md5,
                    (StateRuleTarget::Local, StateRuleTarget::Remote) => file_state.local_md5 == file_state.remote_md5,
                    (StateRuleTarget::Registry, StateRuleTarget::Remote) => file_state.registry_md5 == file_state.remote_md5,
                    _ => false,
                }
            },
            StateRuleCondition::NotEqual(target1, target2) => {
                match (target1, target2) {
                    (StateRuleTarget::Local, StateRuleTarget::Registry) => file_state.local_md5 != file_state.registry_md5,
                    (StateRuleTarget::Local, StateRuleTarget::Remote) => file_state.local_md5 != file_state.remote_md5,
                    (StateRuleTarget::Registry, StateRuleTarget::Remote) => file_state.registry_md5 != file_state.remote_md5,
                    _ => false,
                }
            },
        }
    }
}

#[derive(Debug)]
pub enum StateRuleAction {
    None,
    Pull,
    Push,
    PushAndPull,
    Conflict,
}

#[derive(Debug)]
enum StateRuleTarget {
    Local,
    Registry,
    Remote,
}

const NO_FILES_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::NotExists(StateRuleTarget::Local),
        StateRuleCondition::NotExists(StateRuleTarget::Registry),
        StateRuleCondition::NotExists(StateRuleTarget::Remote),
    ],
    action: StateRuleAction::None,
};

const NEW_LOCAL_FILE_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::Exists(StateRuleTarget::Local),
        StateRuleCondition::NotExists(StateRuleTarget::Registry),
        StateRuleCondition::NotExists(StateRuleTarget::Remote),
    ],
    action: StateRuleAction::Push,
};

const DELETED_LOCAL_AND_REMOTE_FILE_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::NotExists(StateRuleTarget::Local),
        StateRuleCondition::Exists(StateRuleTarget::Registry),
        StateRuleCondition::NotExists(StateRuleTarget::Remote),
    ],
    action: StateRuleAction::None,
};

const NEW_REMOTE_FILE_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::NotExists(StateRuleTarget::Local),
        StateRuleCondition::NotExists(StateRuleTarget::Registry),
        StateRuleCondition::Exists(StateRuleTarget::Remote),
    ],
    action: StateRuleAction::Pull,
};

const DELETED_REMOTE_FILE_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::Exists(StateRuleTarget::Local),
        StateRuleCondition::Exists(StateRuleTarget::Registry),
        StateRuleCondition::NotExists(StateRuleTarget::Remote),
    ],
    action: StateRuleAction::PushAndPull,
};

const LOCAL_FILE_DELETED_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::NotExists(StateRuleTarget::Local),
        StateRuleCondition::Exists(StateRuleTarget::Registry),
        StateRuleCondition::Exists(StateRuleTarget::Remote),
    ],
    action: StateRuleAction::PushAndPull,
};

const NEW_LOCAL_AND_REMOTE_FILE_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::Exists(StateRuleTarget::Local),
        StateRuleCondition::NotExists(StateRuleTarget::Registry),
        StateRuleCondition::Exists(StateRuleTarget::Remote),
    ],
    action: StateRuleAction::Conflict,
};

const NOTHING_CHANGED_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::Equal(StateRuleTarget::Local, StateRuleTarget::Registry),
        StateRuleCondition::Equal(StateRuleTarget::Local, StateRuleTarget::Remote),
        StateRuleCondition::Equal(StateRuleTarget::Registry, StateRuleTarget::Remote),
    ],
    action: StateRuleAction::None,
};

const LOCAL_FILE_CHANGED_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::NotEqual(StateRuleTarget::Local, StateRuleTarget::Registry),
        StateRuleCondition::Equal(StateRuleTarget::Registry, StateRuleTarget::Remote),
    ],
    action: StateRuleAction::Push,
};

const LOCAL_AND_REMOTE_FILE_CHANGED_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::NotEqual(StateRuleTarget::Local, StateRuleTarget::Registry),
        StateRuleCondition::NotEqual(StateRuleTarget::Registry, StateRuleTarget::Remote),
    ],
    action: StateRuleAction::Conflict,
};

const REMOTE_FILE_CHANGED_RULE: &'static StateRule = &StateRule {
    conditions: &[
        StateRuleCondition::Equal(StateRuleTarget::Local, StateRuleTarget::Registry),
        StateRuleCondition::NotEqual(StateRuleTarget::Registry, StateRuleTarget::Remote),
    ],
    action: StateRuleAction::Pull,
};

// Using CRUD acronym for naming
const STATE_CREATE_DELETE_RULES: &'static [&StateRule] = &[
    NO_FILES_RULE,
    NEW_LOCAL_FILE_RULE,
    DELETED_LOCAL_AND_REMOTE_FILE_RULE,
    NEW_REMOTE_FILE_RULE,
    DELETED_REMOTE_FILE_RULE,
    LOCAL_FILE_DELETED_RULE,
    NEW_LOCAL_AND_REMOTE_FILE_RULE,
];

const STATE_UPDATE_RULES: &'static [&StateRule] = &[
    NOTHING_CHANGED_RULE,
    LOCAL_FILE_CHANGED_RULE,
    LOCAL_AND_REMOTE_FILE_CHANGED_RULE,
    REMOTE_FILE_CHANGED_RULE,
];

#[derive(Debug)]
pub struct CloudState<'a> {
    entries: HashMap<PathBuf, FileState<'a>>, // local path to state

    // stats
    total_count: usize,
    push_count: usize,
    pull_count: usize,
    conflict_count: usize,
}

impl<'a> CloudState<'a> {
    pub async fn load(config: &Config, cloud: &CloudService, verbose: bool) -> Result<Self, StateError> {
        let mut this = Self {
            entries: HashMap::new(),
            total_count: 0,
            push_count: 0,
            pull_count: 0,
            conflict_count: 0,
        };

        println_verbose!(verbose, "Loading remote files...");

        let remote_files = cloud.get_remote_files(config, verbose).await;

        if let Err(error) = remote_files {
            eprintln!("Failed to retrieve remote files: {:?}", error);
            return Err(StateError::RemoteError);
        }

        println_verbose!(verbose, "Loading local files...");

        let remote_files = remote_files.unwrap();
        let local_files = CloudState::get_local_files(config).await?;

        println_verbose!(verbose, "Files loaded");
        println_verbose!(verbose, "Processing found entries...");

        for local_file in local_files {
            let local_path = config.get_system_local_path()
                .map(|path| path)
                .map_err(|_| StateError::IOError)?;

            let rel_path = local_file.path.strip_prefix(local_path);

            if let Err(error) = rel_path {
                eprintln!("Failed to strip prefix: {:?}", error);

                return Err(StateError::IOError);
            }
            let rel_path = Config::format_path(&rel_path.unwrap().to_path_buf());

            let mut file_state = FileState::new(
                config.resolve_abs_path(&rel_path),
                rel_path.clone(),
            );

            file_state.set_local_md5(local_file.hash);

            this.entries.insert(rel_path, file_state);
        }

        for remote_file in remote_files {
            let formatted_path = Config::format_path(&remote_file.path);

            if let Some(file_state) = this.entries.get_mut(&formatted_path) {
                file_state.set_remote_md5(remote_file.hash);
            }
            else {
                let mut file_state = FileState::new(
                    config.resolve_abs_path(&formatted_path),
                    formatted_path.clone(),
                );

                file_state.set_remote_md5(remote_file.hash.clone());
                file_state.set_registry_entry(remote_file);

                this.entries.insert(formatted_path, file_state);
            }
        }

        for registry_entry in config.registry.iter() {
            let formatted_path = Config::format_path(&registry_entry.path);

            if let Some(file_state) = this.entries.get_mut(&formatted_path) {
                file_state.set_registry_md5(registry_entry.hash.clone());
                file_state.set_registry_entry(registry_entry.clone());
            }
            else {
                let mut file_state = FileState::new(
                    config.resolve_abs_path(&formatted_path),
                    formatted_path.clone(),
                );

                println_verbose!(verbose, "Attaching registry entry {} to file {:?}", &registry_entry, &file_state);

                file_state.set_registry_md5(registry_entry.hash.clone());
                file_state.set_registry_entry(registry_entry.clone());

                this.entries.insert(formatted_path, file_state);
            }
        }

        println_verbose!(verbose, "Entries processed");
        println_verbose!(verbose, "Parsing state...");

        for file_state in this.entries.values_mut() {
            let result = file_state.parse_state(config, verbose)?;

            match result {
                Some(rule) => {
                    match rule.action {
                        StateRuleAction::Pull => this.pull_count += 1,
                        StateRuleAction::Push => this.push_count += 1,
                        StateRuleAction::PushAndPull => {
                            this.pull_count += 1;
                            this.push_count += 1;
                        },
                        StateRuleAction::Conflict => this.conflict_count += 1,
                        _ => (),
                    }
                },
                None => (),
            }
        }

        println_verbose!(verbose, "State parsed");

        Ok(this)
    }

    async fn get_local_files(config: &Config) -> Result<Vec<RegistryEntry>, StateError> {
        let mut locals = vec![];

        let local_path = config.get_system_local_path()
            .map(|path| path)
            .map_err(|_| StateError::IOError)?;

        for entry in WalkDir::new(&local_path) {
            if let Err(error) = entry {
                eprintln!("Fell over walking in path: {:?}, {:?}", &local_path, error);

                return Err(StateError::IOError);
            }

            let entry = entry.unwrap();
            let path = entry.path();
            let name = entry.file_name().to_str();

            if path.is_dir() {
                continue;
            }

            if name.is_none() {
                eprintln!("Failed to get file name: {:?}", path);

                return Err(StateError::IOError);
            }

            let md5 = compute_file_md5(path).await;

            if let Err(error) = md5 {
                eprintln!("Failed to compute MD5: {:?}", error);

                return Err(StateError::IOError);
            }

            let md5 = md5.unwrap();
            let name = name.unwrap();

            locals.push(RegistryEntry {
                id: String::from(""),
                path: path.to_path_buf(),
                name: name.to_string(),
                hash: md5,
            })
        }

        Ok(locals)
    }

    pub fn get_total_count(&self) -> usize {
        self.total_count
    }

    pub fn get_push_count(&self) -> usize {
        self.push_count
    }

    pub fn get_pull_count(&self) -> usize {
        self.pull_count
    }

    pub fn get_conflict_count(&self) -> usize {
        self.conflict_count
    }

    pub fn get_push_iterator(&self) -> impl Iterator<Item = &FileState> {
        self.entries.values().filter(|file_state| file_state.can_push().unwrap_or(false))
    }

    pub fn get_pull_iterator(&self) -> impl Iterator<Item = &FileState> {
        self.entries.values().filter(|file_state| file_state.can_pull().unwrap_or(false))
    }

    pub fn get_conflict_iterator(&self) -> impl Iterator<Item = &FileState> {
        self.entries.values().filter(|file_state| file_state.is_conflict().unwrap_or(false))
    }
}

pub struct FileState<'a> {
    registry_entry: Option<RegistryEntry>,
    abs_path: PathBuf,
    rel_path: PathBuf,
    local_md5: Option<String>,
    registry_md5: Option<String>,
    remote_md5: Option<String>,
    can_pull: bool,
    can_push: bool,
    is_conflict: bool,
    is_state_parsed: bool,
    rule_action: Option<&'a &'a StateRule>,
}

impl<'a> FileState<'a> {
    pub fn new(abs_path: PathBuf, rel_path: PathBuf) -> Self {
        Self {
            registry_entry: None,
            abs_path,
            rel_path,
            local_md5: None,
            registry_md5: None,
            remote_md5: None,
            can_pull: false,
            can_push: false,
            is_conflict: false,
            is_state_parsed: false,
            rule_action: None,
        }
    }

    pub fn rule_action(&self) -> Option<&StateRuleAction> {
        self.rule_action.map(|rule| &rule.action)
    }

    pub fn registry_entry(&self) -> Option<&RegistryEntry> {
        self.registry_entry.as_ref()
    }

    pub fn set_registry_entry(&mut self, entry: RegistryEntry) {
        self.registry_entry = Some(entry);
    }

    pub fn abs_path(&self) -> &PathBuf {
        &self.abs_path
    }

    pub fn rel_path(&self) -> &PathBuf {
        &self.rel_path
    }

    pub fn file_name(&self) -> Option<&str> {
        self.abs_path.file_name().and_then(|name| name.to_str())
    }

    pub fn local_md5(&self) -> Option<&String> {
        self.local_md5.as_ref()
    }

    pub fn set_local_md5(&mut self, md5: String) {
        self.local_md5 = Some(md5);
    }

    pub fn registry_md5(&self) -> Option<&String> {
        self.registry_md5.as_ref()
    }

    pub fn set_registry_md5(&mut self, md5: String) {
        self.registry_md5 = Some(md5);
    }

    pub fn remote_md5(&self) -> Option<&String> {
        self.remote_md5.as_ref()
    }

    pub fn set_remote_md5(&mut self, md5: String) {
        self.remote_md5 = Some(md5);
    }

    pub fn parse_state(&mut self, config: &Config, verbose: bool) -> Result<Option<&&StateRule>, StateError> {
        if self.is_state_parsed {
            println_verbose!(verbose, "State already parsed for file: {:?}", self.rel_path);
            return Ok(self.rule_action);
        }

        let is_excluded = config.is_path_excluded(self.abs_path(), verbose);

        if is_excluded {
            println_verbose!(verbose, "File is excluded: {:?}", self.rel_path);

            self.can_pull = false;
            self.can_push = false;
            self.is_state_parsed = true;

            return Ok(None);
        }

        let mut result_rule: Option<&&StateRule> = None;

        println_verbose!(verbose, "Parsing file state for {:?}...", &self.rel_path);

        let rules = if self.local_md5.is_none() || self.registry_md5.is_none() || self.remote_md5.is_none() {
            println_verbose!(verbose, "Checking create/delete rules...");
            STATE_CREATE_DELETE_RULES
        }
        else {
            println_verbose!(verbose, "Checking update rules...");
            STATE_UPDATE_RULES
        };

        for rule in rules {
            println_verbose!(verbose, "Testing rule: {:?}", rule);

            if rule.applies(self) {
                println_verbose!(verbose, "Rule applies: {:?}", rule);

                result_rule = Some(rule);
                break;
            }
        }

        if let Some(rule) = result_rule {
            match rule.action {
                StateRuleAction::None => {
                    self.can_pull = false;
                    self.can_push = false;
                },
                StateRuleAction::Pull => {
                    self.can_pull = true;
                    self.can_push = false;
                },
                StateRuleAction::Push => {
                    self.can_pull = false;
                    self.can_push = true;
                },
                StateRuleAction::PushAndPull => {
                    self.can_pull = true;
                    self.can_push = true;
                },
                StateRuleAction::Conflict => {
                    self.can_pull = false;
                    self.can_push = false;
                    self.is_conflict = true;
                },
            }
        }
        else {
            return Err(StateError::ParseError);
        }

        println_verbose!(verbose, "State parsed for file: {:?}", self);

        self.rule_action = result_rule;
        self.is_state_parsed = true;

        Ok(result_rule)
    }

    pub fn can_push(&self) -> Result<bool, StateError> {
        if !self.is_state_parsed {
            return Err(StateError::NotLoaded);
        }

        Ok(self.can_push)
    }

    pub fn can_pull(&self) -> Result<bool, StateError> {
        if !self.is_state_parsed {
            return Err(StateError::NotLoaded);
        }

        Ok(self.can_pull)
    }

    pub fn is_conflict(&self) -> Result<bool, StateError> {
        if !self.is_state_parsed {
            return Err(StateError::NotLoaded);
        }

        Ok(self.is_conflict)
    }
}

impl<'a> std::fmt::Debug for FileState<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<FileState abs_path={} rel_path={} local_md5={} registry_md5={} remote_md5={} can_pull={} can_push={} state_loaded={}>", self.abs_path.display(), self.rel_path.display(), self.local_md5.as_ref().unwrap_or(&String::from("None")), self.registry_md5.as_ref().unwrap_or(&String::from("None")), self.remote_md5.as_ref().unwrap_or(&String::from("None")), self.can_pull, self.can_push, self.is_state_parsed)
    }
}