mod command;
mod registry;
mod config;
mod cloud;
mod cloud_state;
mod log;

use futures;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use clap::Parser;
use command::{Cli, Commands, PullArgs, PushArgs, InitArgs, ExcludeArgs};
use config::Config;
use crate::cloud::CloudError;
use crate::cloud_state::{CloudState, FileState};
use crate::command::{ResetArgs, SetRemoteArgs};
use crate::registry::{compute_file_md5, RegistryEntry};

const CONFIG_FILENAME: &str = "cloud-share.toml";

#[tokio::main]
async fn main() {
    cloud::init_crypto();

    let cli = Cli::parse();
    let verbose = cli.verbose.unwrap_or(false);

    match cli.command {
        Some(Commands::Init(args)) => handle_init(args, verbose),
        Some(Commands::Reset(args)) => handle_reset(args, verbose),
        Some(Commands::SetRemote(args)) => handle_set_remote(args, verbose),
        Some(Commands::Pull(args)) => handle_pull(args, verbose).await,
        Some(Commands::Push(args)) => handle_push(args, verbose).await,
        Some(Commands::Exclude(args)) => handle_exclude(args, verbose),
        Some(Commands::Include(args)) => handle_include(args, verbose),
        Some(Commands::Status) => handle_status(verbose).await,
        Some(Commands::ListConflicts) => handle_list_conflicts(verbose).await,
        Some(Commands::ListRegistry) => handle_list_registry(verbose).await,
        Some(Commands::ListExclusions) => handle_list_exclusions(verbose),
        None => {}  // Handled by clap's built-in help
    }
}

fn handle_init(_args: InitArgs, verbose: bool) {
    println!("Initializing new configuration...");

    let path = _args.path.unwrap_or_else(|| String::from("."));

    let canonical_path = Path::new(&path);

    if !canonical_path.exists() {
        // Create the directory if it doesn't exist
        match std::fs::create_dir_all(&canonical_path) {
            Ok(_) => println!("Created directory: {:?}", canonical_path),
            Err(e) => {
                eprintln!("Failed to create directory: {:?}", e);
                return;
            }
        }
    }

    println!("Creating {} in {:?}", CONFIG_FILENAME, canonical_path);

    let result = Config::new(
        _args.url,
        canonical_path.to_path_buf(),
        CONFIG_FILENAME
    ).save();

    match result {
        Ok(_) => println!("Configuration saved"),
        Err(e) => eprintln!("Failed to save configuration: {:?}", e),
    }
}

fn handle_reset(_args: ResetArgs, verbose: bool) {
    let result = if let Some(path) = _args.path {
        println!("Resetting state for {:?}", path);

        Config::load(CONFIG_FILENAME)
            .map(|mut config| {
                config.remove_registry_entry(PathBuf::from(path))
                    .save()
            })
            .map(|_| ())
    }
    else {
        println!("Resetting state for all paths");

        Config::load(CONFIG_FILENAME)
            .map(|mut config| {
                config.clear_registry()
                    .clear_exclusions()
                    .save()
            })
            .map(|_| ())
    };

    match result {
        Ok(_) => println!("State reset"),
        Err(e) => eprintln!("Failed to reset state: {:?}", e),
    }
}

fn handle_set_remote(_args: SetRemoteArgs, verbose: bool) {
    println!("Setting remote URL to {}", _args.url);

    let result = Config::load(CONFIG_FILENAME)
        .map(|mut config| {
            config.set_remote(_args.url)
                .save()
        })
        .map(|_| ());

    match result {
        Ok(_) => println!("Remote URL set"),
        Err(e) => eprintln!("Failed to set remote URL: {:?}", e),
    }
}

async fn handle_pull<'a>(_args: PullArgs, verbose: bool) {
    println!("Pulling files from cloud storage...");

    let config_raw = Config::load(CONFIG_FILENAME);

    if config_raw.is_err() {
        eprintln!("Failed to load configuration: {:?}", config_raw.err());
        return;
    }
    let config_raw = config_raw.unwrap();

    let cloud_raw = cloud::CloudService::new(verbose).await;

    if cloud_raw.is_err() {
        eprintln!("Failed to initialize cloud service: {:?}", cloud_raw.err());
        return;
    }
    let cloud_raw = cloud_raw.unwrap();

    println!("Connected to cloud storage");
    println!("Loading and parsing state...");

    let state = CloudState::load(&config_raw, &cloud_raw, verbose)
        .await;

    if state.is_err() {
        eprintln!("Failed to load cloud state: {:?}", state.err());
        return;
    }
    let state = state.unwrap();

    println!("State loaded, beginning pull operations...");

    // Wrap config in Arc<Mutex> for thread-safe access
    let local_path = config_raw.get_system_local_path();

    if local_path.is_err() {
        eprintln!("Failed to get local path: {:?}", local_path.err());
        return;
    }
    let local_path = local_path.unwrap();

    let config_mutex = Arc::new(Mutex::new(config_raw));

    // Create a vector to hold task handles
    let mut tasks: Vec<tokio::task::JoinHandle<Result<(), CloudError>>> = Vec::new();

    for file in state.get_pull_iterator() {
        // Clone Arc references for each task
        let cloud = cloud_raw.clone();
        let config = Arc::clone(&config_mutex);
        let local_path_copy = local_path.clone();
        let rel_path = file.rel_path().clone();
        let remote_exists = file.remote_md5().is_some();
        let registry_entry = file.registry_entry();

        if registry_entry.is_none() {
            eprintln!("[{:?}] Remote entry not found", rel_path);
            continue;
        }
        let registry_entry = registry_entry.unwrap().clone();

        // Spawn a new async task for each download
        let handle = tokio::spawn(async move {
            // Download the file
            println!("[{:?}] Starting download", rel_path);

            cloud.download_file(&registry_entry, Path::new(&local_path_copy), verbose)
                .await
                .map_err(|e| {
                    eprintln!("[{:?}] Download failed: {}", rel_path, e);
                    e
                })?;

            // Re-acquire lock for registry update
            let mut locked_config = config.lock().await;

            let entry_exists = locked_config.contains_registry_entry(registry_entry.id.clone());

            if !remote_exists && entry_exists {
                locked_config.remove_registry_entry(registry_entry.path.clone());
            }
            else if entry_exists {
                locked_config.update_entry_hash(registry_entry.id.clone(), registry_entry.hash.clone());
            }
            else {
                locked_config.add_registry_entry(&registry_entry);
            }

            locked_config.save().map_err(|e| CloudError::SyncError(
                e.to_string()
            ))?;

            if remote_exists {
                println!("[{:?}] Download complete", rel_path);
            }
            else {
                println!("[{:?}] File removed from local storage, was removed in cloud", rel_path);
            }

            Ok(())
        });

        tasks.push(handle);
    }

    if tasks.is_empty() {
        println!("Up to date, nothing to pull");
        return;
    }

    // Wait for all downloads to complete
    let results = futures::future::join_all(tasks).await;

    // Check for errors
    for result in results {
        match result {
            Ok(Ok(_)) => {},
            Ok(Err(e)) => eprintln!("Task failed: {}", e),
            Err(e) => eprintln!("Task panicked: {:?}", e),
        }
    }

    display_conflicts(&state, verbose);
}

async fn handle_push(_args: PushArgs, verbose: bool) {
    println!("Pushing files to cloud storage...");

    let config_raw = Config::load(CONFIG_FILENAME);

    if config_raw.is_err() {
        eprintln!("Failed to load configuration: {:?}", config_raw.err());
        return;
    }
    let mut config_raw = config_raw.unwrap();

    let cloud_raw = cloud::CloudService::new(verbose).await;

    if cloud_raw.is_err() {
        eprintln!("Failed to initialize cloud service: {:?}", cloud_raw.err());
        return;
    }
    let cloud_raw = cloud_raw.unwrap();

    println!("Connected to cloud storage");
    println!("Loading and parsing state...");

    let state = CloudState::load(&config_raw, &cloud_raw, verbose)
        .await;

    if state.is_err() {
        eprintln!("Failed to load cloud state: {:?}", state.err());
        return;
    }
    let state = state.unwrap();

    println!("State loaded, beginning push operations...");

    let mut push_attempt_counter = 0;

    for file in state.get_push_iterator() {
        push_attempt_counter += 1;
        println!("[{:?}] Starting upload", &file.rel_path());

        let mut existing_id: Option<String> = None;
        let registry_entry = file.registry_entry();

        if registry_entry.is_some() {
            existing_id = Some(registry_entry.unwrap().id.clone());
        }

        let local_path = config_raw.get_system_local_path();

        if local_path.is_err() {
            eprintln!("Failed to get local path: {:?}", local_path.err());
            return;
        }
        let local_path = Config::make_path_remote(&local_path.unwrap());

        println_verbose!(verbose, "Local path: {:?}", local_path);

        let rel_path = file.rel_path();
        let name = file.file_name();

        if name.is_none() {
            eprintln!("[{:?}] Failed to get filename", &file.rel_path());
            continue;
        }
        let name = name.unwrap();

        println!("Uploading file with ID: {:?}", existing_id);

        let remote_id = cloud_raw.upload_file(
            existing_id.clone(),
            &file.abs_path(),
            &config_raw.remote_url,
            &local_path,
            verbose,
        )
            .await;

        if remote_id.is_err() {
            eprintln!("[{}] Upload failed: {}", &file.rel_path().to_str().unwrap_or(""), remote_id.err().unwrap());
            continue;
        }
        let (remote_id, remote_hash_optional) = remote_id.unwrap();

        match remote_hash_optional {
            Some(remote_hash) => {
                if existing_id.is_some() {
                    println_verbose!(verbose, "[{:?}] Updating registry entry", &rel_path);

                    config_raw.update_entry_hash(remote_id, remote_hash);
                }
                else {
                    println_verbose!(verbose, "[{:?}] Adding registry entry", &rel_path);

                    config_raw.add_registry_entry(&RegistryEntry {
                        id: remote_id,
                        name: name.to_string(),
                        path: rel_path.clone(),
                        hash: remote_hash,
                    });
                }
            }
            None => {
                if existing_id.is_some() {
                    println_verbose!(verbose, "[{:?}] File removed from cloud storage, removing from registry...", &rel_path);

                    config_raw.remove_registry_entry(rel_path.clone());
                }
            }
        }

        println!("[{:?}] Upload complete", &rel_path);
    }

    if push_attempt_counter == 0 {
        println!("Up to date, nothing to push");
        return;
    }

    display_conflicts(&state, verbose);

    match config_raw.save() {
        Ok(_) => println!("Configuration saved"),
        Err(e) => eprintln!("Failed to save configuration: {:?}", e),
    }
}

fn handle_exclude(_args: ExcludeArgs, verbose: bool) {
    let formatted_path = Config::format_path(&PathBuf::from(_args.path.clone()));
    let pattern_display = _args.filename_pattern.clone().unwrap_or_else(|| String::from("*"));

    println!("Excluding path: {} with pattern: {}", formatted_path.to_str().unwrap(), pattern_display);

    let result = Config::load(CONFIG_FILENAME)
        .map(|mut config| {
            config.add_exclusion_rule(_args.path, _args.filename_pattern)
                .save()
        })
        .map(|_| ());

    match result {
        Ok(_) => println!("Path excluded"),
        Err(e) => eprintln!("Failed to exclude path: {:?}", e),
    }
}

fn handle_include(_args: ExcludeArgs, verbose: bool) {
    println!("Including path: {}", _args.path);

    let result = Config::load(CONFIG_FILENAME)
        .map(|mut config| {
            config.remove_exclusion_rule(_args.path, _args.filename_pattern)
                .save()
        })
        .map(|_| ());

    match result {
        Ok(_) => println!("Path included"),
        Err(e) => eprintln!("Failed to include path: {:?}", e),
    }
}

async fn handle_status(verbose: bool) {
    println!("Displaying status...");

    let mut up_to_date = true;
    let config_raw = Config::load(CONFIG_FILENAME);

    if config_raw.is_err() {
        eprintln!("Failed to load configuration: {:?}", config_raw.err());
        return;
    }
    let config_raw = config_raw.unwrap();

    let cloud_raw = cloud::CloudService::new(verbose).await;

    if cloud_raw.is_err() {
        eprintln!("Failed to initialize cloud service: {:?}", cloud_raw.err());
        return;
    }
    let cloud_raw = cloud_raw.unwrap();

    println!("Connected to cloud storage");
    println!("Loading and parsing state...");

    let state = CloudState::load(&config_raw, &cloud_raw, verbose)
        .await;

    if state.is_err() {
        eprintln!("Failed to load cloud state: {:?}", state.err());
        return;
    }
    let state = state.unwrap();

    println!("State loaded\nFound {} entries", state.get_total_count());
    println!("\nPush actions ({}) [path]: local/registry/remote:", state.get_push_count());

    let mut show_empty_message = true;

    for entry in state.get_push_iterator() {
        println_file_state(entry);
        show_empty_message = false;
        up_to_date = false;
    }

    if show_empty_message {
        println!("\tNo push actions");
    }

    println!("\nPull actions ({}) [path]: local/registry/remote:", state.get_pull_count());

    show_empty_message = true;

    for entry in state.get_pull_iterator() {
        println_file_state(entry);
        show_empty_message = false;
        up_to_date = false;
    }

    if show_empty_message {
        println!("\tNo pull actions");
    }

    if display_conflicts(&state, verbose) {
        up_to_date = false;
    }

    if up_to_date {
        println!("\nUp to date");
    }
}

async fn handle_list_conflicts(verbose: bool) {
    println!("Listing conflicts...");

    let config_raw = Config::load(CONFIG_FILENAME);

    if config_raw.is_err() {
        eprintln!("Failed to load configuration: {:?}", config_raw.err());
        return;
    }
    let config_raw = config_raw.unwrap();

    let cloud_raw = cloud::CloudService::new(verbose).await;

    if cloud_raw.is_err() {
        eprintln!("Failed to initialize cloud service: {:?}", cloud_raw.err());
        return;
    }
    let cloud_raw = cloud_raw.unwrap();

    println!("Connected to cloud storage");
    println!("Loading and parsing state...");

    let state = CloudState::load(&config_raw, &cloud_raw, verbose).await;

    if state.is_err() {
        eprintln!("Failed to load cloud state: {:?}", state.err());
        return;
    }
    let state = state.unwrap();

    display_conflicts(&state, verbose);
}

/// Display conflicts and return true if any conflicts were found
fn display_conflicts(state: &CloudState, verbose: bool) -> bool {
    println!("\nConflicts ({}) [path]: local/registry/remote:", state.get_conflict_count());

    let mut show_empty_message = true;

    for entry in state.get_conflict_iterator() {
        println_file_state(entry);
        show_empty_message = false;
    }

    if show_empty_message {
        println!("\tNo conflicts");

        false
    }
    else {
        println!("\nResolve conflicts manually and run push/pull again");

        true
    }
}

fn println_file_state(entry: &FileState) {
    let rel_path_display = entry.rel_path().to_str().unwrap_or_else(|| "None");
    let none_display = String::from("None");
    let local_hash_display = entry.local_md5().unwrap_or_else(|| &none_display);
    let registry_hash_display = entry.registry_md5().unwrap_or_else(|| &none_display);
    let remote_hash_display = entry.remote_md5().unwrap_or_else(|| &none_display);

    let bullet_char = match entry.rule_action() {
        Some(cloud_state::StateRuleAction::Pull) => {
            " ↓ "
        }
        Some(cloud_state::StateRuleAction::Push) => {
            " ↑ "
        }
        Some(cloud_state::StateRuleAction::PushAndPull) => {
            " ↕ "
        }
        Some(cloud_state::StateRuleAction::Conflict) => {
            " ✗ "
        }

        Some(cloud_state::StateRuleAction::None) |
        None => {
            " • "
        }
    };

    println!("\t{}[{}] {}/{}/{}", bullet_char, rel_path_display, local_hash_display, registry_hash_display, remote_hash_display);
}

async fn handle_list_registry(verbose: bool) {
    let config = Config::load(CONFIG_FILENAME);

    if config.is_err() {
        eprintln!("Failed to load config: {:?}", config.err());
        return;
    }
    let config = config.unwrap();

    let none_display = String::from("None");

    for entry in &config.registry {
        let abs_path = Config::format_path(&config.resolve_abs_path(&entry.path));

        println!(
            "[{}] id={}\n\tLocal MD5: {}\n\tRegistry MD5: {}\n\t",
            abs_path.to_str().unwrap_or(&none_display),
            entry.id,
            compute_file_md5(&Config::make_path_local(&abs_path)).await.unwrap_or_else(|_| none_display.clone()),
            entry.hash,
        );
    }
}

fn handle_list_exclusions(verbose: bool) {
    let config = Config::load(CONFIG_FILENAME);

    if config.is_err() {
        eprintln!("Failed to load config: {:?}", config.err());
        return;
    }
    let config = config.unwrap();

    for rule in config.exclusions {
        println!("[{}]: [{}]", rule.path, rule.filename_pattern.unwrap_or_else(|| String::from("*")));
    }
}