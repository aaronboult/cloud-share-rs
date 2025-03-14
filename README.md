## What is it?
Cloud share is a command line tool enabling basic version controlling of
files in Google Drive. The tool is a portable executable for Windows.

## How does it work?

Cloud share is designed to be placed in the root directory of the project,
or in a parent directory with a defined subdirectory to synchronize.

The tool uses the Google Drive API to synchronize files between the local
directory and the Google Drive folder.

Version controlling relies on the MD5 checksum of the files, abiding by the
following table of MD5 checksum permutations:

```text
|-------------------------------------------------|
| Local | Registry | Remote | Can Pull | Can Push |
|-------------------------------------------------|
|  None |   None   |  None  |   No     |   No     | No files
|   1   |   None   |  None  |   No     |   Yes    | New local file
|  None |    1     |  None  |   No     |   No     | Deleted local file, Deleted remote file. Conflicted
|  None |   None   |   1    |   Yes    |   No     | New remote file
|   1   |    1     |  None  |   Yes    |   Yes    | Deleted remote file
|  None |    1     |   1    |   Yes    |   Yes    | Deleted local file
|   1   |   None   |   1    |   No     |   No     | New local file, New remote file
|   1   |    1     |   1    |   No     |   No     | Nothing changed
|   2   |    1     |   1    |   No     |   Yes    | Changed local file
|   1   |    2     |   1    |   No     |   No     | Changed local file, Changed remote file. Conflicted
|   1   |    1     |   2    |   Yes    |   No     | Changed remote file
|-------------------------------------------------|
```

## Usage
The following shows an example for setting up a synchronization configuration in an Unreal Engine 5 project.

### 1. Initialize a synchronization configuration by running:
```shell
cloud-share.exe init --url "https://drive.google.com/drive/u/0/folders/1xHSJiSFQqcjy1opVYLJ4NpPLwLLd_myh" --path "./"
```

### 2. Exclude directories we do not want to version control
```shell
cloud-share.exe exclude -- --paths "./Binaries" "./DerivedDataCache" "./Intermediate" "./Source"
```

### 3. Check the current status
```shell
cloud-share.exe status
```

### 4. Synchronize with cloud
```shell
cloud-share.exe sync
```

### Further usage
```shell
cloud-share.exe --help # Show a full list of commands
cloud-share.exe pull --help # Show the arguments for the pull command
cloud-share.exe exclude --help # Show the arguments for the exclude command
```
