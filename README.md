# Simple Backup and Restore

A small portable utility for backing up and restoring files. The project
contains a GUI application for creating backups and a companion script for
automated restores.

## Features

- Select multiple files and folders to back up.
- Backups are stored in directories such as
  `<DEST>\\<MACHINE>\\_backups\\<PREFIX>_YYYYmmdd-HHMMSS`.
- A JSON manifest is written next to the executable and copied into the backup
  folder so restores can find the data.
- Restore items to their original locations or to a custom folder. Restores are
  overwrite-only.

## Usage

### Create a backup

1. Run `python SimpleBackupandRestore.py`.
2. Choose a destination, machine ID and optional prefix.
3. Add files or folders to include and click **Run Backup**.

### Restore

- To restore manually, open the Restore tab in the GUI and select a manifest.
- For an automated restore, run `python MasterRestore.py` beside the backup
  folders. It picks the newest manifest matching the configured prefix and
  restores every item listed.

## Building executables

The scripts can be bundled using [PyInstaller](https://www.pyinstaller.org/):

```bash
pyinstaller --noconsole --onefile SimpleBackupandRestore.py
pyinstaller --noconsole --onefile MasterRestore.py
```

Place the resulting executables in `D:\\SimpleBackupandRestore\\` along with
the backup data directories.

