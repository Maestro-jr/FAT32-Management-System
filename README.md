# FAT32 Disk Management System

This project provides two interfaces for managing FAT32 disk images: a **Graphical User Interface (GUI)** and a **Command Line Interface (CLI)**. Both tools allow creating, formatting, and manipulating FAT32 virtual disks.

---

## Graphical User Interface (GUI)

The GUI application provides a user-friendly interface for disk and file operations.

### Key Features

1. **Disk Operations**
   - Create new disk images
   - Delete existing disks
   - Format disks
   - Clone disks
   - Mount disks for file access

2. **File Management**
   - Browse files and directories (with recursive listing option)
   - View file contents (supports text and binary files)
   - Create new files (with optional encryption)
   - Edit and save file changes
   - Delete files and directories

3. **System Information**
   - Disk health reports showing:
     - Disk geometry
     - FAT statistics
     - Slack space analysis
     - File system health
   - Real-time log viewer for:
     - Application operations (normal log)
     - Error messages (error log)
   - Configuration viewer displaying current FAT32 settings

4. **User Interface**
   - Dashboard navigation
   - Tab-based organization
   - Real-time disk space monitoring
   - File explorer with detailed metadata
   - Text editor for file content

### Usage

1. Disk operations are accessed through the main dashboard
2. Select a disk image to browse and manage its contents
3. Use the file explorer to navigate directories
4. Click on files to view/edit content
5. Access logs through dedicated tabs
6. View configuration via the designated button

### Requirements
- Python 3.x
- PyQt5
- FAT32 management module

---

## Command Line Interface (CLI)

The CLI tool allows scripting and automation of disk operations.

### Features
- Create and format new virtual disks (FAT32)
- Clone existing disk images
- Mount disks and perform file operations:
  - List directories (with optional recursion)
  - Search files by date range and/or name pattern
  - Create, read, write, delete files (with optional encryption)
  - Create and delete directories (recursive deletion with confirmation)
- Generate a detailed health report (disk geometry, FAT usage, slack space, integrity checks)
- Delete disk images

### Installation

Clone this repository:
```
git clone https://github.com/your-repo/fat32-manager.git
cd fat32-manager
```

Install dependencies (recommended to use a virtual environment):
```
pip install -r requirements.txt
```

### Usage

Run the script with one of the supported subcommands:
```
python fat32_manager.py <command> [options]
```

If run without arguments, you'll be prompted to create a default 1 GB disk and shown example commands.

### Commands

| Command         | Description                                      |
|-----------------|--------------------------------------------------|
| create-disk     | Create a new virtual disk image                 |
| clone-disk      | Clone source disk to target path                |
| format-disk     | Format an existing disk image as FAT32          |
| mount           | Mount a disk and optionally show health report  |
| list            | List files and directories on a mounted disk    |
| search          | Search for files by date or name pattern        |
| health-report   | Generate a comprehensive health report          |
| create-file     | Create a (optionally encrypted) file on the disk|
| read-file       | Read (and optionally decrypt) a file from the disk|
| write-file      | Update an existing file (with optional encryption)|
| delete-file     | Remove a file from the disk                     |
| create-dir      | Create a directory on the disk                  |
| delete-dir      | Delete an empty or non-empty directory          |
| delete-disk     | Delete the virtual disk image                   |

Use `-h` or `--help` with any command to see its options:
```
python fat32_manager.py create-disk --help
```

### Examples

```bash
# Create a 512 MB disk with 8 KB clusters
tools/create-disk mydisk.img --size 512 --cluster-size 8192

# List files recursively on /documents
python fat32_manager.py list mydisk.img --path /documents --recursive

# Create and encrypt a file
python fat32_manager.py create-file mydisk.img /secret.txt "Top Secret" --encrypt --password P@ssw0rd

# View health report
python fat32_manager.py health-report mydisk.img

# Delete the disk image
python fat32_manager.py delete-disk mydisk.img
```

---

## Configuration & Logging

- Configuration values can be adjusted in `utils/config.py`
- Logs are recorded via the built-in Logger (check console output for progress and errors)
- GUI maintains persistent logs in `logs/fat32manager.log` and `logs/fat32manager_errors.log`

## License

This project is licensed under the MIT License. Feel free to adapt or extend it for your needs.