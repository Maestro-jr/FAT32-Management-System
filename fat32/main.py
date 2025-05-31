#!/usr/bin/env python3
"""
FAT32 Virtual Disk Management System
Main entry point for creating, formatting, and managing FAT32 virtual disks
"""

import argparse
import sys
import os
from time import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our custom FAT32 modules
from disk.virtual_disk import VirtualDisk
from fat.fat_manager import FATManager
from fs.file_operations import FileOperations
from boot.boot_sector import BootSector
from utils.logger import Logger
from utils.encryption import FileEncryption
from utils.config import Config


ascii_art = [
    r"             ___________              ",
    r"         .-'           '-.           ",
    r"       .'                 '.         ",
    r"      /     _________       \        ",
    r"     |     /         \       |       ",
    r"     |    |  ()   ()  |      |       ",
    r"     |     \    ∆    /       |       ",
    r"      \     '.___.'        /         ",
    r"       '.                 .'         ",
    r"         '-.__________.-'           ",
    r"                                     ",
    r"          /===========\             ",
    r"         |  DISK.IMG   |            ",
    r"          \___________/             ",
    r"                                     ",
    r"       [ MOUNTED STORAGE ]          "
]
for line in ascii_art:
    print(line)




# Constants
DEFAULT_DISK_SIZE_MB = 1024
DEFAULT_SECTOR_SIZE = 512
DEFAULT_CLUSTER_SIZE = 4096
DEFAULT_DISK_IMAGE = 'virtual_disk.img'

class FAT32Manager:
    """Main FAT32 disk management class"""

    def __init__(self):
        self.logger = Logger()
        self.config = Config()

    def create_disk(self, size_mb, filename, cluster_size=DEFAULT_CLUSTER_SIZE):
        """Create a new virtual FAT32 disk"""
        try:
            start_time = time()
            self.logger.info(f"Creating virtual disk: {filename} ({size_mb} MB)")

            # Create virtual disk
            disk = VirtualDisk(filename, size_mb)
            disk.create()

            # Format with FAT32
            boot_sector = BootSector(size_mb, cluster_size)
            # FIX: Pass both disk and boot_sector to FATManager
            fat_manager = FATManager(disk, boot_sector)  # CHANGED HERE

            # Initialize disk structure
            disk.format_fat32(boot_sector, fat_manager)

            end_time = time()
            self.logger.info(f"Disk created successfully in {end_time - start_time:.2f}s")

            # Generate health report
            self.health_report(filename)

            return True

        except Exception as e:
            self.logger.error(f"Failed to create disk: {str(e)}")
            return False

    def clone_disk(self, source_path, target_path):
        """Clone a disk (physical or virtual)"""
        try:
            start_time = time()
            self.logger.info(f"Cloning disk from {source_path} to {target_path}")

            with open(source_path, 'rb') as src:
                with open(target_path, 'wb') as dst:
                    while True:
                        chunk = src.read(1024 * 1024)  # 1MB chunks
                        if not chunk:
                            break
                        dst.write(chunk)

            end_time = time()
            self.logger.info(f"Disk cloned successfully in {end_time - start_time:.2f}s")
            return True

        except Exception as e:
            self.logger.error(f"Failed to clone disk: {str(e)}")
            return False

    def format_disk(self, filename, cluster_size=DEFAULT_CLUSTER_SIZE):
        """Format an existing disk image as FAT32"""
        try:
            start_time = time()
            self.logger.info(f"Formatting disk: {filename} with cluster size {cluster_size} bytes")

            disk = VirtualDisk(filename)
            # Read existing geometry
            boot_sector = BootSector.from_disk(disk)
            # Override cluster size
            boot_sector.cluster_size = cluster_size

            fat_manager = FATManager(disk, boot_sector)
            disk.format_fat32(boot_sector, fat_manager)

            end_time = time()
            self.logger.info(f"Disk formatted successfully in {end_time - start_time:.2f}s")
            return True
        except Exception as e:
            self.logger.error(f"Failed to format disk: {str(e)}")
            return False

    def mount_disk(self, filename):
        """Mount and return disk operations interface"""

        try:
            if not os.path.exists(filename):
                self.logger.error(f"Disk image not found: {filename}")
                return None

            disk = VirtualDisk(filename)
            boot_sector = BootSector.from_disk(disk)

            # ADD VALIDATION - Catch FAT initialization errors
            try:
                fat_manager = FATManager(disk, boot_sector)
            except ValueError as ve:
                self.logger.error(f"FAT initialization failed: {str(ve)}")
                return None

            file_ops = FileOperations(disk, boot_sector, fat_manager)

            self.logger.info(f"Disk mounted: {filename}")
            return file_ops

        except Exception as e:
            self.logger.error(f"Failed to mount disk: {str(e)}")
            return None


    def list_files(self, filename, path="/", recursive=False):
        """List files and directories"""
        file_ops = self.mount_disk(filename)
        if not file_ops:
            return False

        try:
            entries = file_ops.list_directory(path, recursive)

            print(f"\nDirectory listing for {path}:")
            print("-" * 60)
            print(f"{'Name':<20} {'Type':<6} {'Size':<10} {'Modified':<20}")
            print("-" * 60)

            for entry in entries:
                entry_type = "DIR" if entry['is_directory'] else "FILE"
                size = "" if entry['is_directory'] else str(entry['size'])
                print(f"{entry['name']:<20} {entry_type:<6} {size:<10} {entry['modified']:<20}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to list files: {str(e)}")
            return False

    def search_files(self, filename, start_date=None, end_date=None, pattern=None):
        """Search files by date range and/or pattern"""
        file_ops = self.mount_disk(filename)
        if not file_ops:
            return False

        try:
            results = file_ops.search_files(start_date, end_date, pattern)

            print(f"\nSearch results:")
            print("-" * 60)
            print(f"{'Name':<20} {'Path':<25} {'Size':<10} {'Modified':<20}")
            print("-" * 60)

            for result in results:
                print(f"{result['name']:<20} {result['path']:<25} {result['size']:<10} {result['modified']:<20}")

            print(f"\nFound {len(results)} files")
            return True

        except Exception as e:
            self.logger.error(f"Failed to search files: {str(e)}")
            return False

    def health_report(self, filename):
        """Generate comprehensive health report"""
        file_ops = self.mount_disk(filename)
        if not file_ops:
            return False

        try:
            report = file_ops.generate_health_report()

            print(f"\n{'='*60}")
            print(f"HEALTH REPORT FOR: {filename}")
            print(f"{'='*60}")

            print(f"\nDisk Geometry:")
            print(f"  Total Size: {report['total_size'] / (1024*1024):.1f} MB")
            print(f"  Sector Size: {report['sector_size']} bytes")
            print(f"  Cluster Size: {report['cluster_size']} bytes")
            print(f"  Total Clusters: {report['total_clusters']:,}")

            print(f"\nFAT Statistics:")
            print(f"  Free Clusters: {report['free_clusters']:,}")
            print(f"  Used Clusters: {report['used_clusters']:,}")
            print(f"  Bad Clusters: {report['bad_clusters']:,}")
            print(f"  Free Space: {report['free_space'] / (1024*1024):.1f} MB")

            print(f"\nSlack Space Analysis:")
            print(f"  Total Slack Space: {report['total_slack'] / 1024:.1f} KB")
            print(f"  Average Slack per File: {report['avg_slack_per_file']:.1f} bytes")

            print(f"\nFile System Health:")
            print(f"  Cross-linked Clusters: {report['cross_linked_clusters']}")
            print(f"  Lost Chains: {report['lost_chains']}")
            print(f"  Integrity Status: {report['integrity_status']}")

            if report['recommendations']:
                print(f"\nRecommendations:")
                for rec in report['recommendations']:
                    print(f"  • {rec}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to generate health report: {str(e)}")
            return False

    def create_file(self, disk_filename, file_path, content, encrypt=False, password=None):
        """Create a file on the disk"""
        file_ops = self.mount_disk(disk_filename)
        if not file_ops:
            return False

        try:
            if encrypt and password:
                encryptor = FileEncryption()
                content = encryptor.encrypt(content.encode(), password)
            elif isinstance(content, str):
                content = content.encode()

            success = file_ops.create_file(file_path, content)

            if success:
                action = "encrypted file" if encrypt else "file"
                self.logger.info(f"Created {action}: {file_path}")
                return True
            else:
                self.logger.error(f"Failed to create file: {file_path}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to create file: {str(e)}")
            return False

    def read_file(self, disk_filename, file_path, decrypt=False, password=None):
        """Read a file from the disk"""
        file_ops = self.mount_disk(disk_filename)
        if not file_ops:
            return None

        try:
            content = file_ops.read_file(file_path)
            if content is None:
                return None

            if decrypt and password:
                encryptor = FileEncryption()
                content = encryptor.decrypt(content, password)

            return content

        except Exception as e:
            self.logger.error(f"Failed to read file: {str(e)}")
            return None

    def write_file(self, disk_filename, file_path, content, encrypt=False, password=None):
        """Update an existing file on the disk"""
        file_ops = self.mount_disk(disk_filename)
        if not file_ops:
            return False

        try:
            if encrypt and password:
                encryptor = FileEncryption()
                content = encryptor.encrypt(content.encode(), password)
            elif isinstance(content, str):
                content = content.encode()

            success = file_ops.write_file(file_path, content)

            if success:
                action = "encrypted file" if encrypt else "file"
                self.logger.info(f"Updated {action}: {file_path}")
                return True
            else:
                self.logger.error(f"Failed to update file: {file_path}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to update file: {str(e)}")
            return False

    def delete_file(self, disk_filename, file_path):
        """Delete a file from the disk"""
        file_ops = self.mount_disk(disk_filename)
        if not file_ops:
            return False
        try:
            success = file_ops.delete_file(file_path)

            if success:
                self.logger.info(f"Deleted file: {file_path}")
                return True
            else:
                self.logger.error(f"Failed to delete file: {file_path}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to delete file: {str(e)}")
            return False

    def create_directory(self, disk_filename, dir_path):
        """Create a directory on the disk"""
        file_ops = self.mount_disk(disk_filename)
        if not file_ops:
            return False

        try:
            success = file_ops.create_directory(dir_path)

            if success:
                self.logger.info(f"Created directory: {dir_path}")
                return True
            else:
                self.logger.error(f"Failed to create directory: {dir_path}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to create directory: {str(e)}")
            return False

    def delete_directory(self, disk_filename, dir_path):
        """Delete a directory on the disk with confirmation for non-empty directories"""
        file_ops = self.mount_disk(disk_filename)
        if not file_ops:
            return False

        try:
            # Check if directory exists
            if not file_ops._directory_exists(dir_path):
                self.logger.error(f"Directory not found: {dir_path}")
                return False

            # Check if directory is empty
            entries = file_ops.list_directory(dir_path, recursive=False)
            # Filter out '.' and '..' entries
            non_dot_entries = [e for e in entries if e['name'] not in ['.', '..']]

            if non_dot_entries:
                # Directory is not empty - show contents and prompt for confirmation
                print(f"\nDirectory '{dir_path}' is not empty. Contents:")
                print("-" * 60)
                print(f"{'Name':<20} {'Type':<6} {'Size':<10}")
                print("-" * 60)

                for entry in non_dot_entries:
                    entry_type = "DIR" if entry['is_directory'] else "FILE"
                    size = "" if entry['is_directory'] else f"{entry['size']} bytes"
                    print(f"{entry['name']:<20} {entry_type:<6} {size}")
                print("-" * 60)

                # Prompt user for confirmation
                response = input(f"\nDelete {len(non_dot_entries)} items recursively? [y/N]: ").strip().lower()
                if response != 'y':
                    self.logger.info("Directory deletion cancelled by user")
                    return False

            # Delete the directory (with contents if confirmed)
            success = file_ops.delete_directory_recursive(dir_path)

            if success:
                if non_dot_entries:
                    self.logger.info(f"Recursively deleted directory and contents: {dir_path}")
                else:
                    self.logger.info(f"Deleted directory: {dir_path}")
                return True
            else:
                self.logger.error(f"Failed to delete directory: {dir_path}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to delete directory: {str(e)}")
            return False

    def delete_disk(self, filename):
        """Delete a virtual disk"""
        try:
            self.logger.info(f"Deleting virtual disk: {filename}")

            disk = VirtualDisk(filename)
            success = disk.delete()

            if success:
                self.logger.info(f"Disk deleted successfully: {filename}")
                return True
            else:
                self.logger.warning(f"Disk not found: {filename}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to delete disk: {str(e)}")
            return False


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='FAT32 Virtual Disk Management System')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Create disk command
    create_parser = subparsers.add_parser('create-disk', help='Create a new virtual disk')
    create_parser.add_argument('filename', help='Disk image filename')
    create_parser.add_argument('--size', type=int, default=DEFAULT_DISK_SIZE_MB, help='Disk size in MB')
    create_parser.add_argument('--cluster-size', type=int, default=DEFAULT_CLUSTER_SIZE, help='Cluster size in bytes')

    # Clone disk command
    clone_parser = subparsers.add_parser('clone-disk', help='Clone a disk')
    clone_parser.add_argument('source', help='Source disk path')
    clone_parser.add_argument('target', help='Target disk path')

    # List files command
    list_parser = subparsers.add_parser('list', help='List files and directories')
    list_parser.add_argument('disk', help='Disk image filename')
    list_parser.add_argument('--path', default='/', help='Directory path to list')
    list_parser.add_argument('--recursive', action='store_true', help='Recursive listing')

    # Search files command
    search_parser = subparsers.add_parser('search', help='Search files')
    search_parser.add_argument('disk', help='Disk image filename')
    search_parser.add_argument('--start-date', help='Start date (YYYY-MM-DD)')
    search_parser.add_argument('--end-date', help='End date (YYYY-MM-DD)')
    search_parser.add_argument('--pattern', help='Filename pattern')

    # Health report command
    health_parser = subparsers.add_parser('health-report', help='Generate health report')
    health_parser.add_argument('disk', help='Disk image filename')

    # Create file command
    create_file_parser = subparsers.add_parser('create-file', help='Create a file')
    create_file_parser.add_argument('disk', help='Disk image filename')
    create_file_parser.add_argument('path', help='File path on disk')
    create_file_parser.add_argument('content', help='File content')
    create_file_parser.add_argument('--encrypt', action='store_true', help='Encrypt file')
    create_file_parser.add_argument('--password', help='Encryption password')

    # Read file command
    read_file_parser = subparsers.add_parser('read-file', help='Read a file')
    read_file_parser.add_argument('disk', help='Disk image filename')
    read_file_parser.add_argument('path', help='File path on disk')
    read_file_parser.add_argument('--decrypt', action='store_true', help='Decrypt file')
    read_file_parser.add_argument('--password', help='Decryption password')

    # Write file command (update existing file)
    write_file_parser = subparsers.add_parser('write-file', help='Update an existing file')
    write_file_parser.add_argument('disk', help='Disk image filename')
    write_file_parser.add_argument('path', help='File path on disk')
    write_file_parser.add_argument('content', help='New file content')
    write_file_parser.add_argument('--encrypt', action='store_true', help='Encrypt file')
    write_file_parser.add_argument('--password', help='Encryption password')

    # Delete file command
    delete_file_parser = subparsers.add_parser('delete-file', help='Delete a file')
    delete_file_parser.add_argument('disk', help='Disk image filename')
    delete_file_parser.add_argument('path', help='File path on disk')

    # Create directory command
    create_dir_parser = subparsers.add_parser('create-dir', help='Create a directory')
    create_dir_parser.add_argument('disk', help='Disk image filename')
    create_dir_parser.add_argument('path', help='Directory path to create')

    # Delete directory command
    delete_dir_parser = subparsers.add_parser('delete-dir', help='Delete an empty directory')
    delete_dir_parser.add_argument('disk', help='Disk image filename')
    delete_dir_parser.add_argument('path', help='Directory path to delete')

    # Format disk command
    format_parser = subparsers.add_parser('format-disk', help='Format an existing disk image as FAT32')
    format_parser.add_argument('disk', help='Disk image filename to format')
    format_parser.add_argument('--cluster-size', type=int, default=DEFAULT_CLUSTER_SIZE, help='Cluster size in bytes')

    # Mount disk
    mount_parser = subparsers.add_parser('mount', help='Mount a disk and optionally generate health report')
    mount_parser.add_argument('disk', help='Disk image filename to mount')

    # Delete disk command
    delete_parser = subparsers.add_parser('delete-disk', help='Delete a virtual disk')
    delete_parser.add_argument('filename', help='Disk image filename to delete')

    args = parser.parse_args()

    if not args.command:
        print(
            "\n[INFO] No command provided. If you intended to run the app with a GUI, double-clicking may not work properly.")
        print("To use the CLI, try one of the following commands:\n")
        parser.print_help()
        input("\nPress Enter to exit...")
        return

    manager = FAT32Manager()

    if args.command == 'create-disk':
        success = manager.create_disk(args.size, args.filename, args.cluster_size)
        sys.exit(0 if success else 1)

    elif args.command == 'clone-disk':
        success = manager.clone_disk(args.source, args.target)
        sys.exit(0 if success else 1)

    elif args.command == 'list':
        success = manager.list_files(args.disk, args.path, args.recursive)
        sys.exit(0 if success else 1)

    elif args.command == 'search':
        success = manager.search_files(args.disk, args.start_date, args.end_date, args.pattern)
        sys.exit(0 if success else 1)

    elif args.command == 'health-report':
        success = manager.health_report(args.disk)
        sys.exit(0 if success else 1)

    elif args.command == 'create-file':
        success = manager.create_file(args.disk, args.path, args.content, args.encrypt, args.password)
        sys.exit(0 if success else 1)

    elif args.command == 'write-file':
        success = manager.write_file(args.disk, args.path, args.content, args.encrypt, args.password)
        sys.exit(0 if success else 1)

    elif args.command == 'delete-file':
        success = manager.delete_file(args.disk, args.path)
        sys.exit(0 if success else 1)

    elif args.command == 'create-dir':
        success = manager.create_directory(args.disk, args.path)
        sys.exit(0 if success else 1)

    elif args.command == 'delete-dir':
        success = manager.delete_directory(args.disk, args.path)
        sys.exit(0 if success else 1)

    elif args.command == 'delete-disk':
        success = manager.delete_disk(args.filename)
        sys.exit(0 if success else 1)

    elif args.command == 'format-disk':
        success = manager.format_disk(args.disk, args.cluster_size)
        sys.exit(0 if success else 1)

    elif args.command == 'mount':
        file_ops = manager.mount_disk(args.disk)
        if not file_ops:
            sys.exit(1)
        print(f"Disk '{args.disk}' successfully mounted.")
        resp = input("Generate health report for this disk? [y/N]: ").strip().lower()
        if resp == 'y':
            success = manager.health_report(args.disk)
            sys.exit(0 if success else 1)
        else:
            sys.exit(0)

    elif args.command == 'read-file':
        content = manager.read_file(args.disk, args.path, args.decrypt, args.password)
        if content is not None:
            print(content.decode() if isinstance(content, bytes) else content)
            sys.exit(0)
        else:
            sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("FAT32 Virtual Disk Management System")


        # Ask user for disk name
        disk_name = input("Enter disk image filename (press Enter for default 'virtual_disk.img'): ").strip()

        # Use default if empty input
        if not disk_name:
            disk_name = DEFAULT_DISK_IMAGE

        # Add .img extension if not present
        if not disk_name.endswith('.img'):
            disk_name += '.img'

        print(f"Creating example 1GB disk: {disk_name}...")

        manager = FAT32Manager()
        success = manager.create_disk(DEFAULT_DISK_SIZE_MB, disk_name)

        if success:
            print("\nExample usage:")
            print(f"python {sys.argv[0]} list {disk_name}")
            print(f"python {sys.argv[0]} create-file {disk_name} /test.txt 'Hello World!'")
            print(f"python {sys.argv[0]} write-file {disk_name} /test.txt 'Updated content'")
            print(f"python {sys.argv[0]} create-dir {disk_name} /new_directory")
            print(f"python {sys.argv[0]} delete-file {disk_name} /test.txt")
            print(f"python {sys.argv[0]} health-report {disk_name}")
            print(f"python {sys.argv[0]} delete-disk {disk_name}")
            print(f"python {sys.argv[0]} delete-dir {disk_name} /documents")
    else:
        main()
