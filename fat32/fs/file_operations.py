"""
fs/file_operations.py
File System Operations Module
Handles CRUD operations, directory traversal, and file search
"""

import struct
import datetime
import fnmatch
from typing import List, Dict, Optional, Tuple
from pathlib import Path


class DirectoryEntry:
    """Represents a FAT32 directory entry"""

    # File attributes
    ATTR_READ_ONLY = 0x01
    ATTR_HIDDEN = 0x02
    ATTR_SYSTEM = 0x04
    ATTR_VOLUME_ID = 0x08
    ATTR_DIRECTORY = 0x10
    ATTR_ARCHIVE = 0x20
    ATTR_LONG_NAME = 0x0F

    def __init__(self):
        self.name = ""
        self.extension = ""
        self.attributes = 0
        self.reserved = 0
        self.creation_time_tenths = 0
        self.creation_time = 0
        self.creation_date = 0
        self.last_access_date = 0
        self.first_cluster_high = 0
        self.write_time = 0
        self.write_date = 0
        self.first_cluster_low = 0
        self.file_size = 0

        # Computed properties
        self.is_directory = False
        self.is_deleted = False
        self.long_name = ""

    @property
    def first_cluster(self) -> int:
        return (self.first_cluster_high << 16) | self.first_cluster_low

    @first_cluster.setter
    def first_cluster(self, value: int):
        self.first_cluster_high = (value >> 16) & 0xFFFF
        self.first_cluster_low = value & 0xFFFF

    @property
    def full_name(self) -> str:
        if self.long_name:
            return self.long_name
        name = self.name.strip()
        ext = self.extension.strip()
        return f"{name}.{ext}" if ext else name

    def to_bytes(self) -> bytes:
        """Convert directory entry to 32-byte structure"""
        entry = bytearray(32)

        # Name and extension (8.3 format)
        name_bytes = self.name.encode('ascii', errors='replace')[:8]
        ext_bytes = self.extension.encode('ascii', errors='replace')[:3]
        entry[0:8] = name_bytes.ljust(8, b' ')
        entry[8:11] = ext_bytes.ljust(3, b' ')

        # Pack other fields
        struct.pack_into('<B', entry, 11, self.attributes)
        struct.pack_into('<B', entry, 12, self.reserved)
        struct.pack_into('<B', entry, 13, self.creation_time_tenths)
        struct.pack_into('<H', entry, 14, self.creation_time)
        struct.pack_into('<H', entry, 16, self.creation_date)
        struct.pack_into('<H', entry, 18, self.last_access_date)
        struct.pack_into('<H', entry, 20, self.first_cluster_high)
        struct.pack_into('<H', entry, 22, self.write_time)
        struct.pack_into('<H', entry, 24, self.write_date)
        struct.pack_into('<H', entry, 26, self.first_cluster_low)
        struct.pack_into('<L', entry, 28, self.file_size)

        return bytes(entry)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DirectoryEntry':
        """Create DirectoryEntry from 32-byte directory entry data"""
        if len(data) < 32:
            raise ValueError("Directory entry data must be at least 32 bytes")

        entry = cls()

        # Extract name and extension
        entry.name = data[0:8].decode('ascii', errors='replace').rstrip()
        entry.extension = data[8:11].decode('ascii', errors='replace').rstrip()

        # Unpack other fields
        entry.attributes = struct.unpack('<B', data[11:12])[0]
        entry.reserved = struct.unpack('<B', data[12:13])[0]
        entry.creation_time_tenths = struct.unpack('<B', data[13:14])[0]
        entry.creation_time = struct.unpack('<H', data[14:16])[0]
        entry.creation_date = struct.unpack('<H', data[16:18])[0]
        entry.last_access_date = struct.unpack('<H', data[18:20])[0]
        entry.first_cluster_high = struct.unpack('<H', data[20:22])[0]
        entry.write_time = struct.unpack('<H', data[22:24])[0]
        entry.write_date = struct.unpack('<H', data[24:26])[0]
        entry.first_cluster_low = struct.unpack('<H', data[26:28])[0]
        entry.file_size = struct.unpack('<L', data[28:32])[0]

        # Set computed properties
        entry.is_directory = bool(entry.attributes & cls.ATTR_DIRECTORY)
        entry.is_deleted = data[0] == 0xE5

        return entry

    def get_creation_datetime(self) -> datetime.datetime:
        """Convert FAT32 date/time to Python datetime"""
        return self._fat_datetime_to_python(self.creation_date, self.creation_time)

    def get_write_datetime(self) -> datetime.datetime:
        """Convert FAT32 write date/time to Python datetime"""
        return self._fat_datetime_to_python(self.write_date, self.write_time)

    @staticmethod
    def _fat_datetime_to_python(fat_date: int, fat_time: int) -> datetime.datetime:
        """Convert FAT32 date/time format to Python datetime"""
        if fat_date == 0 and fat_time == 0:
            return datetime.datetime(1980, 1, 1)

        # Extract date components
        year = 1980 + ((fat_date >> 9) & 0x7F)
        month = (fat_date >> 5) & 0x0F
        day = fat_date & 0x1F

        # Extract time components
        hour = (fat_time >> 11) & 0x1F
        minute = (fat_time >> 5) & 0x3F
        second = (fat_time & 0x1F) * 2

        # Validate components
        if month < 1 or month > 12:
            month = 1
        if day < 1 or day > 31:
            day = 1
        if hour > 23:
            hour = 0
        if minute > 59:
            minute = 0
        if second > 59:
            second = 0

        try:
            return datetime.datetime(year, month, day, hour, minute, second)
        except ValueError:
            return datetime.datetime(1980, 1, 1)


class FileOperations:
    """Handles file system operations for FAT32"""

    def __init__(self, disk, boot_sector, fat_manager):
        """Initialize with disk, boot sector, and FAT manager"""
        self.disk = disk
        self.boot_sector = boot_sector
        self.fat_manager = fat_manager
        self.fat = fat_manager

        # Calculate commonly used values
        self.bytes_per_cluster = boot_sector.bytes_per_sector * boot_sector.sectors_per_cluster
        self.root_cluster = boot_sector.root_cluster

    def create_file(self, path: str, content: bytes = b"") -> bool:
        """Create a new file at the specified path"""
        try:
            parent_path, filename = self._split_path(path)
            parent_cluster = self._find_directory_cluster(parent_path)

            if parent_cluster is None:
                return False

            # Check if file already exists
            if self._find_file_in_directory(parent_cluster, filename):
                return False

            # Allocate cluster for file content if needed
            file_cluster = None
            if content:
                file_cluster = self.fat_manager.allocate_cluster()
                if file_cluster is None:
                    return False
                self._write_cluster(file_cluster, content)

            # Create directory entry
            entry = DirectoryEntry()
            name_parts = self._split_filename(filename)
            entry.name = name_parts[0]
            entry.extension = name_parts[1]
            entry.attributes = DirectoryEntry.ATTR_ARCHIVE
            entry.first_cluster = file_cluster or 0
            entry.file_size = len(content)

            # Set timestamps
            now = datetime.datetime.now()
            fat_date, fat_time = self._python_datetime_to_fat(now)
            entry.creation_date = fat_date
            entry.creation_time = fat_time
            entry.write_date = fat_date
            entry.write_time = fat_time
            entry.last_access_date = fat_date

            # Add entry to parent directory
            return self._add_directory_entry(parent_cluster, entry)

        except Exception as e:
            print(f"Error creating file {path}: {e}")
            return False

    def read_file(self, path: str) -> Optional[bytes]:
        """Read file content from the specified path"""
        try:
            parent_path, filename = self._split_path(path)
            parent_cluster = self._find_directory_cluster(parent_path)

            if parent_cluster is None:
                return None

            entry = self._find_file_in_directory(parent_cluster, filename)
            if not entry or entry.is_directory:
                return None

            if entry.file_size == 0:
                return b""

            # Read file content from clusters
            content = bytearray()
            cluster = entry.first_cluster

            while cluster and not self.fat_manager.is_end_of_cluster(cluster):
                cluster_data = self._read_cluster(cluster)
                if cluster_data is None:
                    break
                content.extend(cluster_data)
                cluster = self.fat_manager.get_next_cluster(cluster)

            # Truncate to actual file size
            return bytes(content[:entry.file_size])

        except Exception as e:
            print(f"Error reading file {path}: {e}")
            return None

    def write_file(self, path: str, content: bytes) -> bool:
        """Write content to file, creating if it doesn't exist"""
        try:
            parent_path, filename = self._split_path(path)
            parent_cluster = self._find_directory_cluster(parent_path)

            if parent_cluster is None:
                return False

            entry = self._find_file_in_directory(parent_cluster, filename)

            if entry:
                # Update existing file
                if entry.is_directory:
                    return False

                # Free old clusters if file had content
                if entry.first_cluster:
                    self.fat_manager.free_cluster_chain(entry.first_cluster)

                # Allocate new clusters for content
                if content:
                    new_cluster = self._write_file_content(content)
                    if new_cluster is None:
                        return False
                    entry.first_cluster = new_cluster
                else:
                    entry.first_cluster = 0

                entry.file_size = len(content)

                # Update timestamps
                now = datetime.datetime.now()
                fat_date, fat_time = self._python_datetime_to_fat(now)
                entry.write_date = fat_date
                entry.write_time = fat_time
                entry.last_access_date = fat_date

                return self._update_directory_entry(parent_cluster, entry)
            else:
                # Create new file
                return self.create_file(path, content)

        except Exception as e:
            print(f"Error writing file {path}: {e}")
            return False

    def delete_file(self, path: str) -> bool:
        """Delete file at the specified path"""
        try:
            parent_path, filename = self._split_path(path)
            parent_cluster = self._find_directory_cluster(parent_path)

            if parent_cluster is None:
                return False

            entry = self._find_file_in_directory(parent_cluster, filename)
            if not entry or entry.is_directory:
                return False

            # Free file clusters
            if entry.first_cluster:
                self.fat_manager.free_cluster_chain(entry.first_cluster)

            # Mark directory entry as deleted
            return self._delete_directory_entry(parent_cluster, filename)

        except Exception as e:
            print(f"Error deleting file {path}: {e}")
            return False

    def _read_directory_entries(self, cluster: int) -> list:
        """Read all directory entries from a directory cluster"""
        try:
            entries = []
            current_cluster = cluster

            while current_cluster != 0x0FFFFFFF:  # End of cluster chain
                # Calculate the sector for the current cluster
                sector = self.boot_sector.first_data_sector + \
                         (current_cluster - 2) * self.boot_sector.sectors_per_cluster

                # Read the entire cluster
                cluster_data = self.disk.read_sectors(sector, self.boot_sector.sectors_per_cluster)

                # Parse directory entries in the cluster (32 bytes each)
                for i in range(0, len(cluster_data), 32):
                    entry_data = cluster_data[i:i + 32]

                    # Check for end of entries
                    if entry_data[0] == 0x00:
                        return entries

                    # Skip deleted entries (0xE5) and volume labels
                    if entry_data[0] in (0xE5, 0x05) or entry_data[11] == 0x08:
                        continue

                    # Parse directory entry
                    entry = DirectoryEntry()
                    entry.parse(entry_data)
                    entries.append(entry)

                # Get next cluster in chain
                current_cluster = self.fat_manager.get_fat_entry(current_cluster)

            return entries

        except Exception as e:
            print(f"Error reading directory entries: {e}")
            return []

    def _directory_exists(self, path: str) -> bool:
        """Check if a directory exists"""
        if path == "/":
            return True  # Root always exists

        parent_path, dir_name = self._split_path(path)
        parent_cluster = self._find_directory_cluster(parent_path)

        if parent_cluster is None:
            return False

        entry = self._find_file_in_directory(parent_cluster, dir_name)
        return entry is not None and entry.is_directory

    def create_directory(self, path: str) -> bool:
        """Create a new directory at the specified path"""
        try:
            parent_path, dirname = self._split_path(path)
            parent_cluster = self._find_directory_cluster(parent_path)

            if parent_cluster is None:
                return False

            # Check if directory already exists
            if self._find_file_in_directory(parent_cluster, dirname):
                return False

            # Allocate cluster for directory
            dir_cluster = self.fat_manager.allocate_cluster()
            if dir_cluster is None:
                return False

            # Initialize directory with . and .. entries
            self._initialize_directory(dir_cluster, parent_cluster)

            # Create directory entry in parent
            entry = DirectoryEntry()
            name_parts = self._split_filename(dirname)
            entry.name = name_parts[0]
            entry.extension = name_parts[1]
            entry.attributes = DirectoryEntry.ATTR_DIRECTORY
            entry.first_cluster = dir_cluster
            entry.file_size = 0

            # Set timestamps
            now = datetime.datetime.now()
            fat_date, fat_time = self._python_datetime_to_fat(now)
            entry.creation_date = fat_date
            entry.creation_time = fat_time
            entry.write_date = fat_date
            entry.write_time = fat_time
            entry.last_access_date = fat_date

            return self._add_directory_entry(parent_cluster, entry)

        except Exception as e:
            print(f"Error creating directory {path}: {e}")
            return False

    def delete_directory(self, path: str) -> bool:
        """Delete a directory at the specified path"""
        try:
            # Split the path into parent path and directory name
            parent_path, dirname = self._split_path(path)
            parent_cluster = self._find_directory_cluster(parent_path)

            if parent_cluster is None:
                return False

            # Find the directory entry
            entry = self._find_file_in_directory(parent_cluster, dirname)
            if not entry or not entry.is_directory:
                return False

            # Check if directory is empty
            dir_cluster = entry.first_cluster
            if not self._is_directory_empty(dir_cluster):
                return False

            # Free the directory's cluster
            if dir_cluster:
                self.fat_manager.free_cluster_chain(dir_cluster)

            # Mark directory entry as deleted
            return self._delete_directory_entry(parent_cluster, dirname)

        except Exception as e:
            print(f"Error deleting directory {path}: {e}")
            return False

    def delete_directory_recursive(self, path: str) -> bool:
        """Recursively delete a directory and its contents"""
        try:
            # List all entries in the directory
            entries = self.list_directory(path, recursive=False)

            # Process each entry (except . and ..)
            for entry in entries:
                if entry['name'] in ['.', '..']:
                    continue

                entry_path = f"{path.rstrip('/')}/{entry['name']}"

                if entry['is_directory']:
                    # Recursively delete subdirectories
                    if not self.delete_directory_recursive(entry_path):
                        return False
                else:
                    # Delete files
                    if not self.delete_file(entry_path):
                        return False

            # Now delete the empty directory
            return self.delete_directory(path)

        except Exception as e:
            print(f"Error recursively deleting directory: {e}")
            return False

    def _is_directory_empty(self, cluster: int) -> bool:
        """Check if a directory contains only . and .. entries"""
        entries = self._read_directory_entries(cluster)

        # A directory should have at least . and .. entries
        if len(entries) < 2:
            return False

        # Check if there are any entries beyond . and ..
        for entry in entries:
            if entry.name not in ['.', '..'] and not entry.is_deleted:
                return False

        return True

    def list_directory(self, path: str = "/", recursive: bool = False) -> List[Dict]:
        """List contents of directory at path"""
        try:
            cluster = self._find_directory_cluster(path)
            if cluster is None:
                return []

            entries = []
            current_cluster = cluster

            while current_cluster and not self.fat_manager.is_end_of_cluster(current_cluster):
                cluster_data = self._read_cluster(current_cluster)
                if not cluster_data:
                    break

                # Process directory entries in this cluster
                for i in range(0, len(cluster_data), 32):
                    if i + 32 > len(cluster_data):
                        break

                    entry_data = cluster_data[i:i+32]
                    if entry_data[0] == 0:  # End of directory
                        break
                    if entry_data[0] == 0xE5:  # Deleted entry
                        continue

                    entry = DirectoryEntry.from_bytes(entry_data)

                    # Skip volume labels and long name entries
                    if (entry.attributes & DirectoryEntry.ATTR_VOLUME_ID or
                        entry.attributes == DirectoryEntry.ATTR_LONG_NAME):
                        continue

                    # Skip . and .. entries
                    if entry.name in ['.', '..']:
                        continue

                    entry_info = {
                        'name': entry.full_name,
                        'path': self._join_paths(path, entry.full_name),
                        'size': entry.file_size,
                        'is_directory': entry.is_directory,
                        'created': entry.get_creation_datetime(),
                        'modified': entry.get_write_datetime(),
                        'attributes': entry.attributes
                    }
                    entries.append(entry_info)

                    # Add recursive entries if requested
                    if recursive and entry.is_directory:
                        subdir_path = self._join_paths(path, entry.full_name)
                        subentries = self.list_directory(subdir_path, recursive=True)
                        entries.extend(subentries)

                current_cluster = self.fat_manager.get_next_cluster(current_cluster)

            return entries

        except Exception as e:
            print(f"Error listing directory {path}: {e}")
            return []

    def search_files(self, start_date=None, end_date=None, pattern=None, search_path: str = "/") -> List[Dict]:
        """Search for files by date range and/or pattern"""
        matches = []

        def search_in_directory(dir_path: str, depth: int = 0):
            if depth > 100:  # Prevent infinite recursion
                return

            entries = self.list_directory(dir_path, recursive=False)
            for entry in entries:
                # Check pattern match
                pattern_match = True
                if pattern:
                    pattern_match = fnmatch.fnmatch(entry['name'].lower(), pattern.lower())

                # Check date range
                date_match = True
                if start_date or end_date:
                    modified_date = entry['modified'].date()
                    if start_date:
                        start_dt = datetime.datetime.strptime(start_date, '%Y-%m-%d').date()
                        if modified_date < start_dt:
                            date_match = False
                    if end_date:
                        end_dt = datetime.datetime.strptime(end_date, '%Y-%m-%d').date()
                        if modified_date > end_dt:
                            date_match = False

                if pattern_match and date_match:
                    matches.append(entry)

                if entry['is_directory']:
                    search_in_directory(entry['path'], depth + 1)

        try:
            search_in_directory(search_path)
            return matches
        except Exception as e:
            print(f"Error searching files: {e}")
            return []

    def generate_health_report(self) -> Dict:
        """Generate comprehensive health report with volume label"""
        try:
            # Get volume label from boot sector
            label = self.boot_sector.volume_label.strip().decode('ascii', errors='ignore')

            # Calculate basic disk geometry
            total_size = self.boot_sector.total_sectors * self.boot_sector.bytes_per_sector
            total_clusters = self.boot_sector.data_sectors // self.boot_sector.sectors_per_cluster

            # Analyze FAT usage
            free_clusters = 0
            used_clusters = 0
            bad_clusters = 0

            for cluster in range(2, total_clusters + 2):  # FAT clusters start at 2
                fat_entry = self.fat_manager.get_fat_entry(cluster)
                if fat_entry == 0:
                    free_clusters += 1
                elif fat_entry == 0x0FFFFFF7:  # Bad cluster marker
                    bad_clusters += 1
                else:
                    used_clusters += 1

            free_space = free_clusters * self.bytes_per_cluster

            # Calculate slack space
            total_slack = 0
            file_count = 0

            def analyze_directory(path: str):
                nonlocal total_slack, file_count
                entries = self.list_directory(path, recursive=False)
                for entry in entries:
                    if not entry['is_directory']:
                        file_count += 1
                        # Calculate slack space (unused space in last cluster)
                        if entry['size'] > 0:
                            clusters_needed = (entry['size'] + self.bytes_per_cluster - 1) // self.bytes_per_cluster
                            allocated_space = clusters_needed * self.bytes_per_cluster
                            slack = allocated_space - entry['size']
                            total_slack += slack
                    else:
                        analyze_directory(entry['path'])

            analyze_directory("/")

            avg_slack_per_file = total_slack / max(file_count, 1)

            # Check for file system issues
            cross_linked_clusters = self._check_cross_linked_clusters()
            lost_chains = self._check_lost_chains()

            # Determine integrity status
            integrity_status = "GOOD"
            recommendations = []

            if bad_clusters > 0:
                integrity_status = "WARNING"
                recommendations.append(f"Found {bad_clusters} bad clusters - consider disk replacement")

            if cross_linked_clusters > 0:
                integrity_status = "ERROR"
                recommendations.append(f"Found {cross_linked_clusters} cross-linked clusters - run disk repair")

            if lost_chains > 0:
                integrity_status = "WARNING"
                recommendations.append(f"Found {lost_chains} lost cluster chains - run disk cleanup")

            if free_space < (total_size * 0.1):  # Less than 10% free
                recommendations.append("Low disk space - consider cleanup or expansion")

            if avg_slack_per_file > (self.bytes_per_cluster * 0.5):  # High slack space
                recommendations.append("High slack space detected - consider smaller cluster size for new disks")

            return {
                'label': label,  # Added volume label
                'total_size': total_size,
                'sector_size': self.boot_sector.bytes_per_sector,
                'cluster_size': self.bytes_per_cluster,
                'total_clusters': total_clusters,
                'free_clusters': free_clusters,
                'used_clusters': used_clusters,
                'bad_clusters': bad_clusters,
                'free_space': free_space,
                'total_slack': total_slack,
                'avg_slack_per_file': avg_slack_per_file,
                'cross_linked_clusters': cross_linked_clusters,
                'lost_chains': lost_chains,
                'integrity_status': integrity_status,
                'recommendations': recommendations
            }

        except Exception as e:
            print(f"Error generating health report: {e}")
            return {
                'label': "UNKNOWN",  # Default label in error case
                'total_size': 0, 'sector_size': 0, 'cluster_size': 0, 'total_clusters': 0,
                'free_clusters': 0, 'used_clusters': 0, 'bad_clusters': 0, 'free_space': 0,
                'total_slack': 0, 'avg_slack_per_file': 0, 'cross_linked_clusters': 0,
                'lost_chains': 0, 'integrity_status': 'ERROR', 'recommendations': []
            }


    def get_file_info(self, path: str) -> Optional[Dict]:
        """Get detailed information about a file or directory"""
        try:
            parent_path, filename = self._split_path(path)
            parent_cluster = self._find_directory_cluster(parent_path)

            if parent_cluster is None:
                return None

            entry = self._find_file_in_directory(parent_cluster, filename)
            if not entry:
                return None

            return {
                'name': entry.full_name,
                'path': path,
                'size': entry.file_size,
                'is_directory': entry.is_directory,
                'is_read_only': bool(entry.attributes & DirectoryEntry.ATTR_READ_ONLY),
                'is_hidden': bool(entry.attributes & DirectoryEntry.ATTR_HIDDEN),
                'is_system': bool(entry.attributes & DirectoryEntry.ATTR_SYSTEM),
                'created': entry.get_creation_datetime(),
                'modified': entry.get_write_datetime(),
                'first_cluster': entry.first_cluster,
                'attributes': entry.attributes
            }

        except Exception as e:
            print(f"Error getting file info for {path}: {e}")
            return None

    # Helper methods

    def _check_cross_linked_clusters(self) -> int:
        """Check for cross-linked clusters (clusters used by multiple files)"""
        try:
            cluster_usage = {}
            cross_linked = 0

            def check_file_clusters(path: str):
                nonlocal cross_linked
                entries = self.list_directory(path, recursive=False)
                for entry in entries:
                    if not entry['is_directory'] and entry['size'] > 0:
                        # Get file info to access first_cluster
                        file_info = self.get_file_info(entry['path'])
                        if file_info and file_info['first_cluster'] > 0:
                            cluster = file_info['first_cluster']
                            while cluster and not self.fat_manager.is_end_of_cluster(cluster):
                                if cluster in cluster_usage:
                                    cross_linked += 1
                                else:
                                    cluster_usage[cluster] = entry['path']
                                cluster = self.fat_manager.get_next_cluster(cluster)
                    elif entry['is_directory']:
                        check_file_clusters(entry['path'])

            check_file_clusters("/")
            return cross_linked

        except Exception:
            return 0

    def _check_lost_chains(self) -> int:
        """Check for lost cluster chains (allocated but not referenced)"""
        try:
            # This is a simplified check - in a real implementation,
            # you'd need to traverse all files and mark referenced clusters
            return 0
        except Exception:
            return 0

    def _read_cluster(self, cluster_num: int) -> Optional[bytes]:
        """Read a full cluster from disk, or return None on error."""
        try:
            # Where the data region really starts:
            data_start_sector = self.boot_sector.get_data_start_sector()
            # Offset into that region:
            first_sector = data_start_sector + (cluster_num - 2) * self.boot_sector.sectors_per_cluster

            buf = bytearray()
            for i in range(self.boot_sector.sectors_per_cluster):
                sector = self.disk.read_sector(first_sector + i)
                if sector is None:
                    return None
                buf.extend(sector)
            return bytes(buf)
        except Exception as e:
            print(f"_read_cluster error: {e}")
            return None

    def _write_cluster(self, cluster_num: int, data: bytes) -> bool:
        """Write data to a cluster, padding to full cluster size."""
        try:
            data_start_sector = self.boot_sector.get_data_start_sector()
            first_sector = data_start_sector + (cluster_num - 2) * self.boot_sector.sectors_per_cluster

            # Pad to cluster size
            full = data.ljust(self.bytes_per_cluster, b'\x00')

            for i in range(self.boot_sector.sectors_per_cluster):
                start = i * self.boot_sector.bytes_per_sector
                end   = start + self.boot_sector.bytes_per_sector
                if not self.disk.write_sector(first_sector + i, full[start:end]):
                    return False
            return True
        except Exception as e:
            print(f"_write_cluster error: {e}")
            return False

    def _find_directory_cluster(self, path: str) -> Optional[int]:
        """Find the cluster number for a directory path"""
        if path == '/' or path == '':
            return self.root_cluster

        # Navigate path components
        current_cluster = self.root_cluster
        path_parts = [p for p in path.strip('/').split('/') if p]

        for part in path_parts:
            entry = self._find_file_in_directory(current_cluster, part)
            if not entry or not entry.is_directory:
                return None
            current_cluster = entry.first_cluster

        return current_cluster

    def _split_path(self, path: str) -> Tuple[str, str]:
        """Split path into parent directory and filename"""
        path = path.replace('\\', '/').strip('/')
        if '/' not in path:
            return '/', path

        parts = path.split('/')
        filename = parts[-1]
        parent = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'
        return parent.rstrip('/') or '/', filename

    def _split_filename(self, filename: str) -> Tuple[str, str]:
        """Split filename into name and extension for 8.3 format"""
        if '.' in filename:
            name, ext = filename.rsplit('.', 1)
            return name[:8].upper(), ext[:3].upper()
        return filename[:8].upper(), ''

    def _join_paths(self, *paths) -> str:
        """Join path components"""
        result = []
        for path in paths:
            path = str(path).replace('\\', '/').strip('/')
            if path:
                result.append(path)
        return '/' + '/'.join(result)

    def _find_file_in_directory(self, cluster: int, filename: str) -> Optional[DirectoryEntry]:
        """Find a file entry in the specified directory cluster"""
        current_cluster = cluster

        while current_cluster and not self.fat_manager.is_end_of_cluster(current_cluster):
            cluster_data = self._read_cluster(current_cluster)
            if not cluster_data:
                break

            for i in range(0, len(cluster_data), 32):
                if i + 32 > len(cluster_data):
                    break

                entry_data = cluster_data[i:i+32]
                if entry_data[0] == 0:  # End of directory
                    return None
                if entry_data[0] == 0xE5:  # Deleted entry
                    continue

                entry = DirectoryEntry.from_bytes(entry_data)

                if entry.full_name.upper() == filename.upper():
                    return entry

            current_cluster = self.fat_manager.get_next_cluster(current_cluster)

        return None

    def _write_file_content(self, content: bytes) -> Optional[int]:
        """Write file content to clusters and return first cluster"""
        if not content:
            return None

        clusters = []
        bytes_per_cluster = self.bytes_per_cluster

        # Split content into clusters
        for i in range(0, len(content), bytes_per_cluster):
            chunk = content[i:i + bytes_per_cluster]
            cluster = self.fat_manager.allocate_cluster()
            if cluster is None:
                # Clean up allocated clusters on failure
                for c in clusters:
                    self.fat_manager.free_cluster(c)
                return None

            clusters.append(cluster)
            self._write_cluster(cluster, chunk)

        # Link clusters together
        for i in range(len(clusters) - 1):
            self.fat_manager.set_next_cluster(clusters[i], clusters[i + 1])

        # Mark last cluster as end of chain
        if clusters:
            self.fat_manager.set_end_of_cluster(clusters[-1])

        return clusters[0] if clusters else None

    def _add_directory_entry(self, dir_cluster: int, entry: DirectoryEntry) -> bool:
        """Add a directory entry to the specified directory"""
        try:
            # Find empty slot in directory
            current_cluster = dir_cluster

            while current_cluster and not self.fat_manager.is_end_of_cluster(current_cluster):
                cluster_data = bytearray(self._read_cluster(current_cluster))

                for i in range(0, len(cluster_data), 32):
                    if i + 32 > len(cluster_data):
                        break

                    # Check if slot is empty (starts with 0x00 or 0xE5)
                    if cluster_data[i] == 0x00 or cluster_data[i] == 0xE5:
                        # Write entry to this slot
                        entry_bytes = entry.to_bytes()
                        cluster_data[i:i+32] = entry_bytes
                        self._write_cluster(current_cluster, bytes(cluster_data))
                        return True

                current_cluster = self.fat_manager.get_next_cluster(current_cluster)

            # If we reach here, directory is full - would need to allocate new cluster
            return False

        except Exception as e:
            print(f"Error adding directory entry: {e}")
            return False

    def _update_directory_entry(self, dir_cluster: int, entry: DirectoryEntry) -> bool:
        """Update an existing directory entry"""
        # Similar to _add_directory_entry but finds and updates existing entry
        # Implementation would be specific to the filesystem
        try:
            current_cluster = dir_cluster

            while current_cluster and not self.fat_manager.is_end_of_cluster(current_cluster):
                cluster_data = bytearray(self._read_cluster(current_cluster))

                for i in range(0, len(cluster_data), 32):
                    if i + 32 > len(cluster_data):
                        break

                    existing_entry = DirectoryEntry.from_bytes(cluster_data[i:i+32])

                    if (existing_entry.full_name.upper() == entry.full_name.upper() and
                        not existing_entry.is_deleted):
                        # Update this entry
                        entry_bytes = entry.to_bytes()
                        cluster_data[i:i+32] = entry_bytes
                        self._write_cluster(current_cluster, bytes(cluster_data))
                        return True

                current_cluster = self.fat_manager.get_next_cluster(current_cluster)

            return False

        except Exception as e:
            print(f"Error updating directory entry: {e}")
            return False

    def _delete_directory_entry(self, dir_cluster: int, filename: str) -> bool:
        """Mark directory entry as deleted"""
        try:
            current_cluster = dir_cluster

            while current_cluster and not self.fat_manager.is_end_of_cluster(current_cluster):
                cluster_data = bytearray(self._read_cluster(current_cluster))

                for i in range(0, len(cluster_data), 32):
                    if i + 32 > len(cluster_data):
                        break

                    entry = DirectoryEntry.from_bytes(cluster_data[i:i+32])

                    if entry.full_name.upper() == filename.upper() and not entry.is_deleted:
                        # Mark as deleted
                        cluster_data[i] = 0xE5
                        self._write_cluster(current_cluster, bytes(cluster_data))
                        return True

                current_cluster = self.fat_manager.get_next_cluster(current_cluster)

            return False

        except Exception as e:
            print(f"Error deleting directory entry: {e}")
            return False

    def _initialize_directory(self, dir_cluster: int, parent_cluster: int):
        """Initialize a new directory with . and .. entries"""
        cluster_data = bytearray(self.bytes_per_cluster)

        # Create . entry (current directory)
        dot_entry = DirectoryEntry()
        dot_entry.name = "."
        dot_entry.attributes = DirectoryEntry.ATTR_DIRECTORY
        dot_entry.first_cluster = dir_cluster
        cluster_data[0:32] = dot_entry.to_bytes()

        # Create .. entry (parent directory)
        dotdot_entry = DirectoryEntry()
        dotdot_entry.name = ".."
        dotdot_entry.attributes = DirectoryEntry.ATTR_DIRECTORY
        dotdot_entry.first_cluster = parent_cluster if parent_cluster != self.root_cluster else 0
        cluster_data[32:64] = dotdot_entry.to_bytes()

        self._write_cluster(dir_cluster, bytes(cluster_data))

    @staticmethod
    def _python_datetime_to_fat(dt: datetime.datetime) -> Tuple[int, int]:
        """Convert Python datetime to FAT32 date/time format"""
        # FAT date: bits 15-9 year (relative to 1980), bits 8-5 month, bits 4-0 day
        fat_date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day

        # FAT time: bits 15-11 hour, bits 10-5 minute, bits 4-0 second/2
        fat_time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)

        return fat_date, fat_time
