"""
disk/virtual_disk.py
Virtual Disk Management Module
Handles disk creation, cloning, and low-level operations
"""

import os
import struct
from typing import Optional, Union


class VirtualDisk:
    """Virtual disk management class for FAT32 operations"""
    
    def __init__(self, filename: str, size_mb: Optional[int] = None):
        self.filename = filename
        self.size_mb = size_mb
        self.sector_size = 512
        self.file_handle = None
        self._is_open = False
        
    def create(self) -> bool:
        """Create a new virtual disk image"""
        try:
            if not self.size_mb:
                raise ValueError("Size must be specified for new disk creation")
                
            disk_size_bytes = self.size_mb * 1024 * 1024
            
            with open(self.filename, 'wb') as f:
                # Initialize with zeros - more efficient than writing byte by byte
                chunk_size = 1024 * 1024  # 1MB chunks
                remaining = disk_size_bytes
                
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(b'\x00' * write_size)
                    remaining -= write_size
                    
            return True
            
        except Exception as e:
            raise Exception(f"Failed to create virtual disk: {str(e)}")
    
    def open(self, mode: str = 'r+b') -> bool:
        """Open the disk image for operations"""
        try:
            if self._is_open:
                return True
                
            self.file_handle = open(self.filename, mode)
            self._is_open = True
            return True
            
        except Exception as e:
            raise Exception(f"Failed to open disk: {str(e)}")
    
    def close(self):
        """Close the disk image"""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
            self._is_open = False
    
    def read_sector(self, sector_number: int) -> bytes:
        """Read a specific sector from the disk"""
        if not self._is_open:
            self.open()
            
        offset = sector_number * self.sector_size
        self.file_handle.seek(offset)
        return self.file_handle.read(self.sector_size)
    
    def write_sector(self, sector_number: int, data: bytes) -> bool:
        """Write data to a specific sector"""
        if not self._is_open:
            self.open()
            
        if len(data) != self.sector_size:
            # Pad or truncate to sector size
            if len(data) < self.sector_size:
                data = data + b'\x00' * (self.sector_size - len(data))
            else:
                data = data[:self.sector_size]
        
        offset = sector_number * self.sector_size
        self.file_handle.seek(offset)
        self.file_handle.write(data)
        self.file_handle.flush()
        return True
    
    def read_sectors(self, start_sector: int, count: int) -> bytes:
        """Read multiple consecutive sectors"""
        if not self._is_open:
            self.open()
            
        offset = start_sector * self.sector_size
        size = count * self.sector_size
        self.file_handle.seek(offset)
        return self.file_handle.read(size)
    
    def write_sectors(self, start_sector: int, data: bytes) -> bool:
        """Write data to multiple consecutive sectors"""
        if not self._is_open:
            self.open()
            
        # Ensure data is sector-aligned
        sector_count = (len(data) + self.sector_size - 1) // self.sector_size
        padded_size = sector_count * self.sector_size
        
        if len(data) < padded_size:
            data = data + b'\x00' * (padded_size - len(data))
        
        offset = start_sector * self.sector_size
        self.file_handle.seek(offset)
        self.file_handle.write(data)
        self.file_handle.flush()
        return True
    
    def get_size(self) -> int:
        """Get the size of the disk in bytes"""
        if not os.path.exists(self.filename):
            return 0
        return os.path.getsize(self.filename)
    
    def get_sector_count(self) -> int:
        """Get the total number of sectors"""
        return self.get_size() // self.sector_size

    def format_fat32(self, boot_sector, fat_manager):
        """Format the disk with FAT32 file system"""
        try:
            # Open disk for writing
            self.open('r+b')

            # Write boot sector
            boot_data = boot_sector.generate_boot_sector()
            self.write_sector(0, boot_data)

            # Write FSInfo sector
            fsinfo_data = boot_sector.generate_fsinfo_sector()
            self.write_sector(1, fsinfo_data)

            # Write backup boot sector
            self.write_sector(6, boot_data)

            # Initialize FAT tables
            fat_manager.initialize_fat_tables(self, boot_sector)

            # Initialize root directory
            self._initialize_root_directory(boot_sector)

            return True

        except Exception as e:
            raise Exception(f"Failed to format disk: {str(e)}")

    def _initialize_root_directory(self, boot_sector):
        """Initialize the root directory cluster"""
        try:
            # Root directory starts at cluster 2
            root_cluster = 2
            cluster_size = boot_sector.sectors_per_cluster * self.sector_size

            # Calculate root directory sector
            data_start_sector = (boot_sector.reserved_sectors +
                               (boot_sector.num_fats * boot_sector.sectors_per_fat))
            root_sector = data_start_sector + ((root_cluster - 2) * boot_sector.sectors_per_cluster)

            # Create empty root directory
            empty_cluster = b'\x00' * cluster_size
            self.write_sectors(root_sector, empty_cluster)

        except Exception as e:
            raise Exception(f"Failed to initialize root directory: {str(e)}")
    
    def clone_from(self, source_path: str) -> bool:
        """Clone this disk from another disk (physical or virtual)"""
        try:
            with open(source_path, 'rb') as source:
                with open(self.filename, 'wb') as target:
                    chunk_size = 1024 * 1024  # 1MB chunks
                    
                    while True:
                        chunk = source.read(chunk_size)
                        if not chunk:
                            break
                        target.write(chunk)
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to clone disk: {str(e)}")
    
    def verify_integrity(self) -> dict:
        """Verify disk integrity and return status"""
        try:
            if not os.path.exists(self.filename):
                return {'status': 'error', 'message': 'Disk file does not exist'}
            
            file_size = self.get_size()
            if file_size == 0:
                return {'status': 'error', 'message': 'Empty disk file'}
            
            # Check if file size is reasonable
            if file_size < 1024 * 1024:  # Less than 1MB
                return {'status': 'warning', 'message': 'Unusually small disk size'}
            
            # Try to read boot sector
            self.open('rb')
            boot_sector_data = self.read_sector(0)
            
            # Check boot signature
            if len(boot_sector_data) >= 512:
                signature = struct.unpack('<H', boot_sector_data[510:512])[0]
                if signature != 0xAA55:
                    return {'status': 'warning', 'message': 'Invalid boot signature'}
            
            self.close()
            
            return {'status': 'ok', 'message': 'Disk integrity verified'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Integrity check failed: {str(e)}'}
    
    def get_disk_info(self) -> dict:
        """Get comprehensive disk information"""
        try:
            info = {
                'filename': self.filename,
                'exists': os.path.exists(self.filename),
                'size_bytes': self.get_size() if os.path.exists(self.filename) else 0,
                'size_mb': 0,
                'sector_count': 0,
            }
            
            if info['exists']:
                info['size_mb'] = info['size_bytes'] / (1024 * 1024)
                info['sector_count'] = info['size_bytes'] // self.sector_size
                
                # Add integrity check
                integrity = self.verify_integrity()
                info['integrity'] = integrity
            
            return info
            
        except Exception as e:
            return {'error': str(e)}

    def delete(self) -> bool:
        """Delete the virtual disk file"""
        try:
            if self._is_open:
                self.close()

            if os.path.exists(self.filename):
                os.remove(self.filename)
                return True
            return False

        except Exception as e:
            raise Exception(f"Failed to delete disk: {str(e)}")
    
    def __enter__(self):
        """Context manager entry"""
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
    
    def __del__(self):
        """Destructor to ensure file is closed"""
        if self._is_open:
            self.close()

