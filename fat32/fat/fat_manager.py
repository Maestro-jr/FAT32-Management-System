"""
fat/fat_manager.py
FAT32 Table Management Module
Handles FAT table operations, cluster allocation, and slack space calculations
"""

import struct
from typing import List, Optional, Tuple, Dict, Any


class FATManager:
    """FAT32 table management and cluster operations"""
    
    # FAT32 entry values
    FREE_CLUSTER = 0x00000000
    RESERVED_CLUSTER = 0x0FFFFFF0
    BAD_CLUSTER = 0x0FFFFFF7
    END_OF_CHAIN = 0x0FFFFFFF

    def __init__(self, disk, boot_sector):
        self.disk = disk
        self.bs = boot_sector
        self.boot_sector = boot_sector
        self.fat_table = []
        self.total_clusters = boot_sector.get_total_clusters()
        self.next_free_cluster = 3  # Start searching from cluster 3

        # Initialize empty FAT table
        self._initialize_fat_table()

    def get_fat_entry(self, cluster: int) -> int:
        """
        Get the FAT32 table entry for a given cluster number
        Returns the entry value with top 4 bits masked out
        """
        FAT_ENTRY_SIZE = 4  # 4 bytes per FAT32 entry

        # Get FAT parameters from boot sector
        fat_start_sector = self.bs.get_fat_start_sector()
        bytes_per_sector = self.bs.bytes_per_sector

        # Calculate position in FAT
        byte_offset = cluster * FAT_ENTRY_SIZE
        sector_offset = byte_offset // bytes_per_sector
        offset_in_sector = byte_offset % bytes_per_sector

        # Read sector containing the FAT entry
        fat_sector = self.disk.read_sector(fat_start_sector + sector_offset)

        # Extract and mask FAT entry (FAT32 uses 28-bit entries)
        return struct.unpack_from("<I", fat_sector, offset_in_sector)[0] & 0x0FFFFFFF


    def initialize_fat(self, disk):
        """
        Initialize both FAT tables on `disk`:
         - Build in-memory table (with reserved entries)
         - Write primary and mirror FAT to disk
        """
        # 1) Rebuild in-memory table (you already do that in __init__)
        self._initialize_fat_table()

        # 2) Turn it into a bytes blob
        fat_blob = self._fat_table_to_bytes()

        # 3) Write primary FAT
        start_sec = self.bs.reserved_sectors
        disk.write_sectors(start_sec, fat_blob)

        # 4) Write mirror FAT
        mirror_sec = start_sec + self.bs.sectors_per_fat
        disk.write_sectors(mirror_sec, fat_blob)


    def _initialize_fat_table(self):
        """Initialize FAT table with default values"""
        # FAT32 uses 28 bits (top 4 bits reserved)
        self.fat_table = [self.FREE_CLUSTER] * (self.total_clusters + 2)
        
        # Set special entries
        self.fat_table[0] = 0x0FFFFF00 | self.boot_sector.media_descriptor
        self.fat_table[1] = self.END_OF_CHAIN
        
        # Root directory (cluster 2)
        if self.boot_sector.root_cluster == 2:
            self.fat_table[2] = self.END_OF_CHAIN
    
    def initialize_fat_tables(self, disk, boot_sector):
        """Initialize FAT tables on disk"""
        try:
            # Calculate FAT start sector
            fat_start_sector = boot_sector.reserved_sectors
            
            # Convert FAT table to bytes
            fat_data = self._fat_table_to_bytes()
            
            # Write primary FAT
            disk.write_sectors(fat_start_sector, fat_data)
            
            # Write backup FAT
            backup_fat_start = fat_start_sector + boot_sector.sectors_per_fat
            disk.write_sectors(backup_fat_start, fat_data)
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to initialize FAT tables: {str(e)}")
    
    def _fat_table_to_bytes(self) -> bytes:
        """Convert FAT table to byte representation"""
        fat_bytes = bytearray(self.boot_sector.sectors_per_fat * self.boot_sector.bytes_per_sector)
        
        for i, entry in enumerate(self.fat_table):
            if i * 4 + 3 < len(fat_bytes):
                # Write 32-bit entry (little-endian)
                struct.pack_into('<L', fat_bytes, i * 4, entry & 0x0FFFFFFF)
        
        return bytes(fat_bytes)
    
    # def load_from_disk(self, disk):
    #     """Load FAT table from disk"""
    #     try:
    #         fat_start_sector = self.boot_sector.reserved_sectors
    #         fat_size_bytes = self.boot_sector.sectors_per_fat * self.boot_sector.bytes_per_sector
    #
    #         # Read primary FAT
    #         fat_data = disk.read_sectors(fat_start_sector, self.boot_sector.sectors_per_fat)
    #
    #         # Parse FAT entries
    #         self.fat_table = []
    #         for i in range(0, min(len(fat_data), (self.total_clusters + 2) * 4), 4):
    #             if i + 3 < len(fat_data):
    #                 entry = struct.unpack('<L', fat_data[i:i+4])[0] & 0x0FFFFFFF
    #                 self.fat_table.append(entry)
    #             else:
    #                 break
    #
    #         # Ensure we have enough entries
    #         while len(self.fat_table) < self.total_clusters + 2:
    #             self.fat_table.append(self.FREE_CLUSTER)
    #
    #         # Update next free cluster hint
    #         self._find_next_free_cluster()
    #
    #         return True
    #
    #     except Exception as e:
    #         raise Exception(f"Failed to load FAT from disk: {str(e)}")

    def is_end_of_cluster(self, entry_value: int) -> bool:
        """
        Return True if the FAT entry value indicates end-of-chain.
        FAT32 marks EOF as any value from 0x0FFFFFF8 up to 0x0FFFFFFF.
        """
        return entry_value >= self.END_OF_CHAIN

    def set_fat_entry(self, cluster: int, value: int):
        """Set a FAT32 table entry for a given cluster number"""
        FAT_ENTRY_SIZE = 4
        # Mask value to 28 bits as per FAT32 spec
        value = value & 0x0FFFFFFF

        # Get FAT parameters from boot sector
        fat_start_sector = self.bs.get_fat_start_sector()
        bytes_per_sector = self.bs.bytes_per_sector

        # Calculate position in FAT
        byte_offset = cluster * FAT_ENTRY_SIZE
        sector_offset = byte_offset // bytes_per_sector
        offset_in_sector = byte_offset % bytes_per_sector

        # Read sector containing the FAT entry
        fat_sector = bytearray(self.disk.read_sector(fat_start_sector + sector_offset))

        # Update FAT entry
        struct.pack_into("<I", fat_sector, offset_in_sector, value)

        # Write back to disk
        self.disk.write_sector(fat_start_sector + sector_offset, bytes(fat_sector))

        # Update backup FAT if exists
        if self.bs.num_fats > 1:
            backup_fat_start = self.bs.get_fat_start_sector(1)
            self.disk.write_sector(backup_fat_start + sector_offset, bytes(fat_sector))

    def write_fat_to_disk(self):
        """Write the entire in-memory FAT to disk"""
        # Write to primary FAT
        fat_start = self.bs.get_fat_start_sector()
        for i in range(self.bs.sectors_per_fat):
            sector_data = bytearray(self.bs.bytes_per_sector)
            start_index = i * (self.bs.bytes_per_sector // 4)
            end_index = start_index + (self.bs.bytes_per_sector // 4)

            # Pack FAT entries into sector
            for j, cluster in enumerate(range(start_index, end_index)):
                if cluster < len(self.fat_table):
                    struct.pack_into("<I", sector_data, j * 4, self.fat_table[cluster])

            self.disk.write_sector(fat_start + i, bytes(sector_data))

        # Write to backup FAT if exists
        if self.bs.num_fats > 1:
            backup_start = self.bs.get_fat_start_sector(1)
            for i in range(self.bs.sectors_per_fat):
                sector_data = self.disk.read_sector(fat_start + i)
                self.disk.write_sector(backup_start + i, sector_data)

    def get_next_cluster(self, cluster: int) -> Optional[int]:
        """
        Return the next cluster in the chain, or None if this was end-of-chain
        (i.e. cluster >= END_OF_CHAIN or out of range).
        """
        # Out of bounds?
        if cluster < 2 or cluster >= len(self.fat_table):
            return None

        entry = self.fat_table[cluster]
        # FAT32 end-of-chain markers are >= END_OF_CHAIN
        if entry >= self.END_OF_CHAIN:
            return None

        return entry

    def allocate_cluster(self) -> Optional[int]:
        """Allocate a free cluster and return its number"""
        # Search for free cluster starting from next_free_cluster
        for cluster in range(self.next_free_cluster, len(self.fat_table)):
            if self.fat_table[cluster] == self.FREE_CLUSTER:
                self.fat_table[cluster] = self.END_OF_CHAIN
                self._find_next_free_cluster()
                return cluster
        
        # Search from beginning if not found
        for cluster in range(2, self.next_free_cluster):
            if self.fat_table[cluster] == self.FREE_CLUSTER:
                self.fat_table[cluster] = self.END_OF_CHAIN
                self.next_free_cluster = cluster + 1
                return cluster
        
        return None  # No free clusters

    def allocate_cluster_chain(self, size_bytes: int) -> List[int]:
        """Allocate a chain of clusters for given size"""
        cluster_size = self.boot_sector.get_cluster_size_bytes()
        clusters_needed = (size_bytes + cluster_size - 1) // cluster_size

        if clusters_needed == 0:
            return []

        chain = []
        for _ in range(clusters_needed):
            cluster = self.allocate_cluster()
            if cluster is None:
                # Clean up partially allocated chain by freeing each cluster individually
                for c in chain:
                    self.free_cluster(c)  # Use your existing free_cluster method
                return []
            chain.append(cluster)

        # Link the chain in the in-memory FAT table
        for i in range(len(chain) - 1):
            self.fat_table[chain[i]] = chain[i + 1]

        # Mark last cluster as end of chain
        self.fat_table[chain[-1]] = 0x0FFFFFFF  # EOC marker

        # Write the updated FAT to disk
        self.write_fat_to_disk()

        return chain


    def free_cluster(self, cluster: int):
        """Free a single cluster"""
        if 2 <= cluster < len(self.fat_table):
            self.fat_table[cluster] = self.FREE_CLUSTER
            if cluster < self.next_free_cluster:
                self.next_free_cluster = cluster
    
    def free_cluster_chain(self, start_cluster: int):
        """
        Free an entire cluster chain starting at `start_cluster`,
        then write the updated FAT tables back to disk.
        """
        # If given a list, free each and flush once
        if isinstance(start_cluster, list):
            for cluster in start_cluster:
                self.fat_table[cluster] = self.FREE_CLUSTER
            # push to disk
            self.save_to_disk(self.disk)
            return

        # Otherwise walk the chain
        current = start_cluster
        while current not in (self.END_OF_CHAIN, self.FREE_CLUSTER):
            # bounds check
            if current < 2 or current >= len(self.fat_table):
                break
            next_cluster = self.fat_table[current]
            self.fat_table[current] = self.FREE_CLUSTER
            current = next_cluster

        # Now flush both FAT copies
        self.save_to_disk(self.disk)
    
    def get_cluster_chain(self, start_cluster: int) -> List[int]:
        """Get the complete cluster chain starting from given cluster"""
        chain = []
        cluster = start_cluster
        
        while (cluster != self.END_OF_CHAIN and 
               cluster != self.FREE_CLUSTER and 
               cluster >= 2 and 
               cluster < len(self.fat_table)):
            
            if cluster in chain:  # Circular reference detection
                break
            
            chain.append(cluster)
            cluster = self.fat_table[cluster]
        
        return chain
    
    def _find_next_free_cluster(self):
        """Update next_free_cluster hint"""
        for cluster in range(self.next_free_cluster, len(self.fat_table)):
            if self.fat_table[cluster] == self.FREE_CLUSTER:
                self.next_free_cluster = cluster
                return
        
        # Search from beginning
        for cluster in range(2, self.next_free_cluster):
            if self.fat_table[cluster] == self.FREE_CLUSTER:
                self.next_free_cluster = cluster
                return
        
        self.next_free_cluster = len(self.fat_table)  # No free clusters
    
    def get_free_clusters(self) -> int:
        """Count free clusters"""
        return sum(1 for entry in self.fat_table[2:] if entry == self.FREE_CLUSTER)
    
    def get_used_clusters(self) -> int:
        """Count used clusters"""
        return sum(1 for entry in self.fat_table[2:] 
                  if entry != self.FREE_CLUSTER and entry != self.BAD_CLUSTER)
    
    def get_bad_clusters(self) -> int:
        """Count bad clusters"""
        return sum(1 for entry in self.fat_table[2:] if entry == self.BAD_CLUSTER)
    
    def mark_bad_cluster(self, cluster: int):
        """Mark a cluster as bad"""
        if 2 <= cluster < len(self.fat_table):
            self.fat_table[cluster] = self.BAD_CLUSTER
    
    def calculate_slack_space(self, disk) -> Dict:
        """Calculate slack space for all files"""
        try:
            total_slack = 0
            file_count = 0
            slack_details = []
            
            # This is a simplified calculation - in real implementation,
            # we would need to traverse all directory entries
            cluster_size = self.boot_sector.get_cluster_size()
            
            # Estimate based on used clusters and typical file sizes
            used_clusters = self.get_used_clusters()
            
            # Simplified calculation: assume average file uses 70% of last cluster
            estimated_slack_per_file = cluster_size * 0.3
            estimated_files = max(1, used_clusters // 2)  # Rough estimate
            
            total_slack = estimated_slack_per_file * estimated_files
            
            return {
                'total_slack_bytes': int(total_slack),
                'cluster_size': cluster_size,
                'estimated_files': estimated_files,
                'avg_slack_per_file': estimated_slack_per_file,
                'slack_percentage': (total_slack / (used_clusters * cluster_size)) * 100 if used_clusters > 0 else 0
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'total_slack_bytes': 0,
                'cluster_size': self.boot_sector.get_cluster_size(),
                'estimated_files': 0,
                'avg_slack_per_file': 0,
                'slack_percentage': 0
            }
    
    def check_integrity(self) -> Dict:
        """Check FAT integrity and find issues"""
        issues = {
            'cross_linked_clusters': [],
            'lost_chains': [],
            'invalid_entries': [],
            'circular_references': []
        }
        
        try:
            # Track cluster usage
            cluster_usage = {}
            
            # Check all FAT entries
            for cluster in range(2, len(self.fat_table)):
                entry = self.fat_table[cluster]
                
                # Check for invalid entries
                if (entry != self.FREE_CLUSTER and 
                    entry != self.END_OF_CHAIN and 
                    entry != self.BAD_CLUSTER and 
                    (entry < 2 or entry >= len(self.fat_table))):
                    issues['invalid_entries'].append(cluster)
                
                # Track cluster references for cross-linking detection
                if (entry >= 2 and entry < len(self.fat_table) and 
                    entry != self.END_OF_CHAIN):
                    if entry in cluster_usage:
                        issues['cross_linked_clusters'].append({
                            'cluster': entry,
                            'referenced_by': [cluster_usage[entry], cluster]
                        })
                    else:
                        cluster_usage[entry] = cluster
            
            # Check for circular references
            for start_cluster in range(2, len(self.fat_table)):
                if self.fat_table[start_cluster] != self.FREE_CLUSTER:
                    chain = self.get_cluster_chain(start_cluster)
                    if len(chain) != len(set(chain)):  # Duplicates indicate circular reference
                        issues['circular_references'].append(start_cluster)
            
            return issues
            
        except Exception as e:
            issues['error'] = str(e)
            return issues
    
    def save_to_disk(self, disk):
        """Save FAT table changes to disk"""
        try:
            fat_data = self._fat_table_to_bytes()
            fat_start_sector = self.boot_sector.reserved_sectors
            
            # Write primary FAT
            disk.write_sectors(fat_start_sector, fat_data)
            
            # Write backup FAT
            backup_fat_start = fat_start_sector + self.boot_sector.sectors_per_fat
            disk.write_sectors(backup_fat_start, fat_data)
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to save FAT to disk: {str(e)}")
    
    def get_statistics(self) -> Dict:
        """Get comprehensive FAT statistics"""
        free_clusters = self.get_free_clusters()
        used_clusters = self.get_used_clusters()
        bad_clusters = self.get_bad_clusters()
        cluster_size = self.boot_sector.get_cluster_size()
        
        return {
            'total_clusters': self.total_clusters,
            'free_clusters': free_clusters,
            'used_clusters': used_clusters,
            'bad_clusters': bad_clusters,
            'cluster_size': cluster_size,
            'free_space_bytes': free_clusters * cluster_size,
            'used_space_bytes': used_clusters * cluster_size,
            'utilization_percent': (used_clusters / self.total_clusters) * 100 if self.total_clusters > 0 else 0,
            'next_free_cluster': self.next_free_cluster
        }
    
    def defragment_suggestions(self) -> List[str]:
        """Provide defragmentation suggestions"""
        suggestions = []
        stats = self.get_statistics()
        
        if stats['utilization_percent'] > 90:
            suggestions.append("Disk is over 90% full - consider freeing space")
        
        if stats['bad_clusters'] > 0:
            suggestions.append(f"Found {stats['bad_clusters']} bad clusters - consider disk replacement")
        
        # Check for fragmentation (simplified)
        fragmented_chains = 0
        for cluster in range(2, len(self.fat_table)):
            if (self.fat_table[cluster] != self.FREE_CLUSTER and 
                self.fat_table[cluster] != self.END_OF_CHAIN and
                self.fat_table[cluster] != self.BAD_CLUSTER):
                next_cluster = self.fat_table[cluster]
                if next_cluster != cluster + 1 and next_cluster != self.END_OF_CHAIN:
                    fragmented_chains += 1
        
        fragmentation_percent = (fragmented_chains / max(1, stats['used_clusters'])) * 100
        
        if fragmentation_percent > 25:
            suggestions.append(f"High fragmentation detected ({fragmentation_percent:.1f}%) - consider defragmentation")
        
        return suggestions
