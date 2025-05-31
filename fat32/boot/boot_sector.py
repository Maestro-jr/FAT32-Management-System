"""
boot/boot_sector.py
Boot Sector and BIOS Parameter Block (BPB) Management
Handles FAT32 boot sector creation and parsing
"""

import struct
import datetime


class BootSector:
    """FAT32 Boot Sector and BPB management
    - disk_size_mb: Size of disk in megabytes
    - cluster_size: Cluster size in bytes (must be multiple of sector size)
    - oem_name: 8-byte OEM identifier
    - volume_label: 11-byte volume label
    """

    SECTOR_SIZE = 512

    def __init__(
        self,
        disk_size_mb: int = 0,
        cluster_size: int = 4096,
        oem_name: bytes = b"PYFAT32 ",
        volume_label: bytes = b"NO NAME    "
    ):
        # --- Standard BPB fields ---
        self.jump_boot = b"\xEB\x58\x90"                 # JMP short + NOP
        self.oem_name = oem_name                         # 8 bytes

        self.bytes_per_sector = 512                      # usually 512
        self.sectors_per_cluster = cluster_size // self.bytes_per_sector
        self.reserved_sectors = 32                       # typical for FAT32
        self.num_fats = 2
        self.root_entries = 0                            # FAT32 ignores this
        self.total_sectors_16 = 0                        # use 32‐bit field
        self.media_descriptor = 0xF8                     # fixed disk
        self.sectors_per_fat_16 = 0                      # use 32‐bit field
        self.sectors_per_track = 63
        self.num_heads = 255
        self.hidden_sectors = 0

        self.sectors_per_cluster = min(cluster_size // self.bytes_per_sector, 255)
        self.reserved_sectors = min(32, 65535)  # Ensure it fits in 16-bit

        # --- total sectors (32‐bit) ---
        if disk_size_mb > 0:
            total = (disk_size_mb * 1024 * 1024) // self.bytes_per_sector
        else:
            total = 0
        self.total_sectors_32 = total

        # --- compute FAT32‐specific fields ---
        self.sectors_per_fat = self._calculate_sectors_per_fat()
        self.ext_flags = 0
        self.fs_version = 0
        self.root_cluster = 2
        self.fsinfo_sector = 1
        self.backup_boot_sector = 6

        # --- drive/volume stuff ---
        self.drive_number = 0x80
        self.reserved1 = 0
        self.boot_signature = 0x29
        self.volume_id = self._generate_volume_id()
        self.volume_label = volume_label                # must be 11 bytes
        self.fs_type = b"FAT32   "                      # 8 bytes

        # --- boot code area (will be padded/truncated to 420 bytes) ---
        self.boot_code = self._generate_boot_code()

    def _calculate_sectors_per_fat(self) -> int:
        """Compute how many sectors each FAT needs."""
        if self.total_sectors_32 == 0:
            return 0

        # First estimate: assume zero FAT size
        data_sectors = self.total_sectors_32 - self.reserved_sectors - (self.num_fats * 0)
        clusters = data_sectors // self.sectors_per_cluster
        fat_bytes = clusters * 4
        sectors = (fat_bytes + self.bytes_per_sector - 1) // self.bytes_per_sector

        # Recompute with that FAT size
        data_sectors = self.total_sectors_32 - self.reserved_sectors - (self.num_fats * sectors)
        clusters = data_sectors // self.sectors_per_cluster
        fat_bytes = clusters * 4
        sectors = (fat_bytes + self.bytes_per_sector - 1) // self.bytes_per_sector

        return max(sectors, 1)

    def _generate_volume_id(self) -> int:
        """Generate a 32‐bit volume ID from current timestamp."""
        now = datetime.datetime.now()
        return ((now.year & 0xFFFF) << 16) | (now.microsecond & 0xFFFF)

    def _generate_boot_code(self) -> bytes:
        """Minimal boot code placeholder (420 bytes)."""
        code = bytearray(420)
        # simple infinite loop: JMP $ at start
        code[0:2] = b"\xEB\xFE"
        return bytes(code)

    def get_total_clusters(self) -> int:
        """Calculate and return the total number of clusters available for data."""
        if self.total_sectors_32 == 0:
            return 0

        # Calculate data sectors (total - reserved - FAT sectors)
        fat_sectors = self.num_fats * self.sectors_per_fat
        data_sectors = self.total_sectors_32 - self.reserved_sectors - fat_sectors

        # Convert to clusters
        total_clusters = data_sectors // self.sectors_per_cluster

        # The actual usable clusters are from 2 to (total_clusters + 1), inclusive
        return max(total_clusters, 0)

    def get_data_start_sector(self) -> int:
        """Get the sector number (logical index) where data area begins."""
        return self.reserved_sectors + (self.num_fats * self.sectors_per_fat)

    def get_fat_start_sector(self, fat_number: int = 0) -> int:
        """Get the starting sector (logical index) of the specified FAT (0 or 1)."""
        if fat_number >= self.num_fats:
            raise ValueError(f"FAT number {fat_number} exceeds available FATs ({self.num_fats})")
        return self.reserved_sectors + (fat_number * self.sectors_per_fat)

    def cluster_to_sector(self, cluster: int) -> int:
        """Convert cluster number to first sector of that cluster."""
        if cluster < 2:
            raise ValueError("Valid cluster numbers start at 2")
        data_start = self.get_data_start_sector()
        return data_start + ((cluster - 2) * self.sectors_per_cluster)

    def sector_to_cluster(self, sector: int) -> int:
        """Convert sector number to cluster number."""
        data_start = self.get_data_start_sector()
        if sector < data_start:
            raise ValueError("Sector is not in data area")
        return ((sector - data_start) // self.sectors_per_cluster) + 2

    def get_cluster_size_bytes(self) -> int:
        """Get cluster size in bytes."""
        return self.sectors_per_cluster * self.bytes_per_sector

    def is_valid_cluster(self, cluster: int) -> bool:
        """Check if cluster number is valid."""
        if cluster < 2:
            return False
        max_cluster = self.get_total_clusters() + 1  # +1 because clusters start at 2
        return cluster <= max_cluster

    def build(self) -> bytes:
        """Build and return the 512‐byte boot sector."""
        # FIXED: Added extra 'H' specifier for num_heads to match parse method
        bpb = struct.pack(
            "<3s8sHBHBHHBHHHII",  # Changed from "<3s8sHBHBHHBHHII" to include num_heads
            self.jump_boot,
            self.oem_name,
            self.bytes_per_sector,
            self.sectors_per_cluster,
            self.reserved_sectors,
            self.num_fats,
            self.root_entries,
            self.total_sectors_16,
            self.media_descriptor,
            self.sectors_per_fat_16,
            self.sectors_per_track,
            self.num_heads,  # Now included correctly
            self.hidden_sectors,
            self.total_sectors_32
        )

        ext_bpb = struct.pack(
            "<I H H I H H",
            self.sectors_per_fat,
            self.ext_flags,
            self.fs_version,
            self.root_cluster,
            self.fsinfo_sector,
            self.backup_boot_sector
        )

        ext_fields = struct.pack(
            "<12s B B B I 11s 8s",
            b"\x00" * 12,
            self.drive_number,
            self.reserved1,
            self.boot_signature,
            self.volume_id,
            self.volume_label,
            self.fs_type
        )

        # 2) Combine these with boot_code—but *do not* add the signature yet:
        sector = bytearray()
        sector += bpb
        sector += ext_bpb
        sector += ext_fields
        sector += self.boot_code  # this is 420 bytes by design

        # 3) Now pad or truncate to *exactly* 510 bytes:
        sector = sector[:510].ljust(510, b"\x00")

        # 4) Append the 2-byte signature at offsets 510–511:
        sector += b"\x55\xAA"

        # 5) As a sanity check, it must now be exactly 512 bytes:
        data = bytes(sector)
        assert len(data) == self.SECTOR_SIZE, f"Boot sector wrong size: {len(data)}"
        assert data[-2:] == b"\x55\xAA", f"Missing signature: {data[-4:]}"

        return data

    def generate_boot_sector(self) -> bytes:
        """Generate and return the complete boot sector as bytes."""
        return self.build()

    @classmethod
    def parse(cls, data: bytes) -> "BootSector":
        if len(data) != cls.SECTOR_SIZE:
            raise ValueError(f"Sector must be exactly {cls.SECTOR_SIZE} bytes")
        if data[-2:] != b"\x55\xAA":
            raise ValueError("Invalid boot sector signature")

        # ALREADY CORRECT: Includes num_heads field
        header = struct.unpack_from("<3s8sHBHBHHBHHHII", data, 0)

        ext_bpb_off = struct.calcsize("<3s8sHBHBHHBHHHII")
        ext_bpb = struct.unpack_from("<I H H I H H", data, ext_bpb_off)

        ext_off = ext_bpb_off + struct.calcsize("<I H H I H H")
        ext = struct.unpack_from("<12s B B B I 11s 8s", data, ext_off)

        obj = cls()
        # Unpack header (14 values now)
        (
            obj.jump_boot,
            obj.oem_name,
            obj.bytes_per_sector,
            obj.sectors_per_cluster,
            obj.reserved_sectors,
            obj.num_fats,
            obj.root_entries,
            obj.total_sectors_16,
            obj.media_descriptor,
            obj.sectors_per_fat_16,
            obj.sectors_per_track,
            obj.num_heads,  # This was previously missing
            obj.hidden_sectors,
            obj.total_sectors_32
        ) = header

        (
            obj.sectors_per_fat,
            obj.ext_flags,
            obj.fs_version,
            obj.root_cluster,
            obj.fsinfo_sector,
            obj.backup_boot_sector
        ) = ext_bpb

        (
            _,
            obj.drive_number,
            obj.reserved1,
            obj.boot_signature,
            obj.volume_id,
            obj.volume_label,
            obj.fs_type
        ) = ext

        # boot_code and signature remain in data[extoffs+...] if needed
        boot_code_start = ext_off + struct.calcsize("<12s B B B I 11s 8s")
        obj.boot_code = data[boot_code_start:-2]
        return obj

    @classmethod
    def from_disk(cls, disk) -> "BootSector":
        """Read and parse boot sector from disk."""
        sector_data = disk.read_sector(0)  # Boot sector is always at sector 0
        if sector_data is None:
            raise ValueError("Failed to read boot sector from disk")
        return cls.parse(sector_data)

    def info(self) -> str:
        """Return a human‐readable summary of all BPB fields."""
        lines = [
            f"OEM Name:           {self.oem_name.decode().strip()}",
            f"Bytes/Sector:       {self.bytes_per_sector}",
            f"Sectors/Cluster:    {self.sectors_per_cluster}",
            f"Reserved Sectors:   {self.reserved_sectors}",
            f"Number of FATs:     {self.num_fats}",
            f"Total Sectors (32): {self.total_sectors_32}",
            f"Sectors/FAT:        {self.sectors_per_fat}",
            f"Root Cluster:       {self.root_cluster}",
            f"FSInfo Sector:      {self.fsinfo_sector}",
            f"Backup Boot Sector: {self.backup_boot_sector}",
            f"Volume ID:          {hex(self.volume_id)}",
            f"Volume Label:       {self.volume_label.decode().strip()}",
            f"FS Type:            {self.fs_type.decode().strip()}",
            f"Total Clusters:     {self.get_total_clusters()}",
            f"Cluster Size:       {self.get_cluster_size_bytes()} bytes",
            f"Data Start Sector:  {self.get_data_start_sector()}",
        ]
        return "\n".join(lines)

    def generate_fsinfo_sector(self) -> bytes:
        """Build and return the 512‐byte FSInfo sector."""
        fsinfo = bytearray(self.SECTOR_SIZE)

        # 1. Lead signature (0x41615252) at offset 0
        struct.pack_into("<I", fsinfo, 0, 0x41615252)

        # 2. Structure signature (0x61417272) at offset 484
        struct.pack_into("<I", fsinfo, 484, 0x61417272)

        # 3. Free cluster count (unknown) at offset 488
        struct.pack_into("<I", fsinfo, 488, 0xFFFFFFFF)

        # 4. Next free cluster (unknown) at offset 492
        struct.pack_into("<I", fsinfo, 492, 0xFFFFFFFF)

        # 5. Trail signature (0xAA55) at offset 510
        fsinfo[510:512] = b"\x55\xAA"

        return bytes(fsinfo)

    @property
    def data_sectors(self) -> int:
        """Calculate and return the number of data sectors available for files/directories."""
        if self.total_sectors_32 == 0:
            return 0

        # Total sectors minus:
        # - Reserved sectors (boot sector, FSInfo, etc.)
        # - FAT sectors (both copies of FAT)
        return (
                self.total_sectors_32
                - self.reserved_sectors
                - (self.num_fats * self.sectors_per_fat))
    @property
    def total_sectors(self) -> int:
        """Total sectors in the volume (32-bit value)"""
        return self.total_sectors_32

    @property
    def first_data_sector(self):
        """Calculate the first data sector (where cluster 2 starts)"""
        return self.reserved_sectors + (self.num_fats * self.sectors_per_fat)




# Example usage:
if __name__ == "__main__":
    bs = BootSector(disk_size_mb=64, cluster_size=4096)
    data = bs.build()
    print(bs.info())
    # Write to file:
    with open("fat32_bootsector.img", "wb") as f:
        f.write(data)