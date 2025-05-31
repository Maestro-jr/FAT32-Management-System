#!/usr/bin/env python3
"""
Configuration Management System for FAT32 Virtual Disk Management
Provides configuration handling with validation, profiles, and persistence
"""

import os
import json
import threading
from typing import Any, Dict, Optional, Union, List
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from copy import deepcopy
import hashlib
from datetime import datetime

# Try to import validation libraries
try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False


class ConfigError(Exception):
    """Base exception for configuration errors"""
    pass


class ConfigValidationError(ConfigError):
    """Exception for configuration validation errors"""
    pass


@dataclass
class ConfigProfile:
    """Configuration profile for different environments"""
    name: str
    description: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


class Config:
    """
    Configuration management system for FAT32 Virtual Disk Management
    """

    # Configuration schema for validation
    SCHEMA = {
        "type": "object",
        "properties": {
            "disk": {
                "type": "object",
                "properties": {
                    "default_size_mb": {"type": "integer", "minimum": 1, "maximum": 1048576},
                    "default_sector_size": {"type": "integer", "enum": [512, 1024, 2048, 4096]},
                    "default_cluster_size": {"type": "integer", "minimum": 512, "maximum": 65536},
                    "max_file_size_mb": {"type": "integer", "minimum": 1},
                    "compression_enabled": {"type": "boolean"},
                    "encryption_enabled": {"type": "boolean"}
                },
                "required": ["default_size_mb", "default_sector_size", "default_cluster_size"]
            },
            "logging": {
                "type": "object",
                "properties": {
                    "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                    "console_logging": {"type": "boolean"},
                    "file_logging": {"type": "boolean"},
                    "log_directory": {"type": "string"},
                    "max_file_size": {"type": "integer", "minimum": 1024},
                    "backup_count": {"type": "integer", "minimum": 1, "maximum": 100}
                }
            },
            "security": {
                "type": "object",
                "properties": {
                    "encryption_algorithm": {"type": "string", "enum": ["aes-256-gcm", "aes-256-cbc"]},
                    "key_derivation": {"type": "string", "enum": ["pbkdf2-sha256", "scrypt"]},
                    "iterations": {"type": "integer", "minimum": 1000, "maximum": 1000000},
                    "require_password": {"type": "boolean"},
                    "password_min_length": {"type": "integer", "minimum": 8, "maximum": 128}
                }
            },
            "performance": {
                "type": "object",
                "properties": {
                    "cache_size_mb": {"type": "integer", "minimum": 1, "maximum": 1024},
                    "buffer_size": {"type": "integer", "minimum": 1024, "maximum": 1048576},
                    "parallel_operations": {"type": "boolean"},
                    "max_threads": {"type": "integer", "minimum": 1, "maximum": 32}
                }
            }
        }
    }

    # Default configuration values
    DEFAULT_CONFIG = {
        "disk": {
            "default_size_mb": 1024,
            "default_sector_size": 512,
            "default_cluster_size": 4096,
            "max_file_size_mb": 4095,  # FAT32 limit
            "compression_enabled": False,
            "encryption_enabled": False,
            "default_image_name": "virtual_disk.img"
        },
        "logging": {
            "level": "INFO",
            "console_logging": True,
            "file_logging": True,
            "log_directory": "logs",
            "max_file_size": 10485760,  # 10MB
            "backup_count": 5,
            "use_colors": True,
            "include_timestamp": True
        },
        "security": {
            "encryption_algorithm": "aes-256-gcm",
            "key_derivation": "pbkdf2-sha256",
            "iterations": 100000,
            "require_password": False,
            "password_min_length": 8,
            "secure_delete": True
        },
        "performance": {
            "cache_size_mb": 32,
            "buffer_size": 65536,  # 64KB
            "parallel_operations": True,
            "max_threads": 4,
            "read_ahead_enabled": True,
            "write_back_cache": True
        },
        "ui": {
            "show_progress": True,
            "verbose_output": False,
            "confirm_destructive_operations": True,
            "table_format": "pretty",
            "date_format": "%Y-%m-%d %H:%M:%S"
        },
        "health": {
            "auto_check_on_mount": True,
            "check_bad_clusters": True,
            "check_lost_chains": True,
            "slack_space_analysis": True,
            "generate_recommendations": True
        }
    }

    def __init__(self,
                 config_file: Optional[Union[str, Path]] = None,
                 profile: str = "default",
                 auto_save: bool = True):
        """
        Initialize configuration manager

        Args:
            config_file: Path to configuration file
            profile: Configuration profile name
            auto_save: Automatically save changes
        """
        self._lock = threading.RLock()
        self._config = deepcopy(self.DEFAULT_CONFIG)
        self._profiles: Dict[str, ConfigProfile] = {}
        self._current_profile = profile
        self._auto_save = auto_save

        # Determine config file path
        if config_file:
            self._config_file = Path(config_file)
        else:
            self._config_file = self._get_default_config_path()

        # Create config directory if needed
        self._config_file.parent.mkdir(parents=True, exist_ok=True)

        # Initialize default profile
        self._profiles[profile] = ConfigProfile(
            name=profile,
            description="Default configuration profile",
            config=deepcopy(self._config)
        )

        # Load existing configuration
        self.load()

    def _get_default_config_path(self) -> Path:
        """Get default configuration file path"""
        # Check common locations
        locations = [
            Path.cwd() / "fat32_config.json",
            Path.home() / ".config" / "fat32manager" / "config.json",
            Path.home() / ".fat32manager" / "config.json"
        ]

        # Use first existing file or default to first location
        for path in locations:
            if path.exists():
                return path

        return locations[0]

    def load(self, config_file: Optional[Union[str, Path]] = None) -> bool:
        """Load configuration from file"""
        config_path = Path(config_file) if config_file else self._config_file

        if not config_path.exists():
            # Create default configuration file
            return self.save()

        try:
            with self._lock:
                with open(config_path, 'r') as f:
                    data = json.load(f)

                # Load profiles if present
                if 'profiles' in data:
                    self._profiles = {}
                    for profile_data in data['profiles']:
                        profile = ConfigProfile(
                            name=profile_data['name'],
                            description=profile_data.get('description', ''),
                            config=profile_data.get('config', {}),
                            created_at=datetime.fromisoformat(
                                profile_data.get('created_at', datetime.now().isoformat()))
                        )
                        self._profiles[profile.name] = profile

                # Load main config (current profile)
                if 'config' in data:
                    self._merge_config(data['config'])

                # Set current profile
                if 'current_profile' in data:
                    self._current_profile = data['current_profile']

                # Apply current profile
                if self._current_profile in self._profiles:
                    self._config = deepcopy(self._profiles[self._current_profile].config)

                return True

        except Exception as e:
            print(f"Warning: Failed to load config: {str(e)}")
            return False

    def save(self, config_file: Optional[Union[str, Path]] = None) -> bool:
        """Save configuration to file"""
        config_path = Path(config_file) if config_file else self._config_file

        try:
            with self._lock:
                # Update current profile
                if self._current_profile in self._profiles:
                    self._profiles[self._current_profile].config = deepcopy(self._config)

                # Prepare data for saving
                data = {
                    'version': '1.0',
                    'current_profile': self._current_profile,
                    'config': self._config,
                    'profiles': [
                        {
                            'name': profile.name,
                            'description': profile.description,
                            'config': profile.config,
                            'created_at': profile.created_at.isoformat()
                        }
                        for profile in self._profiles.values()
                    ],
                    'saved_at': datetime.now().isoformat()
                }

                # Create backup if file exists
                if config_path.exists():
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_path = config_path.with_name(f"{config_path.stem}_backup_{timestamp}{config_path.suffix}")
                    try:
                        config_path.rename(backup_path)
                    except OSError:
                        pass  # Ignore backup errors

                # Save configuration
                with open(config_path, 'w') as f:
                    json.dump(data, f, indent=4, sort_keys=True)

                return True

        except Exception as e:
            print(f"Warning: Failed to save config: {str(e)}")
            return False

    def _merge_config(self, new_config: Dict):
        """Merge new configuration data into existing config"""
        for section, settings in new_config.items():
            if section in self._config:
                if isinstance(settings, dict) and isinstance(self._config[section], dict):
                    self._config[section].update(settings)
                else:
                    self._config[section] = settings
            else:
                self._config[section] = settings

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        try:
            return self._config[section][key]
        except KeyError:
            return default

    def set(self, section: str, key: str, value: Any, auto_save: bool = None):
        """Set a configuration value"""
        with self._lock:
            if section not in self._config:
                self._config[section] = {}
            self._config[section][key] = value

            if auto_save or (auto_save is None and self._auto_save):
                self.save()

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get an entire configuration section"""
        return deepcopy(self._config.get(section, {}))

    def set_section(self, section: str, settings: Dict[str, Any], auto_save: bool = None):
        """Set an entire configuration section"""
        with self._lock:
            self._config[section] = deepcopy(settings)

            if auto_save or (auto_save is None and self._auto_save):
                self.save()

    def validate(self) -> bool:
        """Validate current configuration against schema"""
        if not JSONSCHEMA_AVAILABLE:
            print("Warning: jsonschema not available, skipping validation")
            return True

        try:
            jsonschema.validate(instance=self._config, schema=self.SCHEMA)
            return True
        except jsonschema.ValidationError as e:
            print(f"Configuration validation failed: {e.message}")
            return False
        except Exception as e:
            print(f"Validation error: {str(e)}")
            return False

    def switch_profile(self, profile_name: str):
        """Switch to a different configuration profile"""
        with self._lock:
            if profile_name in self._profiles:
                self._current_profile = profile_name
                self._config = deepcopy(self._profiles[profile_name].config)
                if self._auto_save:
                    self.save()
            else:
                raise ConfigError(f"Profile not found: {profile_name}")

    def create_profile(self, profile_name: str, description: str = ""):
        """Create a new configuration profile"""
        with self._lock:
            if profile_name not in self._profiles:
                self._profiles[profile_name] = ConfigProfile(
                    name=profile_name,
                    description=description,
                    config=deepcopy(self._config)
                )
                if self._auto_save:
                    self.save()
            else:
                print(f"Warning: Profile already exists: {profile_name}")

    def delete_profile(self, profile_name: str):
        """Delete a configuration profile"""
        with self._lock:
            if profile_name == "default":
                raise ConfigError("Cannot delete default profile")

            if profile_name in self._profiles:
                del self._profiles[profile_name]
                if self._current_profile == profile_name:
                    self._current_profile = "default"
                    self._config = deepcopy(self._profiles["default"].config)
                if self._auto_save:
                    self.save()
            else:
                print(f"Warning: Profile not found: {profile_name}")

    def list_profiles(self) -> List[str]:
        """List available profile names"""
        return list(self._profiles.keys())

    def get_current_profile(self) -> str:
        """Get current profile name"""
        return self._current_profile

    def reset_to_defaults(self):
        """Reset configuration to default values"""
        with self._lock:
            self._config = deepcopy(self.DEFAULT_CONFIG)
            if self._auto_save:
                self.save()

    def to_dict(self) -> Dict:
        """Return a deep copy of the entire configuration"""
        return deepcopy(self._config)

    def update(self, new_config: Dict, auto_save: bool = None):
        """Update configuration with new values"""
        with self._lock:
            for section, settings in new_config.items():
                if section not in self._config:
                    self._config[section] = {}
                if isinstance(settings, dict):
                    self._config[section].update(deepcopy(settings))
                else:
                    self._config[section] = deepcopy(settings)

            if auto_save or (auto_save is None and self._auto_save):
                self.save()

    def compute_hash(self) -> str:
        """Compute a hash of the current configuration"""
        config_str = json.dumps(self._config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()

    def export(self, path: Path):
        """Export configuration to a JSON file"""
        data = {
            'version': '1.0',
            'current_profile': self._current_profile,
            'config': self._config,
            'profiles': [
                {
                    'name': profile.name,
                    'description': profile.description,
                    'config': profile.config,
                    'created_at': profile.created_at.isoformat()
                }
                for profile in self._profiles.values()
            ],
            'exported_at': datetime.now().isoformat()
        }

        with open(path, 'w') as f:
            json.dump(data, f, indent=4)

    def import_config(self, path: Path):
        """Import configuration from a JSON file"""
        if not path.exists():
            raise ConfigError(f"Import file not found: {path}")

        try:
            with open(path, 'r') as f:
                data = json.load(f)

            # Merge imported config
            self.update(data.get('config', {}), auto_save=False)

            # Import profiles
            if 'profiles' in data:
                for profile_data in data['profiles']:
                    profile = ConfigProfile(
                        name=profile_data['name'],
                        description=profile_data.get('description', ''),
                        config=profile_data.get('config', {}),
                        created_at=datetime.fromisoformat(profile_data.get('created_at', datetime.now().isoformat()))
                    )
                    self._profiles[profile.name] = profile

            # Set current profile if specified
            if 'current_profile' in data and data['current_profile'] in self._profiles:
                self.switch_profile(data['current_profile'])

            if self._auto_save:
                self.save()

        except Exception as e:
            raise ConfigError(f"Failed to import config: {str(e)}") from e

    def __str__(self) -> str:
        """Return string representation of current configuration"""
        return json.dumps(self._config, indent=2)

    def __contains__(self, key: str) -> bool:
        """Check if configuration has a specific section"""
        return key in self._config

    def __getitem__(self, section: str) -> Dict[str, Any]:
        """Get configuration section using dict-like access"""
        return self.get_section(section)

    def __setitem__(self, section: str, value: Dict[str, Any]):
        """Set configuration section using dict-like access"""
        self.set_section(section, value)


# Convenience functions for common configuration patterns
def get_disk_defaults() -> Dict[str, Any]:
    """Get default disk configuration values"""
    config = Config()
    return config.get_section('disk')


def get_logging_config() -> Dict[str, Any]:
    """Get logging configuration"""
    config = Config()
    return config.get_section('logging')


def get_security_config() -> Dict[str, Any]:
    """Get security configuration"""
    config = Config()
    return config.get_section('security')


def get_performance_config() -> Dict[str, Any]:
    """Get performance configuration"""
    config = Config()
    return config.get_section('performance')


# Example usage and testing
if __name__ == "__main__":
    # Create and test configuration
    config = Config()

    print("=== FAT32 Configuration System ===")
    print(f"Default disk size: {config.get('disk', 'default_size_mb')} MB")
    print(f"Default cluster size: {config.get('disk', 'default_cluster_size')} bytes")
    print(f"Logging level: {config.get('logging', 'level')}")
    print(f"Cache size: {config.get('performance', 'cache_size_mb')} MB")

    # Update a setting
    config.set("disk", "default_size_mb", 2048)
    print(f"Updated disk size: {config.get('disk', 'default_size_mb')} MB")

    # Create a new profile
    config.create_profile("production", "Production environment settings")
    config.set("disk", "default_size_mb", 4096)
    config.set("logging", "level", "WARNING")

    # Switch profiles
    config.switch_profile("default")
    print(f"Default profile disk size: {config.get('disk', 'default_size_mb')} MB")

    config.switch_profile("production")
    print(f"Production profile disk size: {config.get('disk', 'default_size_mb')} MB")

    # Show all profiles
    print(f"Available profiles: {config.list_profiles()}")
    print(f"Current profile: {config.get_current_profile()}")

    # Validate configuration
    if config.validate():
        print("Configuration is valid")
    else:
        print("Configuration validation failed")

    # Show configuration hash
    print(f"Configuration hash: {config.compute_hash()[:16]}...")

    # Export configuration
    export_path = Path("config_export.json")
    config.export(export_path)
    print(f"Configuration exported to: {export_path}")

    # Show disk defaults
    print("\nDisk defaults:")
    for key, value in get_disk_defaults().items():
        print(f"  {key}: {value}")