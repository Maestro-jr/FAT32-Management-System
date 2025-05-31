#!/usr/bin/env python3
"""
Advanced Logging System for FAT32 Virtual Disk Management
Provides comprehensive logging with multiple handlers, formatting, and rotation
"""

import logging
import logging.handlers
import os
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
import traceback
from enum import Enum

class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class LogFormatter(logging.Formatter):
    """Custom formatter with color support and structured output"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[91m',   # Bright Red
        'RESET': '\033[0m'        # Reset
    }
    
    def __init__(self, use_colors=True, include_thread=True, structured=False):
        self.use_colors = use_colors and sys.stderr.isatty()
        self.include_thread = include_thread
        self.structured = structured
        
        if structured:
            super().__init__()
        else:
            fmt = self._build_format()
            super().__init__(fmt)
    
    def _build_format(self):
        """Build the log format string"""
        components = [
            '%(asctime)s',
            '[%(levelname)8s]'
        ]
        
        if self.include_thread:
            components.append('[%(threadName)s]')
        
        components.extend([
            '%(name)s:%(lineno)d',
            '- %(message)s'
        ])
        
        return ' '.join(components)
    
    def format(self, record):
        if self.structured:
            return self._format_structured(record)
        else:
            return self._format_standard(record)
    
    def _format_structured(self, record):
        """Format as structured JSON log"""
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
            'thread': record.threadName,
            'process': record.process
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'getMessage']:
                log_entry['extra'] = log_entry.get('extra', {})
                log_entry['extra'][key] = value
        
        return json.dumps(log_entry, default=str)
    
    def _format_standard(self, record):
        """Format as standard text log with optional colors"""
        formatted = super().format(record)
        
        if self.use_colors:
            color = self.COLORS.get(record.levelname, '')
            reset = self.COLORS['RESET']
            formatted = f"{color}{formatted}{reset}"
        
        return formatted

class PerformanceLogger:
    """Context manager for performance logging"""
    
    def __init__(self, logger, operation: str, level: LogLevel = LogLevel.INFO):
        self.logger = logger
        self.operation = operation
        self.level = level
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.log(self.level.value, f"Starting {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.log(self.level.value, f"Completed {self.operation} in {duration:.3f}s")
        else:
            self.logger.error(f"Failed {self.operation} after {duration:.3f}s: {exc_val}")
        
        return False  # Don't suppress exceptions

class Logger:
    """
    Advanced logging system with multiple handlers and configuration options
    """
    
    _instances: Dict[str, 'Logger'] = {}
    _lock = threading.Lock()
    
    def __init__(self, name: str = "FAT32Manager", config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self._logger = None
        self._handlers = []
        self._setup_logger()
    
    @classmethod
    def get_logger(cls, name: str = "FAT32Manager", config: Optional[Dict[str, Any]] = None) -> 'Logger':
        """Get or create a logger instance (singleton pattern)"""
        with cls._lock:
            if name not in cls._instances:
                cls._instances[name] = cls(name, config)
            return cls._instances[name]
    
    def _setup_logger(self):
        """Setup the logger with handlers and formatting"""
        self._logger = logging.getLogger(self.name)
        self._logger.setLevel(self._get_log_level())
        
        # Prevent adding duplicate handlers
        if self._logger.handlers:
            return
        
        # Setup handlers
        self._setup_console_handler()
        self._setup_file_handler()
        self._setup_error_file_handler()
        
        # Setup structured logging if requested
        if self.config.get('structured_logging', False):
            self._setup_structured_handler()
    
    def _get_log_level(self) -> int:
        """Get the configured log level"""
        level_str = self.config.get('log_level', 'INFO').upper()
        return getattr(logging, level_str, logging.INFO)
    
    def _setup_console_handler(self):
        """Setup console handler"""
        if not self.config.get('console_logging', True):
            return
        
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(self._get_log_level())
        
        formatter = LogFormatter(
            use_colors=self.config.get('use_colors', True),
            include_thread=self.config.get('include_thread', True)
        )
        handler.setFormatter(formatter)
        
        self._logger.addHandler(handler)
        self._handlers.append(handler)
    
    def _setup_file_handler(self):
        """Setup rotating file handler"""
        if not self.config.get('file_logging', True):
            return
        
        log_dir = Path(self.config.get('log_directory', 'logs'))
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"{self.name.lower()}.log"
        
        # Use rotating file handler
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.config.get('max_file_size', 10 * 1024 * 1024),  # 10MB
            backupCount=self.config.get('backup_count', 5)
        )
        handler.setLevel(self._get_log_level())
        
        formatter = LogFormatter(
            use_colors=False,
            include_thread=self.config.get('include_thread', True)
        )
        handler.setFormatter(formatter)
        
        self._logger.addHandler(handler)
        self._handlers.append(handler)
    
    def _setup_error_file_handler(self):
        """Setup separate error file handler"""
        if not self.config.get('error_file_logging', True):
            return
        
        log_dir = Path(self.config.get('log_directory', 'logs'))
        log_dir.mkdir(exist_ok=True)
        
        error_file = log_dir / f"{self.name.lower()}_errors.log"
        
        handler = logging.handlers.RotatingFileHandler(
            error_file,
            maxBytes=self.config.get('max_file_size', 10 * 1024 * 1024),
            backupCount=self.config.get('backup_count', 5)
        )
        handler.setLevel(logging.ERROR)
        
        formatter = LogFormatter(
            use_colors=False,
            include_thread=True
        )
        handler.setFormatter(formatter)
        
        self._logger.addHandler(handler)
        self._handlers.append(handler)
    
    def _setup_structured_handler(self):
        """Setup structured JSON logging handler"""
        log_dir = Path(self.config.get('log_directory', 'logs'))
        log_dir.mkdir(exist_ok=True)
        
        json_file = log_dir / f"{self.name.lower()}_structured.log"
        
        handler = logging.handlers.RotatingFileHandler(
            json_file,
            maxBytes=self.config.get('max_file_size', 10 * 1024 * 1024),
            backupCount=self.config.get('backup_count', 5)
        )
        handler.setLevel(self._get_log_level())
        
        formatter = LogFormatter(structured=True)
        handler.setFormatter(formatter)
        
        self._logger.addHandler(handler)
        self._handlers.append(handler)
    
    # Logging methods
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self._logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._logger.warning(message, extra=kwargs)
    
    def warn(self, message: str, **kwargs):
        """Alias for warning"""
        self.warning(message, **kwargs)
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log error message"""
        self._logger.error(message, exc_info=exc_info, extra=kwargs)
    
    def critical(self, message: str, exc_info: bool = False, **kwargs):
        """Log critical message"""
        self._logger.critical(message, exc_info=exc_info, extra=kwargs)
    
    def exception(self, message: str, **kwargs):
        """Log exception with traceback"""
        self._logger.exception(message, extra=kwargs)
    
    def log(self, level: int, message: str, **kwargs):
        """Log with specific level"""
        self._logger.log(level, message, extra=kwargs)
    
    # Context managers
    def performance(self, operation: str, level: LogLevel = LogLevel.INFO) -> PerformanceLogger:
        """Create performance logging context manager"""
        return PerformanceLogger(self, operation, level)
    
    # Utility methods
    def set_level(self, level: LogLevel):
        """Set logging level"""
        self._logger.setLevel(level.value)
        for handler in self._handlers:
            handler.setLevel(level.value)
    
    def add_context(self, **context):
        """Add context to all subsequent log messages"""
        # This could be implemented using contextvars in Python 3.7+
        # For now, we'll store context in the logger instance
        if not hasattr(self, '_context'):
            self._context = {}
        self._context.update(context)
    
    def clear_context(self):
        """Clear logging context"""
        if hasattr(self, '_context'):
            self._context.clear()
    
    def log_system_info(self):
        """Log system information"""
        import platform
        import psutil
        
        self.info("System Information:")
        self.info(f"  Platform: {platform.platform()}")
        self.info(f"  Python: {platform.python_version()}")
        self.info(f"  CPU Count: {psutil.cpu_count()}")
        self.info(f"  Memory: {psutil.virtual_memory().total / (1024**3):.1f} GB")
        self.info(f"  Disk Space: {psutil.disk_usage('/').total / (1024**3):.1f} GB")
    
    def health_check(self) -> Dict[str, Any]:
        """Perform logger health check"""
        health_status = {
            'logger_name': self.name,
            'handlers_count': len(self._handlers),
            'log_level': logging.getLevelName(self._logger.level),
            'handlers': []
        }
        
        for handler in self._handlers:
            handler_info = {
                'type': type(handler).__name__,
                'level': logging.getLevelName(handler.level)
            }
            
            if hasattr(handler, 'baseFilename'):
                handler_info['file'] = handler.baseFilename
                handler_info['file_exists'] = os.path.exists(handler.baseFilename)
            
            health_status['handlers'].append(handler_info)
        
        return health_status
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type is not None:
            self.exception(f"Unhandled exception: {exc_val}")
        return False


# Module-level convenience functions
def get_logger(name: str = "FAT32Manager", config: Optional[Dict[str, Any]] = None) -> Logger:
    """Get a logger instance"""
    return Logger.get_logger(name, config)

def setup_logging(config: Optional[Dict[str, Any]] = None) -> Logger:
    """Setup default logging configuration"""
    default_config = {
        'log_level': 'INFO',
        'console_logging': True,
        'file_logging': True,
        'error_file_logging': True,
        'structured_logging': False,
        'use_colors': True,
        'include_thread': True,
        'log_directory': 'logs',
        'max_file_size': 10 * 1024 * 1024,  # 10MB
        'backup_count': 5
    }
    
    if config:
        default_config.update(config)
    
    return Logger.get_logger("FAT32Manager", default_config)


# Example usage and testing
if __name__ == "__main__":
    # Test the logger
    logger = setup_logging({
        'log_level': 'DEBUG',
        'structured_logging': True
    })
    
    logger.info("Logger initialized")
    logger.debug("Debug message")
    logger.warning("Warning message")
    logger.error("Error message")
    
    # Test performance logging
    with logger.performance("test operation"):
        import time
        time.sleep(0.1)
    
    # Test context
    logger.add_context(operation="test", user="admin")
    logger.info("Message with context")
    logger.clear_context()
    
    # Test health check
    health = logger.health_check()
    logger.info(f"Logger health: {health}")
    
    # Test exception logging
    try:
        raise ValueError("Test exception")
    except Exception:
        logger.exception("Caught test exception")
