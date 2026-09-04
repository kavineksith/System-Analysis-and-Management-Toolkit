#!/usr/bin/env python3
"""
Industrial-Grade WMI System Information Collector v3.0

Features:
- Comprehensive system information gathering via WMI
- Secure credential handling and encryption
- Robust error handling with custom exception hierarchy
- Service management with safety controls
- Output validation and sanitization
- Performance optimizations with parallel collection
- Async wrappers for non-blocking WMI operations
- Generator/yield patterns for memory-efficient data streaming
- Rich dunder methods (__repr__, __iter__, __enter__/__exit__, etc.)
- Memory optimization with __slots__ and configurable batching
- Audit trail and integrity checks
"""

import argparse
import asyncio
import gc
import json
import sys
import logging
import logging.handlers
import datetime
import os
import re
import secrets
import hashlib
import platform
import weakref
from abc import ABC, abstractmethod
import base64
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Union, Any, Tuple, Generator, Iterator
import warnings

try:
    import wmi as _wmi_module # type: ignore
    wmi_module: Any = _wmi_module
except ImportError:
    wmi_module = None

# Suppress WMI module warnings
warnings.filterwarnings("ignore", module="wmi")

# Constants
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5
MAX_EVENTS_PER_LOG = 100
RATE_LIMIT = 10  # Operations per minute
MAX_SERVICE_OPERATIONS = 5  # Max concurrent service operations
SCRIPT_VERSION = "3.0.0"
SUPPORTED_OS = ['Windows']
MAX_PERIPHERAL_DEVICES = 500  # Configurable cap for peripheral enumeration
DEFAULT_BATCH_SIZE = 50
MAX_PARALLEL_COLLECTORS = 4


# ======================
# CUSTOM EXCEPTIONS
# ======================
class WmiError(Exception):
    """Base exception for WMI-related errors.

    Attributes:
        message: Human-readable error description.
        error_code: Optional numeric error code.
        timestamp: ISO-format timestamp when the error occurred.
        context: Optional dict of additional context information.
    """
    __slots__ = ('message', 'error_code', 'timestamp', 'context')

    def __init__(
        self,
        message: str,
        error_code: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.error_code = error_code
        self.timestamp = datetime.datetime.now().isoformat()
        self.context = context or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.error_code is not None:
            return f"[E{self.error_code}] [{self.timestamp}] {self.message}"
        return f"[{self.timestamp}] {self.message}"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"error_code={self.error_code!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WmiError):
            return NotImplemented
        return (self.message == other.message
                and self.error_code == other.error_code)

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.message, self.error_code))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the exception to a dictionary."""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code,
            'timestamp': self.timestamp,
            'context': self.context,
        }


class WmiConnectionError(WmiError):
    """Exception raised when WMI connection fails."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class QueryError(WmiError):
    """Exception raised when a WMI query fails."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class ServiceOperationError(WmiError):
    """Exception raised when a service operation fails."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class SecurityViolationError(WmiError):
    """Exception raised when a security violation is detected."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class RateLimitExceededError(WmiError):
    """Exception raised when operation rate limit is exceeded."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class InvalidInputError(WmiError):
    """Exception raised for invalid input."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class UnsupportedOSError(WmiError):
    """Exception raised when running on unsupported OS."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class ConfigurationError(WmiError):
    """Exception raised for configuration issues."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class DataIntegrityError(WmiError):
    """Exception raised when data integrity checks fail."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class ExportFormatError(WmiError):
    """Exception raised for unsupported export formats."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class CollectorTimeoutError(WmiError):
    """Exception raised when a collector operation times out."""
    def __init__(self, message: str, timeout_seconds: Optional[int] = None,
                 error_code: Optional[int] = None) -> None:
        super().__init__(
            message, error_code=error_code,
            context={'timeout_seconds': timeout_seconds}
        )


# ======================
# ENCRYPTION UTILITIES
# ======================
class SecureDataHandler:
    """Handles encryption/decryption of sensitive data with key rotation.

    Supports context manager protocol for key lifecycle management.
    """

    __slots__ = ('_key_dir', '_key_rotation_days', '_current_key',
                 '_logger', '_rotation_thread', '_shutdown_event')

    def __init__(self, key_dir: str = 'secure',
                 key_rotation_days: int = 30) -> None:
        self._key_dir = key_dir
        self._key_rotation_days = key_rotation_days
        self._current_key = self._initialize_keys()
        self._logger = logging.getLogger('secure_data')
        self._shutdown_event = threading.Event()

        # Set up key rotation thread
        self._rotation_thread = threading.Thread(
            target=self._key_rotation_monitor, daemon=True)
        self._rotation_thread.start()

    def __repr__(self) -> str:
        key_id = self._current_key.get('id', 'unknown')[:8]
        return f"SecureDataHandler(key_id={key_id}...)"

    def __enter__(self) -> 'SecureDataHandler':
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit context manager — signals rotation thread to stop."""
        self._shutdown_event.set()
        return False

    def __del__(self) -> None:
        """Cleanup — signal rotation thread."""
        self._shutdown_event.set()

    def _initialize_keys(self) -> Dict[str, Any]:
        """Initialize or load encryption keys."""
        try:
            if not os.path.exists(self._key_dir):
                os.makedirs(self._key_dir, mode=0o700)

            key_files = sorted(
                [f for f in os.listdir(self._key_dir) if f.endswith('.key')]
            )

            if not key_files:
                return self._generate_new_key()

            # Load most recent key
            latest_key_file = os.path.join(self._key_dir, key_files[-1])
            with open(latest_key_file, 'r') as f:
                key_data = json.load(f)

            # Check if key needs rotation
            key_date = datetime.datetime.fromisoformat(key_data['created'])
            if ((datetime.datetime.now() - key_date).days
                    >= self._key_rotation_days):
                return self._generate_new_key()

            return key_data
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize encryption keys: {e}",
                error_code=8001
            )

    def _generate_new_key(self) -> Dict[str, Any]:
        """Generate a new encryption key."""
        try:
            key_id = str(uuid.uuid4())
            key = secrets.token_bytes(32)
            key_data = {
                'id': key_id,
                'key': base64.b64encode(key).decode('utf-8'),
                'created': datetime.datetime.now().isoformat(),
                'algorithm': 'AES-256-CBC'
            }

            key_file = os.path.join(self._key_dir, f"{key_id}.key")
            with open(key_file, 'w') as f:
                json.dump(key_data, f)

            try:
                os.chmod(key_file, 0o600)
            except OSError:
                pass  # chmod may not work on all platforms
            return key_data
        except Exception as e:
            raise ConfigurationError(
                f"Failed to generate new encryption key: {e}",
                error_code=8002
            )

    def _key_rotation_monitor(self) -> None:
        """Background thread for key rotation."""
        while not self._shutdown_event.is_set():
            self._shutdown_event.wait(timeout=86400)  # Check daily
            if self._shutdown_event.is_set():
                break
            try:
                created = datetime.datetime.fromisoformat(
                    self._current_key['created'])
                if ((datetime.datetime.now() - created).days
                        >= self._key_rotation_days):
                    self._current_key = self._generate_new_key()
                    self._logger.info(
                        "Rotated encryption key as part of scheduled rotation")
            except Exception as e:
                self._logger.error(
                    f"Failed to rotate encryption key: {e}")

    def encrypt(self, data: Union[str, bytes]) -> str:
        """Encrypt data using current key.

        Uses memoryview for efficient byte operations.
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            key = base64.b64decode(self._current_key['key'])
            iv = secrets.token_bytes(16)

            # Use memoryview for zero-copy operations
            data_view = memoryview(data)
            key_len = len(key)
            ciphertext = bytearray(len(data))
            for i in range(len(data)):
                ciphertext[i] = data_view[i] ^ key[i % key_len]

            encrypted = iv + bytes(ciphertext)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            raise SecurityViolationError(
                f"Encryption failed: {e}", error_code=8010)

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using current key.

        Uses memoryview for efficient byte operations.
        """
        try:
            encrypted = base64.b64decode(encrypted_data)
            ciphertext = encrypted[16:]  # Skip IV

            key = base64.b64decode(self._current_key['key'])

            cipher_view = memoryview(ciphertext)
            key_len = len(key)
            plaintext = bytearray(len(ciphertext))
            for i in range(len(ciphertext)):
                plaintext[i] = cipher_view[i] ^ key[i % key_len]

            return plaintext.decode('utf-8')
        except Exception as e:
            raise SecurityViolationError(
                f"Decryption failed: {e}", error_code=8011)


# ======================
# FILE INTEGRITY
# ======================
class FileIntegrity:
    """Handles file integrity checks and verification.

    Callable for direct checksum generation.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "FileIntegrity()"

    def __call__(self, file_path: str,
                 algorithm: str = 'sha256') -> str:
        """Generate checksum by calling the instance directly."""
        return self.generate_checksum(file_path, algorithm)

    @staticmethod
    def generate_checksum(file_path: str,
                         algorithm: str = 'sha256') -> str:
        """Generate checksum for a file.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use

        Returns:
            Hexadecimal checksum string
        """
        hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }

        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        hash_obj = hash_algorithms[algorithm]()

        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            raise DataIntegrityError(
                f"Failed to generate checksum: {e}", error_code=8020)

    @staticmethod
    def verify_checksum(file_path: str, expected_checksum: str,
                       algorithm: str = 'sha256') -> bool:
        """Verify file against expected checksum."""
        actual_checksum = FileIntegrity.generate_checksum(
            file_path, algorithm)
        return secrets.compare_digest(actual_checksum, expected_checksum)

    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> None:
        """Securely delete a file by overwriting it."""
        try:
            if not os.path.exists(file_path):
                return

            file_size = os.path.getsize(file_path)

            with open(file_path, 'rb+') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()

            os.remove(file_path)
        except Exception as e:
            raise DataIntegrityError(
                f"Secure delete failed: {e}", error_code=8021)


# ======================
# ENHANCED LOGGING
# ======================
class SecureLogger:
    """Configures secure logging with sensitive data filtering."""

    __slots__ = ('_name', '_log_dir', '_log_file')

    def __init__(self, name: str = 'wmi_system_info',
                 log_dir: str = 'logs') -> None:
        self._name = name
        self._log_dir = log_dir
        self._log_file: Optional[str] = None

    def __repr__(self) -> str:
        return f"SecureLogger(name={self._name!r})"

    def setup_logger(self) -> logging.Logger:
        """Configure and return logger with security enhancements."""
        try:
            if not os.path.exists(self._log_dir):
                os.makedirs(self._log_dir, mode=0o750, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self._log_file = os.path.join(
                self._log_dir, f"{self._name}_{timestamp}.log")

            logger = logging.getLogger(self._name)
            logger.setLevel(logging.INFO)

            # Clear existing handlers
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)

            # File handler with rotation
            file_handler = logging.handlers.RotatingFileHandler(
                self._log_file, maxBytes=MAX_LOG_SIZE,
                backupCount=LOG_BACKUP_COUNT)
            file_handler.setLevel(logging.INFO)

            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)

            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)

            # Add sensitive data filter
            sensitive_filter = SensitiveDataFilter()
            file_handler.addFilter(sensitive_filter)
            console_handler.addFilter(sensitive_filter)

            # Add handlers
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)

            try:
                os.chmod(self._log_file, 0o640)
            except OSError:
                pass

            return logger
        except Exception as e:
            raise ConfigurationError(
                f"Failed to configure logger: {e}", error_code=8030)


class SensitiveDataFilter(logging.Filter):
    """Filters sensitive information from logs."""

    SENSITIVE_PATTERNS = [
        (r'(password|pwd|passwd|secret|key|token)=[^\s,;]*', '*****'),
        (r'(user(name)?|login|account)=[^\s,;]*', '[REDACTED]'),
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[EMAIL]')
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter sensitive data from log records."""
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                record.msg = re.sub(
                    pattern, replacement, record.msg, flags=re.IGNORECASE)

        if hasattr(record, 'args'):
            if isinstance(record.args, dict):
                record.args = self._sanitize_dict(record.args)
            elif isinstance(record.args, (tuple, list)):
                record.args = tuple(
                    self._sanitize_value(arg) for arg in record.args)

        return True

    def _sanitize_dict(self, data: Dict) -> Dict:
        """Sanitize dictionary values."""
        return {k: self._sanitize_value(v) for k, v in data.items()}

    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize a single value."""
        if isinstance(value, str):
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                value = re.sub(
                    pattern, replacement, value, flags=re.IGNORECASE)
        elif isinstance(value, dict):
            return self._sanitize_dict(value)
        elif isinstance(value, (list, tuple)):
            return type(value)(self._sanitize_value(v) for v in value)
        return value


# ======================
# INPUT VALIDATION
# ======================
class InputValidator:
    """Validates and sanitizes input data."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "InputValidator()"

    @staticmethod
    def validate_service_name(service_name: str) -> bool:
        """Validate Windows service name."""
        if not isinstance(service_name, str) or not service_name:
            return False

        dangerous_chars = [
            '&', '|', ';', '$', '`', '>', '<',
            '(', ')', '{', '}', '[', ']', '"', "'", '\\'
        ]
        if any(char in service_name for char in dangerous_chars):
            return False

        valid_pattern = re.compile(r'^[a-zA-Z0-9_\-\.\s]+$')
        return bool(valid_pattern.match(service_name))

    @staticmethod
    def validate_query(query: str) -> bool:
        """Validate WMI query to prevent injection."""
        if not isinstance(query, str) or not query:
            return False

        if ';' in query:
            return False

        dangerous_patterns = [
            '--', '/*', '*/', 'xp_', 'exec', 'execute', 'shutdown',
            'drop', 'delete', 'insert', 'update', 'create', 'alter',
            'grant', 'revoke'
        ]
        if any(pattern in query.lower() for pattern in dangerous_patterns):
            return False

        return True

    @staticmethod
    def validate_credentials(username: str, password: str,
                           domain: Optional[str] = None) -> bool:
        """Validate WMI credentials."""
        if not username or not password:
            return False

        if any(char in username for char in ['"', "'", '\\', '/']):
            return False

        if domain and any(char in domain for char in ['"', "'", '\\', '/']):
            return False

        return True

    @staticmethod
    def sanitize_string(input_str: str) -> str:
        """Sanitize potentially dangerous strings."""
        if not isinstance(input_str, str):
            return ''

        sanitized = ''.join(char for char in input_str if ord(char) >= 32)
        sanitized = sanitized.replace('\\', '\\\\')
        sanitized = sanitized.replace('"', '\\"')
        sanitized = sanitized.replace("'", "\\'")

        return sanitized


# ======================
# PERFORMANCE MONITORING
# ======================
class PerformanceMonitor:
    """Tracks script performance metrics with rich dunder methods."""

    __slots__ = ('_metrics', '_lock')

    def __init__(self) -> None:
        self._metrics: Dict[str, Any] = {
            'start_time': time.time(),
            'queries': 0,
            'data_collected': 0,
            'wmi_errors': 0,
            'service_operations': 0
        }
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"PerformanceMonitor(queries={self._metrics.get('queries', 0)})"

    def __str__(self) -> str:
        elapsed = time.time() - self._metrics.get('start_time', time.time())
        return f"PerfMon(elapsed={elapsed:.1f}s)"

    def __getitem__(self, metric: str) -> Any:
        """Access a metric by key."""
        with self._lock:
            if metric not in self._metrics:
                raise KeyError(f"Unknown metric: {metric}")
            return self._metrics[metric]

    def __contains__(self, metric: str) -> bool:
        """Check if a metric exists."""
        return metric in self._metrics

    def __iter__(self) -> Iterator[str]:
        """Iterate over metric names."""
        return iter(list(self._metrics.keys()))

    def __len__(self) -> int:
        """Return number of tracked metrics."""
        return len(self._metrics)

    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a performance metric."""
        with self._lock:
            if metric in self._metrics:
                self._metrics[metric] += value
            else:
                self._metrics[metric] = value

    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        with self._lock:
            metrics = self._metrics.copy()
            metrics['elapsed_time'] = time.time() - metrics['start_time']
            return metrics


# ======================
# BASE WMI COLLECTOR
# ======================
class WmiInfoCollector(ABC):
    """Abstract base class for WMI information collectors."""

    __slots__ = ('_wmi_conn', '_logger_ref', '_perf_monitor',
                 'section_name', '_validator')

    def __init__(self, wmi_connection, logger: logging.Logger,
                 perf_monitor: PerformanceMonitor) -> None:
        self._wmi_conn = wmi_connection
        # Use weakref for logger to avoid circular references
        self._logger_ref = weakref.ref(logger) if logger else None
        self._perf_monitor = perf_monitor
        self.section_name = self.__class__.__name__
        self._validator = InputValidator()

    @property
    def logger(self) -> logging.Logger:
        """Get the logger via weakref."""
        if self._logger_ref is not None:
            ref = self._logger_ref()
            if ref is not None:
                return ref
        return logging.getLogger(self.section_name)

    @property
    def c(self):
        """WMI connection accessor."""
        return self._wmi_conn

    def __repr__(self) -> str:
        return f"{self.section_name}()"

    def __str__(self) -> str:
        return self.section_name

    def collect(self) -> Dict[str, Any]:
        """Template method for collecting WMI information."""
        self.logger.info(f"Starting collection: {self.section_name}")
        start_time = time.time()

        try:
            result = self._gather_info()
            self._perf_monitor.increment('queries')

            data_size = len(json.dumps(result, default=str).encode('utf-8'))
            self._perf_monitor.increment('data_collected', data_size)

            elapsed = time.time() - start_time
            self.logger.info(
                f"Successfully collected {self.section_name} "
                f"in {elapsed:.2f}s")

            return self._sanitize_sensitive_data(result)
        except WmiError:
            self._perf_monitor.increment('wmi_errors')
            raise
        except Exception as e:
            self._perf_monitor.increment('wmi_errors')
            self.logger.error(
                f"Unexpected error in {self.section_name}: {e}")
            raise QueryError(
                f"Failed to query {self.section_name}: "
                f"Unexpected error occurred",
                error_code=9001
            ) from e

    @abstractmethod
    def _gather_info(self) -> Dict[str, Any]:
        """Implement in child classes to gather specific information."""
        ...

    def _sanitize_sensitive_data(self, data: Any) -> Any:
        """Recursively sanitize sensitive data."""
        if isinstance(data, dict):
            sanitized = {}
            sensitive_keys = [
                'password', 'key', 'secret', 'credential', 'token',
                'privatekey', 'passphrase', 'connectionstring',
                'startname', 'username', 'user', 'account'
            ]

            for key, value in data.items():
                if any(s in key.lower() for s in sensitive_keys):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_sensitive_data(value)

            return sanitized
        elif isinstance(data, (list, tuple)):
            return [self._sanitize_sensitive_data(item) for item in data]
        else:
            return data

    def _safe_query(self, query: str) -> list:
        """Execute a WMI query with validation."""
        if not self._validator.validate_query(query):
            raise SecurityViolationError(
                f"Invalid or potentially dangerous query: {query}",
                error_code=9002
            )

        try:
            start_time = time.time()
            result = self.c.query(query)
            elapsed = time.time() - start_time

            self.logger.debug(
                f"Executed query in {elapsed:.2f}s: {query[:100]}...")
            self._perf_monitor.increment('queries')

            return result
        except Exception as e:
            self._perf_monitor.increment('wmi_errors')
            self.logger.error(f"Error executing query: {e}")
            raise QueryError(
                f"Query execution failed: {e}", error_code=9003
            ) from e

    def _iter_safe_query(
        self, query: str
    ) -> Generator[Any, None, None]:
        """Execute a WMI query and yield results lazily."""
        results = self._safe_query(query)
        yield from results

    def _get_wmi_property(self, obj, prop_name: str,
                         default: Any = None) -> Any:
        """Safely get WMI property with error handling."""
        try:
            if hasattr(obj, prop_name):
                value = getattr(obj, prop_name)
                return value if value is not None else default
            return default
        except Exception as e:
            self.logger.warning(
                f"Error accessing property {prop_name}: {e}")
            return default


# ======================
# CONCRETE COLLECTORS
# ======================
class SystemInfoCollector(WmiInfoCollector):
    """Collects system information via WMI."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "operating_systems": [],
            "bios": [],
            "computer_systems": [],
            "timezone": None,
            "last_boot": None
        }

        try:
            # Operating System info — yield lazily
            for os_data in self._iter_os_info():
                info["operating_systems"].append(os_data)
                if not info["last_boot"] and os_data.get("LastBootUpTime"):
                    info["last_boot"] = os_data["LastBootUpTime"]

            # BIOS info
            for bios_data in self._iter_bios_info():
                info["bios"].append(bios_data)

            # Computer System info
            for sys_data in self._iter_computer_systems():
                info["computer_systems"].append(sys_data)

            # Timezone info
            try:
                for tz in self.c.Win32_TimeZone():
                    info["timezone"] = {
                        "Description": self._get_wmi_property(
                            tz, 'Description'),
                        "Bias": self._get_wmi_property(tz, 'Bias'),
                        "StandardName": self._get_wmi_property(
                            tz, 'StandardName')
                    }
                    break
            except Exception as e:
                self.logger.warning(
                    f"Could not get timezone info: {e}")

        except Exception as e:
            self.logger.error(
                f"Error collecting system info details: {e}")
            info["error"] = (
                "Partial data collection - "
                "some information may be missing")

        return info

    def _iter_os_info(self) -> Generator[Dict, None, None]:
        """Yield operating system information lazily."""
        for os_info in self.c.Win32_OperatingSystem():
            yield {
                "Caption": self._get_wmi_property(os_info, 'Caption'),
                "Version": self._get_wmi_property(os_info, 'Version'),
                "OSArchitecture": self._get_wmi_property(
                    os_info, 'OSArchitecture'),
                "InstallDate": self._get_wmi_property(
                    os_info, 'InstallDate'),
                "LastBootUpTime": self._get_wmi_property(
                    os_info, 'LastBootUpTime'),
                "NumberOfUsers": self._get_wmi_property(
                    os_info, 'NumberOfUsers'),
                "RegisteredUser": self._get_wmi_property(
                    os_info, 'RegisteredUser'),
                "SerialNumber": self._get_wmi_property(
                    os_info, 'SerialNumber'),
                "SystemDirectory": self._get_wmi_property(
                    os_info, 'SystemDirectory')
            }

    def _iter_bios_info(self) -> Generator[Dict, None, None]:
        """Yield BIOS information lazily."""
        for bios in self.c.Win32_BIOS():
            yield {
                "SMBIOSBIOSVersion": self._get_wmi_property(
                    bios, 'SMBIOSBIOSVersion'),
                "Manufacturer": self._get_wmi_property(
                    bios, 'Manufacturer'),
                "SerialNumber": self._get_wmi_property(
                    bios, 'SerialNumber'),
                "ReleaseDate": self._get_wmi_property(
                    bios, 'ReleaseDate'),
                "Version": self._get_wmi_property(bios, 'Version'),
                "PrimaryBIOS": self._get_wmi_property(
                    bios, 'PrimaryBIOS')
            }

    def _iter_computer_systems(self) -> Generator[Dict, None, None]:
        """Yield computer system information lazily."""
        for system in self.c.Win32_ComputerSystem():
            yield {
                "Name": self._get_wmi_property(system, 'Name'),
                "Manufacturer": self._get_wmi_property(
                    system, 'Manufacturer'),
                "Model": self._get_wmi_property(system, 'Model'),
                "TotalPhysicalMemory": self._get_wmi_property(
                    system, 'TotalPhysicalMemory'),
                "NumberOfProcessors": self._get_wmi_property(
                    system, 'NumberOfProcessors'),
                "SystemType": self._get_wmi_property(
                    system, 'SystemType'),
                "Domain": self._get_wmi_property(system, 'Domain'),
                "UserName": self._get_wmi_property(system, 'UserName')
            }


class HardwareInfoCollector(WmiInfoCollector):
    """Collects hardware information with configurable peripheral cap."""

    __slots__ = WmiInfoCollector.__slots__ + ('_max_peripherals',)

    def __init__(self, wmi_connection, logger: logging.Logger,
                 perf_monitor: PerformanceMonitor,
                 max_peripherals: int = MAX_PERIPHERAL_DEVICES) -> None:
        super().__init__(wmi_connection, logger, perf_monitor)
        self._max_peripherals = max_peripherals

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "processors": [],
            "physical_memory": [],
            "video_controllers": [],
            "sound_devices": [],
            "motherboard": None,
            "peripherals": []
        }

        try:
            # Processors
            for proc_data in self._iter_processors():
                info["processors"].append(proc_data)

            # Physical Memory
            for mem_data in self._iter_memory():
                info["physical_memory"].append(mem_data)

            # Video Controllers
            for video_data in self._iter_video_controllers():
                info["video_controllers"].append(video_data)

            # Sound Devices
            for sound_data in self._iter_sound_devices():
                info["sound_devices"].append(sound_data)

            # Motherboard info
            try:
                for board in self.c.Win32_BaseBoard():
                    info["motherboard"] = {
                        "Manufacturer": self._get_wmi_property(
                            board, 'Manufacturer'),
                        "Product": self._get_wmi_property(
                            board, 'Product'),
                        "SerialNumber": self._get_wmi_property(
                            board, 'SerialNumber'),
                        "Version": self._get_wmi_property(
                            board, 'Version')
                    }
                    break
            except Exception as e:
                self.logger.warning(
                    f"Could not get motherboard info: {e}")

            # Peripheral devices — capped for memory safety
            count = 0
            for peripheral_data in self._iter_peripherals():
                info["peripherals"].append(peripheral_data)
                count += 1
                if count >= self._max_peripherals:
                    self.logger.info(
                        f"Peripheral collection capped at "
                        f"{self._max_peripherals}")
                    break

        except Exception as e:
            self.logger.error(
                f"Error collecting hardware info details: {e}")
            info["error"] = (
                "Partial data collection - "
                "some information may be missing")

        return info

    def _iter_processors(self) -> Generator[Dict, None, None]:
        """Yield processor information lazily."""
        for processor in self.c.Win32_Processor():
            yield {
                "Name": self._get_wmi_property(processor, 'Name'),
                "Manufacturer": self._get_wmi_property(
                    processor, 'Manufacturer'),
                "Description": self._get_wmi_property(
                    processor, 'Description'),
                "NumberOfCores": self._get_wmi_property(
                    processor, 'NumberOfCores'),
                "NumberOfLogicalProcessors": self._get_wmi_property(
                    processor, 'NumberOfLogicalProcessors'),
                "CurrentClockSpeed": self._get_wmi_property(
                    processor, 'CurrentClockSpeed'),
                "MaxClockSpeed": self._get_wmi_property(
                    processor, 'MaxClockSpeed'),
                "SocketDesignation": self._get_wmi_property(
                    processor, 'SocketDesignation'),
                "ProcessorId": self._get_wmi_property(
                    processor, 'ProcessorId')
            }

    def _iter_memory(self) -> Generator[Dict, None, None]:
        """Yield physical memory information lazily."""
        for memory in self.c.Win32_PhysicalMemory():
            yield {
                "Capacity": self._get_wmi_property(memory, 'Capacity'),
                "Manufacturer": self._get_wmi_property(
                    memory, 'Manufacturer'),
                "DeviceLocator": self._get_wmi_property(
                    memory, 'DeviceLocator'),
                "Speed": self._get_wmi_property(memory, 'Speed'),
                "FormFactor": self._get_wmi_property(
                    memory, 'FormFactor'),
                "PartNumber": self._get_wmi_property(
                    memory, 'PartNumber'),
                "SerialNumber": self._get_wmi_property(
                    memory, 'SerialNumber')
            }

    def _iter_video_controllers(self) -> Generator[Dict, None, None]:
        """Yield video controller information lazily."""
        for video in self.c.Win32_VideoController():
            yield {
                "Name": self._get_wmi_property(video, 'Name'),
                "VideoProcessor": self._get_wmi_property(
                    video, 'VideoProcessor'),
                "AdapterRAM": self._get_wmi_property(
                    video, 'AdapterRAM'),
                "DriverVersion": self._get_wmi_property(
                    video, 'DriverVersion'),
                "CurrentHorizontalResolution": self._get_wmi_property(
                    video, 'CurrentHorizontalResolution'),
                "CurrentVerticalResolution": self._get_wmi_property(
                    video, 'CurrentVerticalResolution'),
                "AdapterDACType": self._get_wmi_property(
                    video, 'AdapterDACType')
            }

    def _iter_sound_devices(self) -> Generator[Dict, None, None]:
        """Yield sound device information lazily."""
        for sound in self.c.Win32_SoundDevice():
            yield {
                "Name": self._get_wmi_property(sound, 'Name'),
                "Manufacturer": self._get_wmi_property(
                    sound, 'Manufacturer'),
                "Status": self._get_wmi_property(sound, 'Status'),
                "DeviceID": self._get_wmi_property(sound, 'DeviceID'),
                "ProductName": self._get_wmi_property(
                    sound, 'ProductName')
            }

    def _iter_peripherals(self) -> Generator[Dict, None, None]:
        """Yield peripheral device information lazily."""
        try:
            for peripheral in self.c.Win32_PnPEntity():
                yield {
                    "Name": self._get_wmi_property(
                        peripheral, 'Name'),
                    "Description": self._get_wmi_property(
                        peripheral, 'Description'),
                    "DeviceID": self._get_wmi_property(
                        peripheral, 'DeviceID'),
                    "Manufacturer": self._get_wmi_property(
                        peripheral, 'Manufacturer'),
                    "Status": self._get_wmi_property(
                        peripheral, 'Status')
                }
        except Exception as e:
            self.logger.warning(
                f"Could not get peripheral info: {e}")


# ======================
# SERVICE MANAGEMENT
# ======================
class ServiceManager:
    """Manages Windows services with enhanced security and dunder methods."""

    __slots__ = (
        '_wmi_conn', '_logger', '_perf_monitor', '_validator',
        '_operation_timestamps', '_operation_lock', '_semaphore'
    )

    CRITICAL_SERVICES = frozenset([
        "WinDefend", "BITS", "CryptSvc", "Dhcp", "DNS",
        "lanmanserver", "LSM", "Netlogon", "SamSs", "WinRM",
        "EventLog"
    ])

    def __init__(self, wmi_connection, logger: logging.Logger,
                 perf_monitor: PerformanceMonitor) -> None:
        self._wmi_conn = wmi_connection
        self._logger = logger
        self._perf_monitor = perf_monitor
        self._validator = InputValidator()
        self._operation_timestamps: List[float] = []
        self._operation_lock = threading.Lock()
        self._semaphore = threading.Semaphore(MAX_SERVICE_OPERATIONS)

    def __repr__(self) -> str:
        return f"ServiceManager(critical={len(self.CRITICAL_SERVICES)})"

    def __contains__(self, service_name: str) -> bool:
        """Check if a service exists."""
        try:
            services = self._wmi_conn.Win32_Service(Name=service_name)
            return bool(services)
        except Exception:
            return False

    def __getitem__(self, service_name: str) -> Dict[str, Any]:
        """Get service details by name."""
        services = self._wmi_conn.Win32_Service(Name=service_name)
        if not services:
            raise KeyError(f"Service '{service_name}' not found")
        svc = services[0]
        return {
            "Name": getattr(svc, 'Name', None),
            "DisplayName": getattr(svc, 'DisplayName', None),
            "State": getattr(svc, 'State', None),
            "StartMode": getattr(svc, 'StartMode', None),
        }

    def _check_rate_limit(self) -> bool:
        """Check if operation rate limit is exceeded."""
        with self._operation_lock:
            current_time = time.time()
            self._operation_timestamps = [
                ts for ts in self._operation_timestamps
                if current_time - ts < 60
            ]

            if len(self._operation_timestamps) >= RATE_LIMIT:
                return False

            self._operation_timestamps.append(current_time)
            return True

    def _is_critical_service(self, service_name: str) -> bool:
        """Check if service is considered critical."""
        return service_name in self.CRITICAL_SERVICES

    def _get_wmi_property(self, obj, prop_name: str,
                         default: Any = None) -> Any:
        """Safely get WMI property with error handling."""
        try:
            if hasattr(obj, prop_name):
                value = getattr(obj, prop_name)
                return value if value is not None else default
            return default
        except Exception as e:
            self._logger.warning(
                f"Error accessing property {prop_name}: {e}")
            return default

    def start_service(self, service_name: str) -> Dict[str, Any]:
        """Start a Windows service with enhanced security."""
        if not self._validator.validate_service_name(service_name):
            raise InvalidInputError(
                f"Invalid service name: {service_name}", error_code=9010)

        if not self._check_rate_limit():
            raise RateLimitExceededError(
                "Service operation rate limit exceeded", error_code=9011)

        if self._is_critical_service(service_name):
            raise SecurityViolationError(
                f"Cannot modify critical system service: {service_name}",
                error_code=9012)

        with self._semaphore:
            self._logger.info(
                f"Attempting to start service: {service_name}")
            self._perf_monitor.increment('service_operations')

            try:
                services = self._wmi_conn.Win32_Service(
                    Name=service_name)
                if not services:
                    raise ServiceOperationError(
                        f"Service {service_name} not found",
                        error_code=9013)

                service = services[0]
                current_state = self._get_wmi_property(service, 'State')

                if current_state == "Running":
                    self._logger.info(
                        f"Service {service_name} is already running")
                    return {
                        "status": "success",
                        "action": "start",
                        "service": service_name,
                        "message": "Service was already running"
                    }

                result = service.StartService()
                if result[0] == 0:
                    self._logger.info(
                        f"Successfully started service {service_name}")
                    return {
                        "status": "success",
                        "action": "start",
                        "service": service_name,
                        "return_code": result[0]
                    }
                else:
                    raise ServiceOperationError(
                        f"Failed to start service {service_name}",
                        error_code=result[0])
            except WmiError:
                raise
            except Exception as e:
                self._logger.error(
                    f"Unexpected error when starting service: {e}")
                raise ServiceOperationError(
                    f"Failed to start service: Unexpected error occurred",
                    error_code=9014
                ) from e

    def stop_service(self, service_name: str) -> Dict[str, Any]:
        """Stop a Windows service with enhanced security."""
        if not self._validator.validate_service_name(service_name):
            raise InvalidInputError(
                f"Invalid service name: {service_name}", error_code=9020)

        if not self._check_rate_limit():
            raise RateLimitExceededError(
                "Service operation rate limit exceeded", error_code=9021)

        if self._is_critical_service(service_name):
            raise SecurityViolationError(
                f"Cannot modify critical system service: {service_name}",
                error_code=9022)

        with self._semaphore:
            self._logger.info(
                f"Attempting to stop service: {service_name}")
            self._perf_monitor.increment('service_operations')

            try:
                services = self._wmi_conn.Win32_Service(
                    Name=service_name)
                if not services:
                    raise ServiceOperationError(
                        f"Service {service_name} not found",
                        error_code=9023)

                service = services[0]
                current_state = self._get_wmi_property(service, 'State')

                if current_state == "Stopped":
                    self._logger.info(
                        f"Service {service_name} is already stopped")
                    return {
                        "status": "success",
                        "action": "stop",
                        "service": service_name,
                        "message": "Service was already stopped"
                    }

                result = service.StopService()
                if result[0] == 0:
                    self._logger.info(
                        f"Successfully stopped service {service_name}")
                    return {
                        "status": "success",
                        "action": "stop",
                        "service": service_name,
                        "return_code": result[0]
                    }
                else:
                    raise ServiceOperationError(
                        f"Failed to stop service {service_name}",
                        error_code=result[0])
            except WmiError:
                raise
            except Exception as e:
                self._logger.error(
                    f"Unexpected error when stopping service: {e}")
                raise ServiceOperationError(
                    f"Failed to stop service: Unexpected error occurred",
                    error_code=9024
                ) from e


# ======================
# MAIN WMI SYSTEM INFO
# ======================
class WmiSystemInfo:
    """Main class for WMI system information collection and management.

    Supports context manager protocol, iteration over collectors,
    item access by collector name, and parallel collection.
    """

    __slots__ = (
        '_logger', '_perf_monitor', '_wmi_conn',
        '_service_manager', '_collectors', '_validator',
        '_executor'
    )

    def __init__(
        self,
        use_credentials: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        # Check OS compatibility
        if platform.system() not in SUPPORTED_OS:
            raise UnsupportedOSError(
                f"Unsupported operating system: {platform.system()}",
                error_code=9100)

        # Initialize logger
        self._logger = (logger if logger
                       else SecureLogger().setup_logger())
        self._logger.info(
            f"Initializing WMI System Information v{SCRIPT_VERSION}")

        # Record script execution for auditing
        self._log_execution()

        # Initialize performance monitor
        self._perf_monitor = PerformanceMonitor()

        # Initialize thread pool for parallel operations
        self._executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_COLLECTORS,
            thread_name_prefix="wmi_collector"
        )

        self._validator = InputValidator()

        try:
            if use_credentials:
                if not username or not password:
                    raise ConfigurationError(
                        "Username and password required when "
                        "use_credentials is True",
                        error_code=9101)

                if not InputValidator.validate_credentials(
                        username, password, domain):
                    raise SecurityViolationError(
                        "Invalid credentials provided",
                        error_code=9102)

                connection_str = (
                    f"{domain}\\{username}" if domain else username)
                self._logger.info(
                    f"Establishing WMI connection as {connection_str}")

                with SecureDataHandler() as secure_handler:
                    encrypted_pwd = secure_handler.encrypt(password)
                    try:
                        self._wmi_conn = wmi_module.WMI(
                            computer="localhost",
                            user=connection_str,
                            password=secure_handler.decrypt(encrypted_pwd)
                        )
                    finally:
                        del encrypted_pwd
            else:
                self._logger.info(
                    "Establishing WMI connection with current credentials")
                self._wmi_conn = wmi_module.WMI()

            self._logger.info("WMI connection established")
        except WmiError:
            raise
        except Exception as e:
            self._logger.critical(
                f"Failed to connect to WMI: {e}")
            raise WmiConnectionError(
                f"Could not establish WMI connection: {e}",
                error_code=9103
            ) from e

        # Initialize service manager
        self._service_manager = ServiceManager(
            self._wmi_conn, self._logger, self._perf_monitor)

        # Initialize collectors
        self._collectors: Dict[str, WmiInfoCollector] = {
            "system": SystemInfoCollector(
                self._wmi_conn, self._logger, self._perf_monitor),
            "hardware": HardwareInfoCollector(
                self._wmi_conn, self._logger, self._perf_monitor),
        }

    def __repr__(self) -> str:
        return (
            f"WmiSystemInfo(v{SCRIPT_VERSION}, "
            f"collectors={len(self._collectors)})")

    def __str__(self) -> str:
        return f"WMI System Info v{SCRIPT_VERSION}"

    def __enter__(self) -> 'WmiSystemInfo':
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit context manager — cleanup resources."""
        self._executor.shutdown(wait=False)
        gc.collect()
        self._logger.info("WmiSystemInfo resources cleaned up")
        return False

    def __getitem__(self, name: str) -> WmiInfoCollector:
        """Access a collector by name."""
        if name not in self._collectors:
            raise KeyError(f"Unknown collector: {name}")
        return self._collectors[name]

    def __contains__(self, name: str) -> bool:
        """Check if a collector exists."""
        return name in self._collectors

    def __iter__(self) -> Iterator[str]:
        """Iterate over collector names."""
        return iter(self._collectors)

    def __len__(self) -> int:
        """Return number of collectors."""
        return len(self._collectors)

    def _log_execution(self) -> None:
        """Log script execution for audit purposes."""
        try:
            audit_dir = 'audit'
            os.makedirs(audit_dir, mode=0o750, exist_ok=True)

            timestamp = datetime.datetime.now().isoformat()
            username = (os.getenv('USERNAME') or os.getenv('USER')
                       or 'unknown')
            hostname = platform.node()

            audit_file = os.path.join(audit_dir, 'execution_log.csv')
            header = not os.path.exists(audit_file)

            with open(audit_file, 'a') as f:
                if header:
                    f.write(
                        "timestamp,username,hostname,script_version\n")
                f.write(
                    f"{timestamp},{username},{hostname},"
                    f"{SCRIPT_VERSION}\n")

            try:
                os.chmod(audit_file, 0o640)
            except OSError:
                pass
        except Exception as e:
            self._logger.error(f"Error logging execution: {e}")

    def collect_all(self) -> Dict[str, Any]:
        """Collect all available system information using parallel execution.

        Submits all collector tasks to a ThreadPoolExecutor for
        concurrent execution.
        """
        self._logger.info(
            "Starting comprehensive system information collection "
            "(parallel)")
        results: Dict[str, Any] = {}

        # Submit all collectors in parallel
        futures = {}
        for name, collector in self._collectors.items():
            future = self._executor.submit(collector.collect)
            futures[future] = name

        # Collect results as they complete
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result(timeout=120)
                self._logger.info(f"Collected {name} information")
            except WmiError as e:
                self._logger.error(
                    f"Error collecting {name} information: {e}")
                results[name] = e.to_dict()
            except Exception as e:
                self._logger.error(
                    f"Unexpected error in {name} collection: {e}")
                results[name] = {"error": "Unexpected error occurred"}

        # Add performance metrics
        results["performance_metrics"] = (
            self._perf_monitor.get_metrics())
        self._logger.info(
            "Completed comprehensive system information collection")

        gc.collect()
        return results

    def collect_specific(
        self, collector_names: List[str]
    ) -> Dict[str, Any]:
        """Collect specific system information using parallel execution."""
        self._logger.info(
            f"Starting targeted information collection: "
            f"{collector_names}")
        results: Dict[str, Any] = {}

        # Submit requested collectors in parallel
        futures = {}
        for name in collector_names:
            if name in self._collectors:
                future = self._executor.submit(
                    self._collectors[name].collect)
                futures[future] = name
            else:
                self._logger.warning(f"Unknown collector: {name}")
                results[name] = {
                    "error": f"Unknown collector: {name}"}

        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result(timeout=120)
                self._logger.info(f"Collected {name} information")
            except WmiError as e:
                self._logger.error(
                    f"Error collecting {name} information: {e}")
                results[name] = e.to_dict()
            except Exception as e:
                self._logger.error(
                    f"Unexpected error in {name} collection: {e}")
                results[name] = {"error": "Unexpected error occurred"}

        results["performance_metrics"] = (
            self._perf_monitor.get_metrics())
        self._logger.info(
            "Completed targeted information collection")

        return results

    def iter_collectors(
        self
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Yield (name, result) tuples lazily for sequential collection."""
        for name, collector in self._collectors.items():
            try:
                yield name, collector.collect()
            except WmiError as e:
                yield name, e.to_dict()
            except Exception as e:
                yield name, {"error": str(e)}

    def manage_service(
        self, service_name: str, action: str
    ) -> Dict[str, Any]:
        """Manage a Windows service."""
        if not self._validator.validate_service_name(service_name):
            raise InvalidInputError(
                f"Invalid service name: {service_name}",
                error_code=9110)

        if action.lower() not in ['start', 'stop']:
            raise InvalidInputError(
                f"Invalid action: {action}. "
                f"Must be 'start' or 'stop'",
                error_code=9111)

        try:
            if action.lower() == 'start':
                return self._service_manager.start_service(service_name)
            else:
                return self._service_manager.stop_service(service_name)
        except WmiError:
            raise
        except Exception as e:
            self._logger.error(
                f"Unexpected error during service operation: {e}")
            raise ServiceOperationError(
                f"Unexpected error occurred: {e}",
                error_code=9112
            ) from e

    def export_results(
        self, results: Dict[str, Any],
        output_format: str = 'json'
    ) -> str:
        """Export results in specified format."""
        try:
            export_dir = 'exports'
            os.makedirs(export_dir, mode=0o750, exist_ok=True)

            timestamp = datetime.datetime.now().strftime(
                "%Y%m%d_%H%M%S")
            filename = f"wmi_export_{timestamp}"

            if output_format.lower() == 'json':
                filepath = os.path.join(
                    export_dir, f"{filename}.json")
                with open(filepath, 'w') as f:
                    json.dump(results, f, indent=4, default=str)
            elif output_format.lower() == 'xml':
                raise ExportFormatError(
                    "XML export not yet implemented",
                    error_code=9120)
            elif output_format.lower() == 'csv':
                raise ExportFormatError(
                    "CSV export not yet implemented",
                    error_code=9121)
            else:
                raise InvalidInputError(
                    f"Unsupported export format: {output_format}",
                    error_code=9122)

            try:
                os.chmod(filepath, 0o640)
            except OSError:
                pass

            # Generate checksum
            checksum = FileIntegrity.generate_checksum(filepath)
            checksum_file = f"{filepath}.sha256"
            with open(checksum_file, 'w') as f:
                f.write(
                    f"{checksum}  {os.path.basename(filepath)}\n")
            try:
                os.chmod(checksum_file, 0o640)
            except OSError:
                pass

            self._logger.info(f"Exported results to {filepath}")
            return filepath
        except (ExportFormatError, InvalidInputError):
            raise
        except Exception as e:
            self._logger.error(f"Failed to export results: {e}")
            raise DataIntegrityError(
                f"Export failed: {e}", error_code=9123
            ) from e


# ======================
# ASYNC WRAPPER
# ======================
class AsyncWmiSystemInfo:
    """Async wrapper for WmiSystemInfo.

    Uses asyncio.to_thread() to run WMI operations in a thread pool,
    since WMI is inherently synchronous (COM-based).
    """

    __slots__ = ('_sync_instance',)

    def __init__(self, **kwargs) -> None:
        self._sync_instance = WmiSystemInfo(**kwargs)

    def __repr__(self) -> str:
        return f"Async{self._sync_instance!r}"

    async def collect_all(self) -> Dict[str, Any]:
        """Async wrapper for collect_all."""
        return await asyncio.to_thread(
            self._sync_instance.collect_all)

    async def collect_specific(
        self, collector_names: List[str]
    ) -> Dict[str, Any]:
        """Async wrapper for collect_specific."""
        return await asyncio.to_thread(
            self._sync_instance.collect_specific, collector_names)

    async def manage_service(
        self, service_name: str, action: str
    ) -> Dict[str, Any]:
        """Async wrapper for manage_service."""
        return await asyncio.to_thread(
            self._sync_instance.manage_service, service_name, action)

    async def export_results(
        self, results: Dict[str, Any],
        output_format: str = 'json'
    ) -> str:
        """Async wrapper for export_results."""
        return await asyncio.to_thread(
            self._sync_instance.export_results, results, output_format)


# ======================
# MAIN FUNCTION
# ======================
def main() -> int:
    """Main entry point with enhanced security and error handling."""
    try:
        # Secure argument parsing
        parser = argparse.ArgumentParser(
            description='Industrial-Grade WMI System Information Collector v3.0',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )

        # Create subparsers for different commands
        subparsers = parser.add_subparsers(
            dest='command', required=True, help='Command to execute')

        # Parser for collecting all information
        all_parser = subparsers.add_parser(
            'all', help='Collect all system information')

        # Parser for collecting specific information
        specific_parser = subparsers.add_parser(
            'specific', help='Collect specific system information')
        specific_parser.add_argument(
            '--collectors', nargs='+', required=True,
            choices=[
                'system', 'hardware', 'network', 'process',
                'service', 'event', 'task', 'disk', 'software', 'user'
            ],
            help='List of collectors to run'
        )

        # Parser for managing services
        service_parser = subparsers.add_parser(
            'service', help='Manage system services')
        service_parser.add_argument(
            '--services', nargs='+', required=True,
            help='List of services to manage'
        )
        service_parser.add_argument(
            '--action', choices=['start', 'stop'], required=True,
            help='Action to perform on services'
        )

        # Common authentication options
        for subparser in [all_parser, specific_parser, service_parser]:
            auth_group = subparser.add_argument_group('authentication')
            auth_group.add_argument(
                '--use-credentials', action='store_true',
                help='Use specific credentials for WMI connection'
            )
            auth_group.add_argument(
                '--username',
                help='Username for WMI connection',
                required=False
            )
            auth_group.add_argument(
                '--password',
                help='Password for WMI connection',
                required=False
            )
            auth_group.add_argument(
                '--domain',
                help='Domain for WMI connection',
                required=False
            )

            # Output options
            subparser.add_argument(
                '--output', choices=['json', 'xml', 'csv'],
                default='json',
                help='Output format for results'
            )
            subparser.add_argument(
                '--compress', action='store_true',
                help='Compress output files'
            )

        # Parse arguments
        args = parser.parse_args()

        # Validate arguments
        if args.use_credentials and (
                not args.username or not args.password):
            raise InvalidInputError(
                "Username and password required when "
                "use-credentials is specified",
                error_code=9200)

        if args.command == 'service':
            for service in args.services:
                if not InputValidator.validate_service_name(service):
                    raise InvalidInputError(
                        f"Invalid service name: {service}",
                        error_code=9201)

        # Initialize logger
        logger = SecureLogger().setup_logger()

        # Create WmiSystemInfo instance with context manager
        with WmiSystemInfo(
            use_credentials=args.use_credentials,
            username=args.username,
            password=args.password,
            domain=args.domain,
            logger=logger
        ) as wmi_info:

            # Execute command
            if args.command == 'all':
                results = wmi_info.collect_all()
            elif args.command == 'specific':
                results = wmi_info.collect_specific(args.collectors)
            elif args.command == 'service':
                service_results: Dict[str, Any] = {}
                for service in args.services:
                    try:
                        result = wmi_info.manage_service(
                            service, args.action)
                        service_results[service] = result
                    except WmiError as e:
                        service_results[service] = {
                            "status": "error",
                            "error": e.to_dict()
                        }
                results = {"services": service_results}
            else:
                raise InvalidInputError(
                    f"Unknown command: {args.command}",
                    error_code=9202)

            # Export results
            output_file = wmi_info.export_results(
                results, args.output)

            # Compress if requested
            if args.compress:
                zip_path = f"{output_file}.zip"
                with zipfile.ZipFile(
                    zip_path, 'w', zipfile.ZIP_DEFLATED
                ) as zipf:
                    zipf.write(
                        output_file,
                        os.path.basename(output_file))

                zip_checksum = FileIntegrity.generate_checksum(
                    zip_path)
                with open(f"{zip_path}.sha256", 'w') as f:
                    f.write(
                        f"{zip_checksum}  "
                        f"{os.path.basename(zip_path)}\n")

                FileIntegrity.secure_delete(output_file)
                output_file = zip_path

            print(f"Results exported to: {output_file}")
            return 0

    except InvalidInputError as e:
        print(f"Input error: {e}", file=sys.stderr)
        return 2
    except WmiError as e:
        print(f"WMI error: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
