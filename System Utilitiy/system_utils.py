#!/usr/bin/env python3
"""
System Utilities Library v2.0
------------------------------
A comprehensive toolkit for system operations including:
- Screen management with cross-platform support
- Process execution with async support
- Data synchronization with parallel processing
- Disk geometry-based storage calculations
- Log analysis with generator-based streaming and parallel search

v2.0 Features:
- Generator/yield patterns for memory-efficient log processing
- Parallel programming via concurrent.futures
- Async subprocess execution via asyncio
- Rich dunder methods (__repr__, __str__, __call__, __iter__, __enter__, etc.)
- Custom exception hierarchy with error codes, timestamps, serialization
- Memory optimization with __slots__ and streaming I/O
"""

import asyncio
import mmap
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import total_ordering
from pathlib import Path
from datetime import datetime
from typing import (
    List, Dict, Tuple, Optional, Union, Any, Generator, Iterator
)


# ======================
# CUSTOM EXCEPTIONS
# ======================
class SystemUtilsError(Exception):
    """Base exception for all system utility errors.

    Attributes:
        message: Human-readable error description.
        error_code: Optional numeric error code for programmatic handling.
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
        self.timestamp = datetime.now().isoformat()
        self.context = context or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        base = f"[{self.timestamp}] {self.message}"
        if self.error_code is not None:
            base = f"[E{self.error_code}] {base}"
        return base

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"error_code={self.error_code!r}, "
            f"timestamp={self.timestamp!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SystemUtilsError):
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


class ProcessExecutionError(SystemUtilsError):
    """Exception for process execution failures."""
    def __init__(self, message: str, error_code: Optional[int] = None,
                 command: str = "") -> None:
        super().__init__(
            message, error_code=error_code,
            context={'command': command}
        )


class LogFileException(SystemUtilsError):
    """Exception for log file operations."""
    def __init__(self, message: str, error_code: Optional[int] = None,
                 file_path: str = "") -> None:
        super().__init__(
            message, error_code=error_code,
            context={'file_path': file_path}
        )


class InvalidInputError(SystemUtilsError):
    """Exception for invalid user input."""
    def __init__(self, message: str, error_code: Optional[int] = None,
                 field: str = "") -> None:
        super().__init__(
            message, error_code=error_code,
            context={'field': field}
        )


class DiskCalculationError(SystemUtilsError):
    """Exception for disk storage calculations."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class FileOperationError(SystemUtilsError):
    """Exception for file system operations."""
    def __init__(self, message: str, error_code: Optional[int] = None,
                 path: str = "") -> None:
        super().__init__(
            message, error_code=error_code,
            context={'path': path}
        )


class SyncTimeoutError(SystemUtilsError):
    """Exception for data synchronization timeouts."""
    def __init__(self, message: str, error_code: Optional[int] = None,
                 timeout_seconds: Optional[int] = None) -> None:
        super().__init__(
            message, error_code=error_code,
            context={'timeout_seconds': timeout_seconds}
        )


# ======================
# SCREEN MANAGEMENT
# ======================
class ScreenManager:
    """Handles screen operations with cross-platform support."""

    __slots__ = ('_clear_command',)

    def __init__(self) -> None:
        self._clear_command: str = 'cls' if os.name == 'nt' else 'clear'

    def __repr__(self) -> str:
        return f"ScreenManager(command={self._clear_command!r})"

    def __str__(self) -> str:
        return f"ScreenManager(platform={'Windows' if os.name == 'nt' else 'Unix'})"

    def clear_screen(self) -> None:
        """Clear the terminal screen with error handling."""
        try:
            os.system(self._clear_command)
        except OSError as e:
            raise SystemUtilsError(
                f"Error clearing the screen: {e}", error_code=3001
            ) from e


# ======================
# PROCESS EXECUTION
# ======================
class ProcessExecutor:
    """Handles execution of system processes and scripts.

    Supports both synchronous and async execution patterns.
    Callable via __call__ for convenient direct execution.
    """

    __slots__ = ('_last_result',)

    def __init__(self) -> None:
        self._last_result: Optional[Tuple[str, str, int]] = None

    def __repr__(self) -> str:
        rc = self._last_result[2] if self._last_result else None
        return f"ProcessExecutor(last_return_code={rc})"

    def __call__(
        self,
        command: Union[str, List[str]],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[str, str, int]:
        """Execute a command directly by calling the executor instance."""
        return self.run_command(command, input_data, timeout)

    def run_command(
        self,
        command: Union[str, List[str]],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[str, str, int]:
        """Execute a system command with robust error handling.

        Args:
            command: Command to execute (string or list of args)
            input_data: Input to pass to the process (optional)
            timeout: Timeout in seconds (optional)

        Returns:
            Tuple of (stdout, stderr, return_code)

        Raises:
            ProcessExecutionError: If command execution fails
        """
        process = None
        try:
            if isinstance(command, str):
                command = command.split()

            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )

            stdout, stderr = process.communicate(
                input=input_data,
                timeout=timeout
            )

            self._last_result = (stdout, stderr, process.returncode)
            return self._last_result

        except subprocess.TimeoutExpired:
            if process is not None:
                process.kill()
                process.communicate()
            raise ProcessExecutionError(
                f"Command timed out after {timeout} seconds",
                error_code=4001,
                command=str(command)
            )
        except FileNotFoundError:
            raise ProcessExecutionError(
                f"Command not found: {command[0]}",
                error_code=4002,
                command=str(command)
            )
        except PermissionError:
            raise ProcessExecutionError(
                f"Permission denied executing: {command[0]}",
                error_code=4003,
                command=str(command)
            )
        except OSError as e:
            raise ProcessExecutionError(
                f"OS error executing command: {e}",
                error_code=4004,
                command=str(command)
            ) from e

    def close(self) -> None:
        """Explicit resource cleanup."""
        self._last_result = None


class AsyncProcessExecutor:
    """Async process executor using asyncio.create_subprocess_exec.

    Provides non-blocking command execution for I/O-bound operations.
    """

    __slots__ = ('_last_result',)

    def __init__(self) -> None:
        self._last_result: Optional[Tuple[str, str, int]] = None

    def __repr__(self) -> str:
        rc = self._last_result[2] if self._last_result else None
        return f"AsyncProcessExecutor(last_return_code={rc})"

    async def run_command(
        self,
        command: Union[str, List[str]],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[str, str, int]:
        """Execute a command asynchronously.

        Args:
            command: Command to execute (string or list of args)
            input_data: Input to pass to the process (optional)
            timeout: Timeout in seconds (optional)

        Returns:
            Tuple of (stdout, stderr, return_code)

        Raises:
            ProcessExecutionError: If command execution fails
        """
        try:
            if isinstance(command, str):
                command = command.split()

            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if timeout is not None:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(
                        input=input_data.encode() if input_data else None
                    ),
                    timeout=timeout,
                )
            else:
                stdout_bytes, stderr_bytes = await process.communicate(
                    input=input_data.encode() if input_data else None
                )

            stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ''
            stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ''
            returncode = process.returncode if process.returncode is not None else -1

            self._last_result = (stdout, stderr, returncode)
            return self._last_result

        except asyncio.TimeoutError:
            if process is not None:
                process.kill()
                await process.communicate()
            raise ProcessExecutionError(
                f"Async command timed out after {timeout} seconds",
                error_code=4010,
                command=str(command)
            )
        except FileNotFoundError:
            raise ProcessExecutionError(
                f"Command not found: {command[0]}",
                error_code=4011,
                command=str(command)
            )
        except PermissionError:
            raise ProcessExecutionError(
                f"Permission denied executing: {command[0]}",
                error_code=4012,
                command=str(command)
            )
        except OSError as e:
            raise ProcessExecutionError(
                f"OS error in async command: {e}",
                error_code=4013,
                command=str(command)
            ) from e


class BashScriptRunner:
    """Specialized executor for Bash scripts.

    Supports direct callable invocation and boolean truthiness check.
    """

    __slots__ = ('_script_path', '_executor')

    def __init__(self, script_path: str) -> None:
        self._script_path = Path(script_path)
        if not self._script_path.exists():
            raise FileNotFoundError(f"Script not found: {script_path}")
        self._executor = ProcessExecutor()

    def __repr__(self) -> str:
        return f"BashScriptRunner(script={self._script_path.name!r})"

    def __str__(self) -> str:
        return f"BashScript({self._script_path})"

    def __bool__(self) -> bool:
        """Return True if the script file exists and is readable."""
        return self._script_path.exists() and self._script_path.is_file()

    def __call__(
        self,
        input_data: Optional[str] = None,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[str, str, int]:
        """Execute the script directly by calling the runner instance."""
        return self.run_script(input_data, args, timeout)

    def run_script(
        self,
        input_data: Optional[str] = None,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[str, str, int]:
        """Execute a Bash script with input and arguments.

        Args:
            input_data: Input to pass to the script (optional)
            args: List of arguments for the script (optional)
            timeout: Timeout in seconds (optional)

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        command: List[str] = ['bash', str(self._script_path)]
        if args:
            command.extend(args)

        return self._executor.run_command(command, input_data, timeout)


# ======================
# DATA SYNCHRONIZATION
# ======================
class DataSyncManager:
    """Manages data synchronization operations.

    Supports context manager protocol and parallel file sync.
    """

    __slots__ = ('_source_dir', '_dest_dir', '_validated')

    def __init__(self, source_dir: str, dest_dir: str) -> None:
        self._source_dir = Path(source_dir)
        self._dest_dir = Path(dest_dir)
        self._validated = False
        self._validate_dirs()

    def __repr__(self) -> str:
        return (
            f"DataSyncManager("
            f"source={self._source_dir.name!r}, "
            f"dest={self._dest_dir.name!r})"
        )

    def __str__(self) -> str:
        return f"Sync({self._source_dir} → {self._dest_dir})"

    def __enter__(self) -> 'DataSyncManager':
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit context manager — no special cleanup needed."""
        return False

    def _validate_dirs(self) -> None:
        """Validate source and destination directories."""
        if not self._source_dir.exists():
            raise FileNotFoundError(
                f"Source directory not found: {self._source_dir}")
        if not self._source_dir.is_dir():
            raise NotADirectoryError(
                f"Source is not a directory: {self._source_dir}")

        try:
            self._dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise FileOperationError(
                f"Could not create destination directory: {e}",
                error_code=5001,
                path=str(self._dest_dir)
            ) from e
        self._validated = True

    def sync_data(
        self, parallel: bool = True, max_workers: Optional[int] = None
    ) -> None:
        """Synchronize data using rsync.

        Args:
            parallel: Whether to use parallel processing (default: True)
            max_workers: Max parallel workers (default: CPU count)

        Raises:
            ProcessExecutionError: If synchronization fails
        """
        try:
            if parallel:
                workers = max_workers or min(os.cpu_count() or 1, 4)
                with ProcessPoolExecutor(max_workers=workers) as pool:
                    future = pool.submit(self._execute_rsync)
                    future.result(timeout=300)
            else:
                self._execute_rsync()
        except SyncTimeoutError:
            raise
        except Exception as e:
            raise ProcessExecutionError(
                f"Data synchronization failed: {e}",
                error_code=5002
            ) from e

    def _execute_rsync(self) -> None:
        """Execute the rsync command."""
        try:
            result = subprocess.run(
                ["rsync", "-arq",
                 str(self._source_dir) + "/",
                 str(self._dest_dir)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            if result.returncode != 0:
                raise ProcessExecutionError(
                    f"rsync failed: {result.stderr}",
                    error_code=5003
                )
        except subprocess.TimeoutExpired:
            raise SyncTimeoutError(
                "rsync operation timed out",
                error_code=5004,
                timeout_seconds=300
            )
        except subprocess.CalledProcessError as e:
            raise ProcessExecutionError(
                f"rsync process failed: {e.stderr}",
                error_code=5005
            ) from e
        except FileNotFoundError:
            raise ProcessExecutionError(
                "rsync command not found. Please install rsync.",
                error_code=5006
            )


# ======================
# DISK STORAGE CALCULATOR
# ======================
@total_ordering
class DiskStorageCalculator:
    """Calculates disk storage based on disk geometry.

    Supports comparison operators, numeric conversion, and scaling.
    """

    __slots__ = ('_input_labels', '_input_values', '_total_bytes')

    def __init__(self, input_labels: List[str]) -> None:
        self._input_labels = input_labels
        self._input_values: List[int] = []
        self._total_bytes: int = 0

    def __repr__(self) -> str:
        return (
            f"DiskStorageCalculator("
            f"labels={self._input_labels!r}, "
            f"bytes={self._total_bytes})"
        )

    def __str__(self) -> str:
        gb = self._total_bytes / (1024 ** 3) if self._total_bytes else 0
        return f"DiskStorage({gb:.2f} GB)"

    def __int__(self) -> int:
        """Return total storage in bytes."""
        return self._total_bytes

    def __float__(self) -> float:
        """Return total storage in gigabytes."""
        return self._total_bytes / (1024 ** 3)

    def __mul__(self, factor: Union[int, float]) -> 'DiskStorageCalculator':
        """Scale storage by a factor and return a new calculator."""
        new = DiskStorageCalculator(self._input_labels[:])
        new._input_values = self._input_values[:]
        new._total_bytes = int(self._total_bytes * factor)
        return new

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DiskStorageCalculator):
            return self._total_bytes == other._total_bytes
        if isinstance(other, (int, float)):
            return self._total_bytes == int(other)
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, DiskStorageCalculator):
            return self._total_bytes < other._total_bytes
        if isinstance(other, (int, float)):
            return self._total_bytes < int(other)
        return NotImplemented

    @staticmethod
    def _validate_input(value: str) -> int:
        """Validate and convert input to positive integer."""
        try:
            num = int(value)
            if num <= 0:
                raise InvalidInputError(
                    "Value must be positive",
                    error_code=6001,
                    field='disk_parameter'
                )
            return num
        except ValueError:
            raise InvalidInputError(
                "Please enter a valid integer",
                error_code=6002,
                field='disk_parameter'
            )

    def _get_user_input(self) -> None:
        """Get and validate user input for disk parameters."""
        self._input_values = []
        for label in self._input_labels:
            while True:
                try:
                    value = input(f'No. of {label}: ')
                    validated = self._validate_input(value)
                    self._input_values.append(validated)
                    break
                except InvalidInputError as e:
                    print(f"Invalid input: {e.message}")
                except KeyboardInterrupt:
                    print("\nOperation cancelled by user.")
                    sys.exit(1)

    def calculate_storage_bytes(self) -> int:
        """Calculate total storage in bytes.

        Returns:
            Total storage in bytes

        Raises:
            DiskCalculationError: If calculation fails
        """
        try:
            self._get_user_input()
            if not self._input_values:
                raise DiskCalculationError(
                    "No input values provided", error_code=6003
                )

            total = 1
            for value in self._input_values:
                total *= value
            self._total_bytes = total
            return total
        except DiskCalculationError:
            raise
        except InvalidInputError:
            raise
        except Exception as e:
            raise DiskCalculationError(
                f"Storage calculation failed: {e}", error_code=6004
            ) from e

    def calculate_storage_gb(self) -> float:
        """Calculate total storage in gigabytes.

        Returns:
            Total storage in GB
        """
        bytes_total = self.calculate_storage_bytes()
        return bytes_total / (1024 ** 3)

    def preview_storage(self) -> None:
        """Display the calculated storage in gigabytes."""
        try:
            total_gb = self.calculate_storage_gb()
            print(f'Total Size of the Disk: {total_gb:.2f} GB')
        except (DiskCalculationError, InvalidInputError) as e:
            print(f"Error: {e.message}")

    def yield_conversions(self) -> Generator[Tuple[str, float], None, None]:
        """Yield storage conversions lazily across all units.

        Yields:
            Tuples of (unit_name, value) for Bytes, KB, MB, GB, TB.
        """
        b = float(self._total_bytes)
        yield ('Bytes', b)
        yield ('KB', b / 1024)
        yield ('MB', b / (1024 ** 2))
        yield ('GB', b / (1024 ** 3))
        yield ('TB', b / (1024 ** 4))


# ======================
# LOG ANALYZER
# ======================
class LogAnalyzer:
    """Analyzes log files with generator-based streaming,
    filtering, parallel search, and export capabilities.

    Supports iteration protocol and containment checks.
    """

    __slots__ = ('_log_file', '_line_count', '_buffer_size')

    LOG_LEVELS = frozenset({'ERROR', 'INFO', 'WARN', 'DEBUG', 'CRITICAL'})

    # Threshold for switching to mmap-based search (10 MB)
    _MMAP_THRESHOLD = 10 * 1024 * 1024

    def __init__(
        self,
        log_file: Union[str, Path],
        buffer_size: int = 8192,
    ) -> None:
        self._log_file = Path(log_file)
        self._buffer_size = buffer_size
        self._line_count: Optional[int] = None
        self._validate_log_file()

    def __repr__(self) -> str:
        return (
            f"LogAnalyzer("
            f"file={self._log_file.name!r}, "
            f"lines={self._line_count})"
        )

    def __str__(self) -> str:
        return f"LogAnalyzer({self._log_file})"

    def __len__(self) -> int:
        """Return total line count of the log file."""
        if self._line_count is None:
            self._line_count = sum(1 for _ in self._iter_lines())
        return self._line_count

    def __iter__(self) -> Generator[str, None, None]:
        """Iterate over all lines in the log file lazily."""
        yield from self._iter_lines()

    def __contains__(self, pattern: str) -> bool:
        """Check if a pattern exists anywhere in the log file.

        Uses mmap for large files for zero-copy scanning.
        """
        file_size = self._log_file.stat().st_size
        pattern_bytes = pattern.encode('utf-8')

        if file_size > self._MMAP_THRESHOLD:
            return self._mmap_contains(pattern_bytes)

        try:
            with open(self._log_file, 'rb') as f:
                for chunk in iter(lambda: f.read(self._buffer_size), b''):
                    if pattern_bytes in chunk:
                        return True
            return False
        except OSError as e:
            raise LogFileException(
                f"Error checking pattern in file: {e}",
                error_code=7001,
                file_path=str(self._log_file)
            ) from e

    def _mmap_contains(self, pattern_bytes: bytes) -> bool:
        """Check pattern existence using memory-mapped file I/O."""
        try:
            with open(self._log_file, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    return mm.find(pattern_bytes) != -1
        except (OSError, ValueError) as e:
            raise LogFileException(
                f"mmap error checking pattern: {e}",
                error_code=7002,
                file_path=str(self._log_file)
            ) from e

    def _validate_log_file(self) -> None:
        """Validate the log file exists and is accessible."""
        if not self._log_file.exists():
            raise LogFileException(
                f"Log file not found: {self._log_file}",
                error_code=7010,
                file_path=str(self._log_file)
            )
        if not self._log_file.is_file():
            raise LogFileException(
                f"Path is not a file: {self._log_file}",
                error_code=7011,
                file_path=str(self._log_file)
            )
        try:
            with open(self._log_file, 'r'):
                pass
        except PermissionError:
            raise LogFileException(
                f"Permission denied accessing: {self._log_file}",
                error_code=7012,
                file_path=str(self._log_file)
            )
        except OSError as e:
            raise LogFileException(
                f"Error accessing log file: {e}",
                error_code=7013,
                file_path=str(self._log_file)
            ) from e

    def _iter_lines(self) -> Generator[str, None, None]:
        """Yield lines from the log file lazily with configurable buffer."""
        try:
            with open(self._log_file, 'r', encoding='utf-8',
                       buffering=self._buffer_size) as f:
                yield from f
        except OSError as e:
            raise LogFileException(
                f"Error reading log file: {e}",
                error_code=7020,
                file_path=str(self._log_file)
            ) from e

    @staticmethod
    def _sanitize_input(input_str: str) -> str:
        """Sanitize user input by stripping whitespace and converting to uppercase."""
        return input_str.strip().upper()

    def search_logs(
        self,
        log_level: str,
        search_text: Optional[str] = None,
    ) -> Generator[str, None, None]:
        """Search logs for specific level and optional text.

        Yields matching log entries lazily — memory efficient for
        multi-gigabyte log files.

        Args:
            log_level: Log level to filter (ERROR, INFO, WARN, DEBUG, CRITICAL)
            search_text: Optional text to search within log entries

        Yields:
            Matching log entry strings

        Raises:
            InvalidInputError: If log level is invalid
            LogFileException: If log processing fails
        """
        sanitized_level = self._sanitize_input(log_level)
        if sanitized_level not in self.LOG_LEVELS:
            raise InvalidInputError(
                f"Invalid log level: {log_level}. "
                f"Must be one of {self.LOG_LEVELS}",
                error_code=7030,
                field='log_level'
            )

        try:
            pattern = re.compile(rf'{sanitized_level}', re.IGNORECASE)
            search_patterns: List[re.Pattern] = []
            if search_text:
                search_patterns = [
                    re.compile(re.escape(word), re.IGNORECASE)
                    for word in search_text.split()
                ]

            for line in self._iter_lines():
                if pattern.search(line):
                    if not search_patterns or all(
                        p.search(line) for p in search_patterns
                    ):
                        yield line
        except (InvalidInputError, LogFileException):
            raise
        except Exception as e:
            raise LogFileException(
                f"Error searching logs: {e}",
                error_code=7031,
                file_path=str(self._log_file)
            ) from e

    def search_logs_parallel(
        self,
        log_files: List[Union[str, Path]],
        log_level: str,
        search_text: Optional[str] = None,
        max_workers: int = 4,
    ) -> Generator[Tuple[str, List[str]], None, None]:
        """Search multiple log files in parallel.

        Args:
            log_files: List of log file paths to search
            log_level: Log level to filter
            search_text: Optional text to search within entries
            max_workers: Maximum parallel workers

        Yields:
            Tuples of (file_path, matching_entries)
        """
        def _search_single(file_path: Union[str, Path]) -> Tuple[str, List[str]]:
            analyzer = LogAnalyzer(file_path, buffer_size=self._buffer_size)
            matches = list(analyzer.search_logs(log_level, search_text))
            return str(file_path), matches

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_search_single, fp): fp
                for fp in log_files
            }
            for future in as_completed(futures):
                try:
                    yield future.result()
                except (LogFileException, InvalidInputError) as e:
                    yield str(futures[future]), []

    def stream_logs(
        self, poll_interval: float = 1.0
    ) -> Generator[str, None, None]:
        """Yield new log lines as they appear (tail -f behavior).

        This is a blocking generator that continuously monitors the
        log file for new content.

        Args:
            poll_interval: Seconds between file polls

        Yields:
            New log lines as they are written to the file
        """
        import time
        try:
            with open(self._log_file, 'r', encoding='utf-8') as f:
                # Seek to end of file
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        yield line
                    else:
                        time.sleep(poll_interval)
        except OSError as e:
            raise LogFileException(
                f"Error streaming log file: {e}",
                error_code=7040,
                file_path=str(self._log_file)
            ) from e

    def export_logs(
        self,
        log_entries: Union[List[str], Generator],
        output_file: Union[str, Path],
    ) -> int:
        """Export log entries to a file.

        Accepts both lists and generators for memory-efficient export.

        Args:
            log_entries: Iterable of log entries to export
            output_file: Path to output file

        Returns:
            Number of entries exported

        Raises:
            LogFileException: If export fails
        """
        output_path = Path(output_file)
        count = 0
        try:
            with open(output_path, 'w', encoding='utf-8') as file:
                for entry in log_entries:
                    file.write(entry)
                    count += 1
            return count
        except PermissionError:
            raise LogFileException(
                f"Permission denied writing to: {output_path}",
                error_code=7050,
                file_path=str(output_path)
            )
        except OSError as e:
            raise LogFileException(
                f"Error exporting logs: {e}",
                error_code=7051,
                file_path=str(output_path)
            ) from e


# ======================
# MAIN
# ======================
def main() -> None:
    """Demonstrate usage of the system utilities."""
    try:
        # Example usage of ScreenManager
        screen = ScreenManager()
        screen.clear_screen()

        # Example usage of DiskStorageCalculator
        print("\nDisk Storage Calculation Example:")
        disk_calc = DiskStorageCalculator(
            ['Cylinders', 'Heads', 'Sectors per Track', 'Bytes per Sector']
        )
        disk_calc.preview_storage()

        # Show conversions using generator
        print("\nStorage unit conversions:")
        for unit, value in disk_calc.yield_conversions():
            print(f"  {unit}: {value:,.2f}")

        # Demonstrate comparison operators
        print(f"\nDisk as int (bytes): {int(disk_calc)}")
        print(f"Disk as float (GB): {float(disk_calc):.2f}")

        # Demonstrate scaling
        doubled = disk_calc * 2
        print(f"Doubled: {doubled}")
        print(f"Original < Doubled: {disk_calc < doubled}")

    except SystemUtilsError as e:
        print(f"System error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
    sys.exit(0)
