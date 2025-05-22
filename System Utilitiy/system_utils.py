#!/usr/bin/env python3
"""
System Utilities Library - A comprehensive toolkit for system operations including:
- Screen management
- Process execution
- Data synchronization
- Disk calculations
- Log analysis
"""

import os
import sys
import re
import subprocess
import multiprocessing
from pathlib import Path
from multiprocessing import Pool
from typing import List, Dict, Tuple, Optional, Union

# Custom Exceptions
class SystemUtilsError(Exception):
    """Base exception for all system utility errors."""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class ProcessExecutionError(SystemUtilsError):
    """Exception for process execution failures."""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class LogFileException(SystemUtilsError):
    """Exception for log file operations."""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class InvalidInputError(SystemUtilsError):
    """Exception for invalid user input."""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class DiskCalculationError(SystemUtilsError):
    """Exception for disk storage calculations."""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class ScreenManager:
    """Handles screen operations with cross-platform support."""
    
    def __init__(self):
        self.clear_command = 'cls' if os.name == 'nt' else 'clear'
    
    def clear_screen(self) -> None:
        """Clear the terminal screen with error handling."""
        try:
            os.system(self.clear_command)
        except OSError as e:
            raise SystemUtilsError(f"Error clearing the screen: {e}")
        except Exception as e:
            raise SystemUtilsError(f"Unexpected error clearing screen: {e}")

class ProcessExecutor:
    """Handles execution of system processes and scripts."""
    
    @staticmethod
    def run_command(command: Union[str, List[str]], 
                   input_data: Optional[str] = None,
                   timeout: Optional[int] = None) -> Tuple[str, str, int]:
        """
        Execute a system command with robust error handling.
        
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
            
            return stdout, stderr, process.returncode
            
        except subprocess.TimeoutExpired:
            process.kill()
            raise ProcessExecutionError(f"Command timed out after {timeout} seconds")
        except FileNotFoundError:
            raise ProcessExecutionError(f"Command not found: {command[0]}")
        except PermissionError:
            raise ProcessExecutionError(f"Permission denied executing: {command[0]}")
        except Exception as e:
            raise ProcessExecutionError(f"Error executing command: {e}")

class BashScriptRunner(ProcessExecutor):
    """Specialized executor for Bash scripts."""
    
    def __init__(self, script_path: str):
        self.script_path = Path(script_path)
        if not self.script_path.exists():
            raise FileNotFoundError(f"Script not found: {script_path}")
    
    def run_script(self, 
                  input_data: Optional[str] = None,
                  args: Optional[List[str]] = None,
                  timeout: Optional[int] = None) -> Tuple[str, str, int]:
        """
        Execute a Bash script with input and arguments.
        
        Args:
            input_data: Input to pass to the script (optional)
            args: List of arguments for the script (optional)
            timeout: Timeout in seconds (optional)
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        command = ['bash', str(self.script_path)]
        if args:
            command.extend(args)
            
        return super().run_command(command, input_data, timeout)

class DataSyncManager:
    """Manages data synchronization operations."""
    
    def __init__(self, source_dir: str, dest_dir: str):
        self.source_dir = Path(source_dir)
        self.dest_dir = Path(dest_dir)
        self._validate_dirs()
    
    def _validate_dirs(self) -> None:
        """Validate source and destination directories."""
        if not self.source_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {self.source_dir}")
        if not self.source_dir.is_dir():
            raise NotADirectoryError(f"Source is not a directory: {self.source_dir}")
        
        try:
            self.dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise ProcessExecutionError(f"Could not create destination directory: {e}")
    
    def sync_data(self, parallel: bool = True) -> None:
        """
        Synchronize data using rsync.
        
        Args:
            parallel: Whether to use parallel processing (default: True)
            
        Raises:
            ProcessExecutionError: If synchronization fails
        """
        try:
            if parallel:
                with Pool(multiprocessing.cpu_count()) as pool:
                    pool.apply(self._execute_rsync)
            else:
                self._execute_rsync()
        except Exception as e:
            raise ProcessExecutionError(f"Data synchronization failed: {e}")
    
    def _execute_rsync(self) -> None:
        """Execute the rsync command."""
        try:
            result = subprocess.run(
                ["rsync", "-arq", str(self.source_dir) + "/", str(self.dest_dir)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode != 0:
                raise ProcessExecutionError(f"rsync failed: {result.stderr}")
        except subprocess.CalledProcessError as e:
            raise ProcessExecutionError(f"rsync process failed: {e.stderr}")
        except Exception as e:
            raise ProcessExecutionError(f"Error during rsync: {e}")

class DiskStorageCalculator:
    """Calculates disk storage based on disk geometry."""
    
    def __init__(self, input_labels: List[str]):
        self.input_labels = input_labels
        self.input_values: List[int] = []
    
    @staticmethod
    def _validate_input(value: str) -> int:
        """Validate and convert input to positive integer."""
        try:
            num = int(value)
            if num <= 0:
                raise InvalidInputError("Value must be positive")
            return num
        except ValueError:
            raise InvalidInputError("Please enter a valid integer")
    
    def _get_user_input(self) -> None:
        """Get and validate user input for disk parameters."""
        self.input_values = []
        for label in self.input_labels:
            while True:
                try:
                    value = input(f'No. of {label}: ')
                    validated = self._validate_input(value)
                    self.input_values.append(validated)
                    break
                except InvalidInputError as e:
                    print(f"Invalid input: {e}")
                except KeyboardInterrupt:
                    print("\nOperation cancelled by user.")
                    sys.exit(1)
    
    def calculate_storage_bytes(self) -> int:
        """
        Calculate total storage in bytes.
        
        Returns:
            Total storage in bytes
            
        Raises:
            DiskCalculationError: If calculation fails
        """
        try:
            self._get_user_input()
            if not self.input_values:
                raise DiskCalculationError("No input values provided")
            
            total = 1
            for value in self.input_values:
                total *= value
            return total
        except Exception as e:
            raise DiskCalculationError(f"Storage calculation failed: {e}")
    
    def calculate_storage_gb(self) -> float:
        """
        Calculate total storage in gigabytes.
        
        Returns:
            Total storage in GB
        """
        bytes_total = self.calculate_storage_bytes()
        return bytes_total / (1024 ** 3)  # Convert bytes to GB
    
    def preview_storage(self) -> None:
        """Display the calculated storage in gigabytes."""
        try:
            total_gb = self.calculate_storage_gb()
            print(f'Total Size of the Disk: {total_gb:.2f} GB')
        except DiskCalculationError as e:
            print(f"Error: {e}")

class LogAnalyzer:
    """Analyzes log files with filtering and export capabilities."""
    
    LOG_LEVELS = {'ERROR', 'INFO', 'WARN'}
    
    def __init__(self, log_file: Union[str, Path]):
        self.log_file = Path(log_file)
        self._validate_log_file()
    
    def _validate_log_file(self) -> None:
        """Validate the log file exists and is accessible."""
        if not self.log_file.exists():
            raise LogFileException(f"Log file not found: {self.log_file}")
        if not self.log_file.is_file():
            raise LogFileException(f"Path is not a file: {self.log_file}")
        try:
            with open(self.log_file, 'r'):
                pass
        except PermissionError:
            raise LogFileException(f"Permission denied accessing: {self.log_file}")
        except Exception as e:
            raise LogFileException(f"Error accessing log file: {e}")
    
    @staticmethod
    def _sanitize_input(input_str: str) -> str:
        """Sanitize user input by stripping whitespace and converting to uppercase."""
        return input_str.strip().upper()
    
    def search_logs(self, log_level: str, search_text: Optional[str] = None) -> List[str]:
        """
        Search logs for specific level and optional text.
        
        Args:
            log_level: Log level to filter (ERROR, INFO, WARN)
            search_text: Optional text to search within log entries
            
        Returns:
            List of matching log entries
            
        Raises:
            LogFileException: If log processing fails
        """
        sanitized_level = self._sanitize_input(log_level)
        if sanitized_level not in self.LOG_LEVELS:
            raise InvalidInputError(f"Invalid log level: {log_level}. Must be one of {self.LOG_LEVELS}")
        
        try:
            pattern = re.compile(rf'{sanitized_level}', re.IGNORECASE)
            search_patterns = []
            if search_text:
                search_patterns = [re.escape(word) for word in search_text.split()]
            
            matches = []
            with open(self.log_file, 'r', encoding='utf-8') as file:
                for line in file:
                    if pattern.search(line):
                        if not search_patterns or all(
                            re.search(p, line, re.IGNORECASE) for p in search_patterns
                        ):
                            matches.append(line)
            return matches
        except Exception as e:
            raise LogFileException(f"Error searching logs: {e}")
    
    def export_logs(self, log_entries: List[str], output_file: Union[str, Path]) -> None:
        """
        Export log entries to a file.
        
        Args:
            log_entries: List of log entries to export
            output_file: Path to output file
            
        Raises:
            LogFileException: If export fails
        """
        output_path = Path(output_file)
        try:
            with open(output_path, 'w', encoding='utf-8') as file:
                file.writelines(log_entries)
        except PermissionError:
            raise LogFileException(f"Permission denied writing to: {output_path}")
        except Exception as e:
            raise LogFileException(f"Error exporting logs: {e}")

def main():
    """Demonstrate usage of the system utilities."""
    try:
        # Example usage of ScreenManager
        screen = ScreenManager()
        screen.clear_screen()
        
        # Example usage of DiskStorageCalculator
        print("\nDisk Storage Calculation Example:")
        disk_calc = DiskStorageCalculator(['Cylinders', 'Heads', 'Sectors per Track', 'Bytes per Sector'])
        disk_calc.preview_storage()
        
        # Example usage of BashScriptRunner
        print("\nBash Script Execution Example:")
        script_runner = BashScriptRunner('example_script.sh')
        stdout, stderr, rc = script_runner.run_script(input_data="test input")
        print(f"Script output:\n{stdout}")
        
        # Example usage of DataSyncManager
        print("\nData Sync Example:")
        source = os.path.expanduser('~/data/prod')
        dest = os.path.expanduser('~/data/prod_backup')
        sync_manager = DataSyncManager(source, dest)
        sync_manager.sync_data()
        print("Data synchronized successfully")
        
        # Example usage of LogAnalyzer
        print("\nLog Analysis Example:")
        analyzer = LogAnalyzer('system.log')
        error_logs = analyzer.search_logs('ERROR')
        analyzer.export_logs(error_logs, 'error_logs.log')
        print(f"Found {len(error_logs)} ERROR logs and exported to error_logs.log")
        
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
