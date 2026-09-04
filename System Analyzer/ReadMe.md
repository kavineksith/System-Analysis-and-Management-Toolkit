# System Analysis Tool v2.0

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive system monitoring and reporting tool that collects detailed system information and presents it in an organized, JSON format for analysis and troubleshooting. Version 2.0 brings industrial-grade Python patterns for maximum performance and reliability.

## Features

- 🖥️ **Comprehensive System Monitoring**:
  - CPU statistics (usage, cores, frequencies, times, stats)
  - Memory usage (virtual and swap with threshold warnings)
  - Disk information (partitions, usage, I/O counters)
  - Network status (interfaces, addresses, connections, traffic)
  - Process details (running processes, resource usage, memory footprint)
  - Battery information (where applicable)
  - System information (OS, boot time, users, uptime)

- 🛠️ **Advanced v2.0 Architecture**:
  - **Parallel Processing**: Uses `ThreadPoolExecutor` for concurrent full system reports, reducing collection time significantly.
  - **Asynchronous Operations**: Uses `asyncio` for non-blocking concurrent network connectivity checks.
  - **Memory Optimization**: Employs `__slots__` and lazy generator/yield patterns (`yield`) to handle massive data sets (like thousands of processes or network connections) with a minimal memory footprint.
  - **Robust Error Handling**: Custom exception hierarchy (`SystemAnalyzerError`, `CollectionError`, `ExportError`) with error codes, contexts, and timestamps.
  - **Object-Oriented Design**: Rich Dunder methods (`__repr__`, `__iter__`, `__len__`, `__contains__`, `__getitem__`) on all manager classes.
  - **Resource Management**: Implements Context Manager protocol (`__enter__`/`__exit__`) for guaranteed thread pool shutdown and resource cleanup.
  - **Performance**: Caching with `functools.lru_cache` and optimized `psutil.process_iter()` usage.

## Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Required Packages
```bash
pip install psutil netifaces
```

## Usage

### Command Line Interface
Run the tool interactively:
```bash
python system_analyzer.py
```

### Programmatic Usage

Leverage the Context Manager for safe execution and resource cleanup:

```python
from system_analyzer import SystemAnalyzerApp

# The context manager ensures thread pools and resources are cleaned up
with SystemAnalyzerApp() as app:
    app.run()
```

### Report Options
The interactive menu provides these options:
1. CPU Information
2. Process Information
3. Memory Information
4. Disk Information
5. Network Information
6. System Information
7. Battery Information
8. All-in-one report (parallel execution)
9. Exit

## Output Format

All reports are generated in JSON format. Example structure:

```json
{
  "cpu_usage": {
    "total": 15.7,
    "per_core": [12.5, 18.9, 10.2, 21.3]
  },
  "logical_cores": 8,
  "physical_cores": 4,
  "cpu_times": {
    "user": 12345.67,
    "system": 2345.67,
    "idle": 34567.89
  },
  "timestamp": "15:30:45 | 15/06/2023"
}
```

## Error Handling

The tool provides comprehensive error handling via a custom exception hierarchy:
- `SystemAnalyzerError`: Base exception with `timestamp` and `error_code`.
- `CollectionError`: Raised when data collection from a system component fails.
- `ExportError`: Raised when saving reports to disk fails.
- `ConfigurationError`: Raised on invalid application configurations.
- `NetworkCheckError`: Raised when network connectivity checks fail.

Exceptions can be serialized for logging or API responses using the `.to_dict()` method.

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions. **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

Users are responsible for:
- Validating results for critical systems
- Ensuring proper permissions for system monitoring
- Complying with all applicable laws and regulations
