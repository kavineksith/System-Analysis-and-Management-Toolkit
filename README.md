# System Analysis and Management Toolkit

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Architecture](https://img.shields.io/badge/architecture-async%20%7C%20parallel-success)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive suite of four advanced Python projects designed for deep system analysis, hardware profiling, secure WMI management, and high-performance system utilities. The toolkit has been upgraded with **senior-level Python architecture**, prioritizing memory optimization, parallel processing, and asynchronous operations.

## 🌟 Advanced Python Architecture

Across all four projects, the toolkit leverages industrial-grade Python patterns:

- **Parallel Processing**: Extensive use of `concurrent.futures.ThreadPoolExecutor` and `ProcessPoolExecutor` for multi-threaded WMI collection, parallel log searching, and rapid directory synchronization.
- **Asynchronous Operations**: Uses `asyncio` for non-blocking network checks, subprocess execution, and async-wrapped WMI collection (`AsyncWmiSystemInfo`).
- **Memory Optimization**: Employs `__slots__` on all data classes to reduce memory footprint, and utilizes `psutil.process_iter()` for race-condition-free process enumeration.
- **Generator / Yield Patterns**: Replaces memory-heavy lists with lazy generators (`yield`) for massive datasets like OS processes, network connections, disk partitions, and database streaming.
- **Robust Custom Exceptions**: A unified custom exception hierarchy across all projects, featuring timestamps, error codes, HTTP status code mapping (in the API), context dictionaries, and `to_dict()` serialization.
- **Object-Oriented Design**: Rich Dunder methods implemented on manager classes (`__repr__`, `__str__`, `__iter__`, `__len__`, `__contains__`, `__getitem__`, `__call__`, and rich comparisons like `__eq__`, `__lt__`).
- **Resource Lifecycle Management**: Implements the Context Manager Protocol (`__enter__`/`__exit__`) to guarantee ThreadPool shutdowns, database connection closures, and safe COM initialization cleanups.

---

## 📦 Projects Overview

### 1. System Analyzer v2.0
A robust tool for collecting system metrics, network status, processes, and battery info.
- **Key Features**: Parallel system report generation, async network connectivity checks, and generator-based disk/process iteration.
- **Run**: `cd "System Analyzer" && python system_analyzer.py`

### 2. System Utility v2.0
A toolkit for script execution, disk storage calculation, rsync data synchronization, and log analysis.
- **Key Features**: Generator-based log streaming (`tail -f` behavior), parallel multi-file log search, disk geometry calculations with total ordering, and `mmap` for massive file scanning.
- **Run**: `cd "System Utilitiy" && python system_utils.py`

### 3. WMI Analyzer v3.0
An industrial-grade Windows Management Instrumentation (WMI) profiler.
- **Key Features**: Secure credential handling with automated AES key rotation, file integrity checks (SHA-256), parallel hardware collection, async wrappers (`AsyncWmiSystemInfo`), and safety constraints preventing critical service modification.
- **Run**: `cd "WMI Analyzer" && python wmi_system_info.py all --output json`

### 4. WMI Management API v2.0
A Flask-based REST API wrapping WMI capabilities for remote administration.
- **Key Features**: JWT & API Key authentication, Role-Based Access Control, rate-limiting, thread-local WMI COM connection pooling, and generator-based database streaming.
- **Run**: `cd "WMI Management API" && python api_wmi_analyzer.py`

---

## ⚙️ Dependencies

| Project | Required Packages |
|---------|-------------------|
| System Analyzer | `psutil`, `netifaces` |
| System Utility | (Standard Library) |
| WMI Analyzer | `wmi`, `pywin32` |
| WMI Management API | `flask`, `flask-cors`, `wmi`, `pywin32`, `pyjwt`, `werkzeug` |

To install all dependencies globally (Windows):
```bash
pip install psutil netifaces wmi pywin32 flask flask-cors pyjwt werkzeug
```

---

## 📝 License

This toolkit is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool provides powerful system management capabilities that could disrupt system operations if used improperly. Always ensure you have proper authorization before managing systems or services. The developers are not responsible for any misuse of this software or any damages caused by its use. Use at your own risk.

**This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software.**
