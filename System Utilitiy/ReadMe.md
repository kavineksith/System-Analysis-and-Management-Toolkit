# System Utilities Library v2.0

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive Python toolkit for system operations, featuring modules for:

* ✅ Terminal screen management
* ✅ Synchronous and **async** command/script execution
* ✅ Data synchronization using `rsync` with **parallel processing**
* ✅ Disk geometry-based storage calculations with **comparison operators**
* ✅ Log file analysis with **generator-based streaming** and **parallel multi-file search**

## 📦 Introduction

The **System Utilities Library** is a modular and extensible collection of utilities aimed at easing common system-level operations. Version 2.0 brings industrial-grade Python patterns: generators, async I/O, parallel processing, rich dunder methods, and a robust custom exception hierarchy.

## ✨ v2.0 Highlights

| Feature | Implementation |
|---------|---------------|
| **Generators/Yields** | `LogAnalyzer.search_logs()` yields matches lazily; `stream_logs()` provides tail-f behavior; `yield_conversions()` for unit chains |
| **Parallel Programming** | `ThreadPoolExecutor` for multi-file log search; `ProcessPoolExecutor` for parallel rsync |
| **Async Programming** | `AsyncProcessExecutor` with `asyncio.create_subprocess_exec` for non-blocking command execution |
| **Dunder Methods** | `__call__`, `__iter__`, `__contains__`, `__len__`, `__int__`, `__float__`, `__mul__`, `__eq__`, `__lt__`, `__enter__`/`__exit__` |
| **Custom Exceptions** | Hierarchy with `error_code`, `timestamp`, `context`, `to_dict()` serialization |
| **Memory Optimization** | `__slots__` on all classes; `mmap` for large file pattern matching; configurable buffer sizes |

## 🚀 Usage

To run the full demo from the command line:

```bash
python3 system_utils.py
```

### Example: Clear Screen

```python
from system_utils import ScreenManager
ScreenManager().clear_screen()
```

### Example: Run a Command (Sync)

```python
from system_utils import ProcessExecutor

executor = ProcessExecutor()
# Standard call
stdout, stderr, rc = executor.run_command("echo hello")

# Or use as a callable
stdout, stderr, rc = executor("echo hello")
```

### Example: Run a Command (Async)

```python
import asyncio
from system_utils import AsyncProcessExecutor

async def main():
    executor = AsyncProcessExecutor()
    stdout, stderr, rc = await executor.run_command(
        ["echo", "hello"], timeout=10
    )
    print(stdout)

asyncio.run(main())
```

### Example: Run Bash Script (Callable)

```python
from system_utils import BashScriptRunner

runner = BashScriptRunner('path/to/script.sh')
# Direct call syntax
stdout, stderr, code = runner(input_data="input", args=["arg1", "arg2"])
# Boolean check
if runner:
    print("Script is valid and ready")
```

### Example: Sync Directories (Context Manager)

```python
from system_utils import DataSyncManager

with DataSyncManager('/source/dir', '/destination/dir') as sync:
    sync.sync_data(parallel=True, max_workers=4)
```

### Example: Calculate Disk Storage

```python
from system_utils import DiskStorageCalculator

calc = DiskStorageCalculator(['Cylinders', 'Heads', 'Sectors', 'Bytes per Sector'])
calc.preview_storage()

# Numeric conversions
print(f"Bytes: {int(calc)}")
print(f"GB: {float(calc):.2f}")

# Scaling and comparison
doubled = calc * 2
print(f"Original < Doubled: {calc < doubled}")

# Lazy unit conversion generator
for unit, value in calc.yield_conversions():
    print(f"{unit}: {value:,.2f}")
```

### Example: Analyze Logs (Generator-Based)

```python
from system_utils import LogAnalyzer

analyzer = LogAnalyzer('system.log')

# Generator-based search — memory efficient for huge files
for entry in analyzer.search_logs('ERROR', 'timeout'):
    print(entry, end='')

# Export from generator directly (no intermediate list needed)
count = analyzer.export_logs(
    analyzer.search_logs('ERROR'),
    'errors.log'
)
print(f"Exported {count} entries")

# Containment check (uses mmap for large files)
if 'CRITICAL' in analyzer:
    print("Found critical entries!")

# Iterate all lines lazily
for line in analyzer:
    process(line)

# Stream new lines in real-time (tail -f)
for new_line in analyzer.stream_logs(poll_interval=0.5):
    print(new_line, end='')
```

### Example: Parallel Multi-File Log Search

```python
from system_utils import LogAnalyzer

analyzer = LogAnalyzer('main.log')
log_files = ['app1.log', 'app2.log', 'app3.log']

for file_path, matches in analyzer.search_logs_parallel(
    log_files, 'ERROR', max_workers=4
):
    print(f"{file_path}: {len(matches)} errors found")
```

## 🛡️ Exception Hierarchy

```
SystemUtilsError (base)
├── ProcessExecutionError — Command/subprocess failures
├── LogFileException — Log file I/O operations
├── InvalidInputError — Input validation failures
├── DiskCalculationError — Disk storage calculations
├── FileOperationError — File system operations
└── SyncTimeoutError — Data sync timeouts
```

All exceptions include:
- `message` — Human-readable description
- `error_code` — Numeric code for programmatic handling
- `timestamp` — ISO-format time of occurrence
- `context` — Additional metadata dict
- `to_dict()` — JSON-serializable representation

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions. **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk. The developers are not responsible for any damage or data loss caused by improper usage or unverified scripts.**
