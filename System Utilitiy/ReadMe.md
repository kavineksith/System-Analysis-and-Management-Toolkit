# System Utilities Library

A comprehensive Python toolkit for system operations, featuring modules for:

* ✅ Terminal screen management
* ✅ System command and Bash script execution
* ✅ Data synchronization using `rsync`
* ✅ Disk geometry-based storage calculations
* ✅ Log file analysis and export

## 📦 Introduction

The **System Utilities Library** is a modular and extensible collection of utilities aimed at easing common system-level operations. Whether you're automating server tasks, building DevOps scripts, or creating admin tools, this library provides a robust, cross-platform foundation with clean exception handling and support for parallel operations.

## 🚀 Features

* Clear and portable screen clearing
* Robust system command runner with timeout and error capturing
* Bash script execution with optional input and arguments
* Reliable data sync using `rsync` with multiprocessing support
* Interactive disk storage calculator based on drive geometry
* Log file analyzer supporting filtering and exporting

## ⚙️ Usage

To run the full demo from the command line:

```bash
python3 system_utils.py
```

### Example: Clear Screen

```python
from system_utils import ScreenManager
ScreenManager().clear_screen()
```

### Example: Run Bash Script

```python
runner = BashScriptRunner('path/to/script.sh')
stdout, stderr, code = runner.run_script(input_data="input", args=["arg1", "arg2"])
```

### Example: Sync Directories

```python
sync = DataSyncManager('/source/dir', '/destination/dir')
sync.sync_data(parallel=True)
```

### Example: Calculate Disk Storage

```python
calc = DiskStorageCalculator(['Cylinders', 'Heads', 'Sectors', 'Bytes per Sector'])
calc.preview_storage()
```

### Example: Analyze Logs

```python
analyzer = LogAnalyzer('system.log')
entries = analyzer.search_logs('ERROR', 'timeout')
analyzer.export_logs(entries, 'errors.log')
```

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk. The developers are not responsible for any damage or data loss caused by improper usage or unverified scripts.**
