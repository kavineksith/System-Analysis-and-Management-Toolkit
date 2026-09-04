# WMI System Information Collector v3.0

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-industrial--grade-orange)

A robust, secure Python tool for comprehensive Windows system information gathering and management via WMI (Windows Management Instrumentation). Version 3.0 introduces parallel collection, async wrappers, generator-based streaming, and production-grade Python patterns.

## ✨ v3.0 Highlights

| Feature | Implementation |
|---------|---------------|
| **Parallel Collection** | `ThreadPoolExecutor` for concurrent system + hardware collection |
| **Async Wrappers** | `AsyncWmiSystemInfo` using `asyncio.to_thread()` for non-blocking WMI |
| **Generators/Yields** | Lazy iteration over OS info, BIOS, processors, memory, peripherals |
| **Dunder Methods** | `__repr__`, `__iter__`, `__len__`, `__contains__`, `__getitem__`, `__enter__`/`__exit__`, `__call__` |
| **Context Managers** | `WmiSystemInfo`, `SecureDataHandler` with guaranteed cleanup |
| **Memory Optimization** | `__slots__`, `weakref` loggers, `memoryview` crypto, peripheral caps |
| **Exception Hierarchy** | `WmiError` base with `error_code`, `timestamp`, `context`, `to_dict()` |

## Features

- **Comprehensive System Profiling**:
  - Operating system details
  - Hardware inventory (CPU, RAM, GPU, sound, motherboard, peripherals)
  - BIOS information
  - Processor and memory specs
  - Peripheral devices (configurable collection cap)

- **Enterprise-Grade Security**:
  - Secure credential handling with encryption and key rotation
  - Input validation and sanitization
  - Sensitive data redaction in logs and output
  - Audit logging with CSV trail
  - File integrity verification (SHA-256 checksums)
  - Secure file deletion (multi-pass overwrite)

- **Service Management**:
  - Safe service start/stop operations
  - Critical service protection (11 critical services blocked)
  - Rate limiting (10 ops/min)
  - Semaphore-controlled concurrency (max 5 concurrent ops)

- **Performance Optimized**:
  - Thread-safe operations with `threading.Lock`
  - Performance metrics tracking
  - Parallel WMI collection
  - Generator-based lazy data streaming

### Prerequisites
- Python 3.10+
- Windows OS (tested on Windows 10/11 and Windows Server 2016+)
- Administrative privileges (for full functionality)
- `wmi` Python package

## Usage

### Basic Information Collection

```bash
# Collect all system information (parallel)
python wmi_system_info.py all --output json

# Collect specific components
python wmi_system_info.py specific --collectors system hardware --output json
```

### Service Management

```bash
# Start a service
python wmi_system_info.py service --services MyService --action start

# Stop multiple services
python wmi_system_info.py service --services Service1 Service2 --action stop
```

### Authentication Options

```bash
python wmi_system_info.py all --use-credentials --username admin --password secure123 --domain CORP
```

### Programmatic Usage (Context Manager)

```python
from wmi_system_info import WmiSystemInfo

# Context manager ensures thread pools and resources are cleaned up
with WmiSystemInfo() as wmi:
    # Parallel collection of all information
    results = wmi.collect_all()

    # Access specific collectors
    if 'hardware' in wmi:
        hw = wmi['hardware']
        print(hw)

    # Iterate over collectors
    for name in wmi:
        print(f"Collector: {name}")

    # Lazy sequential collection via generator
    for name, data in wmi.iter_collectors():
        print(f"{name}: {len(data)} keys")

    # Service management
    result = wmi.manage_service("MyService", "start")

    # Export with checksum
    filepath = wmi.export_results(results, 'json')
```

### Async Usage

```python
import asyncio
from wmi_system_info import AsyncWmiSystemInfo

async def main():
    async_wmi = AsyncWmiSystemInfo()
    results = await async_wmi.collect_all()
    filepath = await async_wmi.export_results(results, 'json')
    print(f"Exported to {filepath}")

asyncio.run(main())
```

## 🛡️ Exception Hierarchy

```
WmiError (base)
├── WmiConnectionError — WMI connection failures
├── QueryError — WMI query failures
├── ServiceOperationError — Service start/stop failures
├── SecurityViolationError — Security policy violations
├── RateLimitExceededError — Rate limit exceeded
├── InvalidInputError — Input validation failures
├── UnsupportedOSError — Unsupported OS
├── ConfigurationError — Configuration issues
├── DataIntegrityError — Checksum/integrity failures
├── ExportFormatError — Unsupported export formats
└── CollectorTimeoutError — Collection timeouts
```

All exceptions support `error_code`, `timestamp`, `context`, and `to_dict()` serialization.

## Command Line Options

### Common Options
| Option | Description |
|--------|-------------|
| `--use-credentials` | Use specific WMI credentials |
| `--username` | WMI username (required with `--use-credentials`) |
| `--password` | WMI password (required with `--use-credentials`) |
| `--domain` | Domain for authentication |
| `--output` | Output format (json/xml/csv, default: json) |
| `--compress` | Compress output files |

### Collector-Specific Options
| Command | Options |
|---------|---------|
| `all` | Collect all available system information |
| `specific` | `--collectors` - List of collectors to run |
| `service` | `--services` - Service names, `--action` - start/stop |

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for authorized system administration and auditing purposes only. The developers are not responsible for any misuse or damage caused by this software. Always:

1. Obtain proper authorization before scanning systems
2. Test in non-production environments first
3. Review collected data for sensitive information before sharing
4. Comply with all applicable laws and organizational policies

This software is provided "as is" without warranty of any kind, express or implied. **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
