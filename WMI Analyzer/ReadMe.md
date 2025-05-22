# WMI System Information Collector

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-industrial--grade-orange)

A robust, secure Python tool for comprehensive Windows system information gathering and management via WMI (Windows Management Instrumentation).

## Features

- **Comprehensive System Profiling**:
  - Operating system details
  - Hardware inventory
  - BIOS information
  - Processor and memory specs
  - Peripheral devices

- **Enterprise-Grade Security**:
  - Secure credential handling with encryption
  - Input validation and sanitization
  - Sensitive data redaction
  - Audit logging
  - File integrity verification

- **Service Management**:
  - Safe service start/stop operations
  - Critical service protection
  - Rate limiting

- **Performance Optimized**:
  - Thread-safe operations
  - Performance metrics tracking
  - Query optimization

### Prerequisites
- Python 3.10+
- Windows OS (tested on Windows 10/11 and Windows Server 2016+)
- Administrative privileges (for full functionality)

## Usage

### Basic Information Collection
Collect all system information:
```bash
python wmi_system_info.py all --output json
```

Collect specific system components:
```bash
python wmi_system_info.py specific --collectors system hardware --output json
```

### Service Management
Start a service:
```bash
python wmi_system_info.py service --services MyService --action start
```

Stop multiple services:
```bash
python wmi_system_info.py service --services Service1 Service2 --action stop
```

### Authentication Options
Use specific credentials:
```bash
python wmi_system_info.py all --use-credentials --username admin --password secure123 --domain CORP
```

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

## Security Considerations

1. **Credential Handling**:
   - Passwords are encrypted in memory
   - Credentials are never logged
   - Secure deletion of temporary files

2. **Input Validation**:
   - All service names and queries are validated
   - Protection against command injection
   - WMI query sanitization

3. **Critical System Protection**:
   - Blocked operations on critical services
   - Rate limiting for service operations

4. **Audit Trail**:
   - All executions are logged with timestamps
   - User and hostname tracking

## Output Formats

The tool supports multiple output formats:

1. **JSON** (default):
   - Structured hierarchical data
   - Best for programmatic processing

2. **XML**:
   - Standardized format for enterprise systems
   - Suitable for legacy integration

3. **CSV**:
   - Tabular format for spreadsheets
   - Automatically compressed with ZIP

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for authorized system administration and auditing purposes only. The developers are not responsible for any misuse or damage caused by this software. Always:

1. Obtain proper authorization before scanning systems
2. Test in non-production environments first
3. Review collected data for sensitive information before sharing
4. Comply with all applicable laws and organizational policies

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**