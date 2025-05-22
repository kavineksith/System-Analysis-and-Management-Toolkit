# System Analysis Tool

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive system monitoring and reporting tool that collects detailed system information and presents it in an organized, JSON format for analysis and troubleshooting.

## Features

- 🖥️ **Comprehensive System Monitoring**:
  - CPU statistics (usage, cores, frequencies)
  - Memory usage (virtual and swap)
  - Disk information (partitions, usage, I/O)
  - Network status (interfaces, connections, traffic)
  - Process details (running processes, resource usage)
  - Battery information (where applicable)
  - System information (OS, users, uptime)

- 🛠️ **Advanced Functionality**:
  - Modular architecture for easy extension
  - Comprehensive error handling
  - Configurable logging (file and console)
  - JSON output for easy parsing
  - Interactive CLI interface
  - File export capabilities
  - Cross-platform compatibility

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
```python
from system_analyzer import SystemAnalyzerApp

app = SystemAnalyzerApp()
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
8. All-in-one report
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

## Sample Reports

### CPU Report
```json
{
  "cpu_usage": {
    "total": 22.3,
    "per_core": [18.5, 25.1, 20.3, 25.2]
  },
  "logical_cores": 4,
  "physical_cores": 2,
  "cpu_times": {
    "user": 4567.89,
    "system": 1234.56,
    "idle": 34567.89
  },
  "cpu_frequencies": {
    "current": 2400.0,
    "min": 1200.0,
    "max": 3200.0
  },
  "timestamp": "14:25:10 | 15/06/2023"
}
```

### Memory Report
```json
{
  "virtual_memory": {
    "total": 17179869184,
    "available": 8589934592,
    "used": 8589934592,
    "free": 8589934592,
    "percent": 50.0,
    "threshold_warning": false
  },
  "swap_memory": {
    "total": 4294967296,
    "used": 1073741824,
    "free": 3221225472,
    "percent": 25.0
  },
  "timestamp": "14:25:15 | 15/06/2023"
}
```

## Configuration

### Logging
By default, logs are written to `system_analysis.log`. You can configure logging by modifying the `LogManager` class.

### Output Directory
Reports are saved to the current directory by default, but you can specify any output directory during report generation.

## Error Handling

The tool provides comprehensive error handling with:
- Clear error messages
- Graceful degradation
- Detailed logging
- Recovery mechanisms

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

## Disclaimer (Sumarized)

This software is provided as-is without any warranties. The developers are not responsible for:
- Any misuse of this software
- System instability caused by the tool
- Data loss or corruption
- Compatibility issues with specific systems or configurations

Users are responsible for:
- Validating results for critical systems
- Ensuring proper permissions for system monitoring
- Complying with all applicable laws and regulations