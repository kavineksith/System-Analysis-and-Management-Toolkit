# WMI Management API v2.0

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Framework](https://img.shields.io/badge/flask-latest-black)

A comprehensive RESTful API for collecting and managing Windows Management Instrumentation (WMI) data. This application provides system administrators and IT professionals with programmatic access to system information, hardware details, running processes, services, and more on Windows systems.

## ✨ v2.0 Highlights

| Feature | Implementation |
|---------|---------------|
| **Parallel WMI Collection** | `ThreadPoolExecutor` enables concurrent WMI queries across all collectors, dramatically reducing response times |
| **Generator Streaming** | Lazily yields database rows (`_iter_db_rows`) and processes (`_iter_processes`) to reduce memory footprint |
| **Object-Oriented API** | Rich dunder methods (`__repr__`, `__str__`, `__enter__`/`__exit__`, `__getitem__`, `__len__`, `__iter__`, `__contains__`) |
| **Thread-Local COM** | `_thread_local` WMI connection management guarantees COM safety in threaded environments |
| **Robust Exception Mapping** | Custom `ApiError` hierarchy automatically maps Python exceptions to HTTP status codes (`400`, `401`, `403`, `404`, `429`, `500`) |
| **Memory Optimization** | Enforces `__slots__` across all core classes and utilizes generator patterns extensively |
| **Security & Bug Fixes** | Signal-based safe shutdown, resolved shadowed built-ins, updated to timezone-aware UTC dates (`datetime.now(timezone.utc)`) |

## Features

- **Secure Authentication**: Uses API keys and JWT tokens
- **Role-Based Access Control**: Distinguishes between `admin`, `user`, and `readonly` roles
- **Comprehensive Data Collection**: Covers System, Hardware, Network, Processes, Services, Event Logs, Scheduled Tasks, Disk Space, Software, and Users
- **Service & Process Management**: Remote start/stop/restart for services; kill running processes
- **Rate Limiting**: Built-in configurable request throttling
- **Request Logging**: Detailed request/response tracing in `logs/wmi_api.log`
- **CORS Support**: Cross-origin resource sharing configured out of the box

## Installation

### Prerequisites
- Python 3.10 or higher
- Windows operating system (WMI is Windows-specific)
- Administrative privileges for full functionality

### Setup
1. Clone or download the repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   # Or manually: pip install flask flask-cors wmi pywin32 pyjwt werkzeug
   ```
3. Initialize the database and start the server:
   ```bash
   python api_wmi_analyzer.py
   ```
   *Note: On first run, it automatically initializes the SQLite database and generates an admin password/API key, which is logged to the console.*

## Usage

### Starting the Server
```bash
python api_wmi_analyzer.py --host 0.0.0.0 --port 5000 --debug
```

### Authentication
The API supports two authentication methods:
1. **API Key**: Pass via the `X-API-Key` HTTP header.
2. **JWT Token**: Pass via the `Authorization: Bearer <token>` HTTP header.

### Key API Endpoints

#### Authentication & Users
- `POST /api/auth/login` - User login (returns JWT token)
- `POST /api/auth/register` - Register new user (admin only)
- `GET /api/users` - List all users (admin only, yields data lazily)

#### System & WMI Collection
- `GET /api/wmi/system` - Get system information
- `GET /api/wmi/hardware` - Get hardware information
- `GET /api/wmi/processes` - Get running processes
- `POST /api/wmi/collect` - Collect specific WMI categories concurrently
- `GET /api/wmi/collect-all` - Collect all WMI information concurrently (admin only)

#### Process & Service Management
- `DELETE /api/wmi/processes/<id>` - Kill a process (admin only)
- `POST /api/wmi/services/<name>/start` - Start a service (admin only)
- `POST /api/wmi/services/<name>/stop` - Stop a service (admin only)
- `PUT /api/wmi/services/<name>/startup` - Change service startup mode (admin only)

#### Utility
- `GET /api/health` - Health check (verifies WMI availability)
- `POST /api/shutdown` - Gracefully shutdown server (admin only)

## Example Requests

**Get system information with API key:**
```bash
curl -X GET -H "X-API-Key: your_api_key_here" http://localhost:5000/api/wmi/system
```

**Login and get JWT token:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"your_password"}' http://localhost:5000/api/auth/login
```

## Programmatic Context Management

The `WmiApi` core class natively supports context management to ensure COM objects are safely released:

```python
from api_wmi_analyzer import WmiApi

with WmiApi() as api:
    # Parallel query execution
    info = api.collect_all_info()

    # Generator streaming access
    for name, data in api.iter_collect_all():
        print(name, len(data))
```

## Rate Limiting

The API implements rate limiting via the `@rate_limit` decorator:
- Default: 60 requests per minute per user/IP
- Headers returned in responses:
  - `X-RateLimit-Limit`: Total allowed requests
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Time until reset (seconds)

## License
This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer
This tool provides powerful system management capabilities that could disrupt system operations if used improperly. Always ensure you have proper authorization before managing systems or services. The developers are not responsible for any misuse of this software or any damages caused by its use. Use at your own risk.
