# WMI API Analyzer - Documentation

## Introduction

The WMI API Analyzer is a comprehensive tool for collecting and managing Windows Management Instrumentation (WMI) data through a secure RESTful API. This application provides system administrators and IT professionals with programmatic access to system information, hardware details, running processes, services, and more on Windows systems.

Key features include:
- Secure authentication via API keys and JWT tokens
- Role-based access control (admin, user, readonly)
- Comprehensive WMI data collection across multiple categories
- Service management capabilities (start/stop/restart services)
- Process management (view/kill processes)
- Built-in rate limiting and request logging
- Cross-origin resource sharing (CORS) support

## Installation

### Prerequisites

- Python 3.7 or higher
- Windows operating system (WMI is Windows-specific)
- Administrative privileges for full functionality

### Setup

1. Clone or download the repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   Or manually install:
   ```bash
   pip install flask flask-cors wmi pythoncom pyjwt werkzeug
   ```

3. Initialize the database:
   ```bash
   python api_wmi_analyzer.py
   ```
   (This will automatically create and initialize the SQLite database)

## Usage

### Starting the Server

Run the application with:
```bash
python api_wmi_analyzer.py
```

Optional arguments:
- `--host`: Specify host (default: 127.0.0.1)
- `--port`: Specify port (default: 5000)
- `--debug`: Enable debug mode

Example:
```bash
python api_wmi_analyzer.py --host 0.0.0.0 --port 8080
```

### Authentication

The API supports two authentication methods:
1. **API Key**: Pass in `X-API-Key` header
2. **JWT Token**: Pass in `Authorization: Bearer <token>` header

An admin user is automatically created on first run with a randomly generated password and API key displayed in the console.

### API Endpoints

#### Authentication
- `POST /api/auth/login` - User login (returns JWT token)
- `POST /api/auth/register` - Register new user (admin only)
- `POST /api/auth/reset-api-key` - Reset API key

#### System Information
- `GET /api/wmi/system` - Get system information
- `GET /api/wmi/hardware` - Get hardware information
- `GET /api/wmi/network` - Get network information
- `POST /api/wmi/collect` - Collect specific WMI categories
- `GET /api/wmi/collect-all` - Collect all WMI information (admin only)

#### Process Management
- `GET /api/wmi/processes` - Get running processes
- `DELETE /api/wmi/processes/<id>` - Kill a process (admin only)

#### Service Management
- `GET /api/wmi/services` - Get services information
- `POST /api/wmi/services/<name>/start` - Start a service (admin only)
- `POST /api/wmi/services/<name>/stop` - Stop a service (admin only)
- `POST /api/wmi/services/<name>/restart` - Restart a service (admin only)
- `PUT /api/wmi/services/<name>/startup` - Change service startup mode (admin only)

#### User Management
- `GET /api/users` - Get all users (admin only)
- `DELETE /api/users/<id>` - Delete a user (admin only)
- `PUT /api/users/<id>/role` - Update user role (admin only)

#### Utility
- `GET /api/health` - Health check endpoint
- `POST /api/shutdown` - Gracefully shutdown server (admin only)

### Example Requests

1. Get system information with API key:
   ```bash
   curl -X GET -H "X-API-Key: your_api_key_here" http://localhost:5000/api/wmi/system
   ```

2. Login and get JWT token:
   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"your_password"}' http://localhost:5000/api/auth/login
   ```

3. Get running processes with JWT token:
   ```bash
   curl -X GET -H "Authorization: Bearer your_jwt_token_here" http://localhost:5000/api/wmi/processes
   ```

## Configuration

Configuration is managed through the `Config` class in the code. Key configuration options include:

- `SECRET_KEY`: Application secret key
- `JWT_SECRET_KEY`: JWT signing key
- `JWT_ACCESS_TOKEN_EXPIRES`: Token expiration time (seconds)
- `RATE_LIMIT_WINDOW`: Rate limit window (seconds)
- `RATE_LIMIT_MAX_REQUESTS`: Max requests per window
- `DATABASE_PATH`: Path to SQLite database
- `LOG_PATH`: Directory for log files
- `CORS_ORIGINS`: Allowed CORS origins

These can be set via environment variables or modified directly in the code.

## Security Considerations

- Always run this service in a secure environment
- Restrict access to trusted networks when possible
- Regularly rotate API keys and JWT secret keys
- The automatic admin password displayed on first run should be changed immediately
- Use HTTPS in production environments

## Rate Limiting

The API implements rate limiting with the following defaults:
- 60 requests per minute per user/IP
- Rate limit headers are included in responses:
  - `X-RateLimit-Limit`: Total allowed requests
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Time until reset (seconds)

## Logging

The application maintains detailed logs in the `logs/` directory, including:
- API request/response logs
- WMI operation logs
- Error logs

Logs are rotated when they reach 10MB, with up to 10 backups kept.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for authorized system administration and auditing purposes only. The developers are not responsible for any misuse or damage caused by this software. Always:

1. Obtain proper authorization before scanning systems
2. Test in non-production environments first
3. Review collected data for sensitive information before sharing
4. Comply with all applicable laws and organizational policies

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

## Disclaimer (Sumarized)

This software is provided "as is" without warranty of any kind. The developers are not responsible for any misuse of this software or any damages caused by its use. 

This tool provides powerful system management capabilities that could disrupt system operations if used improperly. Always ensure you have proper authorization before managing systems or services.