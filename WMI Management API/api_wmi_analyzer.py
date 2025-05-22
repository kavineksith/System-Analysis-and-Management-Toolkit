import argparse
import json
import sys
import wmi
import logging
import datetime
import os
import uuid
import time
import re
import sqlite3
import secrets
import jwt
import pythoncom
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from abc import ABC, abstractmethod
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from functools import wraps
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash


try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    if os.name == 'nt':  # Only warn if actually on Windows
        raise ConnectionError("Warning: wmi package not available - WMI functionality will be disabled")

# Create Flask app
app = Flask(__name__)

# Set up configurations
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    RATE_LIMIT_WINDOW = 60  # 1 minute
    RATE_LIMIT_MAX_REQUESTS = 60  # 60 requests per minute
    DATABASE_PATH = os.path.join(os.getcwd(), 'wmi_api.db')
    LOG_PATH = os.path.join(os.getcwd(), 'logs')
    CORS_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:5000']  # Specify allowed origins

app.config.from_object(Config)

# Configure CORS
cors = CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}})

# Set up logging
if not os.path.exists(Config.LOG_PATH):
    os.makedirs(Config.LOG_PATH)

api_logger = logging.getLogger('wmi_api')
api_logger.setLevel(logging.DEBUG)

# File handler for API logs
api_log_file = os.path.join(Config.LOG_PATH, 'wmi_api.log')
file_handler = RotatingFileHandler(api_log_file, maxBytes=10485760, backupCount=10)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
api_logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(levelname)s: %(message)s')
console_handler.setFormatter(console_formatter)
api_logger.addHandler(console_handler)

# Log request details
@app.before_request
def log_request_info():
    # Don't log health check endpoints
    if request.path == '/api/health':
        return
    
    request_id = str(uuid.uuid4())
    g.request_id = request_id
    
    # Create log entry
    log_data = {
        'request_id': request_id,
        'method': request.method,
        'path': request.path,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'params': dict(request.args),
        'time': datetime.datetime.now().isoformat()
    }
    
    # Don't log sensitive data like passwords
    if request.is_json and request.get_json(silent=True):
        content = request.get_json(silent=True)
        # Sanitize any sensitive fields
        sanitized = {k: '***' if k.lower() in ['password', 'token', 'secret'] else v 
                    for k, v in content.items()} if isinstance(content, dict) else content
        log_data['json'] = sanitized
    
    api_logger.info(f"Request: {json.dumps(log_data)}")

# Log response details
@app.after_request
def log_response_info(response):
    # Don't log health check endpoints
    if request.path == '/api/health':
        return response
    
    request_id = getattr(g, 'request_id', 'unknown')
    
    # Create log entry
    log_data = {
        'request_id': request_id,
        'status_code': response.status_code,
        'time': datetime.datetime.now().isoformat(),
        'response_size': len(response.get_data(as_text=True))
    }
    
    api_logger.info(f"Response: {json.dumps(log_data)}")
    return response

# Database initialization and helpers
def init_db():
    db_conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = db_conn.cursor()
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL,
        api_key TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # API request logs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS request_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        status_code INTEGER,
        ip_address TEXT,
        request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Rate limiting table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        ip_address TEXT,
        request_count INTEGER DEFAULT 1,
        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create admin user if it doesn't exist
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    cursor.execute("SELECT id, api_key FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()
    
    if not admin:
        admin_password = secrets.token_urlsafe(12)
        password_hash = generate_password_hash(admin_password)
        api_key = secrets.token_hex(32)
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role, api_key) VALUES (?, ?, ?, ?, ?)",
            ('admin', password_hash, 'admin@example.com', 'admin', api_key)
        )
        print(f"Admin user created with password: {admin_password}")
        print(f"Admin API key: {api_key}")
    elif not admin[1]:  # Admin exists but has no API key
        api_key = secrets.token_hex(32)
        cursor.execute("UPDATE users SET api_key = ? WHERE username = 'admin'",
                      (api_key,))
        print(f"Admin API key updated: {api_key}")

    # Ensure all users have API keys
    cursor.execute("UPDATE users SET api_key = ? WHERE api_key IS NULL",
                 (secrets.token_hex(32),))
    
    db_conn.commit()
    db_conn.close()

def verify_db_integrity():
    db_conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = db_conn.cursor()
    
    # Check for users without API keys
    cursor.execute("SELECT username FROM users WHERE api_key IS NULL")
    missing_keys = cursor.fetchall()
    
    if missing_keys:
        print(f"Found {len(missing_keys)} users without API keys - initializing...")
        for user in missing_keys:
            new_key = secrets.token_hex(32)
            cursor.execute("UPDATE users SET api_key = ? WHERE username = ?",
                         (new_key, user[0]))
            print(f"Assigned API key to user: {user[0]}")
        
        db_conn.commit()
    
    db_conn.close()

def migrate_db():
    """Add any missing columns to existing tables"""
    db_conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = db_conn.cursor()
    
    try:
        # Check if api_key column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'api_key' not in columns:
            print("Adding api_key column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN api_key TEXT UNIQUE")
            
            # Initialize keys for existing users
            cursor.execute("UPDATE users SET api_key = ?", 
                         (secrets.token_hex(32),))
            
            db_conn.commit()
            print("Database migration complete")
    except Exception as e:
        print(f"Migration error: {e}")
    finally:
        db_conn.close()


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(Config.DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Custom exceptions
class WmiError(Exception):
    """Base exception for WMI-related errors"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class ConnectionError(WmiError):
    """Exception raised when WMI connection fails"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class QueryError(WmiError):
    """Exception raised when a WMI query fails"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class ServiceOperationError(WmiError):
    """Exception raised when a service operation fails"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class AuthenticationError(Exception):
    """Exception raised for authentication errors"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class RateLimitError(Exception):
    """Exception raised when rate limit is exceeded"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

# Security utility functions
def generate_csrf_token():
    """Generate a secure CSRF token"""
    return secrets.token_hex(32)

def validate_input(data, required_fields=None, patterns=None):
    """
    Validate input data against required fields and regex patterns
    
    Args:
        data: The data to validate
        required_fields: List of required field names
        patterns: Dict of field names and regex patterns
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if required_fields:
        for field in required_fields:
            if field not in data or not data[field]:
                return False, f"Missing required field: {field}"
    
    if patterns:
        for field, pattern in patterns.items():
            if field in data and data[field]:
                if not re.match(pattern, str(data[field])):
                    return False, f"Invalid format for field: {field}"
    
    return True, ""

def sanitize_input(input_data):
    """
    Sanitize input data to prevent XSS and injection attacks
    
    Args:
        input_data: The data to sanitize
    
    Returns:
        The sanitized data
    """
    if isinstance(input_data, str):
        # Replace potential script tags
        sanitized = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', input_data, flags=re.IGNORECASE)
        # Replace other dangerous tags
        sanitized = re.sub(r'<(\/?(script|iframe|object|embed|style|onload|onerror|onclick|onmouseover))', '&lt;\\1', sanitized, flags=re.IGNORECASE)
        return sanitized
    elif isinstance(input_data, dict):
        return {k: sanitize_input(v) for k, v in input_data.items()}
    elif isinstance(input_data, list):
        return [sanitize_input(item) for item in input_data]
    else:
        return input_data

def generate_token(user_id, username, role):
    """
    Generate a JWT token
    
    Args:
        user_id: User ID
        username: Username
        role: User role
    
    Returns:
        JWT token
    """
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=Config.JWT_ACCESS_TOKEN_EXPIRES),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')

def decode_token(token):
    """
    Decode and validate JWT token
    
    Args:
        token: JWT token
    
    Returns:
        dict: Token payload
    
    Raises:
        AuthenticationError: If token is invalid
    """
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except InvalidTokenError:
        raise AuthenticationError("Invalid token")

# Authentication and authorization decorators
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check for token in header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        # Check for token in query parameters
        if not token and 'token' in request.args:
            token = request.args.get('token')
        
        # Check for token in JSON body
        if not token and request.is_json:
            json_data = request.get_json(silent=True)
            if json_data and 'token' in json_data:
                token = json_data.get('token')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            payload = decode_token(token)
            g.user = payload
        except AuthenticationError as e:
            return jsonify({'error': str(e)}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = None
        
        # Check for API key in header
        if 'X-API-Key' in request.headers:
            api_key = request.headers['X-API-Key']
        
        # Check for API key in query parameters
        if not api_key and 'api_key' in request.args:
            api_key = request.args.get('api_key')
        
        if not api_key:
            return jsonify({'error': 'API key is missing'}), 401
        
        # Validate API key
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, role FROM users WHERE api_key = ?", (api_key,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        g.user = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
        
        return f(*args, **kwargs)
    
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.get('role') != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    
    return decorated_function

def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip CSRF check for API key authenticated requests
        if request.headers.get('X-API-Key'):
            return f(*args, **kwargs)
        
        # Check CSRF token in header or form
        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        
        if not csrf_token or csrf_token != request.cookies.get('csrf_token'):
            return jsonify({'error': 'CSRF token missing or invalid'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get identifier (user_id or IP address)
        user_id = getattr(g, 'user', {}).get('user_id')
        ip_address = request.remote_addr
        
        db = get_db()
        cursor = db.cursor()
        
        # Check if rate limit exists for this user/IP
        if user_id:
            cursor.execute(
                "SELECT id, request_count, window_start FROM rate_limits WHERE user_id = ? ORDER BY window_start DESC LIMIT 1",
                (user_id,)
            )
        else:
            cursor.execute(
                "SELECT id, request_count, window_start FROM rate_limits WHERE ip_address = ? ORDER BY window_start DESC LIMIT 1",
                (ip_address,)
            )
        
        rate_limit_record = cursor.fetchone()
        current_time = datetime.datetime.now()
        
        if rate_limit_record:
            # Check if window has expired
            window_start = datetime.datetime.fromisoformat(rate_limit_record['window_start'])
            time_diff = (current_time - window_start).total_seconds()
            
            if time_diff < Config.RATE_LIMIT_WINDOW:
                # Window is still active, check count
                if rate_limit_record['request_count'] >= Config.RATE_LIMIT_MAX_REQUESTS:
                    remaining_time = Config.RATE_LIMIT_WINDOW - time_diff
                    headers = {
                        'X-RateLimit-Limit': str(Config.RATE_LIMIT_MAX_REQUESTS),
                        'X-RateLimit-Remaining': '0',
                        'X-RateLimit-Reset': str(int(remaining_time))
                    }
                    return jsonify({'error': 'Rate limit exceeded'}), 429, headers
                
                # Update count
                cursor.execute(
                    "UPDATE rate_limits SET request_count = request_count + 1 WHERE id = ?",
                    (rate_limit_record['id'],)
                )
                db.commit()
                
                # Set headers
                remaining = Config.RATE_LIMIT_MAX_REQUESTS - (rate_limit_record['request_count'] + 1)
                headers = {
                    'X-RateLimit-Limit': str(Config.RATE_LIMIT_MAX_REQUESTS),
                    'X-RateLimit-Remaining': str(remaining),
                    'X-RateLimit-Reset': str(int(Config.RATE_LIMIT_WINDOW - time_diff))
                }
                
            else:
                # Window expired, create new window
                if user_id:
                    cursor.execute(
                        "INSERT INTO rate_limits (user_id, request_count, window_start) VALUES (?, 1, ?)",
                        (user_id, current_time)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO rate_limits (ip_address, request_count, window_start) VALUES (?, 1, ?)",
                        (ip_address, current_time)
                    )
                db.commit()
                
                # Set headers
                headers = {
                    'X-RateLimit-Limit': str(Config.RATE_LIMIT_MAX_REQUESTS),
                    'X-RateLimit-Remaining': str(Config.RATE_LIMIT_MAX_REQUESTS - 1),
                    'X-RateLimit-Reset': str(Config.RATE_LIMIT_WINDOW)
                }
        else:
            # First request, create new window
            if user_id:
                cursor.execute(
                    "INSERT INTO rate_limits (user_id, request_count, window_start) VALUES (?, 1, ?)",
                    (user_id, current_time)
                )
            else:
                cursor.execute(
                    "INSERT INTO rate_limits (ip_address, request_count, window_start) VALUES (?, 1, ?)",
                    (ip_address, current_time)
                )
            db.commit()
            
            # Set headers
            headers = {
                'X-RateLimit-Limit': str(Config.RATE_LIMIT_MAX_REQUESTS),
                'X-RateLimit-Remaining': str(Config.RATE_LIMIT_MAX_REQUESTS - 1),
                'X-RateLimit-Reset': str(Config.RATE_LIMIT_WINDOW)
            }
        
        # Log request
        if user_id:
            cursor.execute(
                "INSERT INTO request_logs (user_id, endpoint, method, status_code, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user_id, request.path, request.method, 200, ip_address)
            )
        else:
            cursor.execute(
                "INSERT INTO request_logs (endpoint, method, status_code, ip_address) VALUES (?, ?, ?, ?)",
                (request.path, request.method, 200, ip_address)
            )
        db.commit()
        
        # Call the original function
        response = f(*args, **kwargs)
        
        # Add rate limit headers to response
        if isinstance(response, tuple):
            response_obj, status_code = response
            response_obj.headers.update(headers)
            return response_obj, status_code
        else:
            response.headers.update(headers)
            return response
    
    return decorated_function

# Setup WMI components from the original code
def setup_wmi_logger():
    """Configure and return logger for WMI operations"""
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/wmi_info_{timestamp}.log"
    
    logger = logging.getLogger('wmi_system_info')
    logger.setLevel(logging.DEBUG)
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    
    # Create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(file_handler)
    
    return logger

# Base class for all WMI information gatherers
class WmiInfoCollector(ABC):
    def __init__(self, wmi_connection, logger):
        """
        Initialize with WMI connection and logger
        
        Args:
            wmi_connection: WMI connection object
            logger: Logger instance
        """
        self.c = wmi_connection
        self.logger = logger
        self.section_name = self.__class__.__name__
    
    def collect(self):
        """Template method for collecting WMI information"""
        self.logger.info(f"Starting collection: {self.section_name}")
        try:
            result = self._gather_info()
            self.logger.info(f"Successfully collected {self.section_name}")
            return result
        except WmiError as e:
            self.logger.error(f"Error collecting {self.section_name}: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in {self.section_name}: {str(e)}")
            raise QueryError(f"Failed to query {self.section_name}: {str(e)}")
    
    @abstractmethod
    def _gather_info(self):
        """Implement in child classes to gather specific information"""
        pass

class SystemInfoCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather system information"""
        info = {"system": {  # Added 'system' wrapper
            "operating_systems": [], 
            "bios": [], 
            "computer_systems": []
        }}
        
        for os_info in self.c.Win32_OperatingSystem():
            os_data = {
                "Caption": os_info.Caption,
                "Version": os_info.Version,
                "OSArchitecture": os_info.OSArchitecture,
                "InstallDate": os_info.InstallDate
            }
            info["system"]["operating_systems"].append(os_data)
            
        for bios in self.c.Win32_BIOS():
            bios_data = {
                "SMBIOSBIOSVersion": bios.SMBIOSBIOSVersion,
                "Manufacturer": bios.Manufacturer,
                "SerialNumber": bios.SerialNumber,
                "ReleaseDate": bios.ReleaseDate
            }
            info["system"]["bios"].append(bios_data)
            
        for system in self.c.Win32_ComputerSystem():
            system_data = {
                "Name": system.Name,
                "Manufacturer": system.Manufacturer,
                "Model": system.Model,
                "TotalPhysicalMemory": system.TotalPhysicalMemory
            }
            info["system"]["computer_systems"].append(system_data)
            
        return info

class HardwareInfoCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather hardware information"""
        info = {"hardware": {  # Added 'hardware' wrapper
            "processors": [], 
            "memory": [], 
            "disks": [], 
            "network_adapters": []
        }}
        
        for processor in self.c.Win32_Processor():
            proc_data = {
                "Name": processor.Name,
                "NumberOfCores": processor.NumberOfCores,
                "MaxClockSpeed": processor.MaxClockSpeed,
                "L2CacheSize": processor.L2CacheSize,
                "L3CacheSize": processor.L3CacheSize
            }
            info["hardware"]["processors"].append(proc_data)
            
        for memory in self.c.Win32_PhysicalMemory():
            mem_data = {
                "Capacity": memory.Capacity,
                "Speed": memory.Speed,
                "Manufacturer": memory.Manufacturer,
                "DeviceLocator": memory.DeviceLocator
            }
            info["hardware"]["memory"].append(mem_data)
            
        for disk in self.c.Win32_DiskDrive():
            disk_data = {
                "Model": disk.Model,
                "Size": disk.Size,
                "InterfaceType": disk.InterfaceType,
                "MediaType": disk.MediaType,
                "SerialNumber": disk.SerialNumber
            }
            info["hardware"]["disks"].append(disk_data)
            
        for adapter in self.c.Win32_NetworkAdapter():
            if adapter.MACAddress:
                adapter_data = {
                    "Name": adapter.Name,
                    "MACAddress": adapter.MACAddress,
                    "AdapterType": adapter.AdapterType,
                    "Speed": adapter.Speed
                }
                info["hardware"]["network_adapters"].append(adapter_data)
                
        return info

class NetworkInfoCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather network configuration information"""
        info = {"network": {  # Added 'network' wrapper
            "network_configs": []
        }}
        
        try:
            for adapter in self.c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                adapter_data = {
                    "Description": adapter.Description,
                    "MACAddress": adapter.MACAddress,
                    "IPAddress": adapter.IPAddress,
                    "IPSubnet": adapter.IPSubnet,
                    "DefaultIPGateway": adapter.DefaultIPGateway,
                    "DNSServerSearchOrder": adapter.DNSServerSearchOrder
                }
                info["network"]["network_configs"].append(adapter_data)
        except Exception as e:
            self.logger.warning(f"Some network adapters might not have complete information: {str(e)}")
            
        return info

class ProcessInfoCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather process information"""
        info = {"processes": {  # Added 'processes' wrapper
            "processes": []
        }}
        
        for process in self.c.Win32_Process():
            try:
                process_data = {
                    "Name": process.Name,
                    "ProcessId": process.ProcessId,
                    "CommandLine": process.CommandLine,
                    "WorkingSetSize": process.WorkingSetSize
                }
                info["processes"]["processes"].append(process_data)
            except Exception as e:
                self.logger.debug(f"Could not get complete info for process {process.Name}: {str(e)}")
                
        return info

class ServiceInfoCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather service information"""
        info = {"services": {  # Added 'services' wrapper
            "services": []
        }}
        
        for service in self.c.Win32_Service():
            service_data = {
                "Name": service.Name,
                "DisplayName": service.DisplayName,
                "State": service.State,
                "StartMode": service.StartMode
            }
            info["services"]["services"].append(service_data)
            
        return info

class EventLogCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather system event logs"""
        info = {"events": {  # Added 'events' wrapper
            "events": []
        }}
        
        try:
            query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile='System' AND TimeGenerated > '20220101000000.000000-000'"
            for event in self.c.query(query)[:100]:  # Limit to 100 events
                event_data = {
                    "EventCode": event.EventCode,
                    "SourceName": event.SourceName,
                    "TimeGenerated": event.TimeGenerated,
                    "Type": event.Type,
                    "Message": event.Message
                }
                info["events"]["events"].append(event_data)
        except Exception as e:
            self.logger.warning(f"Limited event log collection: {str(e)}")
            
        return info

class ScheduledTaskCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather scheduled task information"""
        info = {"tasks": {  # Added 'tasks' wrapper
            "scheduled_tasks": []
        }}
        
        try:
            for task in self.c.Win32_ScheduledJob():
                task_data = {
                    "JobId": task.JobId,
                    "Command": task.Command,
                    "RunTimes": task.RunTimes,
                    "Status": task.Status
                }
                info["tasks"]["scheduled_tasks"].append(task_data)
        except Exception as e:
            self.logger.warning(f"Scheduled task collection issue: {str(e)}")
            info["tasks"]["error"] = str(e)  # Include error in response
            
        return info

class DiskSpaceCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather disk space information"""
        info = {"diskspace": {  # Added 'diskspace' wrapper
            "logical_disks": []
        }}
        
        for disk in self.c.Win32_LogicalDisk(DriveType=3):  # DriveType 3 = Local Disk
            disk_data = {
                "DeviceID": disk.DeviceID,
                "VolumeName": disk.VolumeName,
                "Size": disk.Size,
                "FreeSpace": disk.FreeSpace,
                "FileSystem": disk.FileSystem
            }
            info["diskspace"]["logical_disks"].append(disk_data)
            
        return info

class InstalledSoftwareCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather installed software information"""
        info = {"software": {  # Added 'software' wrapper
            "installed_software": []
        }}
        
        try:
            for app in self.c.Win32_Product():
                app_data = {
                    "Name": app.Name,
                    "Version": app.Version,
                    "Vendor": app.Vendor,
                    "InstallDate": app.InstallDate
                }
                info["software"]["installed_software"].append(app_data)
        except Exception as e:
            self.logger.warning(f"Software collection issue: {str(e)}")
            
        return info

class UserAccountCollector(WmiInfoCollector):
    def _gather_info(self):
        """Gather user account information"""
        info = {"users": {  # Added 'users' wrapper
            "user_accounts": []
        }}
        
        for user in self.c.Win32_UserAccount():
            user_data = {
                "Name": user.Name,
                "Domain": user.Domain,
                "SID": user.SID,
                "AccountType": user.AccountType,
                "Disabled": user.Disabled
            }
            info["users"]["user_accounts"].append(user_data)
            
        return info

class ServiceManager:
    def __init__(self, wmi_connection, logger):
        """
        Initialize service manager
        
        Args:
            wmi_connection: WMI connection object
            logger: Logger instance
        """
        self.c = wmi_connection
        self.logger = logger
    
    def get_service(self, service_name):
        """
        Get service details by name
        
        Args:
            service_name: Name of the service
            
        Returns:
            Service object or None if not found
            
        Raises:
            QueryError: If the query fails
        """
        try:
            services = self.c.Win32_Service(Name=service_name)
            if services:
                return services[0]
            return None
        except Exception as e:
            self.logger.error(f"Failed to get service {service_name}: {str(e)}")
            raise QueryError(f"Failed to query service {service_name}: {str(e)}")
    
    def start_service(self, service_name):
        """
        Start a service
        
        Args:
            service_name: Name of the service
            
        Returns:
            bool: True if successful
            
        Raises:
            ServiceOperationError: If operation fails
        """
        try:
            service = self.get_service(service_name)
            if not service:
                raise ServiceOperationError(f"Service {service_name} not found")
            
            if service.State == 'Running':
                return True
                
            result = service.StartService()
            if result[0] == 0:  # 0 indicates success
                self.logger.info(f"Service {service_name} started successfully")
                return True
            else:
                raise ServiceOperationError(f"Failed to start service {service_name}: error code {result[0]}")
        except Exception as e:
            self.logger.error(f"Error starting service {service_name}: {str(e)}")
            raise ServiceOperationError(f"Failed to start service {service_name}: {str(e)}")
    
    def stop_service(self, service_name):
        """
        Stop a service
        
        Args:
            service_name: Name of the service
            
        Returns:
            bool: True if successful
            
        Raises:
            ServiceOperationError: If operation fails
        """
        try:
            service = self.get_service(service_name)
            if not service:
                raise ServiceOperationError(f"Service {service_name} not found")
            
            if service.State == 'Stopped':
                return True
                
            result = service.StopService()
            if result[0] == 0:  # 0 indicates success
                self.logger.info(f"Service {service_name} stopped successfully")
                return True
            else:
                raise ServiceOperationError(f"Failed to stop service {service_name}: error code {result[0]}")
        except Exception as e:
            self.logger.error(f"Error stopping service {service_name}: {str(e)}")
            raise ServiceOperationError(f"Failed to stop service {service_name}: {str(e)}")
    
    def restart_service(self, service_name):
        """
        Restart a service
        
        Args:
            service_name: Name of the service
            
        Returns:
            bool: True if successful
            
        Raises:
            ServiceOperationError: If operation fails
        """
        try:
            self.stop_service(service_name)
            # Sleep to ensure service has time to stop
            time.sleep(2)
            self.start_service(service_name)
            return True
        except ServiceOperationError as e:
            raise e
        except Exception as e:
            self.logger.error(f"Error restarting service {service_name}: {str(e)}")
            raise ServiceOperationError(f"Failed to restart service {service_name}: {str(e)}")
    
    def change_service_startup(self, service_name, start_mode):
        """
        Change service startup mode
        
        Args:
            service_name: Name of the service
            start_mode: Startup mode (Auto, Manual, Disabled)
            
        Returns:
            bool: True if successful
            
        Raises:
            ServiceOperationError: If operation fails
        """
        valid_modes = ['Auto', 'Manual', 'Disabled']
        if start_mode not in valid_modes:
            raise ServiceOperationError(f"Invalid startup mode: {start_mode}. Must be one of {valid_modes}")
        
        try:
            service = self.get_service(service_name)
            if not service:
                raise ServiceOperationError(f"Service {service_name} not found")
                
            result = service.ChangeStartMode(start_mode)
            if result[0] == 0:  # 0 indicates success
                self.logger.info(f"Service {service_name} startup mode changed to {start_mode}")
                return True
            else:
                raise ServiceOperationError(f"Failed to change startup mode for {service_name}: error code {result[0]}")
        except Exception as e:
            self.logger.error(f"Error changing startup mode for {service_name}: {str(e)}")
            raise ServiceOperationError(f"Failed to change startup mode for {service_name}: {str(e)}")


# WMI API Class - Main handler for WMI operations
class WmiApi:
    def __init__(self):
        """Initialize WMI API"""
        self.logger = setup_wmi_logger()
        self.logger.info("Initializing WMI API")

        # Initialize COM for this thread
        pythoncom.CoInitialize()
        
        try:
            self.c = wmi.WMI()
            self.logger.info("WMI connection established")
        except Exception as e:
            self.logger.error(f"Failed to establish WMI connection: {str(e)}")
            # Uninitialize COM if initialization fails
            pythoncom.CoUninitialize()
            raise ConnectionError(f"Failed to establish WMI connection: {str(e)}")
        
        # Initialize collectors
        self.collectors = {
            'system': SystemInfoCollector(self.c, self.logger),
            'hardware': HardwareInfoCollector(self.c, self.logger),
            'network': NetworkInfoCollector(self.c, self.logger),
            'processes': ProcessInfoCollector(self.c, self.logger),
            'services': ServiceInfoCollector(self.c, self.logger),
            'events': EventLogCollector(self.c, self.logger),
            'tasks': ScheduledTaskCollector(self.c, self.logger),
            'diskspace': DiskSpaceCollector(self.c, self.logger),
            'software': InstalledSoftwareCollector(self.c, self.logger),
            'users': UserAccountCollector(self.c, self.logger)
        }
        
        # Initialize service manager
        self.service_manager = ServiceManager(self.c, self.logger)
    
    def __del__(self):
        """Clean up COM initialization when object is destroyed"""
        pythoncom.CoUninitialize()
    
    def collect_all_info(self):
        """
        Collect all system information
        
        Returns:
            dict: All system information
        """
        self.logger.info("Collecting all system information")
        results = {}
        
        for name, collector in self.collectors.items():
            try:
                results[name] = collector.collect()
            except WmiError as e:
                self.logger.error(f"Error collecting {name} information: {str(e)}")
                results[name] = {"error": str(e)}
        
        return results
    
    def collect_specific_info(self, categories):
        """
        Collect specific system information categories
        
        Args:
            categories: List of category names to collect
            
        Returns:
            dict: Requested information
        """
        self.logger.info(f"Collecting specific information: {categories}")
        results = {}
        
        for category in categories:
            if category not in self.collectors:
                results[category] = {"error": f"Invalid category: {category}"}
                continue
                
            try:
                results[category] = self.collectors[category].collect()
            except WmiError as e:
                self.logger.error(f"Error collecting {category} information: {str(e)}")
                results[category] = {"error": str(e)}
        
        return results
    
    def get_running_processes(self):
        """
        Get list of running processes
        
        Returns:
            list: Running processes
        """
        try:
            processes = self.collectors['processes'].collect()
            return processes
        except WmiError as e:
            self.logger.error(f"Error getting running processes: {str(e)}")
            raise
    
    def kill_process(self, process_id):
        """
        Kill a process by ID
        
        Args:
            process_id: Process ID to kill
            
        Returns:
            bool: True if successful
        """
        try:
            process_id = int(process_id)
            for process in self.c.Win32_Process(ProcessId=process_id):
                self.logger.info(f"Terminating process {process_id} ({process.Name})")
                result = process.Terminate()
                if result[0] == 0:  # 0 indicates success
                    return True
                else:
                    raise QueryError(f"Failed to terminate process {process_id}: error code {result[0]}")
            
            # If we get here, no matching process was found
            raise QueryError(f"Process with ID {process_id} not found")
        except Exception as e:
            self.logger.error(f"Error terminating process {process_id}: {str(e)}")
            raise QueryError(f"Failed to terminate process: {str(e)}")
    
    def start_service(self, service_name):
        """Wrapper for service_manager.start_service"""
        return self.service_manager.start_service(service_name)
    
    def stop_service(self, service_name):
        """Wrapper for service_manager.stop_service"""
        return self.service_manager.stop_service(service_name)
    
    def restart_service(self, service_name):
        """Wrapper for service_manager.restart_service"""
        return self.service_manager.restart_service(service_name)
    
    def change_service_startup(self, service_name, start_mode):
        """Wrapper for service_manager.change_service_startup"""
        return self.service_manager.change_service_startup(service_name, start_mode)


# Initialize the application
def initialize_app():
    """Initialize the application"""
    with app.app_context():
        migrate_db()
        init_db()
        verify_db_integrity()
        api_logger.info("Application initialized")


# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "ok", "timestamp": datetime.datetime.now().isoformat()})

@app.route('/')
def index():
    return jsonify({"message": "Windows Management Interface (WMI) Information Collection Tool"}), 200

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, password_hash, role, api_key FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        api_logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Check if api_key exists, generate if not
    api_key = user['api_key']
    if not api_key:
        api_key = secrets.token_hex(32)
        cursor.execute("UPDATE users SET api_key = ? WHERE id = ?", (api_key, user['id']))
        db.commit()

    # Generate token
    token = generate_token(user['id'], user['username'], user['role'])
    
    # Generate CSRF token
    csrf_token = generate_csrf_token()
    
    api_logger.info(f"User {username} logged in successfully")
    
    # Create response with both tokens
    response = jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "api_key": user['api_key']
        }
    })
    
    # Set CSRF token as a cookie
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    
    return response


@app.route('/api/auth/register', methods=['POST'])
@token_required
@admin_required
def register():
    """Register a new user (admin only)"""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'password', 'email', 'role']
    is_valid, error_message = validate_input(data, required_fields=required_fields)
    if not is_valid:
        return jsonify({"error": error_message}), 400
    
    # Sanitize input
    data = sanitize_input(data)
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role')
    
    # Validate role
    valid_roles = ['admin', 'user', 'readonly']
    if role not in valid_roles:
        return jsonify({"error": f"Invalid role. Must be one of {valid_roles}"}), 400
    
    # Hash password
    password_hash = generate_password_hash(password)
    
    # Generate API key
    api_key = secrets.token_hex(32)
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role, api_key) VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, email, role, api_key)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    
    api_logger.info(f"New user registered: {username} with role {role}")
    return jsonify({
        "message": "User registered successfully",
        "user": {
            "username": username,
            "email": email,
            "role": role,
            "api_key": api_key
        }
    }), 201


@app.route('/api/auth/reset-api-key', methods=['POST'])
@token_required
def reset_api_key():
    """Reset user's API key"""
    user_id = g.user.get('user_id')
    
    # Generate new API key
    new_api_key = secrets.token_hex(32)
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_api_key, user_id))
    db.commit()
    
    api_logger.info(f"API key reset for user ID {user_id}")
    return jsonify({
        "message": "API key reset successfully",
        "api_key": new_api_key
    })


@app.route('/api/wmi/system', methods=['GET'])
@api_key_required
@rate_limit
def get_system_info():
    """Get system information"""
    try:
        wmi_api = WmiApi()
        result = wmi_api.collect_specific_info(['system'])
        return jsonify(result)
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        api_logger.error(f"Error getting system info: {str(e)}")
        return jsonify({"error": "Failed to get system information"}), 500


@app.route('/api/wmi/hardware', methods=['GET'])
@api_key_required
@rate_limit
def get_hardware_info():
    """Get hardware information"""
    try:
        wmi_api = WmiApi()
        result = wmi_api.collect_specific_info(['hardware'])
        return jsonify(result)
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        api_logger.error(f"Error getting hardware info: {str(e)}")
        return jsonify({"error": "Failed to get hardware information"}), 500


@app.route('/api/wmi/processes', methods=['GET'])
@api_key_required
@rate_limit
def get_processes():
    """Get running processes"""
    try:
        wmi_api = WmiApi()
        result = wmi_api.get_running_processes()
        return jsonify(result)
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        api_logger.error(f"Error getting processes: {str(e)}")
        return jsonify({"error": "Failed to get process information"}), 500


@app.route('/api/wmi/processes/<int:process_id>', methods=['DELETE'])
@api_key_required
@rate_limit
@admin_required
def kill_process(process_id):
    """Kill a process by ID (admin only)"""
    try:
        wmi_api = WmiApi()
        wmi_api.kill_process(process_id)
        return jsonify({"message": f"Process {process_id} terminated successfully"})
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except QueryError as e:
        api_logger.error(f"Error killing process: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        api_logger.error(f"Unexpected error killing process: {str(e)}")
        return jsonify({"error": "Failed to terminate process"}), 500


@app.route('/api/wmi/services', methods=['GET'])
@api_key_required
@rate_limit
def get_services():
    """Get services information"""
    try:
        wmi_api = WmiApi()
        result = wmi_api.collect_specific_info(['services'])
        return jsonify(result)
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        api_logger.error(f"Error getting services: {str(e)}")
        return jsonify({"error": "Failed to get service information"}), 500


@app.route('/api/wmi/services/<service_name>/start', methods=['POST'])
@api_key_required
@rate_limit
@admin_required
def start_service(service_name):
    """Start a service (admin only)"""
    try:
        wmi_api = WmiApi()
        wmi_api.start_service(service_name)
        return jsonify({"message": f"Service {service_name} started successfully"})
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except ServiceOperationError as e:
        api_logger.error(f"Error starting service: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        api_logger.error(f"Unexpected error starting service: {str(e)}")
        return jsonify({"error": "Failed to start service"}), 500


@app.route('/api/wmi/services/<service_name>/stop', methods=['POST'])
@api_key_required
@rate_limit
@admin_required
def stop_service(service_name):
    """Stop a service (admin only)"""
    try:
        wmi_api = WmiApi()
        wmi_api.stop_service(service_name)
        return jsonify({"message": f"Service {service_name} stopped successfully"})
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except ServiceOperationError as e:
        api_logger.error(f"Error stopping service: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        api_logger.error(f"Unexpected error stopping service: {str(e)}")
        return jsonify({"error": "Failed to stop service"}), 500


@app.route('/api/wmi/services/<service_name>/restart', methods=['POST'])
@api_key_required
@rate_limit
@admin_required
def restart_service(service_name):
    """Restart a service (admin only)"""
    try:
        wmi_api = WmiApi()
        wmi_api.restart_service(service_name)
        return jsonify({"message": f"Service {service_name} restarted successfully"})
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except ServiceOperationError as e:
        api_logger.error(f"Error restarting service: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        api_logger.error(f"Unexpected error restarting service: {str(e)}")
        return jsonify({"error": "Failed to restart service"}), 500


@app.route('/api/wmi/services/<service_name>/startup', methods=['PUT'])
@api_key_required
@rate_limit
@admin_required
def change_service_startup(service_name):
    """Change service startup mode (admin only)"""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.get_json()
    start_mode = data.get('start_mode')
    
    if not start_mode:
        return jsonify({"error": "Missing start_mode parameter"}), 400
    
    try:
        wmi_api = WmiApi()
        wmi_api.change_service_startup(service_name, start_mode)
        return jsonify({"message": f"Service {service_name} startup mode changed to {start_mode}"})
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except ServiceOperationError as e:
        api_logger.error(f"Error changing service startup: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        api_logger.error(f"Unexpected error changing service startup: {str(e)}")
        return jsonify({"error": "Failed to change service startup mode"}), 500


@app.route('/api/wmi/collect', methods=['POST'])
@api_key_required
@rate_limit
def collect_specific_info():
    """Collect specific WMI information"""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.get_json()
    categories = data.get('categories')
    
    if not categories or not isinstance(categories, list):
        return jsonify({"error": "Missing or invalid categories parameter"}), 400
    
    try:
        wmi_api = WmiApi()
        result = wmi_api.collect_specific_info(categories)
        return jsonify(result)
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        api_logger.error(f"Error collecting WMI info: {str(e)}")
        return jsonify({"error": "Failed to collect WMI information"}), 500


@app.route('/api/wmi/collect-all', methods=['GET'])
@api_key_required
@rate_limit
@admin_required
def collect_all_info():
    """Collect all WMI information (admin only)"""
    try:
        wmi_api = WmiApi()
        result = wmi_api.collect_all_info()
        return jsonify(result)
    except ConnectionError as e:
        api_logger.error(f"WMI connection error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        api_logger.error(f"Error collecting all WMI info: {str(e)}")
        return jsonify({"error": "Failed to collect all WMI information"}), 500


@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users():
    """Get all users (admin only)"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users")
    users = cursor.fetchall()
    
    result = []
    for user in users:
        result.append({
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "created_at": user['created_at']
        })
    
    return jsonify({"users": result})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    """Delete a user (admin only)"""
    # Prevent deleting yourself
    if g.user.get('user_id') == user_id:
        return jsonify({"error": "Cannot delete your own account"}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        return jsonify({"error": "User not found"}), 404
    
    # Delete user
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    
    api_logger.info(f"User ID {user_id} deleted by admin {g.user.get('username')}")
    return jsonify({"message": "User deleted successfully"})


@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@token_required
@admin_required
def update_user_role(user_id):
    """Update user role (admin only)"""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.get_json()
    role = data.get('role')
    
    # Validate role
    valid_roles = ['admin', 'user', 'readonly']
    if role not in valid_roles:
        return jsonify({"error": f"Invalid role. Must be one of {valid_roles}"}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        return jsonify({"error": "User not found"}), 404
    
    # Update role
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    db.commit()
    
    api_logger.info(f"User ID {user_id} role updated to {role} by admin {g.user.get('username')}")
    return jsonify({"message": f"User role updated to {role}"})


@app.route('/api/shutdown', methods=['POST'])
@token_required
@admin_required
def shutdown():
    """Gracefully shutdown the server (admin only)"""
    try:
        # Log the shutdown request
        api_logger.warning(f"Shutdown requested by {g.user.get('username')}")
        
        # Schedule the shutdown after the response is sent
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            api_logger.info('Not running with the Werkzeug Server')
            raise RuntimeError('Not running with the Werkzeug Server')
        
        func()
        return jsonify({'message': 'Server shutting down...'}), 200
    except Exception as e:
        api_logger.error(f"Shutdown failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found", "details": str(error)}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed", "details": str(error)}), 405

@app.errorhandler(500)
def internal_server_error(error):
    api_logger.error(f"Internal server error: {str(error)}")
    return jsonify({"error": "Internal server error", "details": str(error)}), 500


# Main entry point
if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='WMI API Service')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind the server to')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    # Initialize application
    initialize_app()
    
    # Start the Flask app
    app.run(host=args.host, port=args.port, debug=args.debug)

    sys.exit()
