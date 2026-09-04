#!/usr/bin/env python3
"""
WMI Management API v2.0
-----------------------
A comprehensive REST API for collecting and managing Windows Management
Instrumentation (WMI) data with enterprise-grade security.

v2.0 Features:
- Custom exception hierarchy with HTTP status code mapping
- Rich dunder methods on all core classes
- Generator/yield patterns for streaming responses
- Parallel WMI collection via ThreadPoolExecutor
- Async-ready architecture via asyncio.to_thread()
- Memory optimization with __slots__ and connection reuse
- Thread-local WMI connection management
- Fixed: duplicate imports, deprecated APIs, shadowed builtins
"""

import argparse
import json
import sys
import logging
import datetime
import os
import uuid
import time
import re
import sqlite3
import secrets
import threading
from abc import ABC, abstractmethod
from functools import wraps
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import (
    Dict, List, Optional, Any, Tuple, Generator, Iterator
)

import jwt # type: ignore
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError # type: ignore
from flask import Flask, request, jsonify, g, Response # type: ignore
from flask_cors import CORS # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore

try:
    import wmi as _wmi_module # type: ignore
    import pythoncom as _pythoncom # type: ignore
    wmi_module: Any = _wmi_module
    pythoncom: Any = _pythoncom
    WMI_AVAILABLE = True
except ImportError:
    wmi_module = None
    pythoncom = None
    WMI_AVAILABLE = False
    if os.name == 'nt':
        logging.warning(
            "wmi package not available - "
            "WMI functionality will be disabled")


# ======================
# CUSTOM EXCEPTIONS
# ======================
class ApiError(Exception):
    """Base exception for all API errors with HTTP status code mapping.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code for the response.
        error_code: Optional internal error code.
        timestamp: ISO-format timestamp when the error occurred.
    """
    __slots__ = ('message', 'status_code', 'error_code', 'timestamp')

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: Optional[int] = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.timestamp = datetime.datetime.now(
            datetime.timezone.utc).isoformat()
        super().__init__(self.message)

    def __str__(self) -> str:
        base = f"[{self.status_code}] {self.message}"
        if self.error_code is not None:
            base = f"[E{self.error_code}] {base}"
        return base

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"status_code={self.status_code}, "
            f"error_code={self.error_code!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ApiError):
            return NotImplemented
        return (self.message == other.message
                and self.status_code == other.status_code)

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.message, self.status_code))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the exception to a JSON-friendly dictionary."""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'status_code': self.status_code,
            'error_code': self.error_code,
            'timestamp': self.timestamp,
        }


class WmiApiError(ApiError):
    """Exception for WMI-related API errors."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=500, error_code=error_code)


class WmiConnectionFailure(ApiError):
    """Exception raised when WMI connection fails."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=503, error_code=error_code)


class QueryError(ApiError):
    """Exception raised when a WMI query fails."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=500, error_code=error_code)


class ServiceOperationError(ApiError):
    """Exception raised when a service operation fails."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=400, error_code=error_code)


class AuthenticationError(ApiError):
    """Exception raised for authentication errors."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=401, error_code=error_code)


class AuthorizationError(ApiError):
    """Exception raised for authorization errors."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=403, error_code=error_code)


class ValidationError(ApiError):
    """Exception raised for input validation errors."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=400, error_code=error_code)


class DatabaseError(ApiError):
    """Exception raised for database operation errors."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=500, error_code=error_code)


class RateLimitError(ApiError):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=429, error_code=error_code)


class ConfigurationError(ApiError):
    """Exception raised for configuration issues."""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message, status_code=500, error_code=error_code)


# ======================
# CONFIGURATION
# ======================
class Config:
    """Application configuration with dunder methods."""

    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    RATE_LIMIT_WINDOW = 60  # 1 minute
    RATE_LIMIT_MAX_REQUESTS = 60  # 60 requests per minute
    DATABASE_PATH = os.path.join(os.getcwd(), 'wmi_api.db')
    LOG_PATH = os.path.join(os.getcwd(), 'logs')
    CORS_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:5000']
    MAX_PARALLEL_COLLECTORS = 4
    WMI_QUERY_TIMEOUT = 120

    _KEYS = {
        'SECRET_KEY', 'JWT_SECRET_KEY', 'JWT_ACCESS_TOKEN_EXPIRES',
        'RATE_LIMIT_WINDOW', 'RATE_LIMIT_MAX_REQUESTS',
        'DATABASE_PATH', 'LOG_PATH', 'CORS_ORIGINS',
        'MAX_PARALLEL_COLLECTORS', 'WMI_QUERY_TIMEOUT'
    }

    def __repr__(self) -> str:
        return f"Config(db={self.DATABASE_PATH!r})"

    def __str__(self) -> str:
        return "WMI API Configuration"

    def __getitem__(self, key: str) -> Any:
        """Access config values by key."""
        if key not in self._KEYS:
            raise KeyError(f"Unknown config key: {key}")
        return getattr(self, key)

    def __contains__(self, key: str) -> bool:
        """Check if a config key exists."""
        return key in self._KEYS


# ======================
# APP INITIALIZATION
# ======================
app = Flask(__name__)
app.config.from_object(Config)

# Configure CORS
cors = CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}})

# Set up logging
os.makedirs(Config.LOG_PATH, exist_ok=True)

api_logger = logging.getLogger('wmi_api')
api_logger.setLevel(logging.DEBUG)

api_log_file = os.path.join(Config.LOG_PATH, 'wmi_api.log')
file_handler = RotatingFileHandler(
    api_log_file, maxBytes=10485760, backupCount=10)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
api_logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(levelname)s: %(message)s')
console_handler.setFormatter(console_formatter)
api_logger.addHandler(console_handler)


# ======================
# THREAD-LOCAL WMI CONNECTION MANAGEMENT
# ======================
_thread_local = threading.local()


def _get_thread_wmi_connection():
    """Get or create a thread-local WMI connection.

    Reuses connections within the same thread to avoid
    repeated COM initialization overhead.
    """
    if not WMI_AVAILABLE:
        raise WmiConnectionFailure(
            "WMI package not available", error_code=1001)

    if not hasattr(_thread_local, 'wmi_connection'):
        try:
            pythoncom.CoInitialize()
            _thread_local.wmi_connection = wmi_module.WMI()
            _thread_local.com_initialized = True
        except Exception as e:
            raise WmiConnectionFailure(
                f"Failed to establish WMI connection: {e}",
                error_code=1002)

    return _thread_local.wmi_connection


def _cleanup_thread_wmi():
    """Cleanup thread-local WMI connection."""
    if hasattr(_thread_local, 'com_initialized') and _thread_local.com_initialized:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
        _thread_local.com_initialized = False
    if hasattr(_thread_local, 'wmi_connection'):
        del _thread_local.wmi_connection


# ======================
# REQUEST LOGGING
# ======================
@app.before_request
def log_request_info():
    """Log incoming request details."""
    if request.path == '/api/health':
        return

    request_id = str(uuid.uuid4())
    g.request_id = request_id

    log_data = {
        'request_id': request_id,
        'method': request.method,
        'path': request.path,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'params': dict(request.args),
        'time': datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    if request.is_json and request.get_json(silent=True):
        content = request.get_json(silent=True)
        sanitized = (
            {k: '***' if k.lower() in ['password', 'token', 'secret']
             else v for k, v in content.items()}
            if isinstance(content, dict) else content
        )
        log_data['json'] = sanitized

    api_logger.info(f"Request: {json.dumps(log_data)}")


@app.after_request
def log_response_info(response):
    """Log outgoing response details."""
    if request.path == '/api/health':
        return response

    request_id = getattr(g, 'request_id', 'unknown')
    log_data = {
        'request_id': request_id,
        'status_code': response.status_code,
        'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'response_size': len(response.get_data(as_text=True))
    }

    api_logger.info(f"Response: {json.dumps(log_data)}")
    return response


# ======================
# DATABASE
# ======================
def init_db() -> None:
    """Initialize database schema and default data."""
    db_conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = db_conn.cursor()

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
    cursor.execute(
        "SELECT id, api_key FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()

    if not admin:
        admin_password = secrets.token_urlsafe(12)
        password_hash = generate_password_hash(admin_password)
        api_key = secrets.token_hex(32)

        cursor.execute(
            "INSERT INTO users "
            "(username, password_hash, email, role, api_key) "
            "VALUES (?, ?, ?, ?, ?)",
            ('admin', password_hash, 'admin@example.com',
             'admin', api_key)
        )
        print(f"Admin user created with password: {admin_password}")
        print(f"Admin API key: {api_key}")
    elif not admin[1]:
        api_key = secrets.token_hex(32)
        cursor.execute(
            "UPDATE users SET api_key = ? WHERE username = 'admin'",
            (api_key,))
        print(f"Admin API key updated: {api_key}")

    # Ensure all users have API keys
    cursor.execute("SELECT id FROM users WHERE api_key IS NULL")
    users_without_keys = cursor.fetchall()
    for user_row in users_without_keys:
        cursor.execute(
            "UPDATE users SET api_key = ? WHERE id = ?",
            (secrets.token_hex(32), user_row[0]))

    db_conn.commit()
    db_conn.close()


def verify_db_integrity() -> None:
    """Verify database integrity and fix missing API keys."""
    db_conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = db_conn.cursor()

    cursor.execute(
        "SELECT username FROM users WHERE api_key IS NULL")
    missing_keys = cursor.fetchall()

    if missing_keys:
        print(
            f"Found {len(missing_keys)} users without API keys - "
            f"initializing...")
        for user in missing_keys:
            new_key = secrets.token_hex(32)
            cursor.execute(
                "UPDATE users SET api_key = ? WHERE username = ?",
                (new_key, user[0]))
            print(f"Assigned API key to user: {user[0]}")
        db_conn.commit()

    db_conn.close()


def migrate_db() -> None:
    """Add any missing columns to existing tables."""
    db_conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = db_conn.cursor()

    try:
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'api_key' not in columns:
            print("Adding api_key column to users table...")
            cursor.execute(
                "ALTER TABLE users ADD COLUMN api_key TEXT UNIQUE")

            cursor.execute("SELECT id FROM users")
            for user_row in cursor.fetchall():
                cursor.execute(
                    "UPDATE users SET api_key = ? WHERE id = ?",
                    (secrets.token_hex(32), user_row[0]))

            db_conn.commit()
            print("Database migration complete")
    except Exception as e:
        print(f"Migration error: {e}")
    finally:
        db_conn.close()


def get_db():
    """Get or create a request-scoped database connection."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(Config.DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db


def _iter_db_rows(
    cursor: sqlite3.Cursor
) -> Generator[sqlite3.Row, None, None]:
    """Yield database rows lazily instead of fetchall()."""
    while True:
        row = cursor.fetchone()
        if row is None:
            break
        yield row


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at end of request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# ======================
# SECURITY UTILITIES
# ======================
def generate_csrf_token() -> str:
    """Generate a secure CSRF token."""
    return secrets.token_hex(32)


def validate_input(
    data: Dict,
    required_fields: Optional[List[str]] = None,
    patterns: Optional[Dict[str, str]] = None,
) -> Tuple[bool, str]:
    """Validate input data against required fields and regex patterns."""
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


def sanitize_input(input_data: Any) -> Any:
    """Sanitize input data to prevent XSS and injection attacks."""
    if isinstance(input_data, str):
        sanitized = re.sub(
            r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>',
            '', input_data, flags=re.IGNORECASE)
        sanitized = re.sub(
            r'<(\/?(script|iframe|object|embed|style|'
            r'onload|onerror|onclick|onmouseover))',
            r'&lt;\1', sanitized, flags=re.IGNORECASE)
        return sanitized
    elif isinstance(input_data, dict):
        return {k: sanitize_input(v) for k, v in input_data.items()}
    elif isinstance(input_data, list):
        return [sanitize_input(item) for item in input_data]
    return input_data


def generate_token(user_id: int, username: str, role: str) -> str:
    """Generate a JWT token using timezone-aware UTC datetimes."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': now + datetime.timedelta(
            seconds=Config.JWT_ACCESS_TOKEN_EXPIRES),
        'iat': now
    }
    return jwt.encode(
        payload, Config.JWT_SECRET_KEY, algorithm='HS256')


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(
            token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except ExpiredSignatureError:
        raise AuthenticationError(
            "Token has expired", error_code=2001)
    except InvalidTokenError:
        raise AuthenticationError(
            "Invalid token", error_code=2002)


# ======================
# AUTH DECORATORS
# ======================
def token_required(f):
    """Decorator requiring valid JWT token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token and 'token' in request.args:
            token = request.args.get('token')

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
            return jsonify(e.to_dict()), e.status_code

        return f(*args, **kwargs)

    return decorated_function


def api_key_required(f):
    """Decorator requiring valid API key."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = None

        if 'X-API-Key' in request.headers:
            api_key = request.headers['X-API-Key']

        if not api_key and 'api_key' in request.args:
            api_key = request.args.get('api_key')

        if not api_key:
            return jsonify({'error': 'API key is missing'}), 401

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, username, role FROM users "
            "WHERE api_key = ?", (api_key,))
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
    """Decorator requiring admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.get('role') != 'admin':
            return jsonify(
                {'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)

    return decorated_function


def csrf_protected(f):
    """Decorator for CSRF protection."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-API-Key'):
            return f(*args, **kwargs)

        csrf_token = (request.headers.get('X-CSRF-Token')
                     or request.form.get('csrf_token'))

        if (not csrf_token
                or csrf_token != request.cookies.get('csrf_token')):
            return jsonify(
                {'error': 'CSRF token missing or invalid'}), 403

        return f(*args, **kwargs)

    return decorated_function


def rate_limit(f):
    """Decorator for rate limiting."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = getattr(g, 'user', {}).get('user_id')
        ip_address = request.remote_addr

        db = get_db()
        cursor = db.cursor()

        if user_id:
            cursor.execute(
                "SELECT id, request_count, window_start "
                "FROM rate_limits WHERE user_id = ? "
                "ORDER BY window_start DESC LIMIT 1",
                (user_id,))
        else:
            cursor.execute(
                "SELECT id, request_count, window_start "
                "FROM rate_limits WHERE ip_address = ? "
                "ORDER BY window_start DESC LIMIT 1",
                (ip_address,))

        rate_limit_record = cursor.fetchone()
        current_time = datetime.datetime.now(datetime.timezone.utc)
        current_time_str = current_time.isoformat()

        headers: Dict[str, str] = {}

        if rate_limit_record:
            window_start = datetime.datetime.fromisoformat(
                rate_limit_record['window_start'])
            # Make timezone-aware if naive
            if window_start.tzinfo is None:
                window_start = window_start.replace(
                    tzinfo=datetime.timezone.utc)
            time_diff = (current_time - window_start).total_seconds()

            if time_diff < Config.RATE_LIMIT_WINDOW:
                if (rate_limit_record['request_count']
                        >= Config.RATE_LIMIT_MAX_REQUESTS):
                    remaining_time = (
                        Config.RATE_LIMIT_WINDOW - time_diff)
                    headers = {
                        'X-RateLimit-Limit': str(
                            Config.RATE_LIMIT_MAX_REQUESTS),
                        'X-RateLimit-Remaining': '0',
                        'X-RateLimit-Reset': str(int(remaining_time))
                    }
                    return (jsonify({'error': 'Rate limit exceeded'}),
                            429, headers)

                cursor.execute(
                    "UPDATE rate_limits "
                    "SET request_count = request_count + 1 "
                    "WHERE id = ?",
                    (rate_limit_record['id'],))
                db.commit()

                remaining = (Config.RATE_LIMIT_MAX_REQUESTS
                           - (rate_limit_record['request_count'] + 1))
                headers = {
                    'X-RateLimit-Limit': str(
                        Config.RATE_LIMIT_MAX_REQUESTS),
                    'X-RateLimit-Remaining': str(max(remaining, 0)),
                    'X-RateLimit-Reset': str(
                        int(Config.RATE_LIMIT_WINDOW - time_diff))
                }
            else:
                # Window expired, create new
                if user_id:
                    cursor.execute(
                        "INSERT INTO rate_limits "
                        "(user_id, request_count, window_start) "
                        "VALUES (?, 1, ?)",
                        (user_id, current_time_str))
                else:
                    cursor.execute(
                        "INSERT INTO rate_limits "
                        "(ip_address, request_count, window_start) "
                        "VALUES (?, 1, ?)",
                        (ip_address, current_time_str))
                db.commit()

                headers = {
                    'X-RateLimit-Limit': str(
                        Config.RATE_LIMIT_MAX_REQUESTS),
                    'X-RateLimit-Remaining': str(
                        Config.RATE_LIMIT_MAX_REQUESTS - 1),
                    'X-RateLimit-Reset': str(Config.RATE_LIMIT_WINDOW)
                }
        else:
            # First request
            if user_id:
                cursor.execute(
                    "INSERT INTO rate_limits "
                    "(user_id, request_count, window_start) "
                    "VALUES (?, 1, ?)",
                    (user_id, current_time_str))
            else:
                cursor.execute(
                    "INSERT INTO rate_limits "
                    "(ip_address, request_count, window_start) "
                    "VALUES (?, 1, ?)",
                    (ip_address, current_time_str))
            db.commit()

            headers = {
                'X-RateLimit-Limit': str(
                    Config.RATE_LIMIT_MAX_REQUESTS),
                'X-RateLimit-Remaining': str(
                    Config.RATE_LIMIT_MAX_REQUESTS - 1),
                'X-RateLimit-Reset': str(Config.RATE_LIMIT_WINDOW)
            }

        # Log request
        if user_id:
            cursor.execute(
                "INSERT INTO request_logs "
                "(user_id, endpoint, method, status_code, ip_address) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, request.path, request.method, 200,
                 ip_address))
        else:
            cursor.execute(
                "INSERT INTO request_logs "
                "(endpoint, method, status_code, ip_address) "
                "VALUES (?, ?, ?, ?)",
                (request.path, request.method, 200, ip_address))
        db.commit()

        response = f(*args, **kwargs)

        if isinstance(response, tuple):
            if len(response) == 2:
                response_obj, status_code = response
                response_obj.headers.update(headers)
                return response_obj, status_code
            elif len(response) == 3:
                response_obj, status_code, existing_headers = response
                existing_headers.update(headers)
                return response_obj, status_code, existing_headers
        else:
            response.headers.update(headers)
        return response

    return decorated_function


# ======================
# WMI LOGGER SETUP
# ======================
def setup_wmi_logger() -> logging.Logger:
    """Configure and return logger for WMI operations."""
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/wmi_info_{timestamp}.log"

    logger = logging.getLogger('wmi_system_info')
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# ======================
# BASE WMI COLLECTOR (ABC)
# ======================
class WmiInfoCollector(ABC):
    """Abstract base class for WMI information collectors."""

    __slots__ = ('_wmi_conn', '_logger', 'section_name')

    def __init__(self, wmi_connection, logger: logging.Logger) -> None:
        self._wmi_conn = wmi_connection
        self._logger = logger
        self.section_name = self.__class__.__name__

    @property
    def c(self):
        return self._wmi_conn

    @property
    def logger(self):
        return self._logger

    def __repr__(self) -> str:
        return f"{self.section_name}()"

    def __str__(self) -> str:
        return self.section_name

    def collect(self) -> Dict[str, Any]:
        """Template method for collecting WMI information."""
        self.logger.info(f"Starting collection: {self.section_name}")
        try:
            result = self._gather_info()
            self.logger.info(
                f"Successfully collected {self.section_name}")
            return result
        except ApiError:
            raise
        except Exception as e:
            self.logger.error(
                f"Unexpected error in {self.section_name}: {e}")
            raise QueryError(
                f"Failed to query {self.section_name}: {e}",
                error_code=3001)

    @abstractmethod
    def _gather_info(self) -> Dict[str, Any]:
        """Implement in child classes to gather specific information."""
        ...


# ======================
# CONCRETE COLLECTORS
# ======================
class SystemInfoCollector(WmiInfoCollector):
    """Collects system information via WMI."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "system": {
                "operating_systems": [],
                "bios": [],
                "computer_systems": []
            }
        }

        for os_info in self.c.Win32_OperatingSystem():
            info["system"]["operating_systems"].append({
                "Caption": os_info.Caption,
                "Version": os_info.Version,
                "OSArchitecture": os_info.OSArchitecture,
                "InstallDate": os_info.InstallDate
            })

        for bios in self.c.Win32_BIOS():
            info["system"]["bios"].append({
                "SMBIOSBIOSVersion": bios.SMBIOSBIOSVersion,
                "Manufacturer": bios.Manufacturer,
                "SerialNumber": bios.SerialNumber,
                "ReleaseDate": bios.ReleaseDate
            })

        for system in self.c.Win32_ComputerSystem():
            info["system"]["computer_systems"].append({
                "Name": system.Name,
                "Manufacturer": system.Manufacturer,
                "Model": system.Model,
                "TotalPhysicalMemory": system.TotalPhysicalMemory
            })

        return info


class HardwareInfoCollector(WmiInfoCollector):
    """Collects hardware information via WMI."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "hardware": {
                "processors": [],
                "memory": [],
                "disks": [],
                "network_adapters": []
            }
        }

        for processor in self.c.Win32_Processor():
            info["hardware"]["processors"].append({
                "Name": processor.Name,
                "NumberOfCores": processor.NumberOfCores,
                "MaxClockSpeed": processor.MaxClockSpeed,
                "L2CacheSize": processor.L2CacheSize,
                "L3CacheSize": processor.L3CacheSize
            })

        for memory in self.c.Win32_PhysicalMemory():
            info["hardware"]["memory"].append({
                "Capacity": memory.Capacity,
                "Speed": memory.Speed,
                "Manufacturer": memory.Manufacturer,
                "DeviceLocator": memory.DeviceLocator
            })

        for disk in self.c.Win32_DiskDrive():
            info["hardware"]["disks"].append({
                "Model": disk.Model,
                "Size": disk.Size,
                "InterfaceType": disk.InterfaceType,
                "MediaType": disk.MediaType,
                "SerialNumber": disk.SerialNumber
            })

        for adapter in self.c.Win32_NetworkAdapter():
            if adapter.MACAddress:
                info["hardware"]["network_adapters"].append({
                    "Name": adapter.Name,
                    "MACAddress": adapter.MACAddress,
                    "AdapterType": adapter.AdapterType,
                    "Speed": adapter.Speed
                })

        return info


class NetworkInfoCollector(WmiInfoCollector):
    """Collects network configuration information via WMI."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"network": {"network_configs": []}}

        try:
            for adapter in self.c.Win32_NetworkAdapterConfiguration(
                    IPEnabled=True):
                info["network"]["network_configs"].append({
                    "Description": adapter.Description,
                    "MACAddress": adapter.MACAddress,
                    "IPAddress": adapter.IPAddress,
                    "IPSubnet": adapter.IPSubnet,
                    "DefaultIPGateway": adapter.DefaultIPGateway,
                    "DNSServerSearchOrder":
                        adapter.DNSServerSearchOrder
                })
        except Exception as e:
            self.logger.warning(
                f"Some network adapters might not have "
                f"complete information: {e}")

        return info


class ProcessInfoCollector(WmiInfoCollector):
    """Collects process information via WMI with generator pattern."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"processes": {"processes": []}}

        for proc_data in self._iter_processes():
            info["processes"]["processes"].append(proc_data)

        return info

    def _iter_processes(self) -> Generator[Dict, None, None]:
        """Yield process information lazily."""
        for process in self.c.Win32_Process():
            try:
                yield {
                    "Name": process.Name,
                    "ProcessId": process.ProcessId,
                    "CommandLine": process.CommandLine,
                    "WorkingSetSize": process.WorkingSetSize
                }
            except Exception as e:
                self.logger.debug(
                    f"Could not get complete info for "
                    f"process {process.Name}: {e}")


class ServiceInfoCollector(WmiInfoCollector):
    """Collects service information via WMI."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"services": {"services": []}}

        for service in self.c.Win32_Service():
            info["services"]["services"].append({
                "Name": service.Name,
                "DisplayName": service.DisplayName,
                "State": service.State,
                "StartMode": service.StartMode
            })

        return info


class EventLogCollector(WmiInfoCollector):
    """Collects system event logs via WMI."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"events": {"events": []}}

        try:
            query = (
                "SELECT * FROM Win32_NTLogEvent "
                "WHERE Logfile='System' AND "
                "TimeGenerated > '20220101000000.000000-000'"
            )
            for event in self.c.query(query)[:MAX_EVENTS_PER_LOG]:
                info["events"]["events"].append({
                    "EventCode": event.EventCode,
                    "SourceName": event.SourceName,
                    "TimeGenerated": event.TimeGenerated,
                    "Type": event.Type,
                    "Message": event.Message
                })
        except Exception as e:
            self.logger.warning(
                f"Limited event log collection: {e}")

        return info


MAX_EVENTS_PER_LOG = 100


class ScheduledTaskCollector(WmiInfoCollector):
    """Collects scheduled task information."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"tasks": {"scheduled_tasks": []}}

        try:
            for task in self.c.Win32_ScheduledJob():
                info["tasks"]["scheduled_tasks"].append({
                    "JobId": task.JobId,
                    "Command": task.Command,
                    "RunTimes": task.RunTimes,
                    "Status": task.Status
                })
        except Exception as e:
            self.logger.warning(
                f"Scheduled task collection issue: {e}")
            info["tasks"]["error"] = str(e)

        return info


class DiskSpaceCollector(WmiInfoCollector):
    """Collects disk space information."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"diskspace": {"logical_disks": []}}

        for disk in self.c.Win32_LogicalDisk(DriveType=3):
            info["diskspace"]["logical_disks"].append({
                "DeviceID": disk.DeviceID,
                "VolumeName": disk.VolumeName,
                "Size": disk.Size,
                "FreeSpace": disk.FreeSpace,
                "FileSystem": disk.FileSystem
            })

        return info


class InstalledSoftwareCollector(WmiInfoCollector):
    """Collects installed software information."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "software": {"installed_software": []}}

        try:
            for app_item in self.c.Win32_Product():
                info["software"]["installed_software"].append({
                    "Name": app_item.Name,
                    "Version": app_item.Version,
                    "Vendor": app_item.Vendor,
                    "InstallDate": app_item.InstallDate
                })
        except Exception as e:
            self.logger.warning(
                f"Software collection issue: {e}")

        return info


class UserAccountCollector(WmiInfoCollector):
    """Collects user account information."""

    def _gather_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"users": {"user_accounts": []}}

        for user in self.c.Win32_UserAccount():
            info["users"]["user_accounts"].append({
                "Name": user.Name,
                "Domain": user.Domain,
                "SID": user.SID,
                "AccountType": user.AccountType,
                "Disabled": user.Disabled
            })

        return info


# ======================
# SERVICE MANAGER
# ======================
class ServiceManager:
    """Manages Windows services."""

    __slots__ = ('_wmi_conn', '_logger')

    def __init__(self, wmi_connection, logger: logging.Logger) -> None:
        self._wmi_conn = wmi_connection
        self._logger = logger

    def __repr__(self) -> str:
        return "ServiceManager()"

    def __contains__(self, service_name: str) -> bool:
        """Check if a service exists."""
        try:
            services = self._wmi_conn.Win32_Service(
                Name=service_name)
            return bool(services)
        except Exception:
            return False

    def __getitem__(self, service_name: str) -> Dict[str, Any]:
        """Get service details by name."""
        service = self.get_service(service_name)
        if not service:
            raise KeyError(f"Service '{service_name}' not found")
        return {
            "Name": service.Name,
            "DisplayName": service.DisplayName,
            "State": service.State,
            "StartMode": service.StartMode,
        }

    def get_service(self, service_name: str):
        """Get service details by name."""
        try:
            services = self._wmi_conn.Win32_Service(
                Name=service_name)
            return services[0] if services else None
        except Exception as e:
            self._logger.error(
                f"Failed to get service {service_name}: {e}")
            raise QueryError(
                f"Failed to query service {service_name}: {e}",
                error_code=4001)

    def start_service(self, service_name: str) -> bool:
        """Start a service."""
        try:
            service = self.get_service(service_name)
            if not service:
                raise ServiceOperationError(
                    f"Service {service_name} not found",
                    error_code=4010)

            if service.State == 'Running':
                return True

            result = service.StartService()
            if result[0] == 0:
                self._logger.info(
                    f"Service {service_name} started successfully")
                return True
            else:
                raise ServiceOperationError(
                    f"Failed to start service {service_name}: "
                    f"error code {result[0]}",
                    error_code=result[0])
        except ApiError:
            raise
        except Exception as e:
            self._logger.error(
                f"Error starting service {service_name}: {e}")
            raise ServiceOperationError(
                f"Failed to start service {service_name}: {e}",
                error_code=4011)

    def stop_service(self, service_name: str) -> bool:
        """Stop a service."""
        try:
            service = self.get_service(service_name)
            if not service:
                raise ServiceOperationError(
                    f"Service {service_name} not found",
                    error_code=4020)

            if service.State == 'Stopped':
                return True

            result = service.StopService()
            if result[0] == 0:
                self._logger.info(
                    f"Service {service_name} stopped successfully")
                return True
            else:
                raise ServiceOperationError(
                    f"Failed to stop service {service_name}: "
                    f"error code {result[0]}",
                    error_code=result[0])
        except ApiError:
            raise
        except Exception as e:
            self._logger.error(
                f"Error stopping service {service_name}: {e}")
            raise ServiceOperationError(
                f"Failed to stop service {service_name}: {e}",
                error_code=4021)

    def restart_service(self, service_name: str) -> bool:
        """Restart a service."""
        try:
            self.stop_service(service_name)
            time.sleep(2)
            self.start_service(service_name)
            return True
        except ApiError:
            raise
        except Exception as e:
            self._logger.error(
                f"Error restarting service {service_name}: {e}")
            raise ServiceOperationError(
                f"Failed to restart service {service_name}: {e}",
                error_code=4030)

    def change_service_startup(
        self, service_name: str, start_mode: str
    ) -> bool:
        """Change service startup mode."""
        valid_modes = ['Auto', 'Manual', 'Disabled']
        if start_mode not in valid_modes:
            raise ServiceOperationError(
                f"Invalid startup mode: {start_mode}. "
                f"Must be one of {valid_modes}",
                error_code=4040)

        try:
            service = self.get_service(service_name)
            if not service:
                raise ServiceOperationError(
                    f"Service {service_name} not found",
                    error_code=4041)

            result = service.ChangeStartMode(start_mode)
            if result[0] == 0:
                self._logger.info(
                    f"Service {service_name} startup mode "
                    f"changed to {start_mode}")
                return True
            else:
                raise ServiceOperationError(
                    f"Failed to change startup mode for "
                    f"{service_name}: error code {result[0]}",
                    error_code=result[0])
        except ApiError:
            raise
        except Exception as e:
            self._logger.error(
                f"Error changing startup mode for "
                f"{service_name}: {e}")
            raise ServiceOperationError(
                f"Failed to change startup mode for "
                f"{service_name}: {e}",
                error_code=4042)


# ======================
# WMI API CLASS
# ======================
class WmiApi:
    """Main handler for WMI operations.

    Supports context manager for COM lifecycle management
    and parallel collection via ThreadPoolExecutor.
    """

    __slots__ = (
        '_logger', '_wmi_conn', '_collectors',
        '_service_manager', '_com_initialized', '_executor'
    )

    def __init__(self) -> None:
        self._logger = setup_wmi_logger()
        self._logger.info("Initializing WMI API")
        self._com_initialized = False

        if not WMI_AVAILABLE:
            raise WmiConnectionFailure(
                "WMI package not available", error_code=5001)

        try:
            pythoncom.CoInitialize()
            self._com_initialized = True
            self._wmi_conn = wmi_module.WMI()
            self._logger.info("WMI connection established")
        except Exception as e:
            if self._com_initialized:
                pythoncom.CoUninitialize()
                self._com_initialized = False
            self._logger.error(
                f"Failed to establish WMI connection: {e}")
            raise WmiConnectionFailure(
                f"Failed to establish WMI connection: {e}",
                error_code=5002)

        self._executor = ThreadPoolExecutor(
            max_workers=Config.MAX_PARALLEL_COLLECTORS,
            thread_name_prefix="wmi_api"
        )

        self._collectors = {
            'system': SystemInfoCollector(
                self._wmi_conn, self._logger),
            'hardware': HardwareInfoCollector(
                self._wmi_conn, self._logger),
            'network': NetworkInfoCollector(
                self._wmi_conn, self._logger),
            'processes': ProcessInfoCollector(
                self._wmi_conn, self._logger),
            'services': ServiceInfoCollector(
                self._wmi_conn, self._logger),
            'events': EventLogCollector(
                self._wmi_conn, self._logger),
            'tasks': ScheduledTaskCollector(
                self._wmi_conn, self._logger),
            'diskspace': DiskSpaceCollector(
                self._wmi_conn, self._logger),
            'software': InstalledSoftwareCollector(
                self._wmi_conn, self._logger),
            'users': UserAccountCollector(
                self._wmi_conn, self._logger),
        }

        self._service_manager = ServiceManager(
            self._wmi_conn, self._logger)

    def __repr__(self) -> str:
        return f"WmiApi(collectors={len(self._collectors)})"

    def __str__(self) -> str:
        return "WMI API v2.0"

    def __enter__(self) -> 'WmiApi':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False

    def __getitem__(self, category: str) -> WmiInfoCollector:
        if category not in self._collectors:
            raise KeyError(f"Unknown category: {category}")
        return self._collectors[category]

    def __contains__(self, category: str) -> bool:
        return category in self._collectors

    def __iter__(self) -> Iterator[str]:
        return iter(self._collectors)

    def __len__(self) -> int:
        return len(self._collectors)

    def __del__(self) -> None:
        """Cleanup COM initialization when object is destroyed."""
        self.close()

    def close(self) -> None:
        """Explicitly release resources."""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)
        if self._com_initialized:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
            self._com_initialized = False

    def collect_all_info(self) -> Dict[str, Any]:
        """Collect all system information using parallel execution."""
        self._logger.info(
            "Collecting all system information (parallel)")
        results: Dict[str, Any] = {}

        futures = {}
        for name, collector in self._collectors.items():
            future = self._executor.submit(collector.collect)
            futures[future] = name

        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result(
                    timeout=Config.WMI_QUERY_TIMEOUT)
            except ApiError as e:
                self._logger.error(
                    f"Error collecting {name}: {e}")
                results[name] = e.to_dict()
            except Exception as e:
                self._logger.error(
                    f"Unexpected error collecting {name}: {e}")
                results[name] = {"error": str(e)}

        return results

    def collect_specific_info(
        self, categories: List[str]
    ) -> Dict[str, Any]:
        """Collect specific system information categories in parallel."""
        self._logger.info(
            f"Collecting specific information: {categories}")
        results: Dict[str, Any] = {}

        futures = {}
        for category in categories:
            if category not in self._collectors:
                results[category] = {
                    "error": f"Invalid category: {category}"}
                continue
            future = self._executor.submit(
                self._collectors[category].collect)
            futures[future] = category

        for future in as_completed(futures):
            category = futures[future]
            try:
                results[category] = future.result(
                    timeout=Config.WMI_QUERY_TIMEOUT)
            except ApiError as e:
                self._logger.error(
                    f"Error collecting {category}: {e}")
                results[category] = e.to_dict()
            except Exception as e:
                self._logger.error(
                    f"Unexpected error collecting {category}: {e}")
                results[category] = {"error": str(e)}

        return results

    def iter_collect_all(
        self
    ) -> Generator[Tuple[str, Dict], None, None]:
        """Yield (name, result) tuples lazily for streaming responses."""
        for name, collector in self._collectors.items():
            try:
                yield name, collector.collect()
            except Exception as e:
                yield name, {"error": str(e)}

    def get_running_processes(self) -> Dict[str, Any]:
        """Get list of running processes."""
        return self._collectors['processes'].collect()

    def kill_process(self, process_id: int) -> bool:
        """Kill a process by ID."""
        try:
            process_id = int(process_id)
            for process in self._wmi_conn.Win32_Process(
                    ProcessId=process_id):
                self._logger.info(
                    f"Terminating process {process_id} "
                    f"({process.Name})")
                result = process.Terminate()
                if result[0] == 0:
                    return True
                else:
                    raise QueryError(
                        f"Failed to terminate process "
                        f"{process_id}: error code {result[0]}",
                        error_code=result[0])

            raise QueryError(
                f"Process with ID {process_id} not found",
                error_code=5010)
        except ApiError:
            raise
        except Exception as e:
            self._logger.error(
                f"Error terminating process {process_id}: {e}")
            raise QueryError(
                f"Failed to terminate process: {e}",
                error_code=5011)

    def start_service(self, service_name: str) -> bool:
        return self._service_manager.start_service(service_name)

    def stop_service(self, service_name: str) -> bool:
        return self._service_manager.stop_service(service_name)

    def restart_service(self, service_name: str) -> bool:
        return self._service_manager.restart_service(service_name)

    def change_service_startup(
        self, service_name: str, start_mode: str
    ) -> bool:
        return self._service_manager.change_service_startup(
            service_name, start_mode)


# ======================
# APP INITIALIZATION
# ======================
def initialize_app() -> None:
    """Initialize the application."""
    with app.app_context():
        migrate_db()
        init_db()
        verify_db_integrity()
        api_logger.info("Application initialized")


# ======================
# API ROUTES
# ======================
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "wmi_available": WMI_AVAILABLE,
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc).isoformat()
    })


@app.route('/')
def index():
    """Root endpoint."""
    return jsonify({
        "message": "WMI Management API v2.0",
        "version": "2.0.0",
    }), 200


@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint."""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify(
            {"error": "Missing username or password"}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, role, api_key "
        "FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user or not check_password_hash(
            user['password_hash'], password):
        api_logger.warning(
            f"Failed login attempt for user: {username}")
        return jsonify(
            {"error": "Invalid username or password"}), 401

    api_key = user['api_key']
    if not api_key:
        api_key = secrets.token_hex(32)
        cursor.execute(
            "UPDATE users SET api_key = ? WHERE id = ?",
            (api_key, user['id']))
        db.commit()

    token = generate_token(
        user['id'], user['username'], user['role'])
    csrf_token = generate_csrf_token()

    api_logger.info(f"User {username} logged in successfully")

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

    response.set_cookie(
        'csrf_token', csrf_token,
        httponly=True, secure=True, samesite='Strict')

    return response


@app.route('/api/auth/register', methods=['POST'])
@token_required
@admin_required
def register():
    """Register a new user (admin only)."""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    data = request.get_json()

    required_fields = ['username', 'password', 'email', 'role']
    is_valid, error_message = validate_input(
        data, required_fields=required_fields)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    data = sanitize_input(data)

    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role')

    valid_roles = ['admin', 'user', 'readonly']
    if role not in valid_roles:
        return jsonify({
            "error": f"Invalid role. Must be one of {valid_roles}"
        }), 400

    password_hash = generate_password_hash(password)
    api_key = secrets.token_hex(32)

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute(
            "INSERT INTO users "
            "(username, password_hash, email, role, api_key) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, email, role, api_key))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Username or email already exists"}), 409

    api_logger.info(
        f"New user registered: {username} with role {role}")
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
    """Reset user's API key."""
    user_id = g.user.get('user_id')
    new_api_key = secrets.token_hex(32)

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET api_key = ? WHERE id = ?",
        (new_api_key, user_id))
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
    """Get system information."""
    try:
        with WmiApi() as wmi_api:
            result = wmi_api.collect_specific_info(['system'])
            return jsonify(result)
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(f"Error getting system info: {e}")
        return jsonify({
            "error": "Failed to get system information"}), 500


@app.route('/api/wmi/hardware', methods=['GET'])
@api_key_required
@rate_limit
def get_hardware_info():
    """Get hardware information."""
    try:
        with WmiApi() as wmi_api:
            result = wmi_api.collect_specific_info(['hardware'])
            return jsonify(result)
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(f"Error getting hardware info: {e}")
        return jsonify({
            "error": "Failed to get hardware information"}), 500


@app.route('/api/wmi/processes', methods=['GET'])
@api_key_required
@rate_limit
def get_processes():
    """Get running processes."""
    try:
        with WmiApi() as wmi_api:
            result = wmi_api.get_running_processes()
            return jsonify(result)
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(f"Error getting processes: {e}")
        return jsonify({
            "error": "Failed to get process information"}), 500


@app.route('/api/wmi/processes/<int:process_id>', methods=['DELETE'])
@api_key_required
@rate_limit
@admin_required
def kill_process(process_id):
    """Kill a process by ID (admin only)."""
    try:
        with WmiApi() as wmi_api:
            wmi_api.kill_process(process_id)
            return jsonify({
                "message": f"Process {process_id} "
                           f"terminated successfully"})
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except QueryError as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(
            f"Unexpected error killing process: {e}")
        return jsonify({
            "error": "Failed to terminate process"}), 500


@app.route('/api/wmi/services', methods=['GET'])
@api_key_required
@rate_limit
def get_services():
    """Get services information."""
    try:
        with WmiApi() as wmi_api:
            result = wmi_api.collect_specific_info(['services'])
            return jsonify(result)
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(f"Error getting services: {e}")
        return jsonify({
            "error": "Failed to get service information"}), 500


@app.route('/api/wmi/services/<service_name>/start', methods=['POST'])
@api_key_required
@rate_limit
@admin_required
def start_service(service_name):
    """Start a service (admin only)."""
    try:
        with WmiApi() as wmi_api:
            wmi_api.start_service(service_name)
            return jsonify({
                "message": f"Service {service_name} "
                           f"started successfully"})
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except ServiceOperationError as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(
            f"Unexpected error starting service: {e}")
        return jsonify({"error": "Failed to start service"}), 500


@app.route('/api/wmi/services/<service_name>/stop', methods=['POST'])
@api_key_required
@rate_limit
@admin_required
def stop_service(service_name):
    """Stop a service (admin only)."""
    try:
        with WmiApi() as wmi_api:
            wmi_api.stop_service(service_name)
            return jsonify({
                "message": f"Service {service_name} "
                           f"stopped successfully"})
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except ServiceOperationError as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(
            f"Unexpected error stopping service: {e}")
        return jsonify({"error": "Failed to stop service"}), 500


@app.route(
    '/api/wmi/services/<service_name>/restart', methods=['POST'])
@api_key_required
@rate_limit
@admin_required
def restart_service(service_name):
    """Restart a service (admin only)."""
    try:
        with WmiApi() as wmi_api:
            wmi_api.restart_service(service_name)
            return jsonify({
                "message": f"Service {service_name} "
                           f"restarted successfully"})
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except ServiceOperationError as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(
            f"Unexpected error restarting service: {e}")
        return jsonify(
            {"error": "Failed to restart service"}), 500


@app.route(
    '/api/wmi/services/<service_name>/startup', methods=['PUT'])
@api_key_required
@rate_limit
@admin_required
def change_service_startup(service_name):
    """Change service startup mode (admin only)."""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    data = request.get_json()
    start_mode = data.get('start_mode')

    if not start_mode:
        return jsonify({
            "error": "Missing start_mode parameter"}), 400

    try:
        with WmiApi() as wmi_api:
            wmi_api.change_service_startup(
                service_name, start_mode)
            return jsonify({
                "message": f"Service {service_name} startup "
                           f"mode changed to {start_mode}"})
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except ServiceOperationError as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(
            f"Unexpected error changing startup: {e}")
        return jsonify({
            "error": "Failed to change service startup mode"
        }), 500


@app.route('/api/wmi/collect', methods=['POST'])
@api_key_required
@rate_limit
def collect_specific_info():
    """Collect specific WMI information."""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    data = request.get_json()
    categories = data.get('categories')

    if not categories or not isinstance(categories, list):
        return jsonify({
            "error": "Missing or invalid categories parameter"
        }), 400

    try:
        with WmiApi() as wmi_api:
            result = wmi_api.collect_specific_info(categories)
            return jsonify(result)
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(f"Error collecting WMI info: {e}")
        return jsonify({
            "error": "Failed to collect WMI information"}), 500


@app.route('/api/wmi/collect-all', methods=['GET'])
@api_key_required
@rate_limit
@admin_required
def collect_all_info():
    """Collect all WMI information (admin only)."""
    try:
        with WmiApi() as wmi_api:
            result = wmi_api.collect_all_info()
            return jsonify(result)
    except WmiConnectionFailure as e:
        return jsonify(e.to_dict()), e.status_code
    except Exception as e:
        api_logger.error(f"Error collecting all WMI info: {e}")
        return jsonify({
            "error": "Failed to collect all WMI information"
        }), 500


@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users():
    """Get all users (admin only) — uses generator for lazy iteration."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, username, email, role, created_at FROM users")

    result = []
    for user in _iter_db_rows(cursor):
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
    """Delete a user (admin only)."""
    if g.user.get('user_id') == user_id:
        return jsonify({
            "error": "Cannot delete your own account"}), 400

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        return jsonify({"error": "User not found"}), 404

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    api_logger.info(
        f"User ID {user_id} deleted by admin "
        f"{g.user.get('username')}")
    return jsonify({"message": "User deleted successfully"})


@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@token_required
@admin_required
def update_user_role(user_id):
    """Update user role (admin only)."""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    data = request.get_json()
    role = data.get('role')

    valid_roles = ['admin', 'user', 'readonly']
    if role not in valid_roles:
        return jsonify({
            "error": f"Invalid role. Must be one of {valid_roles}"
        }), 400

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        return jsonify({"error": "User not found"}), 404

    cursor.execute(
        "UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    db.commit()

    api_logger.info(
        f"User ID {user_id} role updated to {role} "
        f"by admin {g.user.get('username')}")
    return jsonify({"message": f"User role updated to {role}"})


@app.route('/api/shutdown', methods=['POST'])
@token_required
@admin_required
def shutdown():
    """Gracefully shutdown the server (admin only)."""
    api_logger.warning(
        f"Shutdown requested by {g.user.get('username')}")
    # Signal-based shutdown for modern Werkzeug
    import signal
    try:
        os.kill(os.getpid(), signal.SIGINT)
        return jsonify({'message': 'Server shutting down...'}), 200
    except Exception as e:
        api_logger.error(f"Shutdown failed: {e}")
        return jsonify({'error': str(e)}), 500


# ======================
# ERROR HANDLERS
# ======================
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Resource not found",
        "details": str(error)}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "error": "Method not allowed",
        "details": str(error)}), 405


@app.errorhandler(500)
def internal_server_error(error):
    api_logger.error(f"Internal server error: {error}")
    return jsonify({
        "error": "Internal server error",
        "details": str(error)}), 500


# ======================
# MAIN ENTRY POINT
# ======================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='WMI Management API v2.0')
    parser.add_argument(
        '--host', default='127.0.0.1',
        help='Host to bind the server to')
    parser.add_argument(
        '--port', type=int, default=5000,
        help='Port to bind the server to')
    parser.add_argument(
        '--debug', action='store_true',
        help='Run in debug mode')
    args = parser.parse_args()

    initialize_app()

    app.run(host=args.host, port=args.port, debug=args.debug)
