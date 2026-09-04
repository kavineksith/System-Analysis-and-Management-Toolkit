#!/usr/bin/env python3
"""
Industrial-Grade System Analysis Tool v2.0
------------------------------------------
A comprehensive system monitoring and reporting tool that collects:
- CPU statistics
- Memory usage
- Disk information
- Network status
- Process details
- Battery information (where applicable)
- System information

Features:
- Modular architecture with generator-based data collection
- Parallel report generation via ThreadPoolExecutor
- Async network connectivity checks via asyncio
- Custom exception hierarchy with error codes and timestamps
- Dunder method rich classes (__repr__, __iter__, __len__, __slots__, etc.)
- Context manager support for resource cleanup
- Memory-optimized process iteration
- Comprehensive error handling
- Configurable logging
- JSON output with streaming support
- Interactive CLI
- File export capabilities
"""

import asyncio
import gc
import json
import os
import sys
import platform
import socket
import netifaces # type: ignore
import psutil # type: ignore
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from datetime import datetime
from typing import (
    Dict, List, Union, Optional, Any, Iterator, Generator, Tuple
)

# ======================
# CUSTOM EXCEPTIONS
# ======================
class SystemAnalyzerError(Exception):
    """Base exception for all system analyzer errors.

    Attributes:
        message: Human-readable error description.
        error_code: Optional numeric error code for programmatic handling.
        timestamp: ISO-format timestamp when the error occurred.
        context: Optional dict of additional context information.
    """
    __slots__ = ('message', 'error_code', 'timestamp', 'context')

    def __init__(
        self,
        message: str,
        error_code: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.error_code = error_code
        self.timestamp = datetime.now().isoformat()
        self.context = context or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        base = f"[{self.timestamp}] {self.message}"
        if self.error_code is not None:
            base = f"[E{self.error_code}] {base}"
        return base

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"error_code={self.error_code!r}, "
            f"timestamp={self.timestamp!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SystemAnalyzerError):
            return NotImplemented
        return (self.message == other.message
                and self.error_code == other.error_code)

    def __hash__(self) -> int:
        return hash((self.message, self.error_code))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the exception to a dictionary."""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code,
            'timestamp': self.timestamp,
            'context': self.context,
        }


class CollectionError(SystemAnalyzerError):
    """Raised when data collection from a system component fails."""
    def __init__(self, message: str, component: str = "",
                 error_code: Optional[int] = None) -> None:
        super().__init__(
            message, error_code=error_code,
            context={'component': component}
        )


class ExportError(SystemAnalyzerError):
    """Raised when report export operations fail."""
    def __init__(self, message: str, file_path: str = "",
                 error_code: Optional[int] = None) -> None:
        super().__init__(
            message, error_code=error_code,
            context={'file_path': file_path}
        )


class ConfigurationError(SystemAnalyzerError):
    """Raised when application configuration is invalid."""
    def __init__(self, message: str,
                 error_code: Optional[int] = None) -> None:
        super().__init__(message, error_code=error_code)


class NetworkCheckError(SystemAnalyzerError):
    """Raised when network connectivity checks fail."""
    def __init__(self, message: str, host: str = "",
                 error_code: Optional[int] = None) -> None:
        super().__init__(
            message, error_code=error_code,
            context={'host': host}
        )


# ======================
# LOGGING CONFIGURATION
# ======================
class LogManager:
    """Centralized logging management for the application."""

    __slots__ = ()
    _configured: bool = False

    @classmethod
    def configure_logging(cls, log_file: str = 'system_analysis.log',
                         level: int = logging.DEBUG) -> None:
        """Configure application-wide logging."""
        if cls._configured:
            return

        # Create root logger
        logger = logging.getLogger()
        logger.setLevel(level)

        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        cls._configured = True
        logging.info("Logging configured successfully")

    def __repr__(self) -> str:
        return f"LogManager(configured={self._configured})"


# Initialize logging
LogManager.configure_logging()

# ======================
# UTILITY CLASSES
# ======================
class TimeStampGenerator:
    """Utility class for generating timestamps and time conversions."""

    __slots__ = ()

    @staticmethod
    def current_time() -> str:
        """Get current time in HH:MM:SS format."""
        return datetime.now().strftime('%H:%M:%S')

    @staticmethod
    def current_date() -> str:
        """Get current date in DD/MM/YYYY format."""
        return datetime.now().strftime('%d/%m/%Y')

    @staticmethod
    def generate_report() -> str:
        """Generate a timestamp for reports."""
        return f'{TimeStampGenerator.current_time()} | {TimeStampGenerator.current_date()}'

    @staticmethod
    @lru_cache(maxsize=256)
    def convert_time(seconds: float) -> str:
        """Convert seconds to HH:MM:SS format.

        Results are cached for repeated calls with the same value.
        """
        try:
            seconds_int = int(seconds)
            minutes, secs = divmod(seconds_int, 60)
            hours, minutes = divmod(minutes, 60)
            return f'{hours:02d}:{minutes:02d}:{secs:02d}'
        except (TypeError, ValueError, OverflowError) as e:
            logging.error(f"Error converting time: {e}")
            return "00:00:00"

    def __repr__(self) -> str:
        return "TimeStampGenerator()"


class ScreenManager:
    """Handles terminal screen operations."""

    __slots__ = ()

    @staticmethod
    def clear_screen() -> None:
        """Clear the terminal screen."""
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except Exception as e:
            logging.error(f"Error clearing screen: {e}")

    def __repr__(self) -> str:
        return "ScreenManager()"


class FileManager:
    """Handles file operations for the application."""

    __slots__ = ()

    @staticmethod
    def create_directory(base_directory: str) -> str:
        """Create directory if it doesn't exist."""
        try:
            path = Path(base_directory)
            path.mkdir(parents=True, exist_ok=True)
            return str(path.absolute())
        except OSError as e:
            logging.error(f"Error creating directory: {e}")
            raise ExportError(
                f"Failed to create directory: {base_directory}",
                file_path=base_directory, error_code=1001
            ) from e

    @staticmethod
    def save_to_json(data: Dict, file_path: str) -> None:
        """Save data to JSON file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            logging.info(f"Data saved to {file_path}")
        except (OSError, TypeError) as e:
            logging.error(f"Error saving to JSON: {e}")
            raise ExportError(
                f"Failed to save JSON to {file_path}",
                file_path=file_path, error_code=1002
            ) from e

    def __repr__(self) -> str:
        return "FileManager()"


# ======================
# SYSTEM COMPONENT MANAGERS
# ======================
class BatteryManager:
    """Manages battery information collection."""

    __slots__ = ()

    @staticmethod
    def get_battery_info() -> Dict[str, Any]:
        """Get comprehensive battery information."""
        try:
            battery = psutil.sensors_battery()
            if not battery:
                return {"error": "No battery information available"}

            remaining_time = ("Fully Charged" if battery.percent == 100
                            else TimeStampGenerator.convert_time(
                                battery.secsleft))

            return {
                'battery_percentage': f'{battery.percent}%',
                'power_connected': battery.power_plugged,
                'remaining_time': remaining_time,
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting battery info: {e}")
            raise CollectionError(
                str(e), component='battery', error_code=2001
            ) from e

    def __repr__(self) -> str:
        return "BatteryManager()"


class CPUManager:
    """Manages CPU information collection with rich dunder methods."""

    __slots__ = ('_cpu_data',)

    def __init__(self) -> None:
        self._cpu_data: Dict[str, Any] = {}

    def __repr__(self) -> str:
        cores = self._cpu_data.get('logical_cores', '?')
        return f"CPUManager(logical_cores={cores})"

    def __str__(self) -> str:
        usage = self._cpu_data.get('usage', {}).get('total', 'N/A')
        return f"CPU(usage={usage}%)"

    def __len__(self) -> int:
        """Return the number of logical CPU cores."""
        return self._cpu_data.get('logical_cores', 0) or 0

    def __contains__(self, metric: str) -> bool:
        """Check if a CPU metric is available."""
        return metric in self._cpu_data

    def __getitem__(self, key: str) -> Any:
        """Access CPU metrics by key."""
        if key not in self._cpu_data:
            raise KeyError(f"CPU metric '{key}' not found")
        return self._cpu_data[key]

    def collect_cpu_info(self) -> Dict[str, Any]:
        """Collect comprehensive CPU information."""
        try:
            self._get_cpu_usage()
            self._get_cpu_counts()
            self._get_cpu_times()
            self._get_cpu_frequencies()
            self._get_cpu_stats()

            return {
                'cpu_usage': self._cpu_data.get('usage'),
                'logical_cores': self._cpu_data.get('logical_cores'),
                'physical_cores': self._cpu_data.get('physical_cores'),
                'cpu_times': self._cpu_data.get('times'),
                'cpu_times_percent': self._cpu_data.get('times_percent'),
                'cpu_frequencies': self._cpu_data.get('frequencies'),
                'cpu_stats': self._cpu_data.get('stats'),
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error collecting CPU info: {e}")
            raise CollectionError(
                str(e), component='cpu', error_code=2002
            ) from e

    def _get_cpu_usage(self) -> None:
        """Get CPU usage percentages."""
        self._cpu_data['usage'] = {
            'total': psutil.cpu_percent(interval=1, percpu=False),
            'per_core': psutil.cpu_percent(interval=1, percpu=True)
        }

    def _get_cpu_counts(self) -> None:
        """Get CPU core counts."""
        self._cpu_data['logical_cores'] = psutil.cpu_count(logical=True)
        self._cpu_data['physical_cores'] = psutil.cpu_count(logical=False)

    def _get_cpu_times(self) -> None:
        """Get CPU time statistics."""
        times = psutil.cpu_times(percpu=False)
        self._cpu_data['times'] = {
            'user': times.user,
            'system': times.system,
            'idle': times.idle,
            'interrupt': getattr(times, 'interrupt', 0),
            'dpc': getattr(times, 'dpc', 0)
        }

        times_percent = psutil.cpu_times_percent(interval=1, percpu=False)
        self._cpu_data['times_percent'] = {
            'user': times_percent.user,
            'system': times_percent.system,
            'idle': times_percent.idle,
            'interrupt': getattr(times_percent, 'interrupt', 0),
            'dpc': getattr(times_percent, 'dpc', 0)
        }

    def _get_cpu_frequencies(self) -> None:
        """Get CPU frequency information."""
        freq = psutil.cpu_freq(percpu=False)
        if freq:
            self._cpu_data['frequencies'] = {
                'current': freq.current,
                'min': freq.min,
                'max': freq.max
            }
        else:
            self._cpu_data['frequencies'] = {}

    def _get_cpu_stats(self) -> None:
        """Get CPU statistics."""
        stats = psutil.cpu_stats()
        self._cpu_data['stats'] = {
            'ctx_switches': stats.ctx_switches,
            'interrupts': stats.interrupts,
            'soft_interrupts': stats.soft_interrupts,
            'syscalls': stats.syscalls
        }


class MemoryManager:
    """Manages memory information collection."""

    __slots__ = ('_last_info',)

    def __init__(self) -> None:
        self._last_info: Optional[Dict[str, Any]] = None

    def __repr__(self) -> str:
        return "MemoryManager()"

    def __str__(self) -> str:
        if self._last_info and 'virtual_memory' in self._last_info:
            pct = self._last_info['virtual_memory'].get('percent', 'N/A')
            return f"Memory(used={pct}%)"
        return "Memory(not collected)"

    def __bool__(self) -> bool:
        """Return True if memory threshold warning is active."""
        if self._last_info and 'virtual_memory' in self._last_info:
            return self._last_info['virtual_memory'].get(
                'threshold_warning', False)
        return False

    def get_memory_info(self) -> Dict[str, Any]:
        """Get comprehensive memory information."""
        try:
            virtual_mem = psutil.virtual_memory()
            swap_mem = psutil.swap_memory()

            self._last_info = {
                'virtual_memory': {
                    'total': virtual_mem.total,
                    'available': virtual_mem.available,
                    'used': virtual_mem.used,
                    'free': virtual_mem.free,
                    'percent': virtual_mem.percent,
                    'threshold_warning': (
                        virtual_mem.available <= (100 * 1024 * 1024)
                    )
                },
                'swap_memory': {
                    'total': swap_mem.total,
                    'used': swap_mem.used,
                    'free': swap_mem.free,
                    'percent': swap_mem.percent,
                    'sin': swap_mem.sin,
                    'sout': swap_mem.sout
                },
                'timestamp': TimeStampGenerator.generate_report()
            }
            return self._last_info
        except Exception as e:
            logging.error(f"Error getting memory info: {e}")
            raise CollectionError(
                str(e), component='memory', error_code=2003
            ) from e


class DiskManager:
    """Manages disk information collection with generator-based iteration."""

    __slots__ = ('_partitions', '_partition_data')

    def __init__(self) -> None:
        self._partitions: List[str] = []
        self._partition_data: List[Dict] = []

    def __repr__(self) -> str:
        return f"DiskManager(partitions={len(self._partitions)})"

    def __iter__(self) -> Iterator[Dict]:
        """Iterate over collected partition data."""
        return iter(self._partition_data)

    def __len__(self) -> int:
        """Return number of partitions."""
        return len(self._partitions)

    def get_disk_info(self) -> Dict[str, Any]:
        """Get comprehensive disk information."""
        try:
            # Consume generators into lists for JSON serialization
            partitions = list(self._iter_partitions())
            usage = list(self._iter_disk_usage())
            io_counters = self._get_disk_io()

            return {
                'partitions': partitions,
                'usage': usage,
                'io_counters': io_counters,
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting disk info: {e}")
            raise CollectionError(
                str(e), component='disk', error_code=2004
            ) from e

    def _iter_partitions(self) -> Generator[Dict, None, None]:
        """Yield disk partition information lazily."""
        self._partitions.clear()
        self._partition_data.clear()
        for part in psutil.disk_partitions():
            partition_info: Dict[str, Any] = {
                'device': part.device,
                'mountpoint': part.mountpoint,
                'fstype': part.fstype,
                'opts': part.opts
            }
            try:
                partition_info['maxfile'] = getattr(part, 'maxfile', None)
                partition_info['maxpath'] = getattr(part, 'maxpath', None)
            except AttributeError:
                pass
            self._partitions.append(part.device)
            self._partition_data.append(partition_info)
            yield partition_info

    def _iter_disk_usage(self) -> Generator[Dict, None, None]:
        """Yield disk usage information per partition lazily."""
        for partition in self._partitions:
            try:
                usage_info = psutil.disk_usage(partition)
                yield {
                    'partition': partition,
                    'total': usage_info.total,
                    'used': usage_info.used,
                    'free': usage_info.free,
                    'percent': usage_info.percent
                }
            except (PermissionError, OSError) as e:
                logging.warning(
                    f"Couldn't get usage for {partition}: {e}")

    def _get_disk_io(self) -> Dict:
        """Get disk I/O statistics."""
        io = psutil.disk_io_counters()
        if io:
            return {
                'read_count': io.read_count,
                'write_count': io.write_count,
                'read_bytes': io.read_bytes,
                'write_bytes': io.write_bytes,
                'read_time': io.read_time,
                'write_time': io.write_time
            }
        return {}


class NetworkManager:
    """Manages network information collection with async connectivity checks
    and generator-based data iteration."""

    __slots__ = ('_data',)

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {
            "interface_stats": {},
            "interface_addrs": {},
            "connections": {}
        }

    def __repr__(self) -> str:
        iface_count = len(self._data.get('interface_stats', {}))
        return f"NetworkManager(interfaces={iface_count})"

    def __iter__(self) -> Iterator[str]:
        """Iterate over interface names."""
        return iter(self._data.get('interface_stats', {}))

    def __len__(self) -> int:
        """Return number of network interfaces."""
        return len(self._data.get('interface_stats', {}))

    def get_network_info(self) -> Dict[str, Any]:
        """Get comprehensive network information.

        Uses asyncio for concurrent connectivity checks.
        """
        try:
            # Run async connectivity checks concurrently
            connectivity = asyncio.run(self._async_check_connectivity())
            traffic = self._get_network_traffic()

            # Consume generators
            self._data["interface_stats"] = {}
            self._data["interface_addrs"] = {}
            for stat in self._iter_interface_stats():
                iface = stat.pop('_iface')
                self._data["interface_stats"][iface] = stat
            for addr in self._iter_interface_addrs():
                iface = addr.pop('_iface')
                if iface not in self._data["interface_addrs"]:
                    self._data["interface_addrs"][iface] = []
                self._data["interface_addrs"][iface].append(addr)

            self._data["connections"] = {}
            for kind, conn in self._iter_connections():
                if kind not in self._data["connections"]:
                    self._data["connections"][kind] = []
                self._data["connections"][kind].append(conn)

            detailed_info = self._get_detailed_network_info()

            return {
                'connectivity': connectivity,
                'traffic': traffic,
                'interface_stats': self._data['interface_stats'],
                'interface_addrs': self._data['interface_addrs'],
                'connections': self._data['connections'],
                'detailed_info': detailed_info,
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting network info: {e}")
            raise CollectionError(
                str(e), component='network', error_code=2005
            ) from e

    # --- Async connectivity checks ---
    async def _async_check_connectivity(self) -> Dict[str, str]:
        """Check localhost and internet connectivity concurrently."""
        localhost_task = asyncio.create_task(
            self._async_check_host('127.0.0.1'))
        internet_task = asyncio.create_task(
            self._async_check_host('www.google.com'))

        localhost, internet = await asyncio.gather(
            localhost_task, internet_task, return_exceptions=True
        )

        return {
            'localhost': ("Connected" if localhost is True
                         else "Disconnected"),
            'internet': ("Connected" if internet is True
                        else "Disconnected")
        }

    @staticmethod
    async def _async_check_host(host: str) -> bool:
        """Async DNS resolution check for a host."""
        loop = asyncio.get_event_loop()
        try:
            await loop.getaddrinfo(host, None)
            return True
        except socket.gaierror:
            return False

    # --- Generator-based interface info ---
    def _iter_interface_stats(self) -> Generator[Dict, None, None]:
        """Yield network interface statistics lazily."""
        stats = psutil.net_if_stats()
        for iface, info in stats.items():
            yield {
                '_iface': iface,
                'isup': info.isup,
                'duplex': self._get_duplex_name(info.duplex),
                'speed': info.speed,
                'mtu': info.mtu,
                'flags': info.flags
            }

    def _iter_interface_addrs(self) -> Generator[Dict, None, None]:
        """Yield network interface addresses lazily."""
        addrs = psutil.net_if_addrs()
        for iface, info_list in addrs.items():
            for info in info_list:
                yield {
                    '_iface': iface,
                    'family': self._get_family_name(info.family),
                    'address': info.address,
                    'netmask': info.netmask,
                    'broadcast': info.broadcast,
                    'ptp': info.ptp
                }

    def _iter_connections(
        self
    ) -> Generator[Tuple[str, Dict], None, None]:
        """Yield network connections lazily across all socket kinds."""
        kinds = [
            "inet", "inet4", "inet6", "tcp", "tcp4",
            "tcp6", "udp", "udp4", "udp6"
        ]
        for kind in kinds:
            try:
                connections = psutil.net_connections(kind=kind)
                for conn in connections:
                    yield kind, {
                        'fd': conn.fd,
                        'family': self._get_family_name(conn.family),
                        'type': self._get_socket_type_name(conn.type),
                        'local_address': (
                            f"{conn.laddr.ip}:{conn.laddr.port}"
                            if conn.laddr else None
                        ),
                        'remote_address': (
                            f"{conn.raddr.ip}:{conn.raddr.port}"
                            if conn.raddr else None
                        ),
                        'status': conn.status,
                        'pid': conn.pid
                    }
            except (PermissionError, psutil.AccessDenied) as e:
                logging.warning(
                    f"Couldn't gather connections for {kind}: {e}")

    @staticmethod
    def _get_network_traffic() -> Dict:
        """Get network traffic statistics."""
        io = psutil.net_io_counters()
        return {
            'bytes_sent': io.bytes_sent,
            'bytes_recv': io.bytes_recv,
            'packets_sent': io.packets_sent,
            'packets_recv': io.packets_recv,
            'errin': io.errin,
            'errout': io.errout,
            'dropin': io.dropin,
            'dropout': io.dropout
        }

    @staticmethod
    def _get_detailed_network_info() -> Dict:
        """Get detailed network interface information."""
        addr_family_map = {
            netifaces.AF_INET: 'IPv4',
            netifaces.AF_INET6: 'IPv6',
            netifaces.AF_LINK: 'MAC'
        }

        network_info: Dict[str, Any] = {}
        try:
            interfaces = netifaces.interfaces()
            gateways = netifaces.gateways()

            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                interface_info: Dict[str, Any] = {
                    'interface_name': interface,
                    'mac_address': None,
                    'default_gateway': None,
                    'ip_addresses': []
                }

                if netifaces.AF_LINK in addrs:
                    mac_info = addrs[netifaces.AF_LINK][0]
                    interface_info['mac_address'] = mac_info.get('addr')

                if 'default' in gateways:
                    default_gateways: Any = gateways['default']
                    for _key, value in default_gateways.items():
                        if value[1] == interface:
                            interface_info['default_gateway'] = value[0]
                            break

                for addr_family, addr_info in addrs.items():
                    for addr in addr_info:
                        family_name = addr_family_map.get(
                            addr_family, 'Unknown')
                        address_details = {
                            'address_family': family_name,
                            'ip_address': addr.get('addr'),
                            'subnet_mask': addr.get('netmask'),
                            'broadcast_address': addr.get('broadcast'),
                            'peer_address': addr.get('peer')
                        }
                        interface_info['ip_addresses'].append(
                            address_details)

                network_info[interface] = interface_info

            return network_info
        except Exception as e:
            logging.error(f"Error getting detailed network info: {e}")
            return {"error": str(e)}

    @staticmethod
    def _get_duplex_name(duplex: Any) -> str:
        """Get duplex type name."""
        try:
            return duplex.name
        except AttributeError:
            return str(duplex)

    @staticmethod
    def _get_family_name(family: Any) -> str:
        """Get address family name."""
        try:
            return family.name
        except AttributeError:
            return str(family)

    @staticmethod
    def _get_socket_type_name(socket_type: Any) -> str:
        """Get socket type name."""
        try:
            return socket_type.name
        except AttributeError:
            return str(socket_type)


class ProcessManager:
    """Manages process information collection with generator-based iteration
    and optimized psutil.process_iter() usage."""

    __slots__ = ('_process_count',)

    # Attributes to request from process_iter for efficiency
    _PROCESS_ATTRS = [
        'pid', 'name', 'status', 'cpu_percent',
        'memory_percent', 'create_time', 'exe',
        'cmdline', 'username'
    ]

    def __init__(self) -> None:
        self._process_count: int = 0

    def __repr__(self) -> str:
        return f"ProcessManager(last_count={self._process_count})"

    def __len__(self) -> int:
        """Return last known process count."""
        return self._process_count

    def get_process_info(self) -> Dict[str, Any]:
        """Get comprehensive process information.

        Uses psutil.process_iter() with attrs for memory-efficient,
        race-condition-free process enumeration.
        """
        try:
            processes = list(self._iter_processes())
            self._process_count = len(processes)

            return {
                'process_count': self._process_count,
                'processes': processes,
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting process info: {e}")
            raise CollectionError(
                str(e), component='process', error_code=2006
            ) from e

    def _iter_processes(self) -> Generator[Dict, None, None]:
        """Yield process details lazily using psutil.process_iter().

        This is more memory-efficient and race-condition-safe than
        iterating psutil.pids() and creating Process objects manually.
        """
        for proc in psutil.process_iter(self._PROCESS_ATTRS):
            try:
                info = proc.info
                yield {
                    'pid': info.get('pid'),
                    'name': info.get('name'),
                    'status': info.get('status'),
                    'cpu_percent': info.get('cpu_percent'),
                    'memory_percent': info.get('memory_percent'),
                    'create_time': info.get('create_time'),
                    'exe': info.get('exe'),
                    'cmdline': info.get('cmdline'),
                    'username': info.get('username')
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess) as e:
                logging.debug(f"Couldn't get process info: {e}")


class SystemInfoManager:
    """Manages system information collection."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "SystemInfoManager()"

    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get comprehensive system information."""
        try:
            return {
                'system': SystemInfoManager._get_system_details(),
                'boot': SystemInfoManager._get_boot_info(),
                'users': SystemInfoManager._get_users(),
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting system info: {e}")
            raise CollectionError(
                str(e), component='system', error_code=2007
            ) from e

    @staticmethod
    def _get_system_details() -> Dict:
        """Get detailed system information."""
        return {
            'node': platform.node(),
            'os': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            },
            'python': {
                'version': platform.python_version(),
                'compiler': platform.python_compiler(),
                'implementation': platform.python_implementation()
            },
            'reboot_required': SystemInfoManager._check_reboot()
        }

    @staticmethod
    def _check_reboot() -> bool:
        """Check if system reboot is required."""
        try:
            return os.path.exists('/run/reboot-required')
        except Exception:
            return False

    @staticmethod
    def _get_boot_info() -> Dict:
        """Get system boot information."""
        boot_time = psutil.boot_time()
        return {
            'boot_timestamp': boot_time,
            'boot_time': datetime.fromtimestamp(boot_time).strftime(
                "%Y-%m-%d %H:%M:%S"),
            'uptime': TimeStampGenerator.convert_time(
                datetime.now().timestamp() - boot_time)
        }

    @staticmethod
    def _get_users() -> List[Dict]:
        """Get logged in users."""
        return [{
            'name': user.name,
            'terminal': user.terminal,
            'host': user.host,
            'started': user.started,
            'pid': user.pid
        } for user in psutil.users()]


# ======================
# MAIN APPLICATION
# ======================
class SystemAnalyzerApp:
    """Main application class for system analysis.

    Supports context manager protocol for resource cleanup and
    uses ThreadPoolExecutor for parallel report generation.
    """

    __slots__ = (
        '_cpu_mgr', '_proc_mgr', '_mem_mgr', '_disk_mgr',
        '_net_mgr', '_sys_mgr', '_bat_mgr', '_executor',
        '_report_options'
    )

    _MAX_WORKERS = 4  # Thread pool size for parallel collection

    def __init__(self) -> None:
        self._cpu_mgr = CPUManager()
        self._proc_mgr = ProcessManager()
        self._mem_mgr = MemoryManager()
        self._disk_mgr = DiskManager()
        self._net_mgr = NetworkManager()
        self._sys_mgr = SystemInfoManager()
        self._bat_mgr = BatteryManager()
        self._executor = ThreadPoolExecutor(
            max_workers=self._MAX_WORKERS,
            thread_name_prefix="sys_analyzer"
        )
        self._report_options: Dict[int, Tuple[str, Any]] = {
            1: ("CPU Information", self._cpu_mgr.collect_cpu_info),
            2: ("Process Information", self._proc_mgr.get_process_info),
            3: ("Memory Information", self._mem_mgr.get_memory_info),
            4: ("Disk Information", self._disk_mgr.get_disk_info),
            5: ("Network Information", self._net_mgr.get_network_info),
            6: ("System Information", self._sys_mgr.get_system_info),
            7: ("Battery Information", self._bat_mgr.get_battery_info),
        }
        logging.info("SystemAnalyzerApp initialized")

    def __repr__(self) -> str:
        return (
            f"SystemAnalyzerApp(reports={len(self._report_options)}, "
            f"workers={self._MAX_WORKERS})"
        )

    def __str__(self) -> str:
        return "System Analysis Tool v2.0"

    def __enter__(self) -> 'SystemAnalyzerApp':
        """Enter context manager — returns self."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit context manager — shuts down thread pool and cleans up."""
        self._executor.shutdown(wait=False)
        gc.collect()
        logging.info("SystemAnalyzerApp resources cleaned up")
        return False  # Don't suppress exceptions

    @property
    def report_options(self) -> Dict[int, Tuple[str, Any]]:
        """Read-only access to report options."""
        return self._report_options

    def run(self) -> None:
        """Run the application."""
        try:
            self._display_welcome()
            self._main_loop()
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)
        except SystemAnalyzerError as e:
            logging.error(f"Application error: {e}")
            print(f"Error: {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Unexpected application error: {e}")
            print(f"Unexpected error: {e}")
            sys.exit(1)
        finally:
            self._executor.shutdown(wait=False)

    def _display_welcome(self) -> None:
        """Display welcome message."""
        ScreenManager.clear_screen()
        print("\n" + "=" * 50)
        print("SYSTEM ANALYSIS TOOL v2.0".center(50))
        print("=" * 50)
        print("\nThis tool collects comprehensive system information")
        print("and saves it to JSON files for analysis.\n")

    def _main_loop(self) -> None:
        """Main application loop."""
        while True:
            choice = self._get_user_choice()

            if choice == 0:
                ScreenManager.clear_screen()
                continue
            elif choice == 9:
                print("\nExiting. Goodbye!")
                break
            elif choice == 8:
                self._generate_full_report()
            else:
                self._generate_single_report(choice)

            if not self._ask_to_continue():
                break

    def _get_user_choice(self) -> int:
        """Get user choice for report type."""
        while True:
            print("\nSelect report type:")
            print("0. Clear screen")
            for num, (name, _) in self._report_options.items():
                print(f"{num}. {name}")
            print("8. All-in-one report (parallel)")
            print("9. Exit")

            try:
                choice = int(input("\nEnter your choice (0-9): "))
                if 0 <= choice <= 9:
                    return choice
                print("Invalid choice. Please enter a number "
                      "between 0 and 9.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    def _generate_single_report(self, report_id: int) -> None:
        """Generate a single report based on user selection."""
        try:
            report_name, report_func = self._report_options[report_id]
            print(f"\nGenerating {report_name.lower()}...")

            data = report_func()
            if not data:
                print("Failed to generate report data.")
                return

            self._save_report(data, report_name.replace(" ", "_").lower())
        except CollectionError as e:
            logging.error(f"Collection error for report {report_id}: {e}")
            print(f"Error collecting data: {e}")
        except Exception as e:
            logging.error(f"Error generating report {report_id}: {e}")
            print(f"Error generating report: {e}")

    def _generate_full_report(self) -> None:
        """Generate a comprehensive system report using parallel execution.

        Submits all collection tasks to a ThreadPoolExecutor for
        concurrent execution, significantly reducing total collection time.
        """
        print("\nGenerating all-in-one system report (parallel)...")

        full_report: Dict[str, Any] = {}
        futures = {}

        # Submit all collection tasks in parallel
        for name, func in self._report_options.values():
            section_name = name.replace(" ", "_").lower()
            future = self._executor.submit(func)
            futures[future] = section_name

        # Collect results as they complete
        for future in as_completed(futures):
            section_name = futures[future]
            try:
                full_report[section_name] = future.result(timeout=60)
                print(f"  ✓ {section_name} collected")
            except CollectionError as e:
                logging.error(f"Error generating {section_name}: {e}")
                full_report[section_name] = e.to_dict()
                print(f"  ✗ {section_name} failed: {e.message}")
            except Exception as e:
                logging.error(f"Error generating {section_name}: {e}")
                full_report[section_name] = {"error": str(e)}
                print(f"  ✗ {section_name} failed: {e}")

        self._save_report(full_report, "full_system_report")

        # Hint garbage collection after large report
        gc.collect()

    def _iter_reports(
        self
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Yield (section_name, data) tuples for all report sections.

        Generator pattern for memory-efficient sequential collection.
        """
        for name, func in self._report_options.values():
            section_name = name.replace(" ", "_").lower()
            try:
                yield section_name, func()
            except Exception as e:
                logging.error(f"Error in {section_name}: {e}")
                yield section_name, {"error": str(e)}

    def _save_report(self, data: Dict, default_name: str) -> None:
        """Save report data to JSON file."""
        try:
            output_dir = input(
                "Enter output directory "
                "(leave blank for current): ").strip() or "."
            filename = input(
                f"Enter filename (default: {default_name}.json): "
            ).strip() or default_name

            if not filename.endswith('.json'):
                filename += '.json'

            output_path = os.path.join(
                FileManager.create_directory(output_dir), filename)
            FileManager.save_to_json(data, output_path)

            print(f"\nReport saved successfully to: {output_path}")
        except ExportError as e:
            print(f"Export error: {e}")
        except Exception as e:
            logging.error(f"Error saving report: {e}")
            print(f"Error saving report: {e}")

    @staticmethod
    def _ask_to_continue() -> bool:
        """Ask user if they want to continue."""
        while True:
            response = input(
                "\nWould you like to generate another report? "
                "(y/n): ").lower()
            if response in ('y', 'yes'):
                return True
            elif response in ('n', 'no'):
                return False
            print("Please enter 'y' or 'n'.")


if __name__ == "__main__":
    with SystemAnalyzerApp() as app:
        app.run()
