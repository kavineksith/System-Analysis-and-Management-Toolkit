#!/usr/bin/env python3
"""
Industrial-Grade System Analysis Tool
-------------------------------------
A comprehensive system monitoring and reporting tool that collects:
- CPU statistics
- Memory usage
- Disk information
- Network status
- Process details
- Battery information (where applicable)
- System information

Features:
- Modular architecture
- Comprehensive error handling
- Configurable logging
- JSON output
- Interactive CLI
- File export capabilities
"""

import json
import os
import sys
import platform
import socket
import netifaces
import psutil
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Union, Optional, Any

# ======================
# LOGGING CONFIGURATION
# ======================
class LogManager:
    """Centralized logging management for the application."""
    
    _configured = False
    
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

# Initialize logging
LogManager.configure_logging()

# ======================
# UTILITY CLASSES
# ======================
class TimeStampGenerator:
    """Utility class for generating timestamps and time conversions."""
    
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
    def convert_time(seconds: float) -> str:
        """Convert seconds to HH:MM:SS format."""
        try:
            minutes, seconds = divmod(seconds, 60)
            hours, minutes = divmod(minutes, 60)
            return f'{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}'
        except Exception as e:
            logging.error(f"Error converting time: {e}")
            return "00:00:00"

class ScreenManager:
    """Handles terminal screen operations."""
    
    @staticmethod
    def clear_screen() -> None:
        """Clear the terminal screen."""
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except Exception as e:
            logging.error(f"Error clearing screen: {e}")

class FileManager:
    """Handles file operations for the application."""
    
    @staticmethod
    def create_directory(base_directory: str) -> str:
        """Create directory if it doesn't exist."""
        try:
            path = Path(base_directory)
            path.mkdir(parents=True, exist_ok=True)
            return str(path.absolute())
        except Exception as e:
            logging.error(f"Error creating directory: {e}")
            raise

    @staticmethod
    def save_to_json(data: Dict, file_path: str) -> None:
        """Save data to JSON file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            logging.info(f"Data saved to {file_path}")
        except Exception as e:
            logging.error(f"Error saving to JSON: {e}")
            raise

# ======================
# SYSTEM COMPONENT MANAGERS
# ======================
class BatteryManager:
    """Manages battery information collection."""
    
    @staticmethod
    def get_battery_info() -> Dict[str, Any]:
        """Get comprehensive battery information."""
        try:
            battery = psutil.sensors_battery()
            if not battery:
                return {"error": "No battery information available"}
                
            remaining_time = "Fully Charged" if battery.percent == 100 else \
                           TimeStampGenerator.convert_time(battery.secsleft)
            
            return {
                'battery_percentage': f'{battery.percent}%',
                'power_connected': battery.power_plugged,
                'remaining_time': remaining_time,
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting battery info: {e}")
            return {"error": str(e)}

class CPUManager:
    """Manages CPU information collection."""
    
    def __init__(self):
        self._cpu_data = {}

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
            return {"error": str(e)}

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
        self._cpu_data['frequencies'] = {
            'current': freq.current,
            'min': freq.min,
            'max': freq.max
        }

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
    
    @staticmethod
    def get_memory_info() -> Dict[str, Any]:
        """Get comprehensive memory information."""
        try:
            virtual_mem = psutil.virtual_memory()
            swap_mem = psutil.swap_memory()
            
            return {
                'virtual_memory': {
                    'total': virtual_mem.total,
                    'available': virtual_mem.available,
                    'used': virtual_mem.used,
                    'free': virtual_mem.free,
                    'percent': virtual_mem.percent,
                    'threshold_warning': virtual_mem.available <= (100 * 1024 * 1024)
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
        except Exception as e:
            logging.error(f"Error getting memory info: {e}")
            return {"error": str(e)}

class DiskManager:
    """Manages disk information collection."""
    
    def __init__(self):
        self._partitions = []

    def get_disk_info(self) -> Dict[str, Any]:
        """Get comprehensive disk information."""
        try:
            partitions = self._get_partitions()
            usage = self._get_disk_usage()
            io_counters = self._get_disk_io()
            
            return {
                'partitions': partitions,
                'usage': usage,
                'io_counters': io_counters,
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting disk info: {e}")
            return {"error": str(e)}

    def _get_partitions(self) -> List[Dict]:
        """Get disk partition information."""
        partitions = []
        for part in psutil.disk_partitions():
            partition_info = {
                'device': part.device,
                'mountpoint': part.mountpoint,
                'fstype': part.fstype,
                'opts': part.opts
            }
            try:
                partition_info.update({
                    'maxfile': part.maxfile,
                    'maxpath': part.maxpath
                })
            except AttributeError:
                pass
            partitions.append(partition_info)
            self._partitions.append(part.device)
        return partitions

    def _get_disk_usage(self) -> List[Dict]:
        """Get disk usage information."""
        usage = []
        for partition in self._partitions:
            try:
                usage_info = psutil.disk_usage(partition)
                usage.append({
                    'partition': partition,
                    'total': usage_info.total,
                    'used': usage_info.used,
                    'free': usage_info.free,
                    'percent': usage_info.percent
                })
            except Exception as e:
                logging.warning(f"Couldn't get usage for {partition}: {e}")
        return usage

    def _get_disk_io(self) -> Dict:
        """Get disk I/O statistics."""
        io = psutil.disk_io_counters()
        return {
            'read_count': io.read_count,
            'write_count': io.write_count,
            'read_bytes': io.read_bytes,
            'write_bytes': io.write_bytes,
            'read_time': io.read_time,
            'write_time': io.write_time
        } if io else {}

class NetworkManager:
    """Manages network information collection."""
    
    def __init__(self):
        self._data = {
            "interface_stats": {},
            "interface_addrs": {},
            "connections": {}
        }

    def get_network_info(self) -> Dict[str, Any]:
        """Get comprehensive network information."""
        try:
            connectivity = self._check_connectivity()
            traffic = self._get_network_traffic()
            self._gather_interface_info()
            self._gather_connections()
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
            return {"error": str(e)}

    def _check_connectivity(self) -> Dict:
        """Check network connectivity status."""
        localhost = self._check_localhost()
        internet = self._check_internet()
        return {
            'localhost': localhost,
            'internet': internet
        }

    @staticmethod
    def _check_localhost() -> str:
        """Check localhost connectivity."""
        try:
            socket.gethostbyname('127.0.0.1')
            return "Connected"
        except socket.gaierror:
            return "Disconnected"

    @staticmethod
    def _check_internet() -> str:
        """Check internet connectivity."""
        try:
            socket.gethostbyname('www.google.com')
            return "Connected"
        except socket.gaierror:
            return "Disconnected"

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

    def _gather_interface_info(self) -> None:
        """Gather network interface information."""
        stats = psutil.net_if_stats()
        for iface, info in stats.items():
            self._data["interface_stats"][iface] = {
                "isup": info.isup,
                "duplex": self._get_duplex_name(info.duplex),
                "speed": info.speed,
                "mtu": info.mtu,
                "flags": info.flags
            }

        addrs = psutil.net_if_addrs()
        for iface, info_list in addrs.items():
            self._data["interface_addrs"][iface] = []
            for info in info_list:
                self._data["interface_addrs"][iface].append({
                    "family": self._get_family_name(info.family),
                    "address": info.address,
                    "netmask": info.netmask,
                    "broadcast": info.broadcast,
                    "ptp": info.ptp
                })

    def _gather_connections(self) -> None:
        """Gather network connection information."""
        kinds = ["inet", "inet4", "inet6", "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"]
        for kind in kinds:
            try:
                connections = psutil.net_connections(kind=kind)
                self._data["connections"][kind] = []
                for conn in connections:
                    self._data["connections"][kind].append({
                        "fd": conn.fd,
                        "family": self._get_family_name(conn.family),
                        "type": self._get_socket_type_name(conn.type),
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid
                    })
            except Exception as e:
                logging.warning(f"Couldn't gather connections for {kind}: {e}")

    @staticmethod
    def _get_detailed_network_info() -> Dict:
        """Get detailed network interface information."""
        addr_family_map = {
            netifaces.AF_INET: 'IPv4',
            netifaces.AF_INET6: 'IPv6',
            netifaces.AF_LINK: 'MAC'
        }

        network_info = {}
        try:
            interfaces = netifaces.interfaces()
            gateways = netifaces.gateways()

            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                interface_info = {
                    'interface_name': interface,
                    'mac_address': None,
                    'default_gateway': None,
                    'ip_addresses': []
                }

                if netifaces.AF_LINK in addrs:
                    mac_info = addrs[netifaces.AF_LINK][0]
                    interface_info['mac_address'] = mac_info.get('addr')

                if 'default' in gateways:
                    for key, value in gateways['default'].items():
                        if value[1] == interface:
                            interface_info['default_gateway'] = value[0]
                            break

                for addr_family, addr_info in addrs.items():
                    for addr in addr_info:
                        family_name = addr_family_map.get(addr_family, 'Unknown')
                        address_details = {
                            'address_family': family_name,
                            'ip_address': addr.get('addr'),
                            'subnet_mask': addr.get('netmask'),
                            'broadcast_address': addr.get('broadcast'),
                            'peer_address': addr.get('peer')
                        }
                        interface_info['ip_addresses'].append(address_details)
                
                network_info[interface] = interface_info

            return network_info
        except Exception as e:
            logging.error(f"Error getting detailed network info: {e}")
            return {"error": str(e)}

    @staticmethod
    def _get_duplex_name(duplex: int) -> str:
        """Get duplex type name."""
        try:
            return duplex.name
        except AttributeError:
            return str(duplex)

    @staticmethod
    def _get_family_name(family: int) -> str:
        """Get address family name."""
        try:
            return family.name
        except AttributeError:
            return str(family)

    @staticmethod
    def _get_socket_type_name(socket_type: int) -> str:
        """Get socket type name."""
        try:
            return socket_type.name
        except AttributeError:
            return str(socket_type)

class ProcessManager:
    """Manages process information collection."""
    
    def get_process_info(self) -> Dict[str, Any]:
        """Get comprehensive process information."""
        try:
            process_list = self._get_process_list()
            process_details = self._get_process_details(process_list)
            
            return {
                'process_count': len(process_list),
                'processes': process_details,
                'timestamp': TimeStampGenerator.generate_report()
            }
        except Exception as e:
            logging.error(f"Error getting process info: {e}")
            return {"error": str(e)}

    @staticmethod
    def _get_process_list() -> List[int]:
        """Get list of running process PIDs."""
        return psutil.pids()

    @staticmethod
    def _get_process_details(pids: List[int]) -> List[Dict]:
        """Get details for each process."""
        processes = []
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                processes.append({
                    'pid': pid,
                    'name': proc.name(),
                    'status': proc.status(),
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'create_time': proc.create_time(),
                    'exe': proc.exe(),
                    'cmdline': proc.cmdline(),
                    'username': proc.username()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.debug(f"Couldn't get info for PID {pid}: {e}")
        return processes

class SystemInfoManager:
    """Manages system information collection."""
    
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
            return {"error": str(e)}

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
            'boot_time': datetime.fromtimestamp(boot_time).strftime("%Y-%m-%d %H:%M:%S"),
            'uptime': TimeStampGenerator.convert_time(datetime.now().timestamp() - boot_time)
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
    """Main application class for system analysis."""
    
    REPORT_OPTIONS = {
        1: ("CPU Information", CPUManager().collect_cpu_info),
        2: ("Process Information", ProcessManager().get_process_info),
        3: ("Memory Information", MemoryManager().get_memory_info),
        4: ("Disk Information", DiskManager().get_disk_info),
        5: ("Network Information", NetworkManager().get_network_info),
        6: ("System Information", SystemInfoManager().get_system_info),
        7: ("Battery Information", BatteryManager().get_battery_info)
    }

    def __init__(self):
        self._setup()

    def _setup(self) -> None:
        """Initialize application components."""
        logging.info("SystemAnalyzerApp initialized")

    def run(self) -> None:
        """Run the application."""
        try:
            self._display_welcome()
            self._main_loop()
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Application error: {e}")
            print(f"Error: {e}")
            sys.exit(1)

    def _display_welcome(self) -> None:
        """Display welcome message."""
        ScreenManager.clear_screen()
        print("\n" + "=" * 50)
        print("SYSTEM ANALYSIS TOOL".center(50))
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
            for num, (name, _) in self.REPORT_OPTIONS.items():
                print(f"{num}. {name}")
            print("8. All-in-one report")
            print("9. Exit")
            
            try:
                choice = int(input("\nEnter your choice (0-9): "))
                if 0 <= choice <= 9:
                    return choice
                print("Invalid choice. Please enter a number between 0 and 9.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    def _generate_single_report(self, report_id: int) -> None:
        """Generate a single report based on user selection."""
        try:
            report_name, report_func = self.REPORT_OPTIONS[report_id]
            print(f"\nGenerating {report_name.lower()}...")
            
            data = report_func()
            if not data:
                print("Failed to generate report data.")
                return
                
            self._save_report(data, report_name.replace(" ", "_").lower())
        except Exception as e:
            logging.error(f"Error generating report {report_id}: {e}")
            print(f"Error generating report: {e}")

    def _generate_full_report(self) -> None:
        """Generate a comprehensive system report."""
        print("\nGenerating all-in-one system report...")
        
        full_report = {}
        for name, func in self.REPORT_OPTIONS.values():
            try:
                section_name = name.replace(" ", "_").lower()
                full_report[section_name] = func()
            except Exception as e:
                logging.error(f"Error generating {name} report: {e}")
                full_report[section_name] = {"error": str(e)}
        
        self._save_report(full_report, "full_system_report")

    def _save_report(self, data: Dict, default_name: str) -> None:
        """Save report data to JSON file."""
        try:
            output_dir = input("Enter output directory (leave blank for current): ").strip() or "."
            filename = input(f"Enter filename (default: {default_name}.json): ").strip() or default_name
            
            if not filename.endswith('.json'):
                filename += '.json'
                
            output_path = os.path.join(FileManager.create_directory(output_dir), filename)
            FileManager.save_to_json(data, output_path)
            
            print(f"\nReport saved successfully to: {output_path}")
        except Exception as e:
            logging.error(f"Error saving report: {e}")
            print(f"Error saving report: {e}")

    @staticmethod
    def _ask_to_continue() -> bool:
        """Ask user if they want to continue."""
        while True:
            response = input("\nWould you like to generate another report? (y/n): ").lower()
            if response in ('y', 'yes'):
                return True
            elif response in ('n', 'no'):
                return False
            print("Please enter 'y' or 'n'.")

if __name__ == "__main__":
    app = SystemAnalyzerApp()
    app.run()
