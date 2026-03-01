#!/usr/bin/env python3

import os
import sys
import time
import json
import signal
import socket
import struct
import ipaddress
import argparse
import tempfile
import threading
import functools
import logging
import csv
import re
from typing import Dict, List, Optional, Tuple, Any, Set, Union, Iterator
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque
from contextlib import contextmanager
import resource

AF_INET = 2
AF_INET6 = 10
IPV4_HEX_LENGTH = 8
IPV6_HEX_LENGTH = 32
MIN_PORT = 1
MAX_PORT = 65535
MIN_INTERVAL = 1
MAX_INTERVAL = 3600
MIN_CIDR_IPV4 = 0
MAX_CIDR_IPV4 = 32
MIN_CIDR_IPV6 = 0
MAX_CIDR_IPV6 = 128

TCP_STATES = {
    '01': "ESTABLISHED",
    '02': "SYN_SENT",
    '03': "SYN_RECV",
    '04': "FIN_WAIT1",
    '05': "FIN_WAIT2",
    '06': "TIME_WAIT",
    '07': "CLOSE",
    '08': "CLOSE_WAIT",
    '09': "LAST_ACK",
    '0A': "LISTEN",
    '0B': "CLOSING",
    '0C': "NEW_SYN_RECV",
}

COLORS = {
    'LISTEN': '\033[32m',
    'ESTABLISHED': '\033[36m',
    'TIME_WAIT': '\033[33m',
    'CLOSE_WAIT': '\033[31m',
    'FIN_WAIT1': '\033[35m',
    'FIN_WAIT2': '\033[35m',
    'SYN_RECV': '\033[34m',
    'LAST_ACK': '\033[31m',
    'CLOSING': '\033[33m',
    'reset': '\033[0m'
}

@contextmanager
def timeout(seconds: int):
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    original_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_handler)

class Config:
    _instance = None
    _config = {}
    _defaults = {
        'refresh_interval': 2,
        'max_display_processes': 10,
        'process_cache_ttl': 5,
        'connection_cache_ttl': 1,
        'colors_enabled': True,
        'max_history': 1000,
        'rate_limit_requests': 100,
        'rate_limit_window': 60,
        'max_cache_size': 10000,
        'max_connections_per_scan': 50000,
        'socket_read_timeout': 5,
        'enable_process_scan': True,
        'log_level': 'INFO',
        'max_file_size': 10485760,
        'memory_warning_threshold': 268435456,
        'memory_critical_threshold': 402653184,
        'max_pid': 4194304,
        'max_cache_entries': 10000,
        'max_process_scan_time': 30,
        'process_scan_cooldown': 2,
        'max_inodes_to_scan': 100000,
        'max_watch_connections': 100000,
        'cache_rebuild_lock_timeout': 30,
        'fast_process_scan': True,
        'skip_kernel_threads': True,
        'file_operation_timeout': 5,
    }
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._config = cls._defaults.copy()
        return cls._instance
    
    def get(self, key: str, default=None):
        env_key = f'TCP_MONITOR_{key.upper()}'
        if env_key in os.environ:
            return self._cast_value(os.environ[env_key], key)
        return self._config.get(key, default)
    
    def set(self, key: str, value):
        if key in self._defaults:
            value = self._cast_value(value, key)
        self._config[key] = value
    
    def _cast_value(self, value, key: str):
        if key not in self._defaults:
            return value
        
        default = self._defaults[key]
        if isinstance(default, bool):
            return str(value).lower() in ('true', '1', 'yes')
        elif isinstance(default, int):
            return int(value)
        elif isinstance(default, float):
            return float(value)
        return str(value)
    
    def load_from_file(self, filepath: str):
        try:
            with open(filepath, 'r') as f:
                config = json.load(f)
            
            if not isinstance(config, dict):
                raise ValueError("Invalid JSON structure")
            
            for key, value in config.items():
                if key in self._defaults:
                    expected_type = type(self._defaults[key])
                    if not isinstance(value, expected_type):
                        raise ValueError(f"Config '{key}' expects type {expected_type.__name__}")
                    
                    if any(x in key for x in ['threshold', 'max_', 'limit']) and value < 0:
                        raise ValueError(f"Config '{key}' must be positive")
                    
                    self.set(key, value)
        except Exception as e:
            raise RuntimeError(f"Failed to load config file: {e}")
    
    def load_from_env(self):
        for key, value in os.environ.items():
            if key.startswith('TCP_MONITOR_'):
                config_key = key[12:].lower()
                self.set(config_key, value)
    
    def load_from_env_file(self, filepath: str):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key.startswith('TCP_MONITOR_'):
                            os.environ[key] = value
        except Exception as e:
            raise RuntimeError(f"Failed to load env file: {e}")
    
    def reload(self):
        self._config = self._defaults.copy()
        self.load_from_env()

class Logger:
    _instance = None
    _log_file = None
    _log_level = logging.INFO
    _buffer = []
    _BUFFER_SIZE = 100
    
    LEVELS = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'FATAL': logging.CRITICAL
    }
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup_logger()
        return cls._instance
    
    def _setup_logger(self):
        self.logger = logging.getLogger('tcp_monitor')
        self.logger.setLevel(self._log_level)
        
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
        self.logger.addHandler(console_handler)
        
        self.file_handler = None
    
    def set_log_level(self, level: str):
        level = level.upper()
        if level in self.LEVELS:
            self._log_level = self.LEVELS[level]
            self.logger.setLevel(self._log_level)
    
    def set_log_file(self, filepath: str):
        log_dir = os.path.dirname(filepath)
        if log_dir and not os.path.isdir(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        if log_dir and not os.access(log_dir, os.W_OK):
            raise RuntimeError(f"Log directory not writable: {log_dir}")
        
        if self.file_handler:
            self.logger.removeHandler(self.file_handler)
        
        self.file_handler = logging.FileHandler(filepath)
        self.file_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
        self.logger.addHandler(self.file_handler)
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def fatal(self, message: str):
        self.logger.critical(message)
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

class Security:
    @staticmethod
    def validate_path(path: str) -> bool:
        if '..' in path.split('/') or '//' in path:
            return False
        
        normalized = Security._normalize_path(path)
        
        if not normalized.startswith('/proc/'):
            return False
        
        allowed_patterns = [
            r'^/proc/net/(tcp|tcp6|udp|udp6|raw|raw6|unix)$',
            r'^/proc/\d+$',
            r'^/proc/\d+/(comm|status|cmdline|exe|fd|net|fdinfo)$',
            r'^/proc/\d+/fd/\d+$',
            r'^/proc/version$',
            r'^/proc/self$'
        ]
        
        for pattern in allowed_patterns:
            if re.match(pattern, normalized):
                try:
                    if os.path.islink(path):
                        real_path = os.path.realpath(path)
                        if not real_path.startswith('/proc/'):
                            return False
                    return True
                except OSError:
                    return False
        
        return False
    
    @staticmethod
    def _normalize_path(path: str) -> str:
        path = path.strip()
        if not path:
            return '/'
        
        if path[0] != '/':
            path = '/' + path
        
        parts = path.split('/')
        result = []
        
        for part in parts:
            if part == '' or part == '.':
                continue
            if part == '..':
                if result and result[-1] != 'proc':
                    result.pop()
                continue
            result.append(part)
        
        return '/' + '/'.join(result)
    
    @staticmethod
    def validate_proc_filesystem():
        if not os.path.isdir('/proc'):
            raise RuntimeError("/proc directory does not exist")
        
        if not os.access('/proc/self', os.R_OK) and not os.access('/proc/version', os.R_OK):
            raise RuntimeError("/proc not accessible")
    
    @staticmethod
    def validate_integer(value, min_val=None, max_val=None) -> int:
        try:
            int_val = int(value)
        except (TypeError, ValueError):
            raise ValueError("Value must be numeric")
        
        if min_val is not None and int_val < min_val:
            raise ValueError(f"Value must be at least {min_val}")
        if max_val is not None and int_val > max_val:
            raise ValueError(f"Value must be at most {max_val}")
        
        return int_val
    
    @staticmethod
    def validate_pid(pid: int) -> bool:
        max_pid = Config().get('max_pid', 4194304)
        return pid > 0 and pid <= max_pid
    
    @staticmethod
    def create_temp_file(prefix: str, directory: str = None) -> str:
        directory = directory or tempfile.gettempdir()
        fd, temp_file = tempfile.mkstemp(prefix=prefix, dir=directory)
        os.close(fd)
        TempFileRegistry.register(temp_file)
        return temp_file

class RateLimiter:
    _requests = deque()
    _last_cleanup = 0
    _lock = threading.Lock()
    
    @classmethod
    def check_limit(cls) -> bool:
        max_requests = Config().get('rate_limit_requests', 100)
        window = Config().get('rate_limit_window', 60)
        now = time.time()
        
        with cls._lock:
            if now - cls._last_cleanup > 5:
                while cls._requests and cls._requests[0] < now - window:
                    cls._requests.popleft()
                cls._last_cleanup = now
            
            if len(cls._requests) >= max_requests:
                return False
            
            cls._requests.append(now)
            return True
    
    @classmethod
    def get_current_count(cls) -> int:
        with cls._lock:
            return len(cls._requests)

class PerformanceTracker:
    _start_time = time.time()
    _memory_peak = 0
    _operations = 0
    _memory_checks = []
    _timers = {}
    _gc_triggered = False
    _last_check = 0
    _lock = threading.Lock()
    
    @classmethod
    def start(cls):
        cls._start_time = time.time()
        cls._memory_peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        cls._last_check = int(time.time())
    
    @classmethod
    def record_operation(cls, type: str = 'general'):
        with cls._lock:
            cls._operations += 1
    
    @classmethod
    @contextmanager
    def timer(cls, name: str):
        start = time.time()
        try:
            yield
        finally:
            duration = time.time() - start
            with cls._lock:
                if name not in cls._timers:
                    cls._timers[name] = {'total': 0.0, 'count': 0}
                cls._timers[name]['total'] += duration
                cls._timers[name]['count'] += 1
    
    @classmethod
    def _check_memory_usage(cls):
        pass
    
    @classmethod
    def get_metrics(cls) -> dict:
        end_time = time.time()
        metrics = {
            'execution_time': round(end_time - cls._start_time, 4),
            'memory_peak_mb': round(cls._memory_peak / 1024, 2),
            'operations': cls._operations,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        timers = {}
        for name, timer in cls._timers.items():
            if 'total' in timer:
                timers[name] = {
                    'total': round(timer['total'], 4),
                    'count': timer['count'],
                    'average': round(timer['total'] / timer['count'], 4) if timer['count'] > 0 else 0
                }
        
        if timers:
            metrics['timers'] = timers
        
        return metrics
    
    @classmethod
    def reset(cls):
        cls._start_time = time.time()
        cls._operations = 0
        cls._memory_checks = []
        cls._timers = {}
        cls._gc_triggered = False
        cls._last_check = int(time.time())

class ErrorHandler:
    @staticmethod
    def handle_file_read(filepath: str) -> str:
        if not Security.validate_path(filepath):
            raise RuntimeError(f"Security violation: Invalid file path '{filepath}'")
        
        if not os.path.isfile(filepath) or not os.access(filepath, os.R_OK):
            raise RuntimeError(f"File {filepath} does not exist or is not readable")
        
        file_size = os.path.getsize(filepath)
        max_file_size = Config().get('max_file_size', 10485760)
        
        if file_size > max_file_size:
            raise RuntimeError(f"File {filepath} is too large ({file_size} bytes)")
        
        timeout_seconds = Config().get('file_operation_timeout', 5)
        try:
            with timeout(timeout_seconds):
                with open(filepath, 'r') as f:
                    return f.read()
        except TimeoutError as e:
            raise RuntimeError(f"Timeout reading {filepath}: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to read {filepath}: {e}")
    
    @staticmethod
    def handle_exception(e: Exception, verbose: bool = False):
        message = f"Error: {str(e)}"
        sys.stderr.write(message + "\n")
        Logger.get_instance().error(message)
        
        if verbose:
            import traceback
            traceback.print_exc()

class TempFileRegistry:
    _files = []
    _lock = threading.Lock()
    
    @classmethod
    def register(cls, filepath: str):
        with cls._lock:
            cls._files.append(filepath)
    
    @classmethod
    def cleanup(cls):
        with cls._lock:
            for filepath in cls._files:
                try:
                    os.unlink(filepath)
                except:
                    pass
            cls._files.clear()
    
    @classmethod
    def get_registered_files(cls) -> list:
        with cls._lock:
            return cls._files.copy()

class InputValidator:
    @staticmethod
    def validate_port(port) -> int:
        return Security.validate_integer(port, MIN_PORT, MAX_PORT)
    
    @staticmethod
    def validate_ip_filter(filter_str: str) -> str:
        if not InputValidator._is_valid_ip_or_cidr(filter_str):
            raise ValueError(f"Invalid IP or CIDR notation: {filter_str}")
        return filter_str
    
    @staticmethod
    def _is_valid_ip_or_cidr(input_str: str) -> bool:
        input_str = input_str.strip()
        if not input_str:
            return False
        
        if '/' in input_str:
            parts = input_str.split('/', 1)
            if len(parts) != 2:
                return False
            
            ip, mask = parts
            if not mask or not mask.isdigit():
                return False
            
            mask = int(mask)
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    return MIN_CIDR_IPV4 <= mask <= MAX_CIDR_IPV4
                else:
                    return MIN_CIDR_IPV6 <= mask <= MAX_CIDR_IPV6
            except ValueError:
                return False
        
        try:
            ipaddress.ip_address(input_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_interval(interval) -> int:
        return Security.validate_integer(interval, MIN_INTERVAL, MAX_INTERVAL)
    
    @staticmethod
    def validate_output_file(filepath: str) -> str:
        directory = os.path.dirname(filepath)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        
        if directory and not os.access(directory, os.W_OK):
            raise ValueError(f"Output directory is not writable: {directory}")
        
        return filepath
    
    @staticmethod
    def validate_pid(pid) -> int:
        max_pid = Config().get('max_pid', 4194304)
        return Security.validate_integer(pid, 1, max_pid)

class IPUtils:
    @staticmethod
    def hex_to_ipv4(hex_str: str) -> str:
        hex_str = re.sub(r'[^0-9A-Fa-f]', '', hex_str)
        if len(hex_str) != IPV4_HEX_LENGTH:
            return '0.0.0.0'
        
        parts = []
        for i in range(0, IPV4_HEX_LENGTH, 2):
            parts.append(str(int(hex_str[i:i+2], 16)))
        
        return '.'.join(reversed(parts))
    
    @staticmethod
    def hex_to_ipv6(hex_str: str) -> str:
        hex_str = re.sub(r'[^0-9A-Fa-f]', '', hex_str)
        if not hex_str:
            return '::'
        
        if len(hex_str) != IPV6_HEX_LENGTH:
            hex_str = hex_str.ljust(IPV6_HEX_LENGTH, '0')[:IPV6_HEX_LENGTH]
        
        if not all(c in '0123456789abcdefABCDEF' for c in hex_str):
            return '::'
        
        blocks = [hex_str[i:i+8] for i in range(0, IPV6_HEX_LENGTH, 8)]
        blocks.reverse()
        reordered = ''.join(blocks)
        
        try:
            packed = bytes.fromhex(reordered)
            return str(ipaddress.ip_address(packed))
        except:
            return '::'
    
    @staticmethod
    def ip_in_cidr(ip: str, cidr: str) -> bool:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj in network
        except:
            return False

@dataclass
class Connection:
    proto: str
    state: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    inode: str
    process: str = ''
    timestamp: int = field(default_factory=lambda: int(time.time()))
    
    def key(self) -> str:
        return f"{self.local_ip}:{self.local_port}-{self.remote_ip}:{self.remote_port}-{self.state}"

class ProcessCache:
    _cache = {}
    _last_build = 0
    _building = False
    _connection_inodes = None
    _hits = 0
    _misses = 0
    _last_scan = 0
    _lock = threading.Lock()
    _inode_to_pid = {}
    
    @classmethod
    def get_process_map(cls) -> dict:
        if cls._building:
            return cls._cache.copy() if cls._cache else {}
        
        now = time.time()
        ttl = Config().get('process_cache_ttl', 5)
        
        if not cls._cache or (now - cls._last_build) > ttl:
            with cls._lock:
                if (not cls._cache or (now - cls._last_build) > ttl) and not cls._building:
                    cls._misses += 1
                    cls._building = True
                    try:
                        new_cache = cls._build_process_map_fast()
                        if new_cache or not cls._cache:
                            cls._cache = new_cache
                            cls._last_build = now
                            cls._last_scan = now
                    except Exception as e:
                        Logger.get_instance().error(f"Failed to build process cache: {e}")
                    finally:
                        cls._building = False
        else:
            cls._hits += 1
        
        return cls._cache.copy() if cls._cache else {}
    
    @classmethod
    def _build_process_map_fast(cls) -> dict:
        if not Config().get('enable_process_scan', True):
            return {}
        
        try:
            Security.validate_proc_filesystem()
        except RuntimeError:
            return {}
        
        process_map = {}
        cls._connection_inodes = cls._extract_inodes_from_proc_net_fast()
        
        if not cls._connection_inodes:
            return process_map
        
        inode_set = set(cls._connection_inodes)
        
        scan_start = time.time()
        max_scan_time = Config().get('max_process_scan_time', 30)
        skip_kernel = Config().get('skip_kernel_threads', True)
        
        timeout_seconds = Config().get('file_operation_timeout', 5)
        
        try:
            for entry in os.listdir('/proc'):
                if not entry.isdigit():
                    continue
                
                if time.time() - scan_start > max_scan_time:
                    break
                
                pid = int(entry)
                
                if skip_kernel and pid < 10:
                    continue
                
                try:
                    with timeout(timeout_seconds):
                        status_path = f"/proc/{pid}/status"
                        if not os.path.exists(status_path):
                            continue
                        
                        with open(status_path, 'r') as f:
                            content = f.read(1024)
                        
                        if skip_kernel and 'Kthread' in content:
                            continue
                        
                        inodes = cls._get_process_inodes_fast(pid)
                        
                        if inodes:
                            name_match = re.search(r'Name:\s*(.+)', content)
                            process_name = name_match.group(1).strip() if name_match else f"PID:{pid}"
                            
                            for inode in inodes:
                                if inode in inode_set:
                                    process_map[inode] = f"{process_name} (PID:{pid})"
                                    if len(process_map) >= len(inode_set):
                                        break
                except TimeoutError:
                    continue
                except (OSError, IOError):
                    continue
                
                if len(process_map) >= len(inode_set):
                    break
        except PermissionError:
            pass
        
        return process_map
    
    @classmethod
    def _extract_inodes_from_proc_net_fast(cls) -> List[int]:
        inodes = []
        max_inodes = Config().get('max_inodes_to_scan', 100000)
        files = ['/proc/net/tcp', '/proc/net/tcp6']
        
        timeout_seconds = Config().get('file_operation_timeout', 5)
        
        for filepath in files:
            if len(inodes) >= max_inodes:
                break
            
            if not os.path.exists(filepath):
                continue
            
            try:
                with timeout(timeout_seconds):
                    with open(filepath, 'r') as f:
                        next(f)
                        for line in f:
                            match = re.search(r'\s+(\d+)$', line.strip())
                            if match:
                                inodes.append(int(match.group(1)))
                                if len(inodes) >= max_inodes:
                                    break
            except (TimeoutError, OSError, IOError):
                continue
        
        return list(set(inodes))
    
    @classmethod
    def _get_process_inodes_fast(cls, pid: int) -> Set[int]:
        inodes = set()
        fd_path = f"/proc/{pid}/fd"
        
        if not os.path.isdir(fd_path):
            return inodes
        
        timeout_seconds = Config().get('file_operation_timeout', 5)
        
        try:
            with timeout(timeout_seconds):
                try:
                    for fd in os.listdir(fd_path)[:100]:
                        try:
                            link = os.readlink(os.path.join(fd_path, fd))
                            match = re.search(r'socket:\[(\d+)\]', link)
                            if match:
                                inodes.add(int(match.group(1)))
                        except (OSError, IOError):
                            pass
                except OSError:
                    pass
        except TimeoutError:
            pass
        
        return inodes
    
    @classmethod
    def clear_cache(cls):
        with cls._lock:
            cls._cache = {}
            cls._last_build = 0
            cls._hits = 0
            cls._misses = 0
            cls._last_scan = 0
            cls._building = False
            cls._inode_to_pid = {}
    
    @classmethod
    def disable_process_scan(cls):
        Config().set('enable_process_scan', False)
    
    @classmethod
    def get_stats(cls) -> dict:
        total = cls._hits + cls._misses
        return {
            'cache_size': len(cls._cache),
            'hits': cls._hits,
            'misses': cls._misses,
            'hit_rate': round(cls._hits / total * 100, 2) if total > 0 else 0,
            'building': cls._building
        }

class ConnectionCache:
    _cache = {}
    _hits = 0
    _misses = 0
    _lock = threading.Lock()
    
    @classmethod
    def get_connections(cls, filepath: str, family: int, include_process: bool = False) -> List[Connection]:
        max_connections = Config().get('max_connections_per_scan', 50000)
        timeout_seconds = Config().get('file_operation_timeout', 5)
        
        try:
            with timeout(timeout_seconds):
                stat = os.stat(filepath)
        except (TimeoutError, OSError):
            return []
        
        cache_key = f"{filepath}_{family}_{include_process}_{stat.st_mtime}_{stat.st_size}"
        
        with cls._lock:
            if cache_key in cls._cache:
                cls._hits += 1
                return cls._cache[cache_key]['data'].copy()
            
            cls._misses += 1
            
            with PerformanceTracker.timer(f"read_{os.path.basename(filepath)}"):
                connections = cls._read_connections_fast(filepath, family, include_process)
                
                if len(connections) > max_connections:
                    connections = connections[:max_connections]
                
                cls._cache[cache_key] = {
                    'data': connections,
                    'timestamp': time.time()
                }
                
                if len(cls._cache) > Config().get('max_cache_size', 10000):
                    oldest = min(cls._cache.keys(), key=lambda k: cls._cache[k]['timestamp'])
                    del cls._cache[oldest]
            
            return connections.copy()
    
    @classmethod
    def _read_connections_fast(cls, filepath: str, family: int, include_process: bool) -> List[Connection]:
        if not os.path.isfile(filepath) or not os.access(filepath, os.R_OK):
            return []
        
        connections = []
        process_map = ProcessCache.get_process_map() if include_process else {}
        
        timeout_seconds = Config().get('file_operation_timeout', 5)
        
        try:
            with timeout(timeout_seconds):
                with open(filepath, 'r') as f:
                    next(f)
                    
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        fields = re.split(r'\s+', line)
                        if len(fields) < 10:
                            continue
                        
                        try:
                            local = fields[1].split(':')
                            remote = fields[2].split(':')
                            
                            if len(local) != 2 or len(remote) != 2:
                                continue
                            
                            if family == AF_INET:
                                local_ip = IPUtils.hex_to_ipv4(local[0])
                                remote_ip = IPUtils.hex_to_ipv4(remote[0])
                            else:
                                local_ip = IPUtils.hex_to_ipv6(local[0])
                                remote_ip = IPUtils.hex_to_ipv6(remote[0])
                            
                            local_port = int(local[1], 16)
                            remote_port = int(remote[1], 16)
                            state_code = fields[3].upper()
                            state = TCP_STATES.get(state_code, f"UNKNOWN")
                            proto = 'IPv4' if family == AF_INET else 'IPv6'
                            inode = fields[9]
                            
                            process = ''
                            if include_process and inode.isdigit():
                                process = process_map.get(int(inode), '')
                            
                            connections.append(Connection(
                                proto=proto, state=state, local_ip=local_ip,
                                local_port=local_port, remote_ip=remote_ip,
                                remote_port=remote_port, inode=inode, process=process
                            ))
                        except (ValueError, IndexError):
                            continue
        except (TimeoutError, OSError, IOError):
            return []
        
        return connections
    
    @classmethod
    def clear_cache(cls):
        with cls._lock:
            cls._cache = {}
            cls._hits = 0
            cls._misses = 0
    
    @classmethod
    def get_stats(cls) -> dict:
        total = cls._hits + cls._misses
        return {
            'cache_entries': len(cls._cache),
            'hits': cls._hits,
            'misses': cls._misses,
            'hit_rate': round(cls._hits / total * 100, 2) if total > 0 else 0
        }

class OutputFormatter:
    @staticmethod
    def format_table(connections: List[Connection], show_process: bool = False, use_colors: bool = True) -> str:
        if not connections:
            return "No connections found.\n"
        
        connections.sort(key=lambda x: (x.local_port, x.proto, x.state))
        output = "\nACTIVE TCP CONNECTIONS:\n"
        
        if show_process:
            output += f"{'Proto':<5} {'State':<15} {'Local Address':<25} {'Remote Address':<25} {'Process':<30}\n"
            output += "-" * 105 + "\n"
            
            for conn in connections:
                color = COLORS.get(conn.state, '') if use_colors else ''
                reset = COLORS['reset'] if use_colors else ''
                process = conn.process or '[unknown]'
                output += f"{conn.proto:<5} {color}{conn.state:<15}{reset} {conn.local_ip}:{conn.local_port:<25} {conn.remote_ip}:{conn.remote_port:<25} {process[:30]:<30}\n"
        else:
            output += f"{'Proto':<5} {'State':<15} {'Local Address':<25} {'Remote Address':<25}\n"
            output += "-" * 75 + "\n"
            
            for conn in connections:
                color = COLORS.get(conn.state, '') if use_colors else ''
                reset = COLORS['reset'] if use_colors else ''
                output += f"{conn.proto:<5} {color}{conn.state:<15}{reset} {conn.local_ip}:{conn.local_port:<25} {conn.remote_ip}:{conn.remote_port:<25}\n"
        
        stats = OutputFormatter._get_connection_stats(connections)
        output += OutputFormatter._format_summary(stats, use_colors)
        return output
    
    @staticmethod
    def format_json(connections: List[Connection], include_stats: bool = False) -> str:
        if include_stats:
            output = {
                'connections': [asdict(c) for c in connections],
                'statistics': OutputFormatter._get_connection_stats(connections),
                'metadata': {
                    'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'count': len(connections)
                }
            }
        else:
            output = [asdict(c) for c in connections]
        
        return json.dumps(output, indent=2) + "\n"
    
    @staticmethod
    def format_csv(connections: List[Connection]) -> str:
        if not connections:
            return ""
        
        output = "Protocol,State,Local IP,Local Port,Remote IP,Remote Port,Process,Inode\n"
        
        for conn in connections:
            process = conn.process.replace('"', '""')
            if any(c in process for c in [',', '"', '\n', '\r']):
                process = f'"{process}"'
            
            output += f"{conn.proto},{conn.state},{conn.local_ip},{conn.local_port},{conn.remote_ip},{conn.remote_port},{process},{conn.inode}\n"
        
        return output
    
    @staticmethod
    def format_statistics(connections: List[Connection], use_colors: bool = True) -> str:
        stats = OutputFormatter._get_connection_stats(connections)
        output = "\nDETAILED TCP CONNECTION STATISTICS\n"
        output += "=" * 50 + "\n"
        output += f"Generated at: {stats['timestamp']}\n"
        output += f"Total connections: {stats['total']}\n"
        output += f"IPv4 connections: {stats['ipv4']}\n"
        output += f"IPv6 connections: {stats['ipv6']}\n\n"
        
        output += "Connections by State:\n"
        output += "-" * 30 + "\n"
        for state, count in sorted(stats['by_state'].items()):
            color = COLORS.get(state, '') if use_colors else ''
            reset = COLORS['reset'] if use_colors else ''
            output += f"{color}{state:<20}{reset}: {count}\n"
        
        if stats['by_process']:
            output += "\nConnections by Process (Top 10):\n"
            output += "-" * 50 + "\n"
            
            sorted_processes = sorted(stats['by_process'].items(), key=lambda x: x[1], reverse=True)
            for process, count in sorted_processes[:10]:
                if process and process != '[unknown]':
                    output += f"{process:<40}: {count}\n"
        
        return output
    
    @staticmethod
    def _get_connection_stats(connections: List[Connection]) -> dict:
        stats = {
            'total': len(connections),
            'ipv4': 0,
            'ipv6': 0,
            'by_state': defaultdict(int),
            'by_process': defaultdict(int),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        for conn in connections:
            if conn.proto == 'IPv4':
                stats['ipv4'] += 1
            else:
                stats['ipv6'] += 1
            
            stats['by_state'][conn.state] += 1
            
            if conn.process:
                stats['by_process'][conn.process] += 1
        
        return dict(stats)
    
    @staticmethod
    def _format_summary(stats: dict, use_colors: bool = True) -> str:
        output = f"\nSummary: {stats['total']} total connections ({stats['ipv4']} IPv4, {stats['ipv6']} IPv6)\n"
        
        if stats['by_state']:
            output += "By state: "
            state_strings = []
            for state, count in sorted(stats['by_state'].items()):
                color = COLORS.get(state, '') if use_colors else ''
                reset = COLORS['reset'] if use_colors else ''
                state_strings.append(f"{color}{state}{reset}: {count}")
            output += ", ".join(state_strings) + "\n"
        
        return output
    
    @staticmethod
    def strip_colors(text: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', text)

class ConnectionFilter:
    @staticmethod
    def filter(connections: List[Connection], options: dict) -> List[Connection]:
        states = ConnectionFilter._get_requested_states(options)
        port = options.get('port')
        local_ip = options.get('local_ip')
        remote_ip = options.get('remote_ip')
        ipv4_only = options.get('ipv4', False)
        ipv6_only = options.get('ipv6', False)
        
        if not any([states, port, local_ip, remote_ip, ipv4_only, ipv6_only]):
            return connections
        
        result = []
        for conn in connections:
            if states and conn.state not in states:
                continue
            
            if port and conn.local_port != port and conn.remote_port != port:
                continue
            
            if local_ip and not ConnectionFilter._ip_matches_filter(conn.local_ip, local_ip):
                continue
            
            if remote_ip and not ConnectionFilter._ip_matches_filter(conn.remote_ip, remote_ip):
                continue
            
            if ipv4_only and conn.proto != 'IPv4':
                continue
            
            if ipv6_only and conn.proto != 'IPv6':
                continue
            
            result.append(conn)
        
        return result
    
    @staticmethod
    def _get_requested_states(options: dict) -> List[str]:
        states = []
        if options.get('listen'):
            states.append('LISTEN')
        if options.get('established'):
            states.append('ESTABLISHED')
        if options.get('timewait'):
            states.append('TIME_WAIT')
        if options.get('closewait'):
            states.append('CLOSE_WAIT')
        if options.get('finwait'):
            states.extend(['FIN_WAIT1', 'FIN_WAIT2'])
        return states
    
    @staticmethod
    def _ip_matches_filter(ip: str, filter_str: str) -> bool:
        if ip == filter_str:
            return True
        if '/' in filter_str:
            return IPUtils.ip_in_cidr(ip, filter_str)
        return False

class ConnectionHistory:
    _history = deque(maxlen=1000)
    _lock = threading.Lock()
    
    @classmethod
    def track_changes(cls, current: List[Connection]) -> dict:
        changes = {
            'timestamp': time.time(),
            'total': len(current),
            'added': [],
            'removed': []
        }
        
        with cls._lock:
            if cls._history:
                previous = cls._history[-1]
                current_keys = {c.key() for c in current}
                previous_keys = {c.key() for c in previous}
                
                changes['added'] = list(current_keys - previous_keys)[:10]
                changes['removed'] = list(previous_keys - current_keys)[:10]
            
            cls._history.append(current)
        
        return changes
    
    @classmethod
    def clear_history(cls):
        with cls._lock:
            cls._history.clear()
    
    @classmethod
    def get_history_stats(cls) -> dict:
        with cls._lock:
            return {
                'history_size': len(cls._history),
                'total_tracked': sum(len(h) for h in cls._history)
            }

class SignalHandler:
    _should_exit = False
    _start_time = time.time()
    _initialized = False
    
    @classmethod
    def init(cls):
        if cls._initialized:
            return
        
        cls._start_time = time.time()
        cls._initialized = True
        
        signal.signal(signal.SIGINT, cls._handle_signal)
        signal.signal(signal.SIGTERM, cls._handle_signal)
    
    @classmethod
    def _handle_signal(cls, signum, frame):
        if signum in (signal.SIGINT, signal.SIGTERM):
            cls._should_exit = True
    
    @classmethod
    def should_exit(cls) -> bool:
        return cls._should_exit

class TCPConnectionMonitor:
    def __init__(self, options: dict):
        self.options = options
    
    def get_connections(self) -> List[Connection]:
        if not RateLimiter.check_limit():
            return []
        
        include_process = self.options.get('processes', False)
        
        connections = []
        connections.extend(ConnectionCache.get_connections('/proc/net/tcp', AF_INET, include_process))
        connections.extend(ConnectionCache.get_connections('/proc/net/tcp6', AF_INET6, include_process))
        
        return ConnectionFilter.filter(connections, self.options)

class ConnectionWatcher:
    def __init__(self, monitor: TCPConnectionMonitor):
        self.monitor = monitor
    
    def watch(self, options: dict, interval: int = 2):
        iteration = 0
        SignalHandler.init()
        
        print(f"Watching TCP connections (refresh every {interval}s). Press Ctrl+C to stop.")
        print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        while not SignalHandler.should_exit():
            iteration += 1
            print("\033[2J\033[;H", end='')
            
            connections = self.monitor.get_connections()
            
            changes = ConnectionHistory.track_changes(connections)
            
            if iteration > 1:
                added = len(changes['added'])
                removed = len(changes['removed'])
                if added or removed:
                    print(f"Changes: +{added} -{removed}")
                else:
                    print("No changes")
            
            print(f"[{time.strftime('%H:%M:%S')}] Iteration: {iteration} | Connections: {len(connections)}")
            print("-" * 60)
            
            if options.get('json'):
                print(OutputFormatter.format_json(connections, options.get('stats', False)), end='')
            else:
                print(OutputFormatter.format_table(connections, options.get('processes', False)), end='')
            
            for _ in range(interval):
                if SignalHandler.should_exit():
                    break
                time.sleep(1)

class Exporter:
    @staticmethod
    def to_file(content: str, filename: str):
        with open(filename, 'w') as f:
            f.write(content)
        Logger.get_instance().info(f"Output written to: {filename}")
    
    @staticmethod
    def to_file_with_backup(content: str, filename: str):
        if os.path.exists(filename):
            backup = filename + '.bak'
            if os.path.exists(backup):
                os.unlink(backup)
            os.rename(filename, backup)
        
        Exporter.to_file(content, filename)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Monitor TCP connections on Linux')
    
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--csv', action='store_true', help='CSV output')
    parser.add_argument('--listen', action='store_true', help='Show listening sockets')
    parser.add_argument('--established', action='store_true', help='Show established connections')
    parser.add_argument('--timewait', action='store_true', help='Show TIME_WAIT connections')
    parser.add_argument('--closewait', action='store_true', help='Show CLOSE_WAIT connections')
    parser.add_argument('--finwait', action='store_true', help='Show FIN_WAIT connections')
    parser.add_argument('--count', action='store_true', help='Show only counts')
    parser.add_argument('--processes', action='store_true', help='Show process info')
    parser.add_argument('--no-processes', action='store_true', help='Disable process scan')
    parser.add_argument('--port', type=int, help='Filter by port')
    parser.add_argument('--local-ip', help='Filter by local IP')
    parser.add_argument('--remote-ip', help='Filter by remote IP')
    parser.add_argument('--ipv4', action='store_true', help='IPv4 only')
    parser.add_argument('--ipv6', action='store_true', help='IPv6 only')
    parser.add_argument('--watch', nargs='?', const=2, type=int, metavar='SEC', help='Watch mode')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--log-file', help='Log file')
    parser.add_argument('--config', help='Config file')
    parser.add_argument('--env-file', help='Environment file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    parser.add_argument('--version', action='store_true', help='Show version')
    
    return parser.parse_args()

def display_performance_metrics(options):
    if options.verbose or options.debug:
        metrics = PerformanceTracker.get_metrics()
        process_stats = ProcessCache.get_stats()
        connection_stats = ConnectionCache.get_stats()
        
        print("\nPerformance:")
        print(f"  Time: {metrics['execution_time']}s")
        print(f"  Memory: {metrics['memory_peak_mb']} KB")
        print(f"  Process cache: {process_stats['cache_size']} entries, {process_stats['hit_rate']}% hits")
        print(f"  Connection cache: {connection_stats['cache_entries']} entries, {connection_stats['hit_rate']}% hits")

def main():
    try:
        PerformanceTracker.start()
        
        if not sys.platform.startswith('linux'):
            raise RuntimeError("Linux only")
        
        Security.validate_proc_filesystem()
        
        options = parse_arguments()
        
        if options.version:
            print("TCP Monitor v1.0")
            return 0
        
        config = Config()
        
        if options.env_file:
            config.load_from_env_file(options.env_file)
        
        if options.config:
            config.load_from_file(options.config)
        
        config.load_from_env()
        
        logger = Logger.get_instance()
        if options.debug:
            logger.set_log_level('DEBUG')
        
        if options.log_file:
            logger.set_log_file(options.log_file)
        
        if options.no_processes:
            ProcessCache.disable_process_scan()
        
        monitor = TCPConnectionMonitor(vars(options))
        
        if options.watch:
            watcher = ConnectionWatcher(monitor)
            watcher.watch(vars(options), options.watch)
            return 0
        
        connections = monitor.get_connections()
        
        if options.count:
            stats = OutputFormatter._get_connection_stats(connections)
            print(f"total={stats['total']} ipv4={stats['ipv4']} ipv6={stats['ipv6']}")
            return 0
        
        if options.stats:
            output = OutputFormatter.format_statistics(connections)
        elif options.json:
            output = OutputFormatter.format_json(connections, options.stats)
        elif options.csv:
            output = OutputFormatter.format_csv(connections)
        else:
            output = OutputFormatter.format_table(connections, options.processes)
        
        if options.output:
            if options.csv or not options.json:
                output = OutputFormatter.strip_colors(output)
            Exporter.to_file_with_backup(output, options.output)
            print(f"Output written to: {options.output}")
        else:
            print(output, end='')
        
        display_performance_metrics(options)
        
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        ErrorHandler.handle_exception(e, options.verbose if 'options' in locals() else False)
        return 1
    finally:
        TempFileRegistry.cleanup()
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
