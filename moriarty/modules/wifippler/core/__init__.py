"""
Core functionality for the WifiPPLER module.

This module provides the core functionality for the WifiPPLER tool,
including network scanning, packet analysis, and attack modules.
"""

from .scanner import WiFiScanner
from .attacks import (
    WPSAttack,
    WPAHandshakeAttack,
    PMKIDAttack,
    WEPAttack,
    DeauthAttack,
    HandshakeCapture
)

# Import utility functions
from .utils import (
    is_root,
    check_dependencies,
    get_network_interfaces,
    get_monitor_interfaces,
    set_monitor_mode,
    restore_network_interface,
    start_monitor_mode,
    stop_monitor_mode,
    run_command_async,
    randomize_mac,
    get_interface_mac,
    get_interface_ip,
    get_interface_netmask,
    get_interface_gateway,
    is_wireless_interface,
    get_interface_signal,
    get_interface_ssid,
    get_interface_channel,
    get_interface_bitrate,
    create_deauth_packet,
    parse_airodump_csv,
    parse_airodump_stations,
    run_command,
    randomize_mac,
    get_wireless_interfaces
)

__all__ = [
    'WiFiScanner',
    'WPSAttack',
    'WPAHandshakeAttack',
    'PMKIDAttack',
    'WEPAttack',
    'DeauthAttack',
    'HandshakeCapture',
    'is_root',
    'check_dependencies',
    'command_exists',
    'get_network_interfaces',
    'get_monitor_interfaces',
    'set_monitor_mode',
    'restore_network_interface',
    'start_monitor_mode',
    'stop_monitor_mode',
    'get_interface_mac',
    'get_interface_ip',
    'get_interface_netmask',
    'get_interface_gateway',
    'is_wireless_interface',
    'get_interface_signal',
    'get_interface_ssid',
    'get_interface_channel',
    'get_interface_bitrate',
    'create_deauth_packet',
    'parse_airodump_csv',
    'parse_airodump_stations',
    'run_command',
    'run_command_async',
    'randomize_mac',
    'get_wireless_interfaces'
]
