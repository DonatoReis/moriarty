"""
Utility functions for WifiPPLER.

This module provides various utility functions used throughout the WifiPPLER
package, including network interface management, dependency checking, and
other helper functions.
"""
import os
import re
import sys
import time
import logging
import subprocess
import shutil
import fcntl
import struct
import array
import socket
import platform
from typing import List, Dict, Tuple, Optional, Union, Any, Callable, Set
from dataclasses import asdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
WIRELESS_EXT = 0x8B01  # SIOCGIWNAME
SIOCGIFHWADDR = 0x8927  # Get hardware address
SIOCGIFADDR = 0x8915    # Get IP address
SIOCGIFNETMASK = 0x891B  # Get netmask
SIOCGIFBRDADDR = 0x8919  # Get broadcast address
SIOCGIFMTU = 0x8921     # Get MTU
SIOCGIFINDEX = 0x8933   # Get interface index
SIOCGIFNAME = 0x8910    # Get interface name
SIOCGIFFLAGS = 0x8913   # Get interface flags
SIOCSIFFLAGS = 0x8914   # Set interface flags

# Platform-specific constants
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'
IS_WINDOWS = platform.system() == 'Windows'

# Network interface flags
IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_DEBUG = 0x4
IFF_LOOPBACK = 0x8
IFF_POINTOPOINT = 0x10
IFF_NOTRAILERS = 0x20
IFF_RUNNING = 0x40
IFF_NOARP = 0x80
IFF_PROMISC = 0x100
IFF_ALLMULTI = 0x200
IFF_MASTER = 0x400
IFF_SLAVE = 0x800
IFF_MULTICAST = 0x1000
IFF_PORTSEL = 0x2000
IFF_AUTOMEDIA = 0x4000
IFF_DYNAMIC = 0x8000

def is_root() -> bool:
    """
    Check if the script is running with root privileges.
    
    Returns:
        bool: True if running as root, False otherwise
    """
    return os.geteuid() == 0

def check_dependencies() -> List[str]:
    """
    Check for required system dependencies.
    
    Returns:
        List[str]: List of missing dependencies
    """
    required = [
        'iwconfig', 'iw', 'ifconfig', 'aircrack-ng', 'airodump-ng',
        'aireplay-ng', 'airmon-ng', 'wash', 'reaver', 'bully', 'hcxdumptool',
        'hcxpcapngtool', 'hashcat', 'tshark', 'macchanger', 'rfkill'
    ]
    
    missing = []
    for cmd in required:
        if not command_exists(cmd):
            missing.append(cmd)
    
    return missing

def command_exists(cmd: str) -> bool:
    """
    Check if a command exists in the system PATH.
    
    Args:
        cmd: Command to check
        
    Returns:
        bool: True if command exists, False otherwise
    """
    return shutil.which(cmd) is not None

def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Get a list of all network interfaces.
    
    Returns:
        List[Dict[str, Any]]: List of interfaces with their properties
    """
    interfaces = []
    
    if IS_LINUX:
        # Linux implementation using /sys/class/net
        net_path = '/sys/class/net'
        if os.path.exists(net_path):
            for ifname in os.listdir(net_path):
                if ifname == 'lo':
                    continue
                    
                iface = {
                    'name': ifname,
                    'wireless': os.path.exists(f"{net_path}/{ifname}/wireless"),
                    'state': 'down',
                    'mac': get_interface_mac(ifname),
                    'ip': get_interface_ip(ifname),
                    'netmask': get_interface_netmask(ifname),
                    'broadcast': get_interface_broadcast(ifname),
                    'mtu': get_interface_mtu(ifname)
                }
                
                # Check if interface is up
                try:
                    with open(f"{net_path}/{ifname}/operstate", 'r') as f:
                        state = f.read().strip()
                        iface['state'] = state if state in ['up', 'down'] else 'unknown'
                except:
                    pass
                
                interfaces.append(iface)
    
    elif IS_MAC:
        # macOS implementation using ifconfig
        try:
            result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                for ifname in result.stdout.strip().split():
                    if ifname == 'lo0':
                        continue
                        
                    iface = {
                        'name': ifname,
                        'wireless': ifname.startswith(('en', 'wl')),  # Approximate
                        'state': 'unknown',
                        'mac': get_interface_mac(ifname),
                        'ip': get_interface_ip(ifname),
                        'netmask': get_interface_netmask(ifname),
                        'broadcast': get_interface_broadcast(ifname),
                        'mtu': get_interface_mtu(ifname)
                    }
                    
                    # Check if interface is up
                    result = subprocess.run(['ifconfig', ifname], capture_output=True, text=True)
                    if 'status: active' in result.stdout or 'UP' in result.stdout:
                        iface['state'] = 'up'
                    else:
                        iface['state'] = 'down'
                    
                    interfaces.append(iface)
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
    
    return interfaces

def get_wireless_interfaces() -> List[Dict[str, Any]]:
    """
    Get a list of wireless network interfaces.
    
    Returns:
        List[Dict[str, Any]]: List of wireless interfaces with their properties
    """
    return [iface for iface in get_network_interfaces() 
            if iface.get('wireless', False)]

def get_interface_mac(interface: str) -> Optional[str]:
    """
    Get the MAC address of a network interface.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[str]: MAC address or None if not found
    """
    try:
        if IS_LINUX or IS_MAC:
            with open(f"/sys/class/net/{interface}/address") as f:
                return f.read().strip()
    except:
        pass
    
    try:
        if IS_LINUX:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15].encode()))
            return ':'.join(f'{b:02x}' for b in info[18:24])
        elif IS_MAC:
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result.stdout)
            if match:
                return match.group(0).lower()
    except:
        pass
    
    return None

def get_interface_ip(interface: str) -> Optional[str]:
    """
    Get the IP address of a network interface.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[str]: IP address or None if not found
    """
    try:
        if IS_LINUX or IS_MAC:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Works for both IPv4 and IPv6
                return socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', interface[:15].encode())
                )[20:24])
            except:
                pass
    except:
        pass
    
    try:
        if IS_MAC:
            result = subprocess.run(['ifconfig', interface, 'inet'], capture_output=True, text=True)
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except:
        pass
    
    return None

def get_interface_netmask(interface: str) -> Optional[str]:
    """
    Get the netmask of a network interface.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[str]: Netmask or None if not found
    """
    try:
        if IS_LINUX or IS_MAC:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                netmask = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x891B,  # SIOCGIFNETMASK
                    struct.pack('256s', interface[:15].encode())
                )[20:24])
                return netmask
            except:
                pass
    except:
        pass
    
    try:
        if IS_MAC:
            result = subprocess.run(['ifconfig', interface, 'inet'], capture_output=True, text=True)
            match = re.search(r'netmask (0x[0-9a-fA-F]+)', result.stdout)
            if match:
                # Convert hex netmask to dotted decimal
                netmask_hex = match.group(1)
                netmask_int = int(netmask_hex, 16)
                return socket.inet_ntoa(struct.pack('>I', netmask_int))
    except:
        pass
    
    return None

def get_interface_broadcast(interface: str) -> Optional[str]:
    """
    Get the broadcast address of a network interface.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[str]: Broadcast address or None if not found
    """
    try:
        if IS_LINUX or IS_MAC:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                broadcast = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x8919,  # SIOCGIFBRDADDR
                    struct.pack('256s', interface[:15].encode())
                )[20:24])
                return broadcast
            except:
                pass
    except:
        pass
    
    try:
        if IS_MAC:
            result = subprocess.run(['ifconfig', interface, 'inet'], capture_output=True, text=True)
            match = re.search(r'broadcast (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except:
        pass
    
    return None

def get_interface_mtu(interface: str) -> Optional[int]:
    """
    Get the MTU of a network interface.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[int]: MTU or None if not found
    """
    try:
        if IS_LINUX:
            with open(f"/sys/class/net/{interface}/mtu", 'r') as f:
                return int(f.read().strip())
        elif IS_MAC:
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            match = re.search(r'mtu (\d+)', result.stdout)
            if match:
                return int(match.group(1))
    except:
        pass
    
    return None

def set_monitor_mode(interface: str, channel: int = None) -> bool:
    """
    Set a wireless interface to monitor mode.
    
    Args:
        interface: Interface name
        channel: Optional channel to set
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not is_root():
        logger.error("Root privileges required to set monitor mode")
        return False
    
    try:
        # Bring interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        
        # Set monitor mode
        subprocess.run(['iw', 'dev', interface, 'set', 'monitor', 'none'], check=True)
        
        # Bring interface up
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        # Set channel if specified
        if channel is not None:
            subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)], check=True)
        
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set monitor mode: {e}")
        return False

def set_managed_mode(interface: str) -> bool:
    """
    Set a wireless interface to managed mode.
    
    Args:
        interface: Interface name
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not is_root():
        logger.error("Root privileges required to set managed mode")
        return False
    
    try:
        # Bring interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        
        # Set managed mode
        subprocess.run(['iw', 'dev', interface, 'set', 'type', 'managed'], check=True)
        
        # Bring interface up
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        # Restart network manager
        if command_exists('systemctl'):
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], check=False)
        elif command_exists('service'):
            subprocess.run(['service', 'network-manager', 'restart'], check=False)
        
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set managed mode: {e}")
        return False

def get_monitor_interfaces() -> List[str]:
    """
    Get a list of interfaces in monitor mode.
    
    Returns:
        List[str]: List of interface names in monitor mode
    """
    interfaces = []
    
    try:
        if IS_LINUX:
            # List all interfaces
            for iface in os.listdir('/sys/class/net'):
                if iface.startswith(('mon', 'wlan', 'wlp', 'wlo')):
                    # Check if in monitor mode
                    proc = subprocess.Popen(['iwconfig', iface], 
                                          stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE)
                    out, _ = proc.communicate()
                    
                    if b'Mode:Monitor' in out:
                        interfaces.append(iface)
        elif IS_MAC:
            # On macOS, interfaces in monitor mode typically start with 'mon'
            result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
            interfaces = [iface for iface in result.stdout.strip().split() 
                         if iface.startswith('en') and 'monitor' in 
                         subprocess.run(['ifconfig', iface], capture_output=True, text=True).stdout]
    except Exception as e:
        logger.error(f"Error getting monitor interfaces: {e}")
    
    return interfaces

def get_interface_signal(interface: str) -> Optional[int]:
    """
    Get the signal strength of a wireless interface in dBm.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[int]: Signal strength in dBm or None if not available
    """
    try:
        if IS_LINUX or IS_MAC:
            proc = subprocess.Popen(['iwconfig', interface], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            
            # Look for signal level in the format "Signal level=-XX dBm"
            match = re.search(r'Signal level=(-\d+)\s*dBm', out.decode('utf-8', 'ignore'))
            if match:
                return int(match.group(1))
    except:
        pass
    
    return None

def get_interface_ssid(interface: str) -> Optional[str]:
    """
    Get the SSID that a wireless interface is connected to.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[str]: SSID or None if not connected
    """
    try:
        if IS_LINUX:
            proc = subprocess.Popen(['iwconfig', interface], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            
            # Look for ESSID in the format "ESSID:"MyWiFi""
            match = re.search(r'ESSID:"([^"]+)"', out.decode('utf-8', 'ignore'))
            if match and match.group(1) != 'off/any':
                return match.group(1)
        elif IS_MAC:
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'], 
                                  capture_output=True, text=True)
            match = re.search(r' SSID: (.+)', result.stdout)
            if match:
                return match.group(1).strip()
    except:
        pass
    
    return None

def get_interface_channel(interface: str) -> Optional[int]:
    """
    Get the current channel of a wireless interface.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[int]: Channel number or None if not available
    """
    try:
        if IS_LINUX or IS_MAC:
            proc = subprocess.Popen(['iwconfig', interface], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            
            # Look for channel in the format "Channel:XX"
            match = re.search(r'Channel:(\d+)', out.decode('utf-8', 'ignore'))
            if match:
                return int(match.group(1))
    except:
        pass
    
    return None

def get_interface_bitrate(interface: str) -> Optional[float]:
    """
    Get the current bitrate of a wireless interface in Mbps.
    
    Args:
        interface: Interface name
        
    Returns:
        Optional[float]: Bitrate in Mbps or None if not available
    """
    try:
        if IS_LINUX or IS_MAC:
            proc = subprocess.Popen(['iwconfig', interface], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            
            # Look for bit rate in the format "Bit Rate=XX Mb/s"
            match = re.search(r'Bit Rate[:=](\d+(?:\.\d+)?)\s*Mb/s', out.decode('utf-8', 'ignore'))
            if match:
                return float(match.group(1))
    except:
        pass
    
    return None

def randomize_mac(interface: str) -> bool:
    """
    Randomize the MAC address of a network interface.
    
    Args:
        interface: Interface name
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not is_root():
        logger.error("Root privileges required to change MAC address")
        return False
    
    try:
        # Generate a random MAC address
        import random
        new_mac = ':'.join(['%02x' % random.randint(0x00, 0xff) for _ in range(6)])
        
        # Bring interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        
        # Set new MAC address
        subprocess.run(['ip', 'link', 'set', 'dev', interface, 'address', new_mac], check=True)
        
        # Bring interface up
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to randomize MAC address: {e}")
        return False

def run_command(cmd: Union[str, List[str]], capture_output: bool = False, 
               check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """
    Run a shell command with error handling.
    
    Args:
        cmd: Command to run (string or list)
        capture_output: Whether to capture stdout/stderr
        check: Whether to raise an exception on non-zero exit code
        **kwargs: Additional arguments to subprocess.run()
        
    Returns:
        subprocess.CompletedProcess: Command execution result
    """
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    kwargs.setdefault('stdout', subprocess.PIPE if capture_output else None)
    kwargs.setdefault('stderr', subprocess.PIPE if capture_output else None)
    kwargs.setdefault('text', True)
    
    try:
        return subprocess.run(cmd, check=check, **kwargs)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}: {' '.join(cmd)}")
        if capture_output and e.stderr:
            logger.error(f"Error output: {e.stderr.strip()}")
        raise

async def run_command_async(cmd: Union[str, List[str]], **kwargs) -> subprocess.CompletedProcess:
    """
    Run a shell command asynchronously.
    
    Args:
        cmd: Command to run (string or list)
        **kwargs: Additional arguments to asyncio.create_subprocess_exec()
        
    Returns:
        subprocess.CompletedProcess: Command execution result
    """
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs
    )
    
    stdout, stderr = await process.communicate()
    
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=process.returncode,
        stdout=stdout.decode() if stdout else '',
        stderr=stderr.decode() if stderr else ''
    )

def get_wireless_drivers() -> List[Dict[str, str]]:
    """
    Get a list of wireless drivers and their information.
    
    Returns:
        List[Dict[str, str]]: List of driver information
    """
    drivers = []
    
    if IS_LINUX:
        try:
            # Check loaded kernel modules
            with open('/proc/modules', 'r') as f:
                for line in f:
                    module = line.split()[0]
                    if any(x in module.lower() for x in ['wlan', 'wireless', '80211', 'ath', 'rtl', 'rtw', 'mt76']):
                        drivers.append({
                            'name': module,
                            'type': 'kernel',
                            'status': 'loaded'
                        })
            
            # Check loaded kernel modules with modinfo
            for driver in drivers[:]:  # Iterate over a copy of the list
                try:
                    result = subprocess.run(['modinfo', driver['name']], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        # Parse modinfo output
                        info = {}
                        for line in result.stdout.splitlines():
                            if ':' in line:
                                key, value = line.split(':', 1)
                                info[key.strip()] = value.strip()
                        
                        # Update driver info
                        driver.update({
                            'description': info.get('description', ''),
                            'version': info.get('version', ''),
                            'author': info.get('author', ''),
                            'license': info.get('license', '')
                        })
                except:
                    pass
            
            # Check for USB wireless devices
            if os.path.exists('/sys/bus/usb/drivers'):
                for driver in os.listdir('/sys/bus/usb/drivers'):
                    if any(x in driver.lower() for x in ['wlan', 'wireless', '80211', 'ath', 'rtl', 'rtw']):
                        drivers.append({
                            'name': driver,
                            'type': 'usb',
                            'status': 'available'
                        })
            
            # Check for PCI wireless devices
            if os.path.exists('/sys/bus/pci/drivers'):
                for driver in os.listdir('/sys/bus/pci/drivers'):
                    if any(x in driver.lower() for x in ['wlan', 'wireless', '80211', 'ath', 'rtl', 'rtw']):
                        drivers.append({
                            'name': driver,
                            'type': 'pci',
                            'status': 'available'
                        })
            
        except Exception as e:
            logger.error(f"Error getting wireless drivers: {e}")
    
    return drivers

def check_wireless_extensions(interface: str) -> bool:
    """
    Check if a network interface supports wireless extensions.
    
    Args:
        interface: Interface name
        
    Returns:
        bool: True if wireless extensions are supported, False otherwise
    """
    try:
        if IS_LINUX:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Try to get wireless name
                fcntl.ioctl(s.fileno(), WIRELESS_EXT, interface.encode() + b'\x00' * 32)
                return True
            except IOError:
                return False
        elif IS_MAC:
            # macOS always supports wireless extensions
            return True
        else:
            return False
    except:
        return False

def get_wireless_capabilities(interface: str) -> Dict[str, Any]:
    """
    Get the wireless capabilities of an interface.
    
    Args:
        interface: Interface name
        
    Returns:
        Dict[str, Any]: Dictionary of wireless capabilities
    """
    capabilities = {
        'monitor': False,
        'injection': False,
        'frequency_bands': [],
        'encryption': [],
        'modes': []
    }
    
    if not check_wireless_extensions(interface):
        return capabilities
    
    try:
        # Check if interface supports monitor mode
        result = subprocess.run(['iw', 'phy', interface, 'info'], 
                              capture_output=True, text=True)
        
        if 'monitor' in result.stdout.lower():
            capabilities['monitor'] = True
        
        # Check for packet injection support
        if 'RX invalid nwid' in result.stdout:
            capabilities['injection'] = True
        
        # Check supported frequency bands
        if '5180 MHz' in result.stdout:
            capabilities['frequency_bands'].append('5GHz')
        if '2412 MHz' in result.stdout:
            capabilities['frequency_bands'].append('2.4GHz')
        
        # Check supported encryption types
        if 'WPA' in result.stdout:
            capabilities['encryption'].append('WPA')
        if 'WPA2' in result.stdout:
            capabilities['encryption'].append('WPA2')
        if 'WEP' in result.stdout:
            capabilities['encryption'].append('WEP')
        
        # Check supported modes
        if 'AP' in result.stdout:
            capabilities['modes'].append('AP')
        if 'station' in result.stdout.lower():
            capabilities['modes'].append('station')
        if 'monitor' in result.stdout.lower():
            capabilities['modes'].append('monitor')
        
    except Exception as e:
        logger.error(f"Error getting wireless capabilities: {e}")
    
    return capabilities
