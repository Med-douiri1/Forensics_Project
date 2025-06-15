import logging
import socket
import struct
from typing import List, Iterable, Tuple

from volatility3.framework import renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)

class ConnScan(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            )
        ]

    def _scan_for_tcp_objects(self, context, layer_name):
        
        layer = context.layers[layer_name]
        
        # Windows uses pool tags to identify different types of objects in memory
        # We try multiple patterns because different Windows versions use different tags
        patterns = [
            b"TCPT",              # Standard TCP connection pool tag
            b"TCPt",              # Alternative case variation
            b"TCPE",              # TCP Endpoint objects for listening connections
            b"UDPE",              # UDP connections - might as well grab these too
            b"TcpC",              # Another TCP variant
            b"TcpE",              # TCP endpoint variant
            b"Tcp\x00",           # Null-terminated version
            b"TCP\x00",           # Another null-terminated version
        ]
        
        connections = []
        
        # Now we scan through the entire memory layer looking for these patterns
        try:
            for pattern in patterns:
                vollog.info(f"Scanning for pattern: {pattern}")
                pattern_count = 0
                
                # Volatility's scanner will find every occurrence of our byte pattern
                for offset in layer.scan(context, scanners.BytesScanner(pattern)):
                    pattern_count += 1
                    try:
                        # When we find a pattern match, try to parse it as a TCP object
                        # Try multiple pool header sizes since they vary
                        for header_size in [0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x40]:
                            tcp_obj = self._parse_tcp_at_offset(layer, offset + header_size)
                            if tcp_obj:
                                connections.append(tcp_obj)
                                vollog.debug(f"Found TCP object at 0x{offset:x} + 0x{header_size:x}")
                                break
                            
                    except Exception as e:
                        # Not every pattern match will be a real TCP object, so we ignore parsing errors
                        vollog.debug(f"Error parsing at 0x{offset:x}: {e}")
                        continue
                        
                vollog.info(f"Pattern {pattern}: found {pattern_count} signatures, extracted {len([c for c in connections if c.get('pattern') == pattern])} connections")
                        
        except Exception as e:
            vollog.error(f"Scanning error: {e}")
            
        return connections

    def _parse_tcp_at_offset(self, layer, offset):
        '''Once we find a potential TCP object signature, this function tries to extract the actual connection data'''
        try:
            # Read 512 bytes starting from where we found the pattern - should be enough for any TCP object
            data = layer.read(offset, 0x200, pad=True)
            
            # Try many different TCP object layouts since Windows versions vary significantly
            # Also try different base offsets within the data
            tcp_layouts = [
                # Basic layouts for different Windows versions
                {'local_ip': 0x0C, 'remote_ip': 0x10, 'local_port': 0x14, 'remote_port': 0x16, 'pid': 0x18},
                {'local_ip': 0x10, 'remote_ip': 0x14, 'local_port': 0x18, 'remote_port': 0x1A, 'pid': 0x1C},
                {'local_ip': 0x14, 'remote_ip': 0x18, 'local_port': 0x1C, 'remote_port': 0x1E, 'pid': 0x20},
                {'local_ip': 0x18, 'remote_ip': 0x1C, 'local_port': 0x20, 'remote_port': 0x22, 'pid': 0x24},
                {'local_ip': 0x1C, 'remote_ip': 0x20, 'local_port': 0x24, 'remote_port': 0x26, 'pid': 0x28},
                {'local_ip': 0x20, 'remote_ip': 0x24, 'local_port': 0x28, 'remote_port': 0x2A, 'pid': 0x2C},
                
                # Try some 64-bit layouts
                {'local_ip': 0x20, 'remote_ip': 0x24, 'local_port': 0x28, 'remote_port': 0x2A, 'pid': 0x30},
                {'local_ip': 0x24, 'remote_ip': 0x28, 'local_port': 0x2C, 'remote_port': 0x2E, 'pid': 0x34},
                {'local_ip': 0x28, 'remote_ip': 0x2C, 'local_port': 0x30, 'remote_port': 0x32, 'pid': 0x38},
                
                # Alternative layouts found in some Windows versions
                {'local_ip': 0x08, 'remote_ip': 0x0C, 'local_port': 0x10, 'remote_port': 0x12, 'pid': 0x14},
                {'local_ip': 0x04, 'remote_ip': 0x08, 'local_port': 0x0C, 'remote_port': 0x0E, 'pid': 0x10},
                
                # More exotic layouts for newer Windows versions
                {'local_ip': 0x30, 'remote_ip': 0x34, 'local_port': 0x38, 'remote_port': 0x3A, 'pid': 0x40},
                {'local_ip': 0x34, 'remote_ip': 0x38, 'local_port': 0x3C, 'remote_port': 0x3E, 'pid': 0x44},
                {'local_ip': 0x38, 'remote_ip': 0x3C, 'local_port': 0x40, 'remote_port': 0x42, 'pid': 0x48},
            ]
            
            # Try each layout with multiple base offsets
            for base_offset in [0x0, 0x4, 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20]:
                for layout in tcp_layouts:
                    try:
                        # Calculate the actual memory offsets for each piece of data
                        local_ip_off = base_offset + layout['local_ip']
                        remote_ip_off = base_offset + layout['remote_ip']
                        local_port_off = base_offset + layout['local_port']
                        remote_port_off = base_offset + layout['remote_port']
                        pid_off = base_offset + layout['pid']
                        
                        # Make sure we're not trying to read past the end of our data buffer
                        if max(local_ip_off, remote_ip_off, local_port_off, remote_port_off, pid_off) + 4 > len(data):
                            continue
                        
                        # Extract the actual values using struct.unpack
                        # '<I' means little-endian 32-bit integer, '<H' means little-endian 16-bit integer
                        local_ip = struct.unpack('<I', data[local_ip_off:local_ip_off+4])[0]
                        remote_ip = struct.unpack('<I', data[remote_ip_off:remote_ip_off+4])[0]
                        local_port = struct.unpack('<H', data[local_port_off:local_port_off+2])[0]
                        remote_port = struct.unpack('<H', data[remote_port_off:remote_port_off+2])[0]
                        pid = struct.unpack('<I', data[pid_off:pid_off+4])[0]
                        
                        # Check if this data actually looks like a real network connection
                        if self._is_valid_connection_data(local_ip, remote_ip, local_port, remote_port, pid):
                            return {
                                'offset': offset,
                                'local_ip': local_ip,
                                'remote_ip': remote_ip,
                                'local_port': local_port,
                                'remote_port': remote_port,
                                'pid': pid
                            }
                            
                    except (struct.error, IndexError):
                        # This layout didn't work, try the next one
                        continue
                    
        except exceptions.InvalidAddressException:
            # This memory address isn't valid or readable
            pass
            
        return None

    def _is_valid_connection_data(self, local_ip, remote_ip, local_port, remote_port, pid):
        '''This function does sanity checks to see if the data we extracted looks like a real network connection'''
        
        # Process ID should be reasonable - but be more lenient
        if not (0 < pid < 65536):  # Increased upper limit
            return False
            
        # Local port must be valid - but allow more range
        if not (0 < local_port < 65536):
            return False
            
        # Remote port should be valid - 0 is actually OK for some connection states
        if not (0 <= remote_port < 65536):
            return False
            
        # Local IP address can't be 0 - every connection needs a local address
        if local_ip == 0:
            return False
            
        # Let's do some basic validation on the IP address format but be more permissive
        try:
            # Convert the IP integer back to bytes so we can examine it
            ip_bytes = struct.pack('<I', local_ip)
            octets = struct.unpack('BBBB', ip_bytes)
            
            # Be more permissive with IP validation
            # Allow loopback addresses (127.x.x.x)
            if octets[0] == 127:
                return True
                
            # Allow private IP ranges
            if (octets[0] == 10 or 
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168)):
                return True
                
            # Allow other common ranges but filter out obviously invalid ones
            if octets[0] == 0 or octets[0] >= 240:  # Class E addresses and invalid ranges
                return False
                
            # Allow if it looks like a reasonable public IP
            if 1 <= octets[0] <= 223:
                return True
                
        except:
            return False
            
        return False

    def _format_ip(self, ip_int):
        '''Convert an IP address from integer format to human-readable dotted decimal like 192.168.1.1'''
        try:
            if ip_int == 0:
                return "0.0.0.0"
            # Pack the integer as little-endian bytes, then use socket library to convert to string
            ip_bytes = struct.pack('<I', ip_int)
            return socket.inet_ntoa(ip_bytes)
        except:
            # If something goes wrong with the conversion, just show the raw hex value
            return f"0x{ip_int:08x}"

    def run(self):
        '''This is the main function that gets called when someone runs our plugin'''
        
        def generator():
            '''This inner function generates the actual results that get displayed to the user'''
            try:
                # Get access to the Windows kernel module we need
                kernel = self.context.modules[self.config["kernel"]]
                
                # Do the actual memory scanning to find TCP connections
                connections = self._scan_for_tcp_objects(self.context, kernel.layer_name)
                
                vollog.info(f"Found {len(connections)} total TCP connections")
                
                # Remove duplicate connections - sometimes we find the same connection multiple times
                unique_connections = []
                seen = set()
                
                for conn in connections:
                    # Create a unique fingerprint for each connection based on its details
                    sig = (conn['local_ip'], conn['remote_ip'], conn['local_port'], conn['remote_port'], conn['pid'])
                    if sig not in seen:
                        seen.add(sig)
                        unique_connections.append(conn)
                
                vollog.info(f"Unique connections after deduplication: {len(unique_connections)}")
                
                # Format each connection for display in the results table
                for conn in unique_connections:
                    try:
                        # Convert IP addresses to readable format and combine with port numbers
                        local_addr = f"{self._format_ip(conn['local_ip'])}:{conn['local_port']}"
                        remote_addr = f"{self._format_ip(conn['remote_ip'])}:{conn['remote_port']}"
                        
                        # Yield the results in the format that Volatility expects
                        yield (0, (
                            format_hints.Hex(conn['offset']),  # Memory offset where we found this connection
                            local_addr,                        # Local IP address and port
                            remote_addr,                       # Remote IP address and port
                            conn['pid']                        # Process ID that owns this connection
                        ))
                        
                    except Exception as e:
                        vollog.debug(f"Error formatting connection: {e}")
                        continue
                        
            except Exception as e:
                vollog.error(f"Plugin error: {e}")
                return

        # Return the results in a nice table format with column headers
        return renderers.TreeGrid([
            ("Offset(P)", format_hints.Hex),  # P indicates this is a physical memory address
            ("LocalAddress", str),
            ("RemoteAddress", str),
            ("PID", int)
        ], generator())
                           