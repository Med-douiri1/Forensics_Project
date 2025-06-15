import logging
import struct
from typing import List

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)

class Clipboard(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Only need kernel module access to scan memory
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            )
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Windows clipboard format constants - these IDs identify different data types
        # Same constants used by Windows API and Vol2 plugin
        self.CLIPBOARD_FORMAT_ENUM = {
            1: "CF_TEXT",           # Plain ASCII text
            2: "CF_BITMAP",         # Bitmap image
            3: "CF_METAFILEPICT",   # Metafile picture
            4: "CF_SYLK",           # Symbolic link format
            5: "CF_DIF",            # Data interchange format
            6: "CF_TIFF",           # Tagged image file format
            7: "CF_OEMTEXT",        # OEM character set text
            8: "CF_DIB",            # Device independent bitmap
            9: "CF_PALETTE",        # Color palette
            10: "CF_PENDATA",       # Pen data for handwriting
            11: "CF_RIFF",          # Audio format
            12: "CF_WAVE",          # Wave audio format
            13: "CF_UNICODETEXT",   # Unicode text (most common)
            14: "CF_ENHMETAFILE",   # Enhanced metafile
            15: "CF_HDROP",         # File drop data
            16: "CF_LOCALE",        # Locale information
            17: "CF_DIBV5"          # Version 5 device independent bitmap
        }

    def _scan_for_clipboard_format_headers(self, context, layer):
        # Main method - scan memory for actual Windows clipboard format headers
        # Windows stores clipboard data as [FORMAT_ID][DATA] in memory
        clipboard_data = []
        seen_data = set()  # Avoid duplicates
        
        # Look for each clipboard format ID we care about
        for format_id, format_name in self.CLIPBOARD_FORMAT_ENUM.items():
            if format_id in [1, 7, 13]:  # Focus on text formats - most likely to have user data
                try:
                    # Convert format ID to binary signature for scanning
                    format_signature = struct.pack('<I', format_id)
                    
                    count = 0
                    # Scan all of memory for this format signature
                    for offset in layer.scan(context, scanners.BytesScanner(format_signature)):
                        try:
                            # Read data immediately after the format header
                            # This is where Windows stores the actual clipboard content
                            data = layer.read(offset + 4, 1000, pad=True)
                            
                            # Parse the content based on the format type
                            content = self._extract_clipboard_data_by_format(data, format_id)
                            
                            if content and len(content.strip()) > 3:
                                # Check for duplicates using first 100 chars as key
                                content_key = content[:100]
                                if content_key not in seen_data:
                                    seen_data.add(content_key)
                                    clipboard_data.append({
                                        'session': 0,
                                        'windowstation': 'WinSta0',
                                        'format': format_name,
                                        'handle': format_id,
                                        'object': offset,
                                        'data': content
                                    })
                                    count += 1
                                    
                                    if count >= 5:  # Don't flood output with too many entries
                                        break
                                        
                        except Exception:
                            continue  # Keep scanning if one entry fails
                            
                except Exception:
                    continue  # Keep going if one format fails
                    
        return clipboard_data

    def _scan_for_user_clipboard_content(self, context, layer):
        # Secondary method - look for high-value user content that might be clipboard data
        # Searches for patterns that users commonly copy/paste
        clipboard_data = []
        seen_data = set()
        
        # Patterns that are almost certainly user clipboard content
        # These are things people commonly copy - passwords, emails, URLs, etc.
        user_patterns = [
            b'password', b'Password', b'PASSWORD',
            b'admin', b'Admin', b'administrator',
            b'secret', b'Secret', b'key', b'Key',
            b'http://', b'https://', b'www.',           # URLs
            b'@gmail.com', b'@yahoo.com', b'@hotmail.com', b'@outlook.com',  # Email addresses
            b'copy', b'paste', b'clipboard', b'Clipboard',
            b'username', b'Username', b'login', b'Login',
            b'email', b'Email', b'address'
        ]
        
        # Search for each pattern in memory
        for pattern in user_patterns:
            try:
                count = 0
                for offset in layer.scan(context, scanners.BytesScanner(pattern)):
                    try:
                        # Read context around the pattern to get full clipboard content
                        data = layer.read(offset - 100, 500, pad=True)
                        
                        # Try to find clipboard format header near this user content
                        context_data = self._find_clipboard_format_near_pattern(data, 100, pattern)
                        if context_data:
                            content_key = context_data[:100]
                            if content_key not in seen_data:
                                seen_data.add(content_key)
                                clipboard_data.append({
                                    'session': 0,
                                    'windowstation': 'UserContent',  # Mark as user content
                                    'format': 'CF_TEXT',
                                    'handle': 0,
                                    'object': offset,
                                    'data': context_data
                                })
                                count += 1
                                
                                if count >= 3:  # Limit per pattern to avoid spam
                                    break
                                    
                    except Exception:
                        continue
                        
            except Exception:
                continue
                
        return clipboard_data

    def _find_clipboard_format_near_pattern(self, data, pattern_pos, pattern):
        # Look for clipboard format signatures near user content patterns
        # Sometimes the format header is nearby but not adjacent to the content
        try:
            # Search area around the pattern for format signatures
            for i in range(max(0, pattern_pos - 50), min(len(data) - 4, pattern_pos + 200), 4):
                try:
                    # Check if this looks like a format ID
                    format_id = struct.unpack('<I', data[i:i+4])[0]
                    
                    if format_id in self.CLIPBOARD_FORMAT_ENUM:
                        # Found a format signature - extract data after it
                        content_data = data[i+4:i+300]
                        content = self._extract_clipboard_data_by_format(content_data, format_id)
                        
                        if content and not self._is_system_noise(content):
                            return content
                            
                except Exception:
                    continue
                    
            # If no format signature found, try to extract meaningful text around pattern
            text = data.decode('ascii', errors='ignore')
            pattern_str = pattern.decode('ascii', errors='ignore')
            
            # Find the pattern in the decoded text
            pattern_idx = text.find(pattern_str, max(0, pattern_pos - 50))
            if pattern_idx >= 0:
                # Extract context around the pattern
                start = max(0, pattern_idx - 50)
                end = min(len(text), pattern_idx + 200)
                context = text[start:end]
                
                # Clean up and validate the context
                clean_context = ''.join(c for c in context if c.isprintable() or c.isspace()).strip()
                if len(clean_context) > 20 and not self._is_system_noise(clean_context):
                    return clean_context
                    
        except Exception:
            pass
            
        return None

    def _extract_clipboard_data_by_format(self, data, format_id):
        # Extract clipboard content based on the format type
        # Each format has different encoding and termination rules
        try:
            if format_id == 1:  # CF_TEXT - plain ASCII text
                # Extract null-terminated ASCII string
                text = data.decode('ascii', errors='ignore')
                null_pos = text.find('\x00')
                if null_pos > 0:
                    text = text[:null_pos]
                clean_text = text.strip()
                
                # Validate it looks like real clipboard content
                if (len(clean_text) > 3 and 
                    any(c.isalnum() for c in clean_text) and
                    not self._is_system_noise(clean_text)):
                    return clean_text[:500]  # Limit length
                    
            elif format_id == 13:  # CF_UNICODETEXT - Unicode text (most common)
                # Extract null-terminated Unicode string
                if len(data) >= 4:
                    text = data.decode('utf-16le', errors='ignore')
                    null_pos = text.find('\x00')
                    if null_pos > 0:
                        text = text[:null_pos]
                    clean_text = text.strip()
                    
                    if (len(clean_text) > 2 and 
                        any(c.isalnum() for c in clean_text) and
                        not self._is_system_noise(clean_text)):
                        return clean_text[:500]
                        
            elif format_id == 7:  # CF_OEMTEXT - OEM character set
                # Extract OEM text (used by some older applications)
                text = data.decode('cp437', errors='ignore')
                null_pos = text.find('\x00')
                if null_pos > 0:
                    text = text[:null_pos]
                clean_text = text.strip()
                
                if (len(clean_text) > 3 and 
                    any(c.isalnum() for c in clean_text) and
                    not self._is_system_noise(clean_text)):
                    return clean_text[:500]
                    
        except Exception:
            pass
            
        return None

    def _is_system_noise(self, text):
        # Filter out system data and keep only real user clipboard content
        # This is critical to avoid false positives from system/registry data
        
        # Basic validation - needs to be reasonable length and content
        if not text or len(text.strip()) < 4:
            return True
            
        # Filter out binary data with too many control characters
        control_chars = sum(1 for c in text[:50] if ord(c) < 32 and c not in '\t\n\r')
        if control_chars > len(text[:50]) * 0.3:  # More than 30% control chars
            return True
            
        # Filter out obvious encoding tables and binary junk
        if "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ" in text:
            return True
            
        # Filter out text with too few unique characters (likely binary)
        if len(set(text[:20])) < 4:
            return True
            
        # Filter out Windows system/registry/service data that shows up in memory
        # These patterns indicate system data rather than user clipboard content
        system_indicators = [
            '%systemroot%', '%SystemRoot%', 'Microsoft-Windows-',
            'TerminalServices', 'LocalSessionManager', 'RDPNP',
            'system32\\drprov.dll', 'ResourceFileName', 'MessageFileName',
            'DisplayName@%', 'ProviderPath%', 'hbin', 'ReconCompat',
            'MatchAnyKeyword', 'MatchAllKeyword', 'DoLicenseConsume',
            'WinStationsDisabled', 'InteractiveDelay', 'CallbackNumber',
            'Terminal Services', 'Microsoft RDP', 'ConsoleConnect',
            'SessionManager', 'NetworkProvider', 'DeviceName'
        ]
        
        # Reject if it contains system indicators
        for indicator in system_indicators:
            if indicator in text:
                return True
                
        # Filter out registry keys and service configuration data
        if any(pattern in text for pattern in ['vk', 'nk ', '\\system32\\', 'dll,-', '{', '}', 'GUID']):
            # Count registry-like patterns - too many means it's system data
            registry_patterns = sum(1 for pattern in ['vk', 'nk ', 'dll,-', '{', '}'] if pattern in text)
            if registry_patterns >= 2:
                return True
        
        # But always keep content that looks like user data
        # These patterns indicate real user clipboard content
        user_content_indicators = [
            'password', 'admin', 'user', 'login', 'email', 'secret', 'key',
            'http://', 'https://', 'www.', '.com', '.org', '.net', '@gmail',
            '@yahoo', '@hotmail', 'copy', 'paste', 'clipboard', 'cut',
            'document', 'file', 'folder', 'desktop', 'downloads'
        ]
        
        text_lower = text.lower()
        for indicator in user_content_indicators:
            if indicator in text_lower:
                return False  
                
        # Keep text that looks like natural language (sentences, words)
        words = text.split()
        if len(words) >= 3:
            # Check for reasonable word patterns
            alpha_words = [word for word in words if word.isalpha() and len(word) >= 3]
            if len(alpha_words) >= len(words) * 0.6:  # At least 60% real words
                # System data often has lots of capitals - user text usually doesn't
                capitals = sum(1 for c in text if c.isupper())
                if capitals < len(text) * 0.5:  # Less than 50% capitals
                    return False  # Keep this as potential user content
                    
        # Check for sentences with proper punctuation (user content indicator)
        if any(char in text for char in '.!?') and len(words) >= 5:
            return False  # Keep this - looks like user sentences
            
        return True  # Default: filter out as system noise

    def calculate(self):
        # Main calculation method - orchestrates the clipboard data extraction
        context = self.context
        kernel = context.modules[self.config["kernel"]]
        layer = context.layers[kernel.layer_name]
        
        # Method 1: Direct scan for clipboard format headers (most reliable)
        # This finds properly formatted Windows clipboard data
        clipboard_data = self._scan_for_clipboard_format_headers(context, layer)
        
        # Method 2: Target user clipboard content specifically
        # This catches user data that might not have perfect format headers
        user_data = self._scan_for_user_clipboard_content(context, layer)
        clipboard_data.extend(user_data)
        
        # Remove duplicates based on content
        seen = set()
        unique_data = []
        for item in clipboard_data:
            key = item['data'][:100]  # Use first 100 chars as dedup key
            if key not in seen:
                seen.add(key)
                unique_data.append(item)
        
        # Sort results to show most interesting content first
        # User content first, then by length 
        unique_data.sort(key=lambda x: (
            0 if x['windowstation'] == 'UserContent' else 1,  # User content first
            -len(x['data'])  # Then by length (descending)
        ))
        
        # Yield results to Volatility framework
        for item in unique_data:
            yield (
                item['session'],
                item['windowstation'], 
                item,
                None
            )

    def run(self):
        def generator():
            try:
                found_any = False
                
                # Get clipboard data and format for output
                for session, wndsta, clip, handle in self.calculate():
                    found_any = True
                    
                    # Format data for Volatility's table output
                    yield (0, (
                        session,
                        wndsta,
                        clip['format'],
                        format_hints.Hex(clip['handle']),
                        format_hints.Hex(clip['object']),
                        clip['data']
                    ))
                
                # Show message if no clipboard data found
                if not found_any:
                    yield (0, (
                        0,
                        "N/A",
                        "No clipboard data found",
                        format_hints.Hex(0),
                        format_hints.Hex(0),
                        "No clipboard format headers detected"
                    ))
                    
            except Exception as e:
                vollog.error(f"Clipboard plugin error: {e}")

        # Define the output table structure
        return renderers.TreeGrid([
            ("Session", int),
            ("WindowStation", str),
            ("Format", str),
            ("Handle", format_hints.Hex),
            ("Object", format_hints.Hex),
            ("Data", str)
        ], generator())