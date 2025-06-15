import logging
import struct
from typing import List, Optional, Tuple, Generator, Any

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)

class Atoms(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)
    _version = (1, 7, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Define what this plugin needs to run
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.ChoiceRequirement(
                name="sort-by",
                description="Sort by [offset | atom | refcount]",
                choices=["offset", "atom", "refcount"],
                default="offset",
                optional=True
            )
        ]

    def _scan_for_atom_tables(self, context, layer_name):
        # Look for atom tables by scanning for 'AtmT' pool signatures
        # Windows marks atom table pools with this specific tag
        layer = context.layers[layer_name]
        found_tables = []
        atmT_count = 0
        
        # Figure out if we're on 32-bit or 64-bit system
        try:
            kernel = context.modules[list(context.modules.keys())[0]]
            is_64bit = kernel.get_type("pointer").size == 8
        except:
            is_64bit = True  # Assume 64-bit if we can't detect
            
        vollog.info(f"Scanning on {'64-bit' if is_64bit else '32-bit'} system")
        
        try:
            # Search memory for the 'AtmT' signature
            for offset in layer.scan(context, scanners.BytesScanner(b'AtmT')):
                atmT_count += 1
                vollog.info(f"Found AtmT #{atmT_count} at {hex(offset)}")
                
                # Try different offsets after the pool tag to find the actual table
                # Pool headers can be different sizes depending on Windows version
                for pool_header_size in [0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x40]:
                    table_offset = offset + pool_header_size
                    
                    try:
                        # Attempt to parse atom table at this location
                        atoms = self._parse_atom_table_at_offset(layer, table_offset, is_64bit)
                        vollog.info(f"  Offset +{hex(pool_header_size)}: Found {len(atoms) if atoms else 0} raw atoms")
                        
                        if atoms and len(atoms) >= 1:
                            # Filter out garbage and keep only legitimate-looking atoms
                            valid_atoms = [a for a in atoms if self._is_legitimate_atom(a)]
                            vollog.info(f"  Valid atoms: {len(valid_atoms)}")
                            
                            if len(valid_atoms) >= 1:
                                # Get session info for this table
                                session_info = self._determine_session_info(table_offset, valid_atoms)
                                
                                found_tables.append((offset, {
                                    'offset': table_offset,
                                    'atoms': valid_atoms,
                                    'session_id': session_info['session_id'],
                                    'window_station': session_info['window_station']
                                }))
                                vollog.info(f"Valid atom table found at {hex(table_offset)} with {len(valid_atoms)} atoms")
                                break
                                
                    except Exception as e:
                        vollog.debug(f"Parse failed at {hex(table_offset)}: {e}")
                        continue
                        
            vollog.info(f"Scanned {atmT_count} AtmT signatures total")
                        
        except Exception as e:
            vollog.debug(f"Scanning error: {e}")
            
        return found_tables

    def _parse_atom_table_at_offset(self, layer, offset, is_64bit):
        # Try to parse an RTL_ATOM_TABLE structure at the given offset
        # This contains the bucket array that holds hash chains of atoms
        pointer_size = 8 if is_64bit else 4
        atoms = []
        
        try:
            # Read the table header to look for the bucket count
            header_data = layer.read(offset, 0x100, pad=True)
            
            # Search for the NumberOfBuckets field at various offsets
            # Different Windows versions put this field in different places
            for bucket_offset in range(0, min(0x80, len(header_data) - 8), 4):
                try:
                    num_buckets = struct.unpack('<I', header_data[bucket_offset:bucket_offset+4])[0]
                    
                    # Bucket count should be reasonable - not too big or small
                    if 1 <= num_buckets <= 1024:
                        vollog.debug(f"  Trying {num_buckets} buckets at offset +{hex(bucket_offset)}")
                        
                        # Calculate where the bucket array starts
                        bucket_array_offset = offset + bucket_offset + 4
                        
                        # Align to pointer boundary for proper memory access
                        aligned_offset = ((bucket_array_offset + pointer_size - 1) // pointer_size) * pointer_size
                        
                        # Parse the hash buckets
                        bucket_atoms = self._parse_hash_buckets(layer, aligned_offset, num_buckets, is_64bit)
                        if bucket_atoms:
                            atoms.extend(bucket_atoms)
                            vollog.debug(f"  Found {len(bucket_atoms)} atoms with {num_buckets} buckets")
                            if len(atoms) >= 5:  # Stop early if we found enough
                                break
                            
                except Exception as e:
                    vollog.debug(f"  Bucket parse error at +{hex(bucket_offset)}: {e}")
                    continue
                    
        except Exception as e:
            vollog.debug(f"Table parse error at {hex(offset)}: {e}")
            
        return atoms

    def _parse_hash_buckets(self, layer, bucket_array_offset, num_buckets, is_64bit):
        # Parse the bucket array - each bucket contains a pointer to a hash chain
        # The hash chains contain the actual atom entries
        pointer_size = 8 if is_64bit else 4
        atoms = []
        
        try:
            # Read the entire bucket array
            bucket_array_size = num_buckets * pointer_size
            bucket_data = layer.read(bucket_array_offset, bucket_array_size, pad=True)
            
            # Process each bucket in the array
            for i in range(num_buckets):
                bucket_ptr_offset = i * pointer_size
                if bucket_ptr_offset + pointer_size > len(bucket_data):
                    continue
                    
                # Extract the pointer to the first atom in this bucket
                if pointer_size == 8:
                    bucket_ptr = struct.unpack('<Q', bucket_data[bucket_ptr_offset:bucket_ptr_offset+8])[0]
                else:
                    bucket_ptr = struct.unpack('<I', bucket_data[bucket_ptr_offset:bucket_ptr_offset+4])[0]
                    
                # Skip empty buckets or invalid pointers
                if bucket_ptr == 0 or bucket_ptr < 0x10000:
                    continue
                    
                # Follow the hash chain starting at this pointer
                chain_atoms = self._follow_hash_chain(layer, bucket_ptr, is_64bit)
                if chain_atoms:
                    atoms.extend(chain_atoms)
                    
                # Don't let one table consume too much memory
                if len(atoms) > 200:
                    break
                    
        except Exception as e:
            vollog.debug(f"Bucket parse error: {e}")
            
        return atoms

    def _follow_hash_chain(self, layer, start_ptr, is_64bit):
        # Follow a linked list of atom entries
        # Each entry has a HashLink pointer to the next entry in the chain
        pointer_size = 8 if is_64bit else 4
        atoms = []
        current_ptr = start_ptr
        seen_ptrs = set()
        
        # Walk the linked list until we hit the end or detect a loop
        while current_ptr and current_ptr not in seen_ptrs and len(seen_ptrs) < 50:
            seen_ptrs.add(current_ptr)
            
            try:
                # Read the atom entry structure
                entry_data = layer.read(current_ptr, 0x100, pad=True)
                
                # Parse this atom entry
                atom = self._parse_atom_entry(layer, current_ptr, entry_data, is_64bit)
                if atom:
                    atoms.append(atom)
                
                # Get pointer to next entry (HashLink field is at offset 0)
                if len(entry_data) >= pointer_size:
                    if pointer_size == 8:
                        next_ptr = struct.unpack('<Q', entry_data[0:8])[0]
                    else:
                        next_ptr = struct.unpack('<I', entry_data[0:4])[0]
                        
                    # Check if we've reached the end of the chain
                    if next_ptr == current_ptr or next_ptr == 0 or next_ptr < 0x10000:
                        break
                        
                    current_ptr = next_ptr
                else:
                    break
                    
            except Exception as e:
                vollog.debug(f"Chain follow error at {hex(current_ptr)}: {e}")
                break
                
        return atoms

    def _parse_atom_entry(self, layer, entry_offset, entry_data, is_64bit):
        # Parse an RTL_ATOM_TABLE_ENTRY structure
        # This contains the atom ID, reference count, flags, and name
        pointer_size = 8 if is_64bit else 4
        
        # Try different known structure layouts since they vary by Windows version
        if is_64bit:
            # 64-bit structure layouts
            layouts = [
                {'atom': 0x10, 'refcount': 0x12, 'flags': 0x14, 'name_len': 0x15, 'name': 0x18},
                {'atom': 0x08, 'refcount': 0x0A, 'flags': 0x0C, 'name_len': 0x0D, 'name': 0x10},
            ]
        else:
            # 32-bit structure layouts
            layouts = [
                {'atom': 0x08, 'refcount': 0x0A, 'flags': 0x0C, 'name_len': 0x0D, 'name': 0x10},
                {'atom': 0x0C, 'refcount': 0x0E, 'flags': 0x10, 'name_len': 0x11, 'name': 0x14},
            ]
        
        # Try each layout until we find one that works
        for layout in layouts:
            try:
                if layout['name'] + 20 > len(entry_data):
                    continue
                
                # Extract the basic atom fields
                atom_id = struct.unpack('<H', entry_data[layout['atom']:layout['atom']+2])[0]
                refcount = struct.unpack('<H', entry_data[layout['refcount']:layout['refcount']+2])[0]
                flags = entry_data[layout['flags']]
                name_length = entry_data[layout['name_len']]
                
                # Make sure the fields look reasonable
                if not self._validate_atom_fields(atom_id, refcount, flags, name_length):
                    continue
                
                # Extract the atom name string
                atom_name = self._extract_atom_name(layer, entry_offset, entry_data, layout, name_length, is_64bit)
                
                if atom_name and self._is_valid_atom_name(atom_name):
                    return {
                        'offset': entry_offset,
                        'atom_id': atom_id,
                        'ref_count': refcount,
                        'name': atom_name,
                        'pinned': 1 if flags & 0x01 else 0,  # Check pinned flag
                        'handle_index': 0
                    }
                    
            except Exception:
                continue
                
        return None

    def _validate_atom_fields(self, atom_id, refcount, flags, name_length):
        # Basic sanity checks on atom entry fields
        # Don't want to be too strict since different Windows versions vary
        
        # Atom ID should be reasonable - not too small
        if atom_id < 0x100 or atom_id == 0xFFFF:
            return False
            
        # Reference count should make sense
        if refcount == 0 or refcount > 65535:
            return False
            
        # Flags shouldn't be too crazy
        if flags > 0xFF:
            return False
            
        # Name length should be sane
        if name_length == 0 or name_length > 255:
            return False
            
        return True

    def _extract_atom_name(self, layer, entry_offset, entry_data, layout, name_length, is_64bit):
        # Extract the atom name string from the entry
        # Can be stored inline or as a pointer to a UNICODE_STRING
        pointer_size = 8 if is_64bit else 4
        name_offset = layout['name']
        
        try:
            # Method 1: Try inline Unicode string (most common case)
            if name_offset + (name_length * 2) <= len(entry_data):
                name = self._decode_unicode_string(entry_data, name_offset, name_length)
                if name:
                    return name
            
            # Method 2: Try UNICODE_STRING structure (has length + buffer pointer)
            if name_offset + 8 + pointer_size <= len(entry_data):
                try:
                    unicode_length = struct.unpack('<H', entry_data[name_offset:name_offset+2])[0]
                    unicode_max_length = struct.unpack('<H', entry_data[name_offset+2:name_offset+4])[0]
                    
                    # Validate UNICODE_STRING structure
                    if (unicode_length > 0 and unicode_length <= unicode_max_length and 
                        unicode_length <= 254 and unicode_length % 2 == 0):
                        
                        # Get pointer to the actual string buffer
                        if pointer_size == 8:
                            buffer_ptr = struct.unpack('<Q', entry_data[name_offset+8:name_offset+16])[0]
                        else:
                            buffer_ptr = struct.unpack('<I', entry_data[name_offset+4:name_offset+8])[0]
                            
                        if buffer_ptr > 0x10000:  # Valid pointer
                            try:
                                name_data = layer.read(buffer_ptr, unicode_length, pad=True)
                                name = self._decode_unicode_string(name_data, 0, unicode_length // 2)
                                if name:
                                    return name
                            except:
                                pass
                except:
                    pass
                    
        except Exception:
            pass
            
        return None

    def _decode_unicode_string(self, data, offset, char_count):
        # Convert Unicode string data to Python string
        # Need to handle various character encodings 
        try:
            name = ""
            actual_count = min(char_count, (len(data) - offset) // 2, 127)
            
            for i in range(actual_count):
                char_offset = offset + (i * 2)
                if char_offset + 1 >= len(data):
                    break
                    
                char_val = struct.unpack('<H', data[char_offset:char_offset+2])[0]
                
                if char_val == 0:  # Null terminator
                    break
                elif 32 <= char_val <= 126:  # Printable ASCII
                    name += chr(char_val)
                elif char_val in [95, 46, 45, 58, 92, 47, 40, 41, 123, 125, 91, 93]:  # Common symbols
                    name += chr(char_val)
                elif 127 <= char_val <= 255:  # Extended ASCII
                    name += chr(char_val)
                else:
                    # Skip weird Unicode chars that might be garbage
                    vollog.debug(f"Skipping char value: {hex(char_val)}")
                    break
                    
            return name if len(name) >= 1 else None
        except Exception as e:
            vollog.debug(f"Unicode decode error: {e}")
            return None

    def _is_valid_atom_name(self, name):
        # Check if an atom name looks legitimate
        # Try to filter out obvious garbage while keeping real atoms
        if not name or len(name) < 1 or len(name) > 127:
            return False
            
        # Must have at least some alphanumeric content
        if not any(c.isalnum() for c in name):
            return False
            
        # Only allow reasonable characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-#()[]{}:;,<>?/\\|=+*&^%$@!~`"\'')
        if not all(c in allowed_chars for c in name):
            return False
            
        # Don't accept names that are all symbols
        alnum_count = sum(1 for c in name if c.isalnum())
        if alnum_count == 0:
            return False
            
        return True

    def _is_legitimate_atom(self, atom):
        # Final check to see if this looks like a real atom entry
        # Used to filter out parsing errors and garbage data
        if not atom:
            return False
            
        # Check atom ID is in reasonable range
        atom_id = atom.get('atom_id', 0)
        if atom_id < 0x100:  # Too small to be a real atom
            return False
            
        # Check reference count makes sense
        refcount = atom.get('ref_count', 0)
        if refcount <= 0 or refcount > 65535:
            return False
            
        # Check the name looks legitimate
        name = atom.get('name', '')
        if not self._is_valid_atom_name(name):
            return False
            
        return True

    def _determine_session_info(self, table_offset, atoms):
        # Figure out which session this atom table belongs to
        # Use memory address and atom content to make educated guess
        try:
            # Derive session ID from memory address bits
            session_id = (table_offset >> 24) & 0xF
            if session_id > 15:
                session_id = session_id % 10
                
            window_station = f"Session-{session_id}"
            
            # Look through atoms for session-related names
            for atom in atoms:
                name = atom.get('name', '').upper()
                if any(keyword in name for keyword in ['WINSTA', 'SESSION', 'SERVICE', 'CONSOLE']):
                    window_station = atom.get('name', window_station)
                    break
                    
            return {
                'session_id': session_id,
                'window_station': window_station
            }
            
        except Exception:
            return {
                'session_id': 0,
                'window_station': 'Unknown'
            }

    def _sort_atoms(self, atoms: List[dict], sort_by: str) -> List[dict]:
        # Sort the atom list based on user preference
        try:
            if sort_by == "atom":
                return sorted(atoms, key=lambda x: x.get('atom_id', 0))
            elif sort_by == "refcount":
                return sorted(atoms, key=lambda x: x.get('ref_count', 0), reverse=True)
            else:
                return sorted(atoms, key=lambda x: x.get('offset', 0))
        except Exception:
            return atoms

    def run(self):
        
        def generator():
            try:
                kernel = self.context.modules[self.config["kernel"]]
                sort_by = self.config.get("sort-by", "offset")
                
                vollog.info("Scanning for Windows atom tables...")
                
                # Find all atom tables in memory
                atom_tables = list(self._scan_for_atom_tables(self.context, kernel.layer_name))
                vollog.info(f"Found {len(atom_tables)} atom table(s)")
                
                total_atoms = 0
                seen_atoms = set()  # For deduplication
                
                # Process each atom table we found
                for table_offset, table_data in atom_tables:
                    atoms = table_data.get('atoms', [])
                    
                    if not atoms:
                        continue
                        
                    vollog.info(f"Table at {hex(table_data['offset'])}: {len(atoms)} atoms "
                               f"(Session: {table_data.get('session_id')}, WS: {table_data.get('window_station')})")
                    
                    # Sort atoms according to user preference
                    sorted_atoms = self._sort_atoms(atoms, sort_by)
                    session_id = table_data.get('session_id', 0)
                    window_station = table_data.get('window_station', 'Unknown')
                    
                    # Output each atom
                    for atom in sorted_atoms:
                        try:
                            atom_name = atom.get('name', '')
                            atom_id = atom.get('atom_id', 0)
                            
                            # Skip duplicates
                            atom_sig = (atom_id, atom_name)
                            if atom_sig in seen_atoms:
                                continue
                                
                            seen_atoms.add(atom_sig)
                            total_atoms += 1
                            
                            # Yield the atom data to Volatility for display
                            yield (0, (
                                format_hints.Hex(atom.get('offset', 0)),
                                session_id,
                                window_station,
                                format_hints.Hex(atom_id),
                                atom.get('ref_count', 0),
                                atom.get('handle_index', 0),
                                atom.get('pinned', 0),
                                atom_name
                            ))
                            
                        except Exception as e:
                            vollog.debug(f"Error yielding atom: {e}")
                            continue
                            
                vollog.info(f"Analysis complete: {total_atoms} atoms found")
                
                if total_atoms == 0:
                    vollog.warning("No valid atoms found")
                    
            except Exception as e:
                vollog.error(f"Plugin execution error: {e}")
                import traceback
                vollog.debug(traceback.format_exc())

        # Define the output table structure
        return renderers.TreeGrid([
            ("Offset(V)", format_hints.Hex),
            ("Session", int),
            ("WindowStation", str),
            ("Atom", format_hints.Hex),
            ("RefCount", int),
            ("HIndex", int),
            ("Pinned", int),
            ("Name", str)
        ], generator())