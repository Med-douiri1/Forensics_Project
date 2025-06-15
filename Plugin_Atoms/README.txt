Windows Atoms Plugin for Volatility 3
=====================================

Overview:
------------
Memory forensics plugin that extracts Windows atom tables from memory dumps.
Atoms are system-wide string storage mechanisms used by applications and the
Windows GUI subsystem for efficient string management and inter-process communication.

How It Works:
-------------
1. Scans memory for 'AtmT' pool signatures marking atom table allocations.
2. Tries multiple pool header sizes to handle different Windows versions.
3. Parses RTL_ATOM_TABLE structures to find bucket arrays.
4. Follows hash bucket chains to extract individual atom entries.
5. Validates atom data and filters out garbage using multiple heuristics.
6. Determines session information and sorts results by user preference.

Setup:
------
Copy atoms.py to your Volatility 3 plugins directory:
volatility3/volatility3/plugins/windows/atoms.py

Usage: (there is a provided memory_dump.raw file)
------

python3 vol.py -f memory_dump.raw windows.atoms


Example Output:
----------------
Offset(V)	Session	WindowStation	Atom	RefCount	HIndex	Pinned	Name

0xfffff8a0008f23d8	0	Session-0	0x2030	143	0	0	SSPICLI.DLL
0xfffff8a0008f23f8	0	Session-0	0x83f8	222	0	0	sspicli.dll
0xfffff8a000ed5c88	0	Session-0	0xb738	231	0	0	stdole2.tlb


Output Fields:
--------------
- Offset(V): Virtual memory address of the atom entry.
- Session: Windows session ID (0 = system session, 1+ = user sessions).
- WindowStation: Window station name for the session.
- Atom: Unique atom identifier (16-bit value).
- RefCount: Number of references to this atom.
- HIndex: Handle index (usually 0 for global atoms).
- Pinned: Whether atom is pinned in memory (1 = pinned, 0 = not pinned).
- Name: The actual string stored in the atom.


Requirements:
-------------
- Volatility 3 Framework 2.0.0+
- Windows memory dumps (XP through Windows 11)
- Supports Intel32 and Intel64 architectures


