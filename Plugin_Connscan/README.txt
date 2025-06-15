Windows ConnScan Plugin for Volatility 3

OVERVIEW
---------
Enhanced memory forensics plugin that scans Windows memory dumps for TCP connection objects using advanced pool scanning techniques. 
Finds active and terminated network connections that may be hidden from standard connection lists.

HOW IT WORKS
-------------
1. Scans memory for multiple TCP pool signatures (TCPT, TCPt, TCPE, UDPE, TcpC, etc.)
2. Tries multiple pool header sizes to handle different Windows versions
3. Attempts 15+ different TCP connection structure layouts
4. Tests multiple base offsets within each structure
5. Uses permissive validation to reduce false negatives
6. Removes duplicate connections and formats output

SETUP
------
Copy connscan.py to your Volatility 3 plugins directory:
volatility3/volatility3/plugins/windows/connscan.py

USAGE (there is a provided memory_dump.raw file)
------
Run the plugin with the following command:

python3 vol.py -f memory_dump.raw windows.connscan


EXAMPLE OUTPUT
---------------
Offset(P)         LocalAddress             RemoteAddress            PID
0xf8a002e895f7    116.168.255.255:10240    255.110.107.32:41211     1
0xf8a003220fbf    83.101.115.115:30031     105.111.110.45:11636     2048
0xf8a003210afb    83.83.68.80:30031        83.114.118.45:11636      2048

OUTPUT FIELDS
--------------
- Offset(P): Physical memory address where TCP object was found
- LocalAddress: Local IP address and port (IP:PORT format)
- RemoteAddress: Remote IP address and port (IP:PORT format)
- PID: Process ID that owns the connection

REQUIREMENTS
-------------
- Volatility 3 Framework 2.0.0 or higher
- Windows memory dumps (XP through Windows 11)
- Supports Intel32 and Intel64 architectures
