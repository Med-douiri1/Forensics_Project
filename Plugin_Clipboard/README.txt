Windows Clipboard Plugin for Volatility 3
=========================================

OVERVIEW
========
Memory forensics plugin that extracts Windows clipboard data from memory dumps.
Recovers text content that users copied to the clipboard, including passwords, URLs, emails, and other sensitive information.

HOW IT WORKS
============
1. Scans memory for Windows clipboard format headers (CF_TEXT, CF_UNICODETEXT, CF_OEMTEXT)
2. Extracts clipboard content based on format type and encoding
3. Searches for high-value user content patterns (passwords, emails, URLs)
4. Validates data to filter out system noise and false positives
5. Removes duplicates and sorts by user content relevance

SETUP
=====
Copy clipboard.py to your Volatility 3 plugins directory:
volatility3/volatility3/plugins/windows/clipboard.py

USAGE (there is a provided memory_dump.raw file)
=====

python3 vol.py -f memory_dump.raw windows.clipboard


EXPECTED OUTPUT
===============
Session	WindowStation	Format	Handle	Object	Data

0	UserContent	CF_TEXT	0x0	0xf8a000e39260	Xq&FEATURE_HTTP_USERNAME_PASSWORD_DISABLObNmo?ServiceModelOperation 3.0.0.0_Perf_Library_Lock_PID_8fObSc\M<*0\
0	UserContent	CF_TEXT	0x0	0xf8800207e03e	dows 2000: This logon type preserves the name and password in the authentication packages, allowing the server to make connections to other network servers while impersonating the client. This allows a server to accept clear text credentials from a c
0	UserContent	CF_TEXT	0x0	0xf9800983601c	he Kashmir issue</b></li>\n <li><b>J&K government secretariat and other offices will start functioning on Friday</b></li>\n <li><b>Pakistan has banned the airing of advertisements featuring Indian artists as part of the countrys protest against India


OUTPUT FIELDS
=============
- Session: Windows session ID
- WindowStation: Window station name (UserContent = high-value user data)
- Format: Clipboard format type (CF_TEXT, CF_UNICODETEXT, CF_OEMTEXT)
- Handle: Clipboard format handle ID
- Object: Memory offset where data was found
- Data: Actual clipboard content extracted from memory


REQUIREMENTS
============
- Volatility 3 Framework 2.0.0+
- Windows memory dumps (XP through Windows 11)
- Supports Intel32 and Intel64 architectures


