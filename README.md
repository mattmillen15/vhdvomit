# VHDVomit
Tool to search SMB shares for VHD backup files, mount them, and dump locally stored credentials within. 
___
## Demo: 
<video src="https://github.com/user-attachments/assets/868660dd-9532-4e81-9824-ac8452f36384" controls width="600">
</video>

---
## Usage:
```python
sudo python3 vhdvomit.py --help                                
usage: vhdvomit.py [-h] -t TARGET [-u USERNAME] [-p PASSWORD] [-d DOMAIN]

Mount SMB shares, find VHD/VHDX backups, extract credentials

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target host IP or hostname
  -u, --username USERNAME
                        Username (default: null auth)
  -p, --password PASSWORD
                        Password (will prompt if username provided without password)
  -d, --domain DOMAIN   Domain name

Examples:
  Null authentication:
    vhdvomit.py -t 192.168.1.10
  
  With credentials:
    vhdvomit.py -t 192.168.1.10 -u administrator -p Password123 -d CORP

```
___
## Pre-Reqs
```bash
sudo apt install -y cifs-utils qemu-utils ntfs-3g
```
```bash
pipx install impacket
```
___
## Limitations
- Currently only supports password based authentication. This tool relies heavily on qemu-nbd for mounting the VHDX file system... which doesn't support PTH.
___
## Shout Out
- This tool is just another stolen idea. Shout out to @ad0nis, especially since I am totally ripping off his tool name cause it's too fitting. 
