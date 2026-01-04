import argparse
from pykeepass import PyKeePass
from multiprocessing import Pool, Manager
import time
import os
import subprocess


# Global lock for YubiKey access (will be initialized in main)
yubikey_lock = None


def init_worker(lock):
    """Initialize worker process with shared lock."""
    global yubikey_lock
    yubikey_lock = lock


def get_yubikey_serial():
    """Get the serial number of the connected YubiKey."""
    try:
        result = subprocess.run(
            ['ykman', 'info'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            raise RuntimeError("Failed to get YubiKey info")
        
        # Parse output to find serial number
        for line in result.stdout.split('\n'):
            if 'Serial number:' in line:
                serial = line.split(':')[1].strip()
                return serial
        
        raise RuntimeError("Could not find YubiKey serial number")
    except FileNotFoundError:
        raise RuntimeError("ykman not found. Please install yubikey-manager")
    except Exception as e:
        raise RuntimeError(f"Error getting YubiKey serial: {e}")


def try_password(args):
    index, password, database_path, keyfile_path, yubikey_slot = args
    password = password.strip()
    try:
        if yubikey_slot:
            # Use keepassxc-cli ls command instead of open to avoid interactive mode
            # This will list entries and exit, proving the password works
            # Use lock to ensure only one process accesses YubiKey at a time
            global yubikey_lock
            with yubikey_lock:
                result = subprocess.run(
                    ['keepassxc-cli', 'ls', '--yubikey', yubikey_slot, database_path, '/'],
                    input=password + '\n',
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            # Success if returncode is 0 and no error message
            if result.returncode == 0 and 'Erro' not in result.stdout and 'Error' not in result.stdout:
                return (password, f"YubiKey {yubikey_slot}")
            return None
        else:
            PyKeePass(database_path, password=password, keyfile=keyfile_path)
            return (password, keyfile_path)
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(
        description="lockpop: a simple multi-process brute-force tool for KeePass (.kdbx) files. Works with password-only, password+keyfile, or password+hardware key setups."
    )
    parser.add_argument("-d", "--database", type=ascii, required=True, help="Path to the KeePass .kdbx file")
    parser.add_argument("-w", "--wordlist", type=ascii, required=True, help="Text file with passwords to try, one per line")
    parser.add_argument("-k", "--keyfile", type=ascii, action='append', required=False, help="Optional keyfile(s) to use if the database requires it. Can be specified multiple times to try multiple keyfiles.")
    parser.add_argument("-y", "--yubikey-slot", type=int, nargs='+', choices=[0, 1, 2], required=False, help="YubiKey slot(s) for challenge-response (0=no hardware key, 1=slot 1, 2=slot 2). Can specify multiple: -y 0 1 2. Use 0 to test without YubiKey.")
    parser.add_argument("-ny", "--no-hardware-key", action="store_true", help="Also test without hardware key (equivalent to adding 0 to -y)")
    parser.add_argument("-o", "--output", action="store_true", help="If the database is unlocked, show all stored entries")
    parser.add_argument("-f", "--outfile", type=str, help="Save dumped entries to a text file")
    parser.add_argument("-t", "--threads", type=int, default=os.cpu_count(), help="Number of parallel processes to use (default: all CPU cores)")
    args = parser.parse_args()

    db_file = args.database.replace("'", "")
    wordlist_file = args.wordlist.replace("'", "")
    keyfile_paths = [kf.replace("'", "") for kf in args.keyfile] if args.keyfile else [None]
    yubikey_slots = args.yubikey_slot if args.yubikey_slot else []
    no_hardware_key = args.no_hardware_key
    output_entries = args.output
    output_file = args.outfile
    num_threads = args.threads
    
    # Add 0 (no hardware key) if --no-hardware-key flag is set
    if no_hardware_key and 0 not in yubikey_slots:
        yubikey_slots = [0] + yubikey_slots

    print("Starting lockpop...")
    print(f"Database file : {db_file}")
    print(f"Wordlist      : {wordlist_file}")
    if keyfile_paths and any(kf is not None for kf in keyfile_paths):
        print(f"Keyfile(s)    : {', '.join(kf for kf in keyfile_paths if kf is not None)}")
    if yubikey_slots:
        slot_desc = ', '.join(str(s) if s != 0 else 'None (password only)' for s in yubikey_slots)
        print(f"YubiKey slots : {slot_desc}")
    if output_file:
        print(f"Output file   : {output_file}")

    max_threads = os.cpu_count()
    if num_threads < 1:
        print("Thread count too low. Using 1 thread instead.")
        num_threads = 1
    elif num_threads > max_threads:
        print(f"Too many threads. Max allowed is {max_threads}. Adjusting accordingly.")
        num_threads = max_threads

    print(f"Threads used  : {num_threads}\n")

    # Verify keepassxc-cli is available and get YubiKey serial if needed
    yubikey_specs = []
    hardware_slots = [s for s in yubikey_slots if s != 0]
    
    if hardware_slots:
        try:
            result = subprocess.run(['keepassxc-cli', '--version'], capture_output=True, timeout=5)
            if result.returncode != 0:
                raise RuntimeError("keepassxc-cli not working properly")
            
            # Get YubiKey serial number once
            serial = get_yubikey_serial()
            
            # Create specs for each hardware slot
            for slot in hardware_slots:
                yubikey_specs.append(f"{slot}:{serial}")
            
            print("YubiKey mode: Using keepassxc-cli for native YubiKey support")
            print(f"YubiKey detected: Serial {serial}")
            print(f"Testing slots: {', '.join(str(s) for s in hardware_slots)}")
            print("Note: YubiKey access will be serialized (one at a time)")
            print("      but other processing remains parallel\n")
        except FileNotFoundError:
            print("Error: keepassxc-cli not found. Required for YubiKey support.")
            print("Install KeePassXC from: https://keepassxc.org/download")
            print("Make sure keepassxc-cli is in your PATH.")
            return
        except Exception as e:
            print(f"Error setting up YubiKey: {e}")
            return

    try:
        with open(wordlist_file, "r", encoding="utf-8-sig") as file:
            passwords = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Wordlist not found: {wordlist_file}")
        return

    # Prepare task arguments - combine all possibilities
    task_args = []
    
    if yubikey_slots:
        # User specified YubiKey slots (including possible 0 for no hardware)
        for i, pw in enumerate(passwords):
            for slot_value in yubikey_slots:
                if slot_value == 0:
                    # Test without hardware key - try with each keyfile
                    for kf in keyfile_paths:
                        task_args.append((i, pw, db_file, kf, None))
                else:
                    # Test with hardware key - find the corresponding spec
                    spec = next((s for s in yubikey_specs if s.startswith(f"{slot_value}:")), None)
                    if spec:
                        # With YubiKey, keyfile is handled differently
                        # For now, test YubiKey separately from keyfiles
                        # TODO: Support combining keyfile + YubiKey if needed
                        task_args.append((i, pw, db_file, None, spec))
    else:
        # No YubiKey specified - normal mode with keyfiles only
        task_args = [(i, pw, db_file, kf, None) for i, pw in enumerate(passwords) for kf in keyfile_paths]
    
    # Show total combinations to user
    total_attempts = len(task_args)
    print(f"Total combinations to test: {total_attempts}")
    print(f"  ({len(passwords)} passwords × {total_attempts // len(passwords)} configurations)\n")

    # Create a lock for YubiKey access if needed
    manager = Manager()
    lock = manager.Lock() if hardware_slots else None

    found_password = None
    found_keyfile = None
    tried = 0
    start_time = time.time()

    # Initialize pool with lock for YubiKey synchronization
    with Pool(processes=num_threads, initializer=init_worker, initargs=(lock,) if lock else ()) as pool:
        for result in pool.imap_unordered(try_password, task_args):
            tried += 1
            if result:
                found_password, found_keyfile = result
                pool.terminate()
                break

    end_time = time.time()
    duration = end_time - start_time

    print("\nBrute-force finished.")
    print(f"Passwords tried : {tried}")
    print(f"Time taken      : {duration:.2f} seconds\n")

    if found_password:
        print(f"Password found: {found_password}")
        if found_keyfile:
            print(f"Keyfile/Key   : {found_keyfile}")
        try:
            # Determine if result used YubiKey
            used_yubikey = found_keyfile and "YubiKey" in found_keyfile
            
            if used_yubikey:
                # For YubiKey, use keepassxc-cli to extract entries
                kp = None  # Can't use PyKeePass with YubiKey
            else:
                kp = PyKeePass(db_file, password=found_password, keyfile=found_keyfile)
            if output_entries or output_file:
                if used_yubikey:
                    print("\nWarning: Entry extraction with YubiKey requires manual access.")
                    yubikey_spec_found = found_keyfile.replace("YubiKey ", "")
                    print(f"Use: keepassxc-cli show --yubikey {yubikey_spec_found} {db_file} <entry-path>")
                elif kp:
                    output_lines = []
                    for entry in kp.entries:
                        output_lines.append("-" * 40)
                        output_lines.append(f"Title       : {entry.title}")
                        output_lines.append(f"Username    : {entry.username}")
                        output_lines.append(f"Password    : {entry.password}")
                        output_lines.append(f"URL         : {entry.url}")
                        output_lines.append(f"Notes       : {entry.notes}")
                        output_lines.append(f"Group       : {entry.group.name if entry.group else 'N/A'}")
                    output_lines.append("-" * 40)

                    if output_entries:
                        print("\nDatabase entries:")
                        for line in output_lines:
                            print(line)

                    if output_file:
                        try:
                            with open(output_file, "w", encoding="utf-8") as f:
                                for line in output_lines:
                                    f.write(line + "\n")
                            print(f"\nEntries written to: {output_file}")
                        except Exception as e:
                            print(f"Error writing to output file: {e}")
        except Exception as e:
            print(f"Error reading entries: {e}")
    else:
        print("No valid password found.")

if __name__ == "__main__":
    main()
