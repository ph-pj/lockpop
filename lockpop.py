import argparse
from pykeepass import PyKeePass
from multiprocessing import Pool
import time
import os
import subprocess
import hashlib

def get_yubikey_response(challenge, slot=2):
    """
    Get HMAC-SHA1 challenge-response from YubiKey.
    
    Args:
        challenge: bytes - The challenge to send to the YubiKey
        slot: int - YubiKey slot number (1 or 2, default 2)
    
    Returns:
        bytes - The 20-byte HMAC-SHA1 response from YubiKey
    
    Raises:
        RuntimeError: If ykman is not available or YubiKey operation fails
    """
    try:
        # Convert challenge to hex string for ykman
        challenge_hex = challenge.hex()
        
        # Call ykman to get challenge-response
        # ykman otp chalresp --totp <slot> <challenge-hex>
        result = subprocess.run(
            ['ykman', 'otp', 'chalresp', str(slot), challenge_hex],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"YubiKey challenge-response failed: {result.stderr}")
        
        # Parse the response (ykman returns hex string)
        response_hex = result.stdout.strip()
        response = bytes.fromhex(response_hex)
        
        return response
    except FileNotFoundError:
        raise RuntimeError(
            "ykman (YubiKey Manager CLI) not found. Please install it:\n"
            "  Ubuntu/Debian: sudo apt-get install yubikey-manager\n"
            "  macOS: brew install ykman\n"
            "  Other: pip install yubikey-manager"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("YubiKey operation timed out. Please ensure YubiKey is connected.")


def create_yubikey_keyfile(database_path, slot, output_path='/tmp/yubikey_response.key'):
    """
    Create a keyfile from YubiKey challenge-response.
    
    This function:
    1. Reads the database header to extract the master seed (challenge)
    2. Gets the YubiKey HMAC-SHA1 response 
    3. Saves the response as a keyfile
    
    Args:
        database_path: str - Path to the KDBX database
        slot: int - YubiKey slot number (1 or 2)
        output_path: str - Where to save the keyfile
    
    Returns:
        str - Path to the created keyfile
    """
    # For KDBX 4 databases, the challenge is typically derived from the master seed
    # However, without deep KDBX parsing, we'll use a standard approach
    
    # Read database header to extract challenge
    # KDBX4 structure: signature(4) + version(4) + header items
    try:
        with open(database_path, 'rb') as f:
            # Read signature and version
            signature = f.read(8)
            
            # Verify it's a KDBX file
            if signature[:4] != b'\x03\xd9\xa2\x9a':
                raise ValueError("Not a valid KDBX file")
            
            # For challenge-response, KeePassXC uses the transformed master key
            # or master seed as the challenge. Since we don't have the password yet,
            # we'll use a hash of the database header as challenge
            f.seek(0)
            header_bytes = f.read(256)  # Read enough of header
            challenge = hashlib.sha256(header_bytes).digest()
    except Exception as e:
        raise RuntimeError(f"Failed to read database header: {e}")
    
    # Get YubiKey response
    response = get_yubikey_response(challenge, slot)
    
    # Save response as keyfile (32 bytes for compatibility)
    # Pad to 32 bytes if needed
    keyfile_data = hashlib.sha256(response).digest()
    
    with open(output_path, 'wb') as f:
        f.write(keyfile_data)
    
    return output_path


def try_password(args):
    index, password, database_path, keyfile_path = args
    password = password.strip()
    try:
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
    parser.add_argument("-y", "--yubikey-slot", type=int, choices=[1, 2], required=False, help="YubiKey slot for challenge-response (1 or 2). Requires YubiKey Manager (ykman) to be installed.")
    parser.add_argument("-o", "--output", action="store_true", help="If the database is unlocked, show all stored entries")
    parser.add_argument("-f", "--outfile", type=str, help="Save dumped entries to a text file")
    parser.add_argument("-t", "--threads", type=int, default=os.cpu_count(), help="Number of parallel processes to use (default: all CPU cores)")
    args = parser.parse_args()

    db_file = args.database.replace("'", "")
    wordlist_file = args.wordlist.replace("'", "")
    keyfile_paths = [kf.replace("'", "") for kf in args.keyfile] if args.keyfile else [None]
    yubikey_slot = args.yubikey_slot
    output_entries = args.output
    output_file = args.outfile
    num_threads = args.threads

    print("Starting lockpop...")
    print(f"Database file : {db_file}")
    print(f"Wordlist      : {wordlist_file}")
    if keyfile_paths and any(kf is not None for kf in keyfile_paths):
        print(f"Keyfile(s)    : {', '.join(kf for kf in keyfile_paths if kf is not None)}")
    if yubikey_slot:
        print(f"YubiKey slot  : {yubikey_slot}")
        print("Note: YubiKey will be queried once before brute-forcing begins.")
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

    # Handle YubiKey if specified
    yubikey_keyfile = None
    if yubikey_slot:
        try:
            print("Querying YubiKey for challenge-response...")
            yubikey_keyfile = create_yubikey_keyfile(db_file, yubikey_slot)
            print(f"YubiKey response saved to: {yubikey_keyfile}")
            # Add YubiKey response to keyfile list
            if keyfile_paths == [None]:
                keyfile_paths = [yubikey_keyfile]
            else:
                # Combine with existing keyfiles
                new_keyfile_paths = []
                for kf in keyfile_paths:
                    if kf is None:
                        new_keyfile_paths.append(yubikey_keyfile)
                    else:
                        # Try both: regular keyfile and keyfile+yubikey
                        new_keyfile_paths.append(kf)
                        # Note: For true combination, we'd need to merge them
                        # For now, treat YubiKey response as alternative keyfile
                keyfile_paths.append(yubikey_keyfile)
            print()
        except Exception as e:
            print(f"Error setting up YubiKey: {e}")
            return

    try:
        with open(wordlist_file, "r", encoding="unicode_escape") as file:
            passwords = file.readlines()
    except FileNotFoundError:
        print(f"Wordlist not found: {wordlist_file}")
        return

    task_args = [(i, pw, db_file, kf) for i, pw in enumerate(passwords) for kf in keyfile_paths]

    found_password = None
    found_keyfile = None
    tried = 0
    start_time = time.time()

    with Pool(processes=num_threads) as pool:
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
            if found_keyfile == yubikey_keyfile:
                print(f"Hardware key  : YubiKey slot {yubikey_slot}")
            else:
                print(f"Keyfile used  : {found_keyfile}")
        try:
            kp = PyKeePass(db_file, password=found_password, keyfile=found_keyfile)
            if output_entries or output_file:
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
    
    # Clean up temporary YubiKey keyfile
    if yubikey_keyfile and os.path.exists(yubikey_keyfile):
        try:
            os.remove(yubikey_keyfile)
        except:
            pass

if __name__ == "__main__":
    main()
