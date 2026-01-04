# Lock POP
lockpop is a simple, multi-process brute-force tool for cracking KeePass .kdbx databases using a password wordlist — with optional support for keyfiles and hardware keys (YubiKey). It's useful for testing, password strength audits, or recovering access to a lost database.

# Features
- Brute-forces password-only, password+keyfile, or password+hardware key protected KeePass databases
- Supports YubiKey HMAC-SHA1 challenge-response for KDBX 4 databases
- Supports testing multiple keyfiles in parallel with passwords
- Uses multiprocessing for fast parallel cracking
- Auto-adjusts thread count to available CPU cores
- Optional entry dump on successful unlock
- Clean, readable CLI output

# Requirements
- Python 3.7+
- pykeepass, install via pip:
```bash
pip install pykeepass
```
- For YubiKey support: YubiKey Manager (ykman)
```bash
# Ubuntu/Debian
sudo apt-get install yubikey-manager

# macOS
brew install ykman

# Other systems
pip install yubikey-manager
```

# Usage
```bash
python lockpop.py -d vault.kdbx -w wordlist.txt [options]
```
Required:
- -d, --database — Path to the KeePass .kdbx file
- -w, --wordlist — Path to a file with passwords (one per line)

Optional:
- -k, --keyfile — Keyfile path if the database requires one. Can be specified multiple times to try multiple keyfiles (e.g., -k key1.key -k key2.key)
- -y, --yubikey-slot — YubiKey slot for challenge-response (1 or 2). For KDBX 4 databases with hardware key protection
- -o, --output — If the vault is cracked, print all entries
- -f, --outfile — Write dumped entries to a file instead of stdout
- -t, --threads — Number of processes to run in parallel (default = all cores)

# Example
```bash
python lockpop.py -d myvault.kdbx -w rockyou.txt -k my.key -o -f cracked.txt -t 4
```
This will:
- Attempt to unlock myvault.kdbx
- Use rockyou.txt as the password list
- Provide my.key as a keyfile
- Dump the unlocked entries into cracked.txt
- Use 4 CPU cores to speed things up

# Example with Multiple Keyfiles
```bash
python lockpop.py -d myvault.kdbx -w rockyou.txt -k key1.key -k key2.key -k key3.key -t 4
```
This will:
- Attempt to unlock myvault.kdbx
- Use rockyou.txt as the password list
- Try each password with key1.key, key2.key, and key3.key
- Use 4 CPU cores to speed things up

# Example with YubiKey Hardware Key
```bash
python lockpop.py -d myvault.kdbx -w rockyou.txt -y 2 -t 4
```
This will:
- Attempt to unlock myvault.kdbx (KDBX 4 database with YubiKey protection)
- Use rockyou.txt as the password list
- Query YubiKey slot 2 for challenge-response authentication
- Use 4 CPU cores to speed things up

**Note:** YubiKey must be connected and properly configured with HMAC-SHA1 challenge-response in the specified slot. The YubiKey is queried once at startup, and the response is used for all password attempts.

# YubiKey Setup
To use YubiKey with KeePass databases:
1. Configure your YubiKey with HMAC-SHA1 challenge-response using `ykman`:
   ```bash
   ykman otp chalresp --generate 2
   ```
2. Create or configure your KeePass database (using KeePassXC) to use YubiKey challenge-response
3. Use lockpop with the `-y` option specifying the slot number (typically slot 2)

For more information on YubiKey setup with KeePass, see the [KeePassXC documentation](https://keepassxc.org/docs/#faq-yubikey).
