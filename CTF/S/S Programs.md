# `gpg`

GPG (GNU Privacy Guard) comes via the `gnupg` package, likely already installed. If not:

```bash
sudo pacman -S gnupg
```

---

## Key Management

```bash
# Generate a new key pair
gpg --full-generate-key

# List your public keys
gpg --list-keys

# List your private/secret keys
gpg --list-secret-keys

# Export your public key (to share)
gpg --export --armor your@email.com > pubkey.asc

# Import someone else's public key
gpg --import theirkey.asc

# Delete a public key
gpg --delete-key their@email.com
```

---

## Encrypt & Decrypt

```bash
# Encrypt a file for a recipient (they need to have a key imported)
gpg --encrypt --recipient their@email.com file.txt
# Output: file.txt.gpg

# Encrypt with a passphrase only (symmetric, no key needed)
gpg --symmetric file.txt

# Decrypt
gpg --decrypt file.txt.gpg > file.txt
# or
gpg --output file.txt --decrypt file.txt.gpg
```

---

## Sign & Verify

```bash
# Sign a file (creates file.txt.sig separately)
gpg --detach-sign file.txt

# Sign and embed signature in one file
gpg --sign file.txt

# Clear-sign text (human-readable + signature)
gpg --clearsign file.txt

# Verify a signature
gpg --verify file.txt.sig file.txt
```

---

## Keyserver (optional)

```bash
# Search for a key
gpg --keyserver keys.openpgp.org --search-keys name@example.com

# Send your key to a keyserver
gpg --keyserver keys.openpgp.org --send-keys YOUR_KEY_ID

# Fetch a key by ID
gpg --keyserver keys.openpgp.org --recv-keys KEYID
```

---

## Useful extras

```bash
# Get your key's fingerprint
gpg --fingerprint your@email.com

# Edit a key (add UIDs, set expiry, sign, etc.)
gpg --edit-key your@email.com

# Show short key ID
gpg --list-keys --keyid-format short
```

Config and keyrings are stored in `~/.gnupg/`. Permissions on that directory should be `700` or GPG will complain.

---

# `openssl`

Here's how to use OpenSSL on Arch Linux:

**Install it first:**

```bash
sudo pacman -S openssl
```

**Common commands:**

Generate a private key:

```bash
openssl genrsa -out private.key 2048
```

Generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Check a certificate:

```bash
openssl x509 -in cert.pem -text -noout
```

Generate a CSR (Certificate Signing Request):

```bash
openssl req -new -key private.key -out request.csr
```

Encrypt a file:

```bash
openssl enc -aes-256-cbc -in file.txt -out file.enc
```

Decrypt a file:

```bash
openssl enc -d -aes-256-cbc -in file.enc -out file.txt
```

Check an SSL connection:

```bash
openssl s_client -connect example.com:443
```

Hash a string:

```bash
echo -n "hello" | openssl dgst -sha256
```

Check version:

```bash
openssl version
```

**Get help on any subcommand:**

```bash
openssl help
openssl <subcommand> --help
# e.g.
openssl req --help
```

The `man openssl` page and `man openssl-<subcommand>` (e.g. `man openssl-req`) are also useful on Arch. 

---

# `steghide`

## Steghide on Arch

Not in the official repos — install from AUR:

```bash
yay -S steghide
# or
paru -S steghide
```

---

## Embed (hide data in an image/audio file)

```bash
steghide embed -cf cover.jpg -sf secret.txt
```

- `-cf` — cover file (the carrier, e.g. jpg, bmp, wav, au)
- `-sf` — secret file to hide
- You'll be prompted for a passphrase

Optional flags:

```bash
# Specify passphrase inline (less secure)
steghide embed -cf cover.jpg -sf secret.txt -p "yourpassphrase"

# Set compression level (1-9, default 6)
steghide embed -cf cover.jpg -sf secret.txt -z 9

# Overwrite output without prompting
steghide embed -cf cover.jpg -sf secret.txt -f
```

The output **overwrites** `cover.jpg` by default. To keep the original:

```bash
steghide embed -cf cover.jpg -sf secret.txt -cf cover.jpg -p "" 
# better: copy first
cp cover.jpg stego.jpg && steghide embed -cf stego.jpg -sf secret.txt
```

---

## Extract (retrieve hidden data)

```bash
steghide extract -sf stego.jpg
```

- `-sf` — the stego file (the one with hidden data)
- You'll be prompted for the passphrase
- Extracts to the original filename by default

```bash
# Extract to a specific output file
steghide extract -sf stego.jpg -p "yourpassphrase" -xf output.txt
```

---

## Inspect (check what's embedded, without extracting)

```bash
steghide info stego.jpg
```

Shows capacity, whether data is embedded, and format — but **won't reveal contents without the passphrase**.

---

## Notes

- Supported formats: **JPEG, BMP, WAV, AU** — PNG is **not supported**
- The passphrase is the only protection; there's no key file mechanism
- Steghide uses a weak-by-modern-standards cipher (Rijndael-128 by default); don't rely on it alone for sensitive data without additional encryption (e.g. GPG-encrypt first, then embed)

---

# `sha256sum`


**`sha256sum` (from `coreutils`, installed by default):**

```bash
# Hash a file
sha256sum file.txt

# Hash multiple files
sha256sum file1.txt file2.txt

# Verify against a checksum file
sha256sum -c checksums.sha256
```

**`b2sum`, `sha512sum`, etc. are also available** from the same `coreutils` package.

---

**If you want just the hash string (no filename):**

```bash
sha256sum file.txt | awk '{print $1}'
```

**Hash a string directly:**

```bash
echo -n "hello" | sha256sum
# -n is important — omitting it includes a trailing newline in the hash
```

---

**Via OpenSSL (alternative):**

```bash
openssl dgst -sha256 file.txt
echo -n "hello" | openssl dgst -sha256
```

---

**Check if it's installed:**

```bash
which sha256sum
# or
pacman -Qo /usr/bin/sha256sum
```

---

# `exiftool`

## ExifTool on Arch

```bash
sudo pacman -S perl-image-exiftool
```

---

## Read Metadata

```bash
# Show all metadata
exiftool file.jpg

# Show specific tag
exiftool -Author file.jpg
exiftool -GPSLatitude -GPSLongitude file.jpg

# Show metadata for all files in a directory
exiftool /path/to/dir/

# Compact output (tag: value format)
exiftool -s file.jpg

# Only show tag names (no values)
exiftool -s -s file.jpg
```

---

## Write / Edit Metadata

```bash
# Set a tag
exiftool -Author="Your Name" file.jpg

# Set multiple tags at once
exiftool -Author="Name" -Copyright="2024" file.jpg

# Apply to all files in a directory
exiftool -Author="Name" /path/to/dir/

# Apply recursively
exiftool -r -Author="Name" /path/to/dir/
```

By default, exiftool **saves a backup** as `file.jpg_original`. To skip the backup:

```bash
exiftool -overwrite_original -Author="Name" file.jpg
```

---

## Remove Metadata

```bash
# Remove ALL metadata
exiftool -all= file.jpg

# Remove a specific tag
exiftool -Author= file.jpg

# Remove all metadata, no backup
exiftool -overwrite_original -all= file.jpg

# Strip metadata from all files in a folder
exiftool -overwrite_original -all= /path/to/dir/
```

---

## Copy Metadata Between Files

```bash
# Copy all metadata from one file to another
exiftool -tagsFromFile source.jpg dest.jpg

# Copy specific tags only
exiftool -tagsFromFile source.jpg -Author -Copyright dest.jpg
```

---

## Rename / Organize Files by Metadata

```bash
# Rename files using date taken
exiftool '-FileName<DateTimeOriginal' -d "%Y-%m-%d_%H-%M-%S.%%e" file.jpg

# Move files into date-based folders
exiftool '-Directory<DateTimeOriginal' -d "/photos/%Y/%m" /path/to/dir/
```

---

## Output Formats

```bash
# Output as JSON
exiftool -json file.jpg

# Output as CSV
exiftool -csv file.jpg

# Output as XML
exiftool -X file.jpg
```

---

## Useful Extras

```bash
# Show only GPS data
exiftool -gps:all file.jpg

# Show what camera took a photo
exiftool -Make -Model file.jpg

# Compare metadata of two files
diff <(exiftool file1.jpg) <(exiftool file2.jpg)

# Find all files with a specific tag value
exiftool -r -if '$Author eq "Name"' -p '$FileName' /path/
```

---

## Notes

- ExifTool supports a huge range of formats: JPEG, PNG, PDF, MP4, RAW formats, audio files, and more
- Always keep the `_original` backup until you've confirmed edits are correct, then clean up with `exiftool -delete_original`
- Stripping metadata before sharing files is good privacy practice

---

# `binwalk`

**Install it first:**

```bash
sudo pacman -S binwalk
```

Or from the AUR if not in official repos:

```bash
yay -S binwalk
```

---

**Basic usage:**

Scan a file for embedded data/signatures:

```bash
binwalk file.bin
```

Extract embedded files:

```bash
binwalk -e file.bin
# extracted files go into _file.bin.extracted/
```

Force extraction even if no known signature:

```bash
binwalk -e --run-as=root file.bin
```

Recursive extraction:

```bash
binwalk -Me file.bin
# -M = recursively scan extracted files
```

---

**Other useful flags:**

```bash
# Show entropy (useful for detecting encryption/compression)
binwalk -E file.bin

# Scan for strings
binwalk -B file.bin

# Search for a specific signature
binwalk -R "\x89PNG" file.bin

# Disassemble opcodes
binwalk -A file.bin

# Output as CSV
binwalk --csv file.bin
```

---

**Check version / help:**

```bash
binwalk --help
binwalk --version
```

---

**Note:** Some extraction tools (`dd`, `7z`, `jefferson`, etc.) are optional dependencies that binwalk calls under the hood. If extraction is incomplete, check:

```bash
sudo pacman -S p7zip squashfs-tools
```

---

# `strings`

## strings on Arch

Part of `binutils`, almost certainly already installed. If not:

```bash
sudo pacman -S binutils
```

---

## Basic Usage

```bash
# Print all printable strings in a file
strings file

# Common use: inspect a binary
strings /usr/bin/someprogram
```

By default, `strings` looks for sequences of **4+ printable characters** followed by a non-printable or end of file.

---

## Useful Flags

```bash
# Set minimum string length (e.g. 8 chars)
strings -n 8 file

# Show the file offset of each string
strings -o file

# Show offset in hex
strings -t x file

# Show offset in decimal
strings -t d file

# Show offset in octal
strings -t o file

# Scan the entire file (not just initialized data sections)
strings -a file
```

---

## Encoding Options

By default it looks for 7-bit ASCII. You can specify encoding with `-e`:

```bash
strings -e s file   # single-byte (default)
strings -e S file   # single-byte big-endian
strings -e b file   # 16-bit big-endian (UTF-16 BE)
strings -e l file   # 16-bit little-endian (UTF-16 LE)
strings -e B file   # 32-bit big-endian
strings -e L file   # 32-bit little-endian
```

Useful for Windows binaries or files that use UTF-16:

```bash
strings -e l file.exe
```

---

## Piping & Filtering

```bash
# Search for something specific
strings file | grep -i "password"
strings file | grep -i "http"
strings file | grep -i "error"

# Count how many strings
strings file | wc -l

# Look for IPs (rough pattern)
strings file | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

# Look for URLs
strings file | grep -E 'https?://'

# Pipe through less
strings file | less
```

---

## Common Use Cases

```bash
# Check what libraries/paths a binary references
strings /usr/bin/curl | grep "/"

# Look for hardcoded credentials or keys (basic check)
strings file | grep -iE "key|token|secret|pass|auth"

# Inspect a firmware or disk image
strings firmware.bin | less

# Inspect a core dump
strings core | grep -i "error"

# Quick malware triage (what domains/IPs does it reference?)
strings suspicious.bin | grep -E 'https?://|[0-9]{1,3}\.[0-9]{1,3}'
```

---

## Notes

- `strings` is a simple static analysis tool — it finds printable character sequences but has no understanding of context
- It won't find obfuscated, encrypted, or runtime-generated strings
- For deeper binary analysis, pair it with `file`, `objdump`, `readelf`, or `strace`

---

# `file`

The `file` command is installed by default on Arch (from the `file` package).

---

**Basic usage:**

Identify a file's type:

```bash
file filename
```

Multiple files:

```bash
file file1 file2 file3
```

---

**Useful flags:**

```bash
# Brief output (just the type, no filename)
file -b filename

# MIME type instead of description
file --mime-type filename

# MIME type + encoding
file --mime filename

# Follow symlinks
file -L symlink

# Read list of files from a file
file -f list.txt

# Don't pad output (useful for scripting)
file -N filename

# Look inside a compressed file
file -z file.gz
```

---

**Common examples:**

```bash
file image.png
# image.png: PNG image data, 800 x 600, 8-bit/color RGB

file mystery_binary
# mystery_binary: ELF 64-bit LSB executable, x86-64

file archive.tar.gz
# archive.tar.gz: gzip compressed data

file script.sh
# script.sh: Bourne-Again shell script, ASCII text executable
```

---

**Scripting use (just get the type string):**

```bash
filetype=$(file -b filename)
echo "$filetype"
```

---

**Check / install:**

```bash
pacman -Qo /usr/bin/file
# or
sudo pacman -S file
```
