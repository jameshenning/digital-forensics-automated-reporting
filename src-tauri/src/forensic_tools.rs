/// Forensic tool knowledge base — Rust mirror of `src/lib/forensic-tools.ts`.
///
/// Used by `reports.rs` to render rich per-tool narratives in court-ready
/// forensic reports. The same KB also lives on the frontend for display in
/// the Tools tab of the case detail page — the two files MUST be kept in
/// sync. When adding or editing an entry, update BOTH files in the same
/// change and add a test if the lookup behavior changes.
///
/// The lookup is alias-aware and case-insensitive; prefix matching handles
/// versioned tool names like `exiftool-13.50` → `exiftool`.
///
/// Unknown tools (not in the KB) are rendered in the report using a minimal
/// fallback template that still includes the user-recorded purpose, command,
/// and files.

// ─── Data types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCategory {
    Hashing,
    Metadata,
    Archive,
    Carving,
    Password,
    Hex,
    Identification,
    Strings,
    DiskImaging,
    Filesystem,
    Memory,
    Network,
    Timeline,
    Registry,
    Malware,
    Mobile,
    Email,
    Web,
    Stego,
    Osint,
}

impl ToolCategory {
    pub fn label(self) -> &'static str {
        match self {
            ToolCategory::Hashing => "Hash verification",
            ToolCategory::Metadata => "Metadata extraction",
            ToolCategory::Archive => "Archive / compression",
            ToolCategory::Carving => "File carving",
            ToolCategory::Password => "Password cracking",
            ToolCategory::Hex => "Hex inspection",
            ToolCategory::Identification => "File identification",
            ToolCategory::Strings => "String extraction",
            ToolCategory::DiskImaging => "Disk imaging",
            ToolCategory::Filesystem => "Filesystem analysis",
            ToolCategory::Memory => "Memory forensics",
            ToolCategory::Network => "Network forensics",
            ToolCategory::Timeline => "Timeline analysis",
            ToolCategory::Registry => "Registry analysis",
            ToolCategory::Malware => "Malware analysis",
            ToolCategory::Mobile => "Mobile forensics",
            ToolCategory::Email => "Email forensics",
            ToolCategory::Web => "Web history",
            ToolCategory::Stego => "Steganography",
            ToolCategory::Osint => "OSINT",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ForensicTool {
    /// Canonical display name.
    pub name: &'static str,
    /// Lowercase aliases matched against the user-recorded tool_name field.
    pub aliases: &'static [&'static str],
    pub category: ToolCategory,
    /// One-paragraph description of what the tool is and what it does.
    pub description: &'static str,
    /// Bullet list of what this tool typically finds.
    pub typical_findings: &'static [&'static str],
    /// Why it matters in a forensic investigation.
    pub why_it_matters: &'static str,
    /// Tool names this one commonly feeds into (for dependency chaining).
    pub feeds_into: &'static [&'static str],
    /// Tool names this one commonly consumes output from.
    pub consumes_from: &'static [&'static str],
    /// Optional reference URL.
    pub reference: Option<&'static str>,
    // ─── Reproducibility (added for the second-examiner workflow) ─────────
    /// Shell commands a reproducing examiner runs ONCE before the tool can
    /// be invoked. Usually package installs or venv activation. Subsequent
    /// runs skip this. Empty array if no setup is needed.
    pub environment_setup: &'static [&'static str],
    /// Ordered reproduction steps with placeholder substitution. Supported
    /// placeholders: {input_file}, {output_file}, {command}, {version},
    /// {operator}, {input_sha256}, {output_sha256}. Unknown placeholders
    /// are left literal so reviewers see the gap. Each entry is one
    /// numbered step.
    pub reproduction_steps: &'static [&'static str],
    /// How the reproducing examiner verifies they got the same result.
    /// Usually instructions to SHA-256 the output and compare with the
    /// recorded {output_sha256}.
    pub verification_steps: &'static [&'static str],
}

// ─── Knowledge base ───────────────────────────────────────────────────────────

pub static TOOLS: &[ForensicTool] = &[
    // Tools present in the user's v1 data
    ForensicTool {
        name: "7-Zip",
        aliases: &["7z", "7zip", "7-zip", "7z.exe", "p7zip"],
        category: ToolCategory::Archive,
        description: "Open-source file archiver with a high compression ratio. In forensics it is used to open suspect .7z, .zip, .rar, .iso, and .tar archives recovered from evidence, including archives that may be password-protected or damaged.",
        typical_findings: &[
            "Contents of compressed archives (documents, images, executables)",
            "Archive header metadata including create time and creator software",
            "Detection of password-protected or encrypted archives",
            "Unexpected nested archives (common for exfiltration staging)",
        ],
        why_it_matters: "Suspects commonly stage exfiltrated data inside compressed archives to hide it, bypass automated filters, or slip it past DLP. Being able to open them — or confirm that they are password-protected — is the gate to the rest of the investigation.",
        feeds_into: &["7z2john", "exiftool", "file", "sha256sum", "strings", "binwalk"],
        consumes_from: &[],
        reference: Some("https://7-zip.org"),
        environment_setup: &[
            "7-Zip (p7zip) is pre-installed on Kali Linux. Verify with: `7z --help | head -2`",
            "If missing, install with: `sudo apt-get install -y p7zip-full p7zip-rar`",
        ],
        reproduction_steps: &[
            "1. Confirm the tool version matches the original run: `7z i 2>&1 | head -3`. Compare against the recorded version {version}. Version drift above a minor release is unusual for archive extraction but note any discrepancy.",
            "2. Verify the input archive has not been modified: `sha256sum {input_file}`. The hash must equal {input_sha256}. Stop and raise a chain-of-custody flag if they differ.",
            "3. Reproduce the original examiner's exact command: `{command}`. If the archive is password-protected and no password was recorded, document the gap and attempt with no password first — 7z exits non-zero and prints 'Wrong password' rather than silently producing garbage output.",
            "4. If the command used `-p` for a password, supply the same password. Confirm each extracted file appears in the output listing. Pitfall: locale settings can affect how non-ASCII filenames are displayed; export `LC_ALL=C.UTF-8` before running if filenames look garbled.",
            "5. Hash each extracted file: `sha256sum {output_file}`. Record hashes in your case notes for downstream tools.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Confirm the list of extracted files matches the original examiner's ({operator}) notes — file count, filenames, and sizes should be identical.",
            "Re-run `7z t {input_file}` (test mode) to confirm the archive reports no CRC errors.",
            "If any extracted file hash differs from the original run, the archive may have been modified or a different password was used — escalate before proceeding.",
        ],
    },
    ForensicTool {
        name: "7z2john",
        aliases: &["7z2john", "7z2john.pl", "7z2john.py"],
        category: ToolCategory::Password,
        description: "A helper script shipped with John the Ripper that extracts the encrypted header bytes from a 7z archive and converts them into the hash format John and hashcat can crack. It does not crack the archive itself — it only prepares the hash.",
        typical_findings: &[
            "Hash string representing the archive's encrypted header",
            "Confirmation of the encryption algorithm (AES-256)",
            "Input ready for John / hashcat attack modes",
        ],
        why_it_matters: "You cannot brute-force a 7z archive directly — you have to extract its header hash first. This tool is the mandatory pre-processing step for any attack on an encrypted 7z, and picking the wrong converter (e.g., using a ZIP helper on a 7z file) means the cracker will never find the password even if it is in the wordlist.",
        feeds_into: &["john", "hashcat"],
        consumes_from: &["7-Zip", "file"],
        reference: Some("https://www.openwall.com/john/"),
        environment_setup: &[
            "7z2john ships with John the Ripper on Kali Linux. Verify with: `locate 7z2john 2>/dev/null || find /usr -name '7z2john*' 2>/dev/null`",
            "If missing, install John the Ripper: `sudo apt-get install -y john`",
            "The script is typically at `/usr/share/john/7z2john.pl` or reachable as `7z2john` on the PATH.",
        ],
        reproduction_steps: &[
            "1. Verify the input archive integrity before extraction: `sha256sum {input_file}`. Must equal {input_sha256}. A mismatch means you are not working from the same file the original examiner used.",
            "2. Confirm the archive is actually a 7z file (not ZIP, RAR, etc.): `file {input_file}`. The output must say '7-zip archive data'. Using 7z2john on a ZIP or RAR produces a silent wrong-format hash — John will simply never crack it.",
            "3. Run the hash-extraction command: `{command}`. This is typically `7z2john {input_file} > {output_file}`. The output file should contain exactly one line beginning with the archive filename followed by a colon.",
            "4. Inspect the hash line to confirm it is well-formed: `cat {output_file}`. A valid 7z hash line contains `$7z$` followed by numeric parameters. If the file is empty or contains an error message, the archive may not be encrypted — confirm with `7z l {input_file}` and check for an 'E' (encrypted) flag.",
            "5. Record the hash file: `sha256sum {output_file}`. This hash uniquely fingerprints the hash-extraction output for chain-of-custody.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Visually confirm the hash line begins with `$7z$` — any other prefix means a wrong tool or wrong archive format was used.",
            "Check that the hash was extracted from the correct archive: the filename prefix in the hash line must match `{input_file}`.",
            "Optionally validate the hash is parseable by John: `john --list=formats | grep 7z` — if the format appears, the John installation can process the hash.",
        ],
    },
    ForensicTool {
        name: "binwalk",
        aliases: &["binwalk"],
        category: ToolCategory::Carving,
        description: "A tool for analyzing, reverse-engineering, and extracting firmware images and binary blobs. It scans a file for embedded file signatures and can automatically carve out hidden files — JPEGs buried in a binary, zip archives concatenated onto an executable, entire filesystems embedded in firmware dumps.",
        typical_findings: &[
            "Embedded files that do not appear in directory listings",
            "Compressed blobs (gzip, LZMA, zlib) inside firmware images",
            "Filesystem images (squashfs, jffs2, cramfs) inside firmware",
            "Code signatures and encryption boundaries in stripped binaries",
        ],
        why_it_matters: "Evidence files often hide additional data that would never show up in a normal file listing — a JPEG appended to a document, a zip embedded in a PNG, malware payloads concatenated onto legitimate binaries. Binwalk is how you find data that was never meant to be found, which is frequently where the incriminating content lives.",
        feeds_into: &["exiftool", "file", "strings", "sha256sum", "7-Zip"],
        consumes_from: &[],
        reference: Some("https://github.com/ReFirmLabs/binwalk"),
        environment_setup: &[
            "binwalk is pre-installed on Kali Linux. Verify with: `binwalk --version`",
            "If missing, install with: `sudo apt-get install -y binwalk`",
            "For full extraction support (squashfs, LZMA, etc.), also install: `sudo apt-get install -y squashfs-tools jefferson sasquatch`",
        ],
        reproduction_steps: &[
            "1. Verify the input file has not changed: `sha256sum {input_file}`. Must equal {input_sha256}. Stop if they differ.",
            "2. Confirm the tool version matches: `binwalk --version`. Compare against recorded version {version}. Binwalk's signature database changes between releases — a newer version may find additional or different signatures.",
            "3. Run the original command exactly: `{command}`. The most common scan-only form is `binwalk {input_file}` and the extraction form is `binwalk -e {input_file}`. Check the original command for flags like `-M` (matryoshka/recursive), `-A` (opcode search), or `--dd` (custom extraction rule) and include them.",
            "4. If extraction was performed (`-e` or `-Me`), binwalk creates a directory named `_{input_file}.extracted` in the working directory. Confirm the same directory appears and that its contents match the original examiner's file listing.",
            "5. Hash every carved file in the extraction directory: `find _{input_file}.extracted -type f -exec sha256sum {} \\; | tee carved_hashes.txt`. Retain this file as a chain-of-custody artifact.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Confirm the scan output lists the same embedded file signatures (type, offset, description) as the original examiner's recorded output.",
            "Verify the extraction directory file count and file sizes match the original run — extra or missing files indicate a version or flag difference.",
            "If carved files differ, re-run with `--verbose` and compare offset-by-offset with the original log to identify where the divergence starts.",
        ],
    },
    ForensicTool {
        name: "ExifTool",
        aliases: &["exiftool", "exif", "exiftool.exe", "exiftool.pl"],
        category: ToolCategory::Metadata,
        description: "A command-line Perl application for reading, writing, and editing metadata in image, audio, video, PDF, and Office documents. Supports over 150 file formats and hundreds of metadata tags including EXIF, IPTC, XMP, GPS, maker notes, and document revision history.",
        typical_findings: &[
            "GPS coordinates and timestamps from images and videos",
            "Camera make/model, lens, and serial number",
            "Author, creator software, and last-modified metadata from Office documents and PDFs",
            "Document revision history and track-changes artifacts",
            "Hidden comments, custom XMP tags, and thumbnails that may differ from the visible image",
        ],
        why_it_matters: "Metadata is often the most direct link between a file and a person, place, or device. GPS coordinates in a photo can place a suspect at a scene; the 'Author' field of a Word document can identify who drafted it even after the filename is changed; camera serial numbers can be matched against devices in custody. Metadata is also the most commonly overlooked evidence because it is invisible in normal file viewers.",
        feeds_into: &["sha256sum"],
        consumes_from: &["7-Zip", "binwalk"],
        reference: Some("https://exiftool.org"),
        environment_setup: &[
            "ExifTool is pre-installed on Kali Linux. Verify with: `exiftool -ver`",
            "If missing, install with: `sudo apt-get install -y libimage-exiftool-perl`",
            "Version matters for metadata parsing: ExifTool adds support for new maker-note formats in nearly every release. Record the version with `exiftool -ver` at the time of the original run.",
        ],
        reproduction_steps: &[
            "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. Metadata output is deterministic for a given file — any byte-level difference will change some tag values.",
            "2. Confirm the ExifTool version: `exiftool -ver`. Compare against recorded version {version}. If the version differs by more than a patch release, note it — newer versions may parse additional tags or correct tag value interpretation.",
            "3. Run the original command: `{command}`. For a full metadata dump the typical form is `exiftool {input_file}` or `exiftool -j {input_file}` (JSON output). Include any flags the original examiner used (e.g., `-a` for duplicate tags, `-u` for unknown tags, `-G` for group names).",
            "4. If output was redirected to a file, replicate the redirection: `exiftool {input_file} > {output_file}`. Pitfall: line endings differ between platforms — if comparing on Windows, use `dos2unix` before diffing.",
            "5. Note any 'Unknown tag' or 'Missing required EXIF IFD' warnings — these are expected for some file types but should match the original run's warnings. Unexpected warnings may indicate a format or version difference.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Diff the tag list against the original examiner's ({operator}) output: key tags like GPSLatitude, CreateDate, Make, Model, and Author must be identical.",
            "Confirm GPS coordinates (if present) to at least 4 decimal places — rounding differences between ExifTool versions are rare but have occurred.",
            "Verify no tags present in the original output are missing from the reproduction — a missing tag may indicate a version difference or a file that has been sanitized.",
        ],
    },
    ForensicTool {
        name: "file",
        aliases: &["file", "file.exe"],
        category: ToolCategory::Identification,
        description: "A Unix utility that identifies a file's type by examining its magic bytes and internal structure — not by trusting its extension. Given a file with no extension, a wrong extension, or a deliberately-disguised extension, it will still tell you whether it is really a JPEG, a 7z archive, a PE executable, or something else entirely.",
        typical_findings: &[
            "Real file type when the extension is wrong or missing",
            "Compression format of an archive",
            "Architecture and target OS of a binary executable",
            "Text encoding of a document (UTF-8, UTF-16, ASCII)",
        ],
        why_it_matters: "Never trust an extension. Suspects rename .exe to .txt, .zip to .jpg, and .docx to .log to evade filters. The 'file' utility is the first step in triage — it tells you what you are actually looking at so you can pick the right follow-up tool. Running exiftool on a file that is actually a 7z archive wastes time; running 7z on a file that is actually an image produces garbage.",
        feeds_into: &["7-Zip", "exiftool", "binwalk", "strings", "xxd"],
        consumes_from: &[],
        reference: Some("https://darwinsys.com/file/"),
        environment_setup: &[
            "The `file` utility is pre-installed on Kali Linux. Verify with: `file --version`",
            "If missing, install with: `sudo apt-get install -y file`",
            "The `file` utility uses the libmagic database (`/usr/share/misc/magic.mgc`). The database version affects identification results — note it with `file --version`.",
        ],
        reproduction_steps: &[
            "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. The `file` utility reads magic bytes, so even a single-byte difference can change the output.",
            "2. Confirm the tool version and magic database: `file --version`. Compare against recorded version {version}. Different magic database versions may classify ambiguous files differently.",
            "3. Run the original command: `{command}`. The standard form is `file {input_file}`. If the original used `-k` (keep-going, show all matches), `-z` (try to look inside compressed files), or `-i` (MIME type output), include those flags.",
            "4. Record the exact output line. Pitfall: if the output says 'ASCII text' but the original said 'PE32 executable', a line-ending conversion or padding stripping may have changed the file — re-hash to confirm.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Confirm the identified file type exactly matches the original examiner's ({operator}) recorded output — a one-word difference (e.g., 'data' vs. '7-zip archive data') changes which tool should be used next.",
            "If the type differs from what the original run recorded, run `xxd {input_file} | head -4` to inspect the first 16 bytes directly and determine whether the file or the tool database has changed.",
        ],
    },
    ForensicTool {
        name: "John the Ripper",
        aliases: &["john", "john-the-ripper", "jtr", "john.exe"],
        category: ToolCategory::Password,
        description: "An open-source password security auditor and cracker. It performs dictionary, brute-force, and rule-based attacks against password hashes from a wide variety of sources — Unix /etc/shadow, Windows SAM, encrypted archives, PDF passwords, SSH keys, and many more. Commonly paired with format-specific helpers like 7z2john, pdf2john, and ssh2john.",
        typical_findings: &[
            "Cleartext passwords recovered from hashes",
            "Rejection of hashes in the wrong format (failure mode signaling a mismatched helper)",
            "Estimated crack time for a given wordlist and attack mode",
        ],
        why_it_matters: "Encrypted evidence is only evidence if you can decrypt it. A single recovered password often unlocks an entire case — an encrypted 7z becomes a trove of exfiltrated files, a PDF password yields a confidential memo, a recovered Windows password gives live access to the user's session. The pre-processing helper (7z2john, pdf2john, etc.) MUST match the container type, or John will churn through wordlists forever without finding the right answer.",
        feeds_into: &["7-Zip", "exiftool", "strings"],
        consumes_from: &["7z2john"],
        reference: Some("https://www.openwall.com/john/"),
        environment_setup: &[
            "John the Ripper is pre-installed on Kali Linux. Verify with: `john --version`",
            "If missing, install with: `sudo apt-get install -y john`",
            "For the Jumbo community build (more formats and rules): `sudo apt-get install -y john-data` or compile from https://github.com/openwall/john",
            "Confirm the wordlist used by the original examiner is available at the same path (commonly `/usr/share/wordlists/rockyou.txt`). Decompress if needed: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`",
        ],
        reproduction_steps: &[
            "1. Verify the hash input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. John operates on the hash — any corruption produces wrong or no candidates.",
            "2. Confirm John version: `john --version`. Compare against recorded version {version}. The Jumbo build and the stock build handle different format sets — mismatches mean John may not recognise the hash format at all.",
            "3. Run the exact original command: `{command}`. Typically: `john --wordlist=/path/to/wordlist --format=<format> {input_file}`. The `--format` flag is critical: if it was not specified in the original run, John auto-detects — reproduce that same auto-detection by also omitting it.",
            "4. After the run completes (or is interrupted), display cracked passwords: `john --show {input_file}`. The output must list the same password(s) the original examiner recorded. Pitfall: John writes a `.john/john.pot` pot file — if a previous run already cracked this hash, `--show` will report it even without running the attack again. Check `~/.john/john.pot` to confirm.",
            "5. If the same password is not recovered, verify the wordlist is identical (byte-for-byte) to the one the original examiner used and that the `--rules` flag (if any) matches exactly.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Confirm `john --show {input_file}` displays exactly the same cracked password(s) recorded by the original examiner ({operator}).",
            "Verify the recovered password successfully opens the target artifact (e.g., `7z e -p<recovered_password> archive.7z`) — this is the ultimate functional test.",
            "If the password is not reproduced, document the wordlist path, John version, format flag, and rule set used — these four variables determine reproducibility.",
        ],
    },
    ForensicTool {
        name: "sha256sum",
        aliases: &["sha256sum", "shasum", "sha256", "sha256sum.exe"],
        category: ToolCategory::Hashing,
        description: "A GNU coreutils utility that computes the SHA-256 cryptographic hash of a file. SHA-256 is the forensic-standard hash function for integrity verification: the same input always produces the same 64-character hex output, and any one-bit change produces a completely different hash.",
        typical_findings: &[
            "Unique SHA-256 fingerprint for each evidence file",
            "Proof that a file has not been altered between collection and analysis",
            "Identification of known files via hash databases (NSRL, VirusTotal)",
            "Duplicate detection across large evidence sets",
        ],
        why_it_matters: "Chain of custody requires proving that the evidence file you are analyzing today is byte-for-byte identical to the one you collected in the field. SHA-256 is the standard accepted by every court in the United States for that proof. Every evidence file should be hashed at collection, at ingest, and before every major analysis step — any mismatch invalidates downstream conclusions and must be investigated.",
        feeds_into: &[],
        consumes_from: &["7-Zip", "binwalk", "exiftool"],
        reference: Some("https://www.gnu.org/software/coreutils/"),
        environment_setup: &[
            "`sha256sum` is part of GNU coreutils and is pre-installed on every Kali Linux system. Verify with: `sha256sum --version`",
            "No installation step is required. If somehow missing: `sudo apt-get install -y coreutils`",
        ],
        reproduction_steps: &[
            "1. Run the original command exactly: `{command}`. The standard form is `sha256sum {input_file}`. Output is a 64-character hex digest followed by two spaces and the filename.",
            "2. Compare the computed hash against the recorded value {input_sha256}. They must be identical byte-for-byte. Any difference — even one character — means the file has changed and the chain of custody is broken.",
            "3. If the original command verified against a checksum file (e.g., `sha256sum -c hashes.txt`), reproduce that check: `sha256sum -c {input_file}`. 'OK' for each line means the files are intact.",
            "4. Record the output: `sha256sum {input_file} | tee {output_file}`. Pitfall: some systems default to BSD-style output (`SHA256 (file) = hash`) rather than GNU style (`hash  file`). Confirm which format the original examiner used — they are not interchangeable for automated verification.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "The 64-character hash in the output must exactly match {input_sha256} — character-for-character, no trailing spaces or newline differences.",
            "If verifying multiple files from a hash manifest, confirm all lines report 'OK' with zero failures.",
            "A mismatch is a chain-of-custody event, not a tool error — escalate before proceeding with any analysis that depends on this file.",
        ],
    },
    ForensicTool {
        name: "strings",
        aliases: &["strings", "strings.exe", "gnu-strings"],
        category: ToolCategory::Strings,
        description: "A GNU Binutils utility that scans a binary file for sequences of printable ASCII (and optionally Unicode) characters and prints them. In forensics it surfaces embedded URLs, filenames, error messages, email addresses, API keys, and other human-readable fragments that are otherwise invisible in a binary.",
        typical_findings: &[
            "URLs, domain names, and IP addresses embedded in malware",
            "Hardcoded paths, filenames, and registry keys",
            "API keys, passwords, and access tokens accidentally compiled in",
            "Error messages and debug symbols that reveal build environment and authorship",
            "Email addresses and contact strings",
        ],
        why_it_matters: "Binaries, memory dumps, and unknown file blobs often contain the smoking gun in plain text: a C2 domain, a command-line argument, a path that points to the attacker's workstation. Running 'strings' is a zero-cost first pass that frequently reveals leads days before deeper reverse engineering would. It is the forensic equivalent of 'grep for anything that looks like words'.",
        feeds_into: &["file", "sha256sum"],
        consumes_from: &["binwalk", "7-Zip"],
        reference: Some("https://www.gnu.org/software/binutils/"),
        environment_setup: &[
            "`strings` is part of GNU Binutils and is pre-installed on Kali Linux. Verify with: `strings --version`",
            "If missing, install with: `sudo apt-get install -y binutils`",
        ],
        reproduction_steps: &[
            "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. The `strings` output is deterministic for a given input — any difference in the file changes the output.",
            "2. Run the original command exactly: `{command}`. The typical form is `strings {input_file} > {output_file}`. Common flags to replicate: `-n <min_length>` (default 4), `-e` for encoding (`-e l` for 16-bit little-endian Unicode, `-e b` for big-endian), `-a` to scan the whole file (not just loaded sections for ELF/PE).",
            "3. If the original command did not include `-n`, the default minimum length is 4 characters. Shorter strings (e.g., `-n 8`) produce less noise but may miss evidence — replicate the original flag exactly.",
            "4. Confirm output file size is in the expected range: `wc -l {output_file}`. A much smaller or larger line count than the original run usually means a flag or encoding difference.",
            "5. Pitfall: on ELF/PE executables, `strings` by default only scans the data section. Use `-a` if the original examiner did — omitting it on a binary can miss strings in non-data sections by a large margin.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Confirm the line count (`wc -l {output_file}`) matches the original run — a significant difference indicates a flag mismatch.",
            "Spot-check 5-10 key strings the original examiner highlighted (URLs, paths, email addresses) and confirm they appear at the same relative positions in the output.",
            "If hashes do not match, diff the outputs: `diff <(sort {output_file}) <(sort original_output.txt)` to identify added or missing strings, then trace back to the flag or encoding difference.",
        ],
    },
    ForensicTool {
        name: "xxd",
        aliases: &["xxd", "xxd.exe"],
        category: ToolCategory::Hex,
        description: "A hex dump utility that shows the raw bytes of a file alongside their ASCII representation. Used for low-level inspection — examining file headers, confirming magic bytes, spotting patterns in encrypted data, and hand-editing binary files. Also performs the reverse (hex → binary) to reconstruct files.",
        typical_findings: &[
            "Magic bytes and file signatures at a file's start",
            "Padding patterns, cipher structure, and repeated blocks in encrypted data",
            "Anomalies in otherwise-normal binary structures",
            "Hidden content in file slack space or after end-of-file markers",
        ],
        why_it_matters: "When automated tools disagree about what a file is, xxd is how you settle it by reading the bytes yourself. It is also the last-resort tool when a file is so corrupted or unusual that no parser will touch it — you can still inspect the raw content and often recover enough to understand what happened. Essential for verifying the work of other tools: 'file said it is a JPEG, but xxd shows no FF D8 magic bytes — the extension is wrong, something is up.'",
        feeds_into: &["file", "strings", "sha256sum"],
        consumes_from: &["binwalk", "7-Zip"],
        reference: Some("https://linux.die.net/man/1/xxd"),
        environment_setup: &[
            "`xxd` ships with the vim package on Kali Linux and is pre-installed. Verify with: `xxd --version 2>&1 | head -1`",
            "If missing, install with: `sudo apt-get install -y xxd` (or `sudo apt-get install -y vim-common`)",
        ],
        reproduction_steps: &[
            "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. xxd output is byte-for-byte deterministic — any change to the file changes the dump.",
            "2. Run the original command exactly: `{command}`. The standard full-file form is `xxd {input_file} > {output_file}`. Replicate any flags: `-l <n>` (limit to first n bytes), `-s <offset>` (start at offset), `-c <cols>` (columns per line, default 16), `-p` (plain hex without ASCII column), `-e` (little-endian word groups).",
            "3. If only a header region was dumped (e.g., `xxd -l 64 {input_file}`), reproduce exactly that byte range — inspecting the wrong region is the most common reproduction mistake.",
            "4. For binary reconstruction (reverse mode, `xxd -r`), confirm the input hex file matches the original before running — a single garbled hex nibble will corrupt the output binary.",
            "5. Confirm output line count with `wc -l {output_file}`. Default format produces one line per 16 bytes, so a 512-byte file produces 32 lines.",
        ],
        verification_steps: &[
            "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
            "Confirm the first and last hex dump lines match the original examiner's ({operator}) recorded output — these anchor the byte-range and catch off-by-one errors in offset flags.",
            "Verify the magic bytes shown in the first line match the expected file type signature (e.g., `7z` archives start with `37 7a bc af 27 1c`, JPEG starts with `ff d8 ff`).",
            "If comparing a partial dump, confirm the `-l` and `-s` values match exactly — even a one-byte difference in start offset shifts every subsequent address and ASCII column.",
        ],
    },

    // Additional common forensic tools (extend as needed)
    ForensicTool {
        name: "Autopsy",
        aliases: &["autopsy"],
        category: ToolCategory::Filesystem,
        description: "An open-source digital forensics platform with a graphical interface that runs on top of The Sleuth Kit. Provides filesystem analysis, keyword search, timeline generation, registry parsing, web history, and much more from a single integrated UI. The de facto free alternative to commercial suites like EnCase and FTK.",
        typical_findings: &[
            "Recoverable deleted files",
            "Full filesystem timeline of creation/modification/access events",
            "Browser history, email, chat artifacts",
            "Keyword hits across the entire drive",
        ],
        why_it_matters: "Most cases start by pointing Autopsy at a disk image and letting it run overnight. It gives you a broad baseline across every standard artifact type before you pick which ones to drill into with specialized tools.",
        feeds_into: &["exiftool", "strings", "sha256sum"],
        consumes_from: &["FTK Imager", "dd"],
        reference: Some("https://www.autopsy.com"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Volatility",
        aliases: &["volatility", "vol.py", "vol"],
        category: ToolCategory::Memory,
        description: "An open-source memory forensics framework for analyzing RAM dumps from Windows, Linux, and Mac systems. Extracts running processes, network connections, loaded DLLs, registry hives in memory, command history, and in-memory malware that never touched disk.",
        typical_findings: &[
            "Running processes including hidden or injected code",
            "Network connections at the time of the dump",
            "Cleartext passwords and encryption keys in memory",
            "In-memory-only malware payloads",
        ],
        why_it_matters: "A memory dump captures what was happening at a single moment — processes the user killed, network connections they closed, and passwords never written to disk. If you have a live system suspected of compromise, memory is often where the evidence is because mature attackers go to great lengths to leave nothing on disk.",
        feeds_into: &["strings", "sha256sum"],
        consumes_from: &[],
        reference: Some("https://www.volatilityfoundation.org"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Wireshark",
        aliases: &["wireshark", "tshark"],
        category: ToolCategory::Network,
        description: "The standard open-source network protocol analyzer. Captures live network traffic or opens saved .pcap/.pcapng files and dissects every packet at every protocol layer. Includes follow-stream views, statistics, and a Lua scripting engine for custom dissectors.",
        typical_findings: &[
            "Reconstructed HTTP/FTP/SMTP conversations including file transfers",
            "DNS queries revealing domains visited",
            "TLS handshakes and SNI fields showing destination even when payload is encrypted",
            "Beaconing patterns consistent with C2 traffic",
        ],
        why_it_matters: "Network captures are the only evidence that tells you what actually traversed the wire. Host-based artifacts can be altered; a pcap from an out-of-band collector cannot. Wireshark turns raw packets into a reconstructed narrative of what the suspect's machine talked to, when, and with what content.",
        feeds_into: &["sha256sum", "strings"],
        consumes_from: &[],
        reference: Some("https://www.wireshark.org"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "FTK Imager",
        aliases: &["ftk imager", "ftkimager", "ftk_imager"],
        category: ToolCategory::DiskImaging,
        description: "A free disk imaging and triage tool from AccessData (now Exterro). Creates forensically-sound bit-for-bit images of physical disks and logical volumes in E01 or raw .dd format with automatic MD5/SHA-1 hashing for integrity verification. Also mounts images read-only for preview.",
        typical_findings: &[
            "Complete bit-for-bit disk image in E01 or .dd format",
            "MD5 and SHA-1 hashes computed during acquisition",
            "Preview of filesystem contents including deleted files",
        ],
        why_it_matters: "Every on-disk investigation begins with imaging. Working from an image rather than the live disk is a fundamental forensic principle: it is repeatable, preserves the original, and protects chain of custody. FTK Imager is the most commonly-used free tool for this step.",
        feeds_into: &["Autopsy", "sha256sum"],
        consumes_from: &[],
        reference: Some("https://www.exterro.com/ftk-imager"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "dd",
        aliases: &["dd", "dcfldd", "dc3dd"],
        category: ToolCategory::DiskImaging,
        description: "A Unix utility that copies data byte-for-byte between files or devices. The forensic variants dcfldd and dc3dd add on-the-fly hashing, logging, and progress reporting. Used to create raw (.dd) disk images from physical media.",
        typical_findings: &[
            "Raw disk image identical to the source device",
            "SHA-256 hash of the captured data (when using forensic variants)",
            "Acquisition log with timestamps and block counts",
        ],
        why_it_matters: "When you need a raw image and cannot boot a GUI imager, dd is the fallback that always works. It is the most portable imaging tool in existence, runs on any Unix-like system, and is the format most other tools accept without complaint.",
        feeds_into: &["Autopsy", "sha256sum"],
        consumes_from: &[],
        reference: None,
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "hashcat",
        aliases: &["hashcat"],
        category: ToolCategory::Password,
        description: "A GPU-accelerated password recovery tool. Supports 300+ hash formats and executes dictionary, mask, rule-based, and hybrid attacks on NVIDIA or AMD hardware. Generally faster than John the Ripper for raw brute-forcing; both tools use the same .hash-format input.",
        typical_findings: &[
            "Cleartext passwords recovered via GPU-accelerated attack",
            "Attack-mode timing and candidate-throughput statistics",
        ],
        why_it_matters: "When John is too slow, hashcat is the upgrade: a modern consumer GPU can test tens of billions of candidates per second against a fast hash. It is the tool of choice for large wordlists or long password spaces.",
        feeds_into: &["7-Zip"],
        consumes_from: &["7z2john"],
        reference: Some("https://hashcat.net"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Sleuth Kit",
        aliases: &["sleuthkit", "sleuth kit", "tsk", "fls", "icat", "fsstat", "mmls", "tsk_recover"],
        category: ToolCategory::Filesystem,
        description: "A command-line suite of filesystem analysis tools (fls, icat, fsstat, mmls, tsk_recover, etc.) that form the engine Autopsy is built on. Works at the file, inode, and block level to recover deleted files, parse filesystems, and extract timeline data.",
        typical_findings: &[
            "Deleted file recovery from unallocated space",
            "Full MAC-time timeline of every filesystem entry",
            "File content recovered directly from inode/block references",
        ],
        why_it_matters: "When Autopsy's GUI is too slow or the system is headless, the underlying Sleuth Kit commands do the same work from a shell and can be scripted. Essential for scripted or large-scale filesystem analysis.",
        feeds_into: &["exiftool", "sha256sum", "strings"],
        consumes_from: &["FTK Imager", "dd"],
        reference: Some("https://www.sleuthkit.org"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "RegRipper",
        aliases: &["regripper", "rip.pl", "rip.exe"],
        category: ToolCategory::Registry,
        description: "An open-source Windows registry parser written in Perl. Runs a library of plugins against NTUSER.DAT, SOFTWARE, SYSTEM, and SECURITY hives to extract user activity, installed software, USB device history, run/runonce entries, and hundreds of other artifacts.",
        typical_findings: &[
            "USB devices plugged into the system and when",
            "Recently opened documents and typed paths",
            "Installed software and autorun entries",
            "Network configuration and wireless SSIDs",
        ],
        why_it_matters: "The Windows registry is a rich, often-underused evidence source. RegRipper turns raw hive files into human-readable reports and is one of the fastest ways to answer 'what did this user do on this machine?'",
        feeds_into: &[],
        consumes_from: &["Autopsy", "FTK Imager"],
        reference: Some("https://github.com/keydet89/RegRipper3.0"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "plaso / log2timeline",
        aliases: &["plaso", "log2timeline", "log2timeline.py", "psort"],
        category: ToolCategory::Timeline,
        description: "A Python-based super-timeline engine that extracts timestamped events from hundreds of artifact types (filesystem, registry, browser history, Windows event logs, etc.) and merges them into a single unified timeline stored in a Plaso database file.",
        typical_findings: &[
            "Merged timeline across filesystem, registry, browser, and event-log sources",
            "Event correlation revealing what happened in what order",
            "Gaps suggesting log deletion or time manipulation",
        ],
        why_it_matters: "A super-timeline is often the only view where the story of an incident becomes visible — a filesystem event on its own means nothing, but seeing it next to a registry write, a browser visit, and a PowerShell launch a second later tells you exactly what happened.",
        feeds_into: &[],
        consumes_from: &["Autopsy", "Sleuth Kit", "RegRipper"],
        reference: Some("https://plaso.readthedocs.io"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "YARA",
        aliases: &["yara"],
        category: ToolCategory::Malware,
        description: "A pattern-matching engine for malware identification. Rules describe byte sequences, strings, and structural features; YARA scans files, processes, or memory dumps and reports every match. The de facto standard for sharing malware signatures between analysts.",
        typical_findings: &[
            "Matches against known malware families",
            "Custom indicators of compromise defined per-case",
            "Suspicious strings and code patterns in unknown binaries",
        ],
        why_it_matters: "YARA is how you go from 'I think this might be malware' to 'this is tracked as APT28 sample X from 2022'. The rule ecosystem is enormous and the scan is fast — running a YARA pass on every binary in an image is cheap and high-signal.",
        feeds_into: &["strings"],
        consumes_from: &[],
        reference: Some("https://virustotal.github.io/yara/"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "steghide",
        aliases: &["steghide"],
        category: ToolCategory::Stego,
        description: "A steganography tool that embeds and extracts hidden payloads inside JPEG, BMP, WAV, and AU files. Uses a password to encrypt the payload before embedding.",
        typical_findings: &[
            "Hidden payloads inside otherwise-innocent media files",
            "Password-protected extraction candidates",
        ],
        why_it_matters: "When exfiltrated data is not in the obvious places, suspects sometimes hide it inside images or audio files using steganography. Steghide is the first tool to try because it is the most commonly-used implementation.",
        feeds_into: &["file", "exiftool", "strings"],
        consumes_from: &[],
        reference: None,
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },

    // ───── OSINT tools (added for Persons + Agent Zero OSINT feature) ─────
    ForensicTool {
        name: "Sherlock",
        aliases: &["sherlock", "sherlock.py"],
        category: ToolCategory::Osint,
        description: "A Python tool that hunts a given username across 300+ social network, forum, and web service sites. For each site it checks whether an account with the username exists and returns the full profile URL if found. The de facto standard for OSINT username enumeration.",
        typical_findings: &[
            "Social media profiles matching a suspect's username",
            "Forum and developer community accounts (GitHub, Reddit, Stack Overflow, etc.)",
            "Dating, shopping, gaming, and other niche site accounts",
            "Username reuse patterns across unrelated services",
        ],
        why_it_matters: "People reuse usernames across dozens of services without realizing it. A single handle often opens the door to a suspect's entire online footprint — personal email addresses, employer info, public posts, photographs, friend networks, even real names. Sherlock is the fastest way to turn a username into a complete OSINT pivot.",
        feeds_into: &["WhatsMyName", "theHarvester", "SpiderFoot"],
        consumes_from: &[],
        reference: Some("https://github.com/sherlock-project/sherlock"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "holehe",
        aliases: &["holehe"],
        category: ToolCategory::Osint,
        description: "A Python OSINT tool that takes an email address and checks which of 120+ major websites have an account registered with it — without sending any login attempts or password-reset emails. Uses site-specific APIs and silent existence checks so the target never learns they were looked up.",
        typical_findings: &[
            "Websites where an email is registered (Instagram, Twitter, Imgur, Spotify, etc.)",
            "Unexpected account presence suggesting hidden online activity",
            "Confirmation or denial of email ownership across major services",
        ],
        why_it_matters: "Holehe answers the question 'what does this person use this email for?' without tipping them off. Because it never sends password-reset emails or login attempts, the suspect does not receive any notification. Essential for covert OSINT where operational security matters.",
        feeds_into: &["Sherlock", "WhatsMyName", "theHarvester", "SpiderFoot"],
        consumes_from: &[],
        reference: Some("https://github.com/megadose/holehe"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "theHarvester",
        aliases: &["theharvester", "theharvester.py", "harvester"],
        category: ToolCategory::Osint,
        description: "An open-source reconnaissance tool that gathers emails, subdomains, hosts, employee names, open ports, and banners from public sources (search engines, LinkedIn, Shodan, DuckDuckGo, crt.sh, Bing, Yahoo, VirusTotal, and many more). One of the oldest and most reliable OSINT collection tools.",
        typical_findings: &[
            "Email addresses associated with a target domain",
            "Subdomains discoverable via passive DNS + certificate transparency",
            "Employees named on LinkedIn and public company pages",
            "Host fingerprints and open ports from Shodan",
        ],
        why_it_matters: "Given a domain or company name, theHarvester returns an entire starting OSINT map: who works there, what external-facing assets exist, and what their email patterns look like. This is the foundation for social engineering reconnaissance, phishing investigations, and understanding an organization's attack surface.",
        feeds_into: &["Amass", "Recon-ng", "SpiderFoot", "holehe"],
        consumes_from: &[],
        reference: Some("https://github.com/laramies/theHarvester"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "SpiderFoot",
        aliases: &["spiderfoot", "sf.py", "spiderfoot-cli"],
        category: ToolCategory::Osint,
        description: "An open-source OSINT automation framework with over 200 modules for gathering information from 100+ public data sources. Accepts any target type (IP, domain, email, name, username, phone, BTC address) and automatically runs relevant modules to build a full intelligence profile. The most comprehensive OSINT tool in the Kali ecosystem.",
        typical_findings: &[
            "Full intelligence profile across every relevant OSINT source",
            "Cross-source correlation (e.g. email → breach database → username → social)",
            "Threat-intelligence hits against malware, botnet, and blocklist feeds",
            "Certificate transparency, DNS history, and web archive records",
            "Dark-web mentions and paste-site leaks (when configured with API keys)",
        ],
        why_it_matters: "SpiderFoot is the orchestrator of OSINT tools. Rather than running Sherlock, holehe, theHarvester, Amass, etc. individually and correlating the output by hand, SpiderFoot runs them together and pivots from any finding to the next logical query automatically. For a serious OSINT investigation this is the tool that ties every other source together.",
        feeds_into: &[],
        consumes_from: &["Sherlock", "holehe", "theHarvester", "Amass"],
        reference: Some("https://www.spiderfoot.net"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Recon-ng",
        aliases: &["recon-ng", "recon-ng.py"],
        category: ToolCategory::Osint,
        description: "A full-featured web-reconnaissance framework written in Python. Modular like Metasploit — hundreds of modules are organized by data type (hosts, contacts, credentials, leaked accounts) and the user loads them one at a time to build up a SQLite workspace of OSINT findings.",
        typical_findings: &[
            "Structured workspace linking hosts, contacts, vulnerabilities, and credentials",
            "Domain enumeration, whois records, and DNS history",
            "Employee contact scraping from LinkedIn and other social sources",
            "Leaked credentials from public breach databases",
        ],
        why_it_matters: "When an investigation is going to produce a lot of OSINT data, Recon-ng's structured workspace is where you keep it organized. Unlike single-purpose tools, it accumulates findings into a database you can query, export, and hand off. Preferred by investigators who want an auditable trail of every OSINT query they ran.",
        feeds_into: &["SpiderFoot"],
        consumes_from: &["theHarvester"],
        reference: Some("https://github.com/lanmaster53/recon-ng"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "WhatsMyName",
        aliases: &["whatsmyname", "whatsmyname.py", "wmn"],
        category: ToolCategory::Osint,
        description: "A community-maintained username enumeration tool that checks 500+ websites for account existence. Larger site list than Sherlock, updated more frequently, and maintained with direct contributions from the OSINT community.",
        typical_findings: &[
            "Account presence across a broader site list than Sherlock covers",
            "Newly-added niche sites that other tools have not caught up to",
            "Cross-corroboration of Sherlock results",
        ],
        why_it_matters: "Running WhatsMyName AFTER Sherlock is standard OSINT practice — the lists overlap but each catches sites the other misses. Together they produce the broadest possible username enumeration.",
        feeds_into: &["SpiderFoot"],
        consumes_from: &["Sherlock"],
        reference: Some("https://github.com/WebBreacher/WhatsMyName"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Amass",
        aliases: &["amass"],
        category: ToolCategory::Osint,
        description: "OWASP's in-depth network-mapping and attack-surface discovery tool. Performs passive and active DNS enumeration, ASN discovery, certificate transparency scraping, and subdomain brute-forcing to map the full external footprint of an organization.",
        typical_findings: &[
            "Complete subdomain list via certificate transparency, DNS brute-force, and passive scraping",
            "ASN and IP range ownership attribution",
            "Related domains sharing the same SSL certificate or registrant",
            "DNS history showing how an organization's infrastructure evolved",
        ],
        why_it_matters: "For any investigation of an organization or domain, Amass is the authoritative subdomain enumerator. Knowing every public-facing host an organization owns is the foundation for every subsequent network or application-layer investigation.",
        feeds_into: &["SpiderFoot"],
        consumes_from: &["theHarvester"],
        reference: Some("https://github.com/owasp-amass/amass"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Maltego CE",
        aliases: &["maltego", "maltego ce", "maltego-ce"],
        category: ToolCategory::Osint,
        description: "A graphical link-analysis tool for OSINT. Represents entities (people, emails, domains, companies, phone numbers) as nodes and runs 'Transforms' that query public and commercial data sources to enrich them. The Community Edition is free and ships in Kali.",
        typical_findings: &[
            "Visual link graphs showing relationships between people, domains, and emails",
            "Enrichment from public WHOIS, DNS, social, and corporate registries",
            "Pivot paths that reveal hidden connections (same phone number, shared addresses, etc.)",
        ],
        why_it_matters: "Some OSINT findings are only obvious visually — a cluster of three people sharing an address, a phone number used by two companies, a domain registered to a shell entity that links back to the suspect. Maltego's graph view surfaces these patterns in ways text-output tools cannot.",
        feeds_into: &[],
        consumes_from: &["theHarvester", "Sherlock"],
        reference: Some("https://www.maltego.com"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Photon",
        aliases: &["photon", "photon.py"],
        category: ToolCategory::Osint,
        description: "A fast web crawler designed for OSINT. Crawls a target domain and extracts URLs, email addresses, JavaScript files, external links, social media handles, and document files. Much faster than general-purpose crawlers because it knows what OSINT investigators want.",
        typical_findings: &[
            "Every internal URL on a target website",
            "Email addresses embedded in pages, comments, and mailto: links",
            "Document file URLs (PDF, DOCX, XLS) for metagoofil follow-up",
            "External links pointing to social media profiles",
        ],
        why_it_matters: "Manual browsing of a target website misses most of the OSINT-relevant content. Photon sweeps the whole site in seconds and produces a structured list of every email, document, and external link — far more than an investigator could find by clicking.",
        feeds_into: &["metagoofil", "theHarvester", "holehe"],
        consumes_from: &[],
        reference: Some("https://github.com/s0md3v/Photon"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "metagoofil",
        aliases: &["metagoofil", "metagoofil.py"],
        category: ToolCategory::Osint,
        description: "An OSINT tool that uses search engines to find public documents on a target domain (PDF, DOC, XLS, PPT, ODT, etc.), downloads them, and extracts embedded metadata via ExifTool. Effectively weaponizes document metadata for open-source investigation.",
        typical_findings: &[
            "Author names embedded in published PDFs and Office documents",
            "Internal usernames and workstation identifiers in file metadata",
            "Software versions used by the organization",
            "Network paths and printer names revealing internal infrastructure",
        ],
        why_it_matters: "Every PDF and Word document published on a company's website leaks metadata about the person who created it. Metagoofil automates what would otherwise be a tedious manual process and often produces the single most valuable OSINT data point in an investigation: a real employee's username or internal network path.",
        feeds_into: &["ExifTool", "Recon-ng"],
        consumes_from: &["Photon"],
        reference: Some("https://github.com/opsdisk/metagoofil"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "dnsrecon",
        aliases: &["dnsrecon", "dnsrecon.py"],
        category: ToolCategory::Osint,
        description: "A DNS enumeration tool that queries a target domain's DNS records through multiple techniques: standard record lookups, zone transfers, brute-force subdomain discovery from a wordlist, reverse lookups on IP ranges, and SRV record probes.",
        typical_findings: &[
            "Complete DNS record set (A, AAAA, MX, NS, SOA, TXT, SPF, DMARC)",
            "Subdomains discovered via wordlist brute-force",
            "Mail server infrastructure and spam-filter configuration",
            "Historical DNS records via reverse lookup",
        ],
        why_it_matters: "DNS is often the most revealing public record about an organization. dnsrecon pulls every interesting DNS artifact in a single run and is the baseline for any subdomain or mail-infrastructure investigation.",
        feeds_into: &["Amass", "Recon-ng", "SpiderFoot"],
        consumes_from: &[],
        reference: Some("https://github.com/darkoperator/dnsrecon"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "fierce",
        aliases: &["fierce", "fierce.pl"],
        category: ToolCategory::Osint,
        description: "A DNS reconnaissance tool focused on locating non-contiguous IP space owned by a target. Walks DNS records, tries zone transfers, and scans surrounding IPs to find hosts that would otherwise be missed by standard enumeration.",
        typical_findings: &[
            "IP ranges owned by the target not discoverable via ASN lookup alone",
            "Hosts on adjacent IPs sharing naming conventions",
            "Hidden or internal subdomains exposed via zone transfer",
        ],
        why_it_matters: "Complements dnsrecon and Amass — where those focus on name-based discovery, fierce finds IP-based neighbors. Together they produce the most complete network-layer footprint of a target.",
        feeds_into: &["Amass"],
        consumes_from: &[],
        reference: None,
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "FinalRecon",
        aliases: &["finalrecon", "finalrecon.py"],
        category: ToolCategory::Osint,
        description: "An all-in-one web reconnaissance tool combining header inspection, WHOIS, DNS lookup, SSL certificate analysis, crawler, traceroute, directory enumeration, subdomain scan, and WAF fingerprinting into a single command. Useful when you want a fast baseline picture of any website.",
        typical_findings: &[
            "HTTP headers revealing web server, framework, and security posture",
            "WHOIS registration details",
            "SSL certificate chain and validity",
            "Detected WAF and CDN",
            "Site directory structure (common paths)",
        ],
        why_it_matters: "When an investigator needs a quick snapshot of an unknown target website, FinalRecon produces in 30 seconds what would take five separate tools and a lot of manual correlation. Not deep, but fast and complete enough to decide which areas deserve deeper follow-up.",
        feeds_into: &["Amass", "theHarvester"],
        consumes_from: &[],
        reference: Some("https://github.com/thewhiteh4t/FinalRecon"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "Shodan CLI",
        aliases: &["shodan", "shodan-cli"],
        category: ToolCategory::Osint,
        description: "The command-line client for Shodan, the search engine for internet-connected devices. Queries Shodan's index of IoT, industrial, and server devices by IP, port, service banner, location, or CVE. Requires an API key (free tier available, paid for heavier use).",
        typical_findings: &[
            "Exposed services and open ports on a target IP",
            "Running software versions and known vulnerabilities",
            "Geolocation and ISP attribution",
            "Historical service banners showing when vulnerabilities were present",
            "Related devices on the same network or owned by the same organization",
        ],
        why_it_matters: "Shodan is the ground-truth source for what is actually reachable from the public internet at a given IP or organization. For any investigation involving an IP address, Shodan reveals exposed infrastructure the target may not even know they have running.",
        feeds_into: &["SpiderFoot"],
        consumes_from: &[],
        reference: Some("https://cli.shodan.io"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "EagleEye",
        aliases: &["eagleeye"],
        category: ToolCategory::Osint,
        description: "A reverse image search tool that takes a photo of a person and searches for matching faces across Facebook, Instagram, Twitter, VK, and other public profile sources. Combines facial recognition with OSINT scraping to identify people from a single photograph.",
        typical_findings: &[
            "Social media profiles containing the same person's face",
            "Name associated with a previously anonymous photograph",
            "Related profile URLs and aliases",
        ],
        why_it_matters: "When an investigation starts with a photograph of an unknown person, EagleEye is the tool that turns that image into a name and a social profile. High-impact, but also requires careful use — facial-recognition OSINT is ethically and legally sensitive and investigators must verify jurisdiction-specific rules before running it.",
        feeds_into: &["Sherlock", "holehe"],
        consumes_from: &["ExifTool"],
        reference: Some("https://github.com/ThoughtfulDev/EagleEye"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
    ForensicTool {
        name: "OSINT-SPY",
        aliases: &["osint-spy", "osintspy"],
        category: ToolCategory::Osint,
        description: "A Python OSINT tool that aggregates searches across email, domain, IP, device, and bitcoin-address data sources into a single command. Useful for quick lookups when you don't need the full depth of SpiderFoot or Recon-ng.",
        typical_findings: &[
            "Quick summary intel about an email, domain, or IP",
            "Malware and bitcoin-address reputation",
            "Associated accounts from breached databases",
        ],
        why_it_matters: "A lightweight 'middle ground' between running a single specialized tool and running SpiderFoot's full orchestration. Good for quick triage when you're not sure whether a target deserves deeper investigation.",
        feeds_into: &["SpiderFoot"],
        consumes_from: &[],
        reference: Some("https://github.com/SharadKumar97/OSINT-SPY"),
        environment_setup: &[],
        reproduction_steps: &[],
        verification_steps: &[],
    },
];

// ─── Lookup ───────────────────────────────────────────────────────────────────

/// Normalize a tool name for fuzzy matching — lowercase, trim, strip `.exe`.
fn normalize(name: &str) -> String {
    let mut s = name.trim().to_lowercase();
    if let Some(stripped) = s.strip_suffix(".exe") {
        s = stripped.to_owned();
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Case-insensitive, alias-aware lookup. Returns a reference to the matching
/// `ForensicTool` or `None` if nothing matches.
///
/// Tries in order: exact name, exact alias, then prefix-match (handles
/// `exiftool-13.50`, `john-1.9.0`, etc.)
pub fn lookup(name: &str) -> Option<&'static ForensicTool> {
    if name.trim().is_empty() {
        return None;
    }
    let n = normalize(name);

    // 1. Exact canonical name
    for t in TOOLS {
        if normalize(t.name) == n {
            return Some(t);
        }
    }
    // 2. Exact alias
    for t in TOOLS {
        if t.aliases.iter().any(|a| normalize(a) == n) {
            return Some(t);
        }
    }
    // 3. Prefix match — `exiftool-13.50` -> `exiftool`, etc.
    for t in TOOLS {
        let cn = normalize(t.name);
        if !cn.is_empty() && n.starts_with(&cn) {
            return Some(t);
        }
        if t.aliases.iter().any(|a| {
            let an = normalize(a);
            !an.is_empty() && n.starts_with(&an)
        }) {
            return Some(t);
        }
    }
    None
}

/// Returns the subset of `case_tool_names` that `tool` feeds into,
/// each resolved to its canonical display name from the KB (or the raw
/// case tool name if unknown). Deduped in input order.
///
/// Matching is strict: two tools match only if they resolve to the SAME
/// canonical KB entry via `lookup()`, or (for unknown tools) if their
/// normalized strings are equal. Prefix matching is deliberately NOT used
/// here — it lives only in `lookup()` for one-tool-to-one-KB resolution.
/// Allowing prefix matches at this layer causes false positives like
/// `"7z2john".starts_with("7z")` matching "7z" as its own dependent.
pub fn dependents_in_case(
    tool: &ForensicTool,
    case_tool_names: &[String],
) -> Vec<(String, Option<&'static ForensicTool>)> {
    resolve_chain(tool.feeds_into, case_tool_names)
}

/// Returns the subset of `case_tool_names` this tool consumes from.
pub fn prerequisites_in_case(
    tool: &ForensicTool,
    case_tool_names: &[String],
) -> Vec<(String, Option<&'static ForensicTool>)> {
    resolve_chain(tool.consumes_from, case_tool_names)
}

/// Shared dependency-chain resolver: for each name in `targets`, find the
/// case tools that match (same canonical KB entry, or same normalized string
/// if neither is in the KB).
fn resolve_chain(
    targets: &'static [&'static str],
    case_tool_names: &[String],
) -> Vec<(String, Option<&'static ForensicTool>)> {
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<(String, Option<&'static ForensicTool>)> = Vec::new();
    for target in targets {
        let target_tool = lookup(target);
        let target_norm = normalize(target);
        for case_name in case_tool_names {
            if seen.iter().any(|s| s == case_name) {
                continue;
            }
            let case_tool = lookup(case_name);
            let case_norm = normalize(case_name);
            let is_match = match (target_tool, case_tool) {
                (Some(t), Some(c)) => t.name == c.name,
                _ => case_norm == target_norm,
            };
            if is_match {
                seen.push(case_name.clone());
                out.push((case_name.clone(), case_tool));
            }
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_exact_name() {
        assert_eq!(lookup("7-Zip").map(|t| t.name), Some("7-Zip"));
        assert_eq!(lookup("ExifTool").map(|t| t.name), Some("ExifTool"));
    }

    #[test]
    fn lookup_alias_case_insensitive() {
        assert_eq!(lookup("exiftool").map(|t| t.name), Some("ExifTool"));
        assert_eq!(lookup("EXIFTOOL").map(|t| t.name), Some("ExifTool"));
        assert_eq!(lookup("7z").map(|t| t.name), Some("7-Zip"));
        assert_eq!(lookup("john").map(|t| t.name), Some("John the Ripper"));
        assert_eq!(lookup("jtr").map(|t| t.name), Some("John the Ripper"));
    }

    #[test]
    fn lookup_strips_exe_suffix() {
        assert_eq!(lookup("exiftool.exe").map(|t| t.name), Some("ExifTool"));
        assert_eq!(lookup("7z.exe").map(|t| t.name), Some("7-Zip"));
    }

    #[test]
    fn lookup_prefix_match_handles_version_suffix() {
        assert_eq!(lookup("exiftool-13.50").map(|t| t.name), Some("ExifTool"));
        assert_eq!(lookup("john-1.9.0").map(|t| t.name), Some("John the Ripper"));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup("nosuchtool").is_none());
        assert!(lookup("").is_none());
        assert!(lookup("   ").is_none());
    }

    #[test]
    fn dependents_filter_resolves_only_case_tools() {
        let case: Vec<String> = vec!["7z".into(), "7z2john".into(), "john".into()];
        let seven_zip = lookup("7z").expect("7z must exist");
        let deps = dependents_in_case(seven_zip, &case);
        // 7-Zip feeds into 7z2john, exiftool, file, sha256sum, strings, binwalk
        // Only 7z2john is in the case list, so only that should come back.
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "7z2john");
    }

    #[test]
    fn prerequisites_resolve_consumes_from() {
        let case: Vec<String> = vec!["7z".into(), "7z2john".into(), "john".into()];
        let john = lookup("john").expect("john must exist");
        let prereqs = prerequisites_in_case(john, &case);
        // John consumes from 7z2john
        assert_eq!(prereqs.len(), 1);
        assert_eq!(prereqs[0].0, "7z2john");
    }

    #[test]
    fn every_tool_has_nonempty_description() {
        for t in TOOLS {
            assert!(!t.description.is_empty(), "tool {} has empty description", t.name);
            assert!(!t.why_it_matters.is_empty(), "tool {} has empty why_it_matters", t.name);
        }
    }
}
