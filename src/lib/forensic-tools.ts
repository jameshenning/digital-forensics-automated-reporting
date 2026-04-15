/**
 * Forensic tool knowledge base.
 *
 * Each entry describes a commonly-used digital-forensics tool so the Tools
 * panel can render a proper narrative — what the tool is, what it typically
 * finds, why it matters, and which other tools it commonly feeds into.
 *
 * Lookups are alias-aware (case-insensitive) and handle common suffixes like
 * ".exe" and GNU version prefixes. Dependency chaining ("feeds into") is
 * resolved against the tool list of the CURRENT case so the UI can show
 * clickable chips linking related tool rows.
 *
 * Add new tools freely — the lookup is forgiving, and unknown tools fall back
 * to a generic narrative built from the user-recorded purpose + command.
 */

export type ToolCategory =
  | "hashing"
  | "metadata"
  | "archive"
  | "carving"
  | "password"
  | "hex"
  | "identification"
  | "strings"
  | "disk-imaging"
  | "filesystem"
  | "memory"
  | "network"
  | "timeline"
  | "registry"
  | "malware"
  | "mobile"
  | "email"
  | "web"
  | "stego"
  | "osint";

export interface ForensicTool {
  /** Canonical display name. */
  name: string;
  /** Lowercase aliases matched against the user-recorded tool_name field. */
  aliases: string[];
  category: ToolCategory;
  /** One-paragraph description of what the tool is and what it does. */
  description: string;
  /** Bullet list of what this tool typically finds. */
  typicalFindings: string[];
  /** Why it matters in a forensic investigation. */
  whyItMatters: string;
  /** Tool names this one commonly feeds into (for dependency chaining). */
  feedsInto: string[];
  /** Tool names this one commonly consumes output from. */
  consumesFrom: string[];
  /** Optional reference URL. */
  reference?: string;
  // ─── Reproducibility (added for the second-examiner workflow) ─────────
  /**
   * Shell commands a reproducing examiner runs ONCE before the tool can
   * be invoked. Usually package installs or venv activation. Empty array
   * if no setup is needed.
   */
  environmentSetup: string[];
  /**
   * Ordered reproduction steps with placeholder substitution. Supported
   * placeholders: {input_file}, {output_file}, {command}, {version},
   * {operator}, {input_sha256}, {output_sha256}. Unknown placeholders
   * are left literal so reviewers see the gap.
   */
  reproductionSteps: string[];
  /**
   * How the reproducing examiner verifies they got the same result.
   * Usually instructions to SHA-256 the output and compare with the
   * recorded {output_sha256}.
   */
  verificationSteps: string[];
}

// ---------------------------------------------------------------------------
// Category labels for UI
// ---------------------------------------------------------------------------

export const CATEGORY_LABEL: Record<ToolCategory, string> = {
  hashing: "Hash verification",
  metadata: "Metadata extraction",
  archive: "Archive / compression",
  carving: "File carving",
  password: "Password cracking",
  hex: "Hex inspection",
  identification: "File identification",
  strings: "String extraction",
  "disk-imaging": "Disk imaging",
  filesystem: "Filesystem analysis",
  memory: "Memory forensics",
  network: "Network forensics",
  timeline: "Timeline analysis",
  registry: "Registry analysis",
  malware: "Malware analysis",
  mobile: "Mobile forensics",
  email: "Email forensics",
  web: "Web history",
  stego: "Steganography",
  osint: "OSINT",
};

// ---------------------------------------------------------------------------
// Knowledge base
// ---------------------------------------------------------------------------

const TOOLS: ForensicTool[] = [
  // ───── Tools present in the user's v1 data ─────
  {
    name: "7-Zip",
    aliases: ["7z", "7zip", "7-zip", "7z.exe", "p7zip"],
    category: "archive",
    description:
      "Open-source file archiver with a high compression ratio. In forensics it is used to open suspect .7z, .zip, .rar, .iso, and .tar archives recovered from evidence, including archives that may be password-protected or damaged.",
    typicalFindings: [
      "Contents of compressed archives (documents, images, executables)",
      "Archive header metadata including create time and creator software",
      "Detection of password-protected or encrypted archives",
      "Unexpected nested archives (common for exfiltration staging)",
    ],
    whyItMatters:
      "Suspects commonly stage exfiltrated data inside compressed archives to hide it, bypass automated filters, or slip it past DLP. Being able to open them — or confirm that they are password-protected — is the gate to the rest of the investigation.",
    feedsInto: ["7z2john", "exiftool", "file", "sha256sum", "strings", "binwalk"],
    consumesFrom: [],
    reference: "https://7-zip.org",
    environmentSetup: [
      "7-Zip (p7zip) is pre-installed on Kali Linux. Verify with: `7z --help | head -2`",
      "If missing, install with: `sudo apt-get install -y p7zip-full p7zip-rar`",
    ],
    reproductionSteps: [
      "1. Confirm the tool version matches the original run: `7z i 2>&1 | head -3`. Compare against the recorded version {version}. Version drift above a minor release is unusual for archive extraction but note any discrepancy.",
      "2. Verify the input archive has not been modified: `sha256sum {input_file}`. The hash must equal {input_sha256}. Stop and raise a chain-of-custody flag if they differ.",
      "3. Reproduce the original examiner's exact command: `{command}`. If the archive is password-protected and no password was recorded, document the gap and attempt with no password first — 7z exits non-zero and prints 'Wrong password' rather than silently producing garbage output.",
      "4. If the command used `-p` for a password, supply the same password. Confirm each extracted file appears in the output listing. Pitfall: locale settings can affect how non-ASCII filenames are displayed; export `LC_ALL=C.UTF-8` before running if filenames look garbled.",
      "5. Hash each extracted file: `sha256sum {output_file}`. Record hashes in your case notes for downstream tools.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Confirm the list of extracted files matches the original examiner's ({operator}) notes — file count, filenames, and sizes should be identical.",
      "Re-run `7z t {input_file}` (test mode) to confirm the archive reports no CRC errors.",
      "If any extracted file hash differs from the original run, the archive may have been modified or a different password was used — escalate before proceeding.",
    ],
  },
  {
    name: "7z2john",
    aliases: ["7z2john", "7z2john.pl", "7z2john.py"],
    category: "password",
    description:
      "A helper script shipped with John the Ripper that extracts the encrypted header bytes from a 7z archive and converts them into the hash format John and hashcat can crack. It does not crack the archive itself — it only prepares the hash.",
    typicalFindings: [
      "Hash string representing the archive's encrypted header",
      "Confirmation of the encryption algorithm (AES-256)",
      "Input ready for John / hashcat attack modes",
    ],
    whyItMatters:
      "You cannot brute-force a 7z archive directly — you have to extract its header hash first. This tool is the mandatory pre-processing step for any attack on an encrypted 7z, and picking the wrong converter (e.g., using a ZIP helper on a 7z file) means the cracker will never find the password even if it is in the wordlist.",
    feedsInto: ["john", "hashcat"],
    consumesFrom: ["7-Zip", "file"],
    reference: "https://www.openwall.com/john/",
    environmentSetup: [
      "7z2john ships with John the Ripper on Kali Linux. Verify with: `locate 7z2john 2>/dev/null || find /usr -name '7z2john*' 2>/dev/null`",
      "If missing, install John the Ripper: `sudo apt-get install -y john`",
      "The script is typically at `/usr/share/john/7z2john.pl` or reachable as `7z2john` on the PATH.",
    ],
    reproductionSteps: [
      "1. Verify the input archive integrity before extraction: `sha256sum {input_file}`. Must equal {input_sha256}. A mismatch means you are not working from the same file the original examiner used.",
      "2. Confirm the archive is actually a 7z file (not ZIP, RAR, etc.): `file {input_file}`. The output must say '7-zip archive data'. Using 7z2john on a ZIP or RAR produces a silent wrong-format hash — John will simply never crack it.",
      "3. Run the hash-extraction command: `{command}`. This is typically `7z2john {input_file} > {output_file}`. The output file should contain exactly one line beginning with the archive filename followed by a colon.",
      "4. Inspect the hash line to confirm it is well-formed: `cat {output_file}`. A valid 7z hash line contains `$7z$` followed by numeric parameters. If the file is empty or contains an error message, the archive may not be encrypted — confirm with `7z l {input_file}` and check for an 'E' (encrypted) flag.",
      "5. Record the hash file: `sha256sum {output_file}`. This hash uniquely fingerprints the hash-extraction output for chain-of-custody.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Visually confirm the hash line begins with `$7z$` — any other prefix means a wrong tool or wrong archive format was used.",
      "Check that the hash was extracted from the correct archive: the filename prefix in the hash line must match `{input_file}`.",
      "Optionally validate the hash is parseable by John: `john --list=formats | grep 7z` — if the format appears, the John installation can process the hash.",
    ],
  },
  {
    name: "binwalk",
    aliases: ["binwalk"],
    category: "carving",
    description:
      "A tool for analyzing, reverse-engineering, and extracting firmware images and binary blobs. It scans a file for embedded file signatures and can automatically carve out hidden files — JPEGs buried in a binary, zip archives concatenated onto an executable, entire filesystems embedded in firmware dumps.",
    typicalFindings: [
      "Embedded files that do not appear in directory listings",
      "Compressed blobs (gzip, LZMA, zlib) inside firmware images",
      "Filesystem images (squashfs, jffs2, cramfs) inside firmware",
      "Code signatures and encryption boundaries in stripped binaries",
    ],
    whyItMatters:
      "Evidence files often hide additional data that would never show up in a normal file listing — a JPEG appended to a document, a zip embedded in a PNG, malware payloads concatenated onto legitimate binaries. Binwalk is how you find data that was never meant to be found, which is frequently where the incriminating content lives.",
    feedsInto: ["exiftool", "file", "strings", "sha256sum", "7-Zip"],
    consumesFrom: [],
    reference: "https://github.com/ReFirmLabs/binwalk",
    environmentSetup: [
      "binwalk is pre-installed on Kali Linux. Verify with: `binwalk --version`",
      "If missing, install with: `sudo apt-get install -y binwalk`",
      "For full extraction support (squashfs, LZMA, etc.), also install: `sudo apt-get install -y squashfs-tools jefferson sasquatch`",
    ],
    reproductionSteps: [
      "1. Verify the input file has not changed: `sha256sum {input_file}`. Must equal {input_sha256}. Stop if they differ.",
      "2. Confirm the tool version matches: `binwalk --version`. Compare against recorded version {version}. Binwalk's signature database changes between releases — a newer version may find additional or different signatures.",
      "3. Run the original command exactly: `{command}`. The most common scan-only form is `binwalk {input_file}` and the extraction form is `binwalk -e {input_file}`. Check the original command for flags like `-M` (matryoshka/recursive), `-A` (opcode search), or `--dd` (custom extraction rule) and include them.",
      "4. If extraction was performed (`-e` or `-Me`), binwalk creates a directory named `_{input_file}.extracted` in the working directory. Confirm the same directory appears and that its contents match the original examiner's file listing.",
      "5. Hash every carved file in the extraction directory: `find _{input_file}.extracted -type f -exec sha256sum {} \\; | tee carved_hashes.txt`. Retain this file as a chain-of-custody artifact.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Confirm the scan output lists the same embedded file signatures (type, offset, description) as the original examiner's recorded output.",
      "Verify the extraction directory file count and file sizes match the original run — extra or missing files indicate a version or flag difference.",
      "If carved files differ, re-run with `--verbose` and compare offset-by-offset with the original log to identify where the divergence starts.",
    ],
  },
  {
    name: "ExifTool",
    aliases: ["exiftool", "exif", "exiftool.exe", "exiftool.pl"],
    category: "metadata",
    description:
      "A command-line Perl application for reading, writing, and editing metadata in image, audio, video, PDF, and Office documents. Supports over 150 file formats and hundreds of metadata tags including EXIF, IPTC, XMP, GPS, maker notes, and document revision history.",
    typicalFindings: [
      "GPS coordinates and timestamps from images and videos",
      "Camera make/model, lens, and serial number",
      "Author, creator software, and last-modified metadata from Office documents and PDFs",
      "Document revision history and track-changes artifacts",
      "Hidden comments, custom XMP tags, and thumbnails that may differ from the visible image",
    ],
    whyItMatters:
      "Metadata is often the most direct link between a file and a person, place, or device. GPS coordinates in a photo can place a suspect at a scene; the 'Author' field of a Word document can identify who drafted it even after the filename is changed; camera serial numbers can be matched against devices in custody. Metadata is also the most commonly overlooked evidence because it is invisible in normal file viewers.",
    feedsInto: ["sha256sum"],
    consumesFrom: ["7-Zip", "binwalk"],
    reference: "https://exiftool.org",
    environmentSetup: [
      "ExifTool is pre-installed on Kali Linux. Verify with: `exiftool -ver`",
      "If missing, install with: `sudo apt-get install -y libimage-exiftool-perl`",
      "Version matters for metadata parsing: ExifTool adds support for new maker-note formats in nearly every release. Record the version with `exiftool -ver` at the time of the original run.",
    ],
    reproductionSteps: [
      "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. Metadata output is deterministic for a given file — any byte-level difference will change some tag values.",
      "2. Confirm the ExifTool version: `exiftool -ver`. Compare against recorded version {version}. If the version differs by more than a patch release, note it — newer versions may parse additional tags or correct tag value interpretation.",
      "3. Run the original command: `{command}`. For a full metadata dump the typical form is `exiftool {input_file}` or `exiftool -j {input_file}` (JSON output). Include any flags the original examiner used (e.g., `-a` for duplicate tags, `-u` for unknown tags, `-G` for group names).",
      "4. If output was redirected to a file, replicate the redirection: `exiftool {input_file} > {output_file}`. Pitfall: line endings differ between platforms — if comparing on Windows, use `dos2unix` before diffing.",
      "5. Note any 'Unknown tag' or 'Missing required EXIF IFD' warnings — these are expected for some file types but should match the original run's warnings. Unexpected warnings may indicate a format or version difference.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Diff the tag list against the original examiner's ({operator}) output: key tags like GPSLatitude, CreateDate, Make, Model, and Author must be identical.",
      "Confirm GPS coordinates (if present) to at least 4 decimal places — rounding differences between ExifTool versions are rare but have occurred.",
      "Verify no tags present in the original output are missing from the reproduction — a missing tag may indicate a version difference or a file that has been sanitized.",
    ],
  },
  {
    name: "file",
    aliases: ["file", "file.exe"],
    category: "identification",
    description:
      "A Unix utility that identifies a file's type by examining its magic bytes and internal structure — not by trusting its extension. Given a file with no extension, a wrong extension, or a deliberately-disguised extension, it will still tell you whether it is really a JPEG, a 7z archive, a PE executable, or something else entirely.",
    typicalFindings: [
      "Real file type when the extension is wrong or missing",
      "Compression format of an archive",
      "Architecture and target OS of a binary executable",
      "Text encoding of a document (UTF-8, UTF-16, ASCII)",
    ],
    whyItMatters:
      "Never trust an extension. Suspects rename .exe to .txt, .zip to .jpg, and .docx to .log to evade filters. The 'file' utility is the first step in triage — it tells you what you are actually looking at so you can pick the right follow-up tool. Running exiftool on a file that is actually a 7z archive wastes time; running 7z on a file that is actually an image produces garbage.",
    feedsInto: ["7-Zip", "exiftool", "binwalk", "strings", "xxd"],
    consumesFrom: [],
    reference: "https://darwinsys.com/file/",
    environmentSetup: [
      "The `file` utility is pre-installed on Kali Linux. Verify with: `file --version`",
      "If missing, install with: `sudo apt-get install -y file`",
      "The `file` utility uses the libmagic database (`/usr/share/misc/magic.mgc`). The database version affects identification results — note it with `file --version`.",
    ],
    reproductionSteps: [
      "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. The `file` utility reads magic bytes, so even a single-byte difference can change the output.",
      "2. Confirm the tool version and magic database: `file --version`. Compare against recorded version {version}. Different magic database versions may classify ambiguous files differently.",
      "3. Run the original command: `{command}`. The standard form is `file {input_file}`. If the original used `-k` (keep-going, show all matches), `-z` (try to look inside compressed files), or `-i` (MIME type output), include those flags.",
      "4. Record the exact output line. Pitfall: if the output says 'ASCII text' but the original said 'PE32 executable', a line-ending conversion or padding stripping may have changed the file — re-hash to confirm.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Confirm the identified file type exactly matches the original examiner's ({operator}) recorded output — a one-word difference (e.g., 'data' vs. '7-zip archive data') changes which tool should be used next.",
      "If the type differs from what the original run recorded, run `xxd {input_file} | head -4` to inspect the first 16 bytes directly and determine whether the file or the tool database has changed.",
    ],
  },
  {
    name: "John the Ripper",
    aliases: ["john", "john-the-ripper", "jtr", "john.exe"],
    category: "password",
    description:
      "An open-source password security auditor and cracker. It performs dictionary, brute-force, and rule-based attacks against password hashes from a wide variety of sources — Unix /etc/shadow, Windows SAM, encrypted archives, PDF passwords, SSH keys, and many more. Commonly paired with format-specific helpers like 7z2john, pdf2john, and ssh2john.",
    typicalFindings: [
      "Cleartext passwords recovered from hashes",
      "Rejection of hashes in the wrong format (failure mode signaling a mismatched helper)",
      "Estimated crack time for a given wordlist and attack mode",
    ],
    whyItMatters:
      "Encrypted evidence is only evidence if you can decrypt it. A single recovered password often unlocks an entire case — an encrypted 7z becomes a trove of exfiltrated files, a PDF password yields a confidential memo, a recovered Windows password gives live access to the user's session. The pre-processing helper (7z2john, pdf2john, etc.) MUST match the container type, or John will churn through wordlists forever without finding the right answer.",
    feedsInto: ["7-Zip", "exiftool", "strings"],
    consumesFrom: ["7z2john"],
    reference: "https://www.openwall.com/john/",
    environmentSetup: [
      "John the Ripper is pre-installed on Kali Linux. Verify with: `john --version`",
      "If missing, install with: `sudo apt-get install -y john`",
      "For the Jumbo community build (more formats and rules): `sudo apt-get install -y john-data` or compile from https://github.com/openwall/john",
      "Confirm the wordlist used by the original examiner is available at the same path (commonly `/usr/share/wordlists/rockyou.txt`). Decompress if needed: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`",
    ],
    reproductionSteps: [
      "1. Verify the hash input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. John operates on the hash — any corruption produces wrong or no candidates.",
      "2. Confirm John version: `john --version`. Compare against recorded version {version}. The Jumbo build and the stock build handle different format sets — mismatches mean John may not recognise the hash format at all.",
      "3. Run the exact original command: `{command}`. Typically: `john --wordlist=/path/to/wordlist --format=<format> {input_file}`. The `--format` flag is critical: if it was not specified in the original run, John auto-detects — reproduce that same auto-detection by also omitting it.",
      "4. After the run completes (or is interrupted), display cracked passwords: `john --show {input_file}`. The output must list the same password(s) the original examiner recorded. Pitfall: John writes a `.john/john.pot` pot file — if a previous run already cracked this hash, `--show` will report it even without running the attack again. Check `~/.john/john.pot` to confirm.",
      "5. If the same password is not recovered, verify the wordlist is identical (byte-for-byte) to the one the original examiner used and that the `--rules` flag (if any) matches exactly.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Confirm `john --show {input_file}` displays exactly the same cracked password(s) recorded by the original examiner ({operator}).",
      "Verify the recovered password successfully opens the target artifact (e.g., `7z e -p<recovered_password> archive.7z`) — this is the ultimate functional test.",
      "If the password is not reproduced, document the wordlist path, John version, format flag, and rule set used — these four variables determine reproducibility.",
    ],
  },
  {
    name: "sha256sum",
    aliases: ["sha256sum", "shasum", "sha256", "sha256sum.exe"],
    category: "hashing",
    description:
      "A GNU coreutils utility that computes the SHA-256 cryptographic hash of a file. SHA-256 is the forensic-standard hash function for integrity verification: the same input always produces the same 64-character hex output, and any one-bit change produces a completely different hash.",
    typicalFindings: [
      "Unique SHA-256 fingerprint for each evidence file",
      "Proof that a file has not been altered between collection and analysis",
      "Identification of known files via hash databases (NSRL, VirusTotal)",
      "Duplicate detection across large evidence sets",
    ],
    whyItMatters:
      "Chain of custody requires proving that the evidence file you are analyzing today is byte-for-byte identical to the one you collected in the field. SHA-256 is the standard accepted by every court in the United States for that proof. Every evidence file should be hashed at collection, at ingest, and before every major analysis step — any mismatch invalidates downstream conclusions and must be investigated.",
    feedsInto: [],
    consumesFrom: ["7-Zip", "binwalk", "exiftool"],
    reference: "https://www.gnu.org/software/coreutils/",
    environmentSetup: [
      "`sha256sum` is part of GNU coreutils and is pre-installed on every Kali Linux system. Verify with: `sha256sum --version`",
      "No installation step is required. If somehow missing: `sudo apt-get install -y coreutils`",
    ],
    reproductionSteps: [
      "1. Run the original command exactly: `{command}`. The standard form is `sha256sum {input_file}`. Output is a 64-character hex digest followed by two spaces and the filename.",
      "2. Compare the computed hash against the recorded value {input_sha256}. They must be identical byte-for-byte. Any difference — even one character — means the file has changed and the chain of custody is broken.",
      "3. If the original command verified against a checksum file (e.g., `sha256sum -c hashes.txt`), reproduce that check: `sha256sum -c {input_file}`. 'OK' for each line means the files are intact.",
      "4. Record the output: `sha256sum {input_file} | tee {output_file}`. Pitfall: some systems default to BSD-style output (`SHA256 (file) = hash`) rather than GNU style (`hash  file`). Confirm which format the original examiner used — they are not interchangeable for automated verification.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "The 64-character hash in the output must exactly match {input_sha256} — character-for-character, no trailing spaces or newline differences.",
      "If verifying multiple files from a hash manifest, confirm all lines report 'OK' with zero failures.",
      "A mismatch is a chain-of-custody event, not a tool error — escalate before proceeding with any analysis that depends on this file.",
    ],
  },
  {
    name: "strings",
    aliases: ["strings", "strings.exe", "gnu-strings"],
    category: "strings",
    description:
      "A GNU Binutils utility that scans a binary file for sequences of printable ASCII (and optionally Unicode) characters and prints them. In forensics it surfaces embedded URLs, filenames, error messages, email addresses, API keys, and other human-readable fragments that are otherwise invisible in a binary.",
    typicalFindings: [
      "URLs, domain names, and IP addresses embedded in malware",
      "Hardcoded paths, filenames, and registry keys",
      "API keys, passwords, and access tokens accidentally compiled in",
      "Error messages and debug symbols that reveal build environment and authorship",
      "Email addresses and contact strings",
    ],
    whyItMatters:
      "Binaries, memory dumps, and unknown file blobs often contain the smoking gun in plain text: a C2 domain, a command-line argument, a path that points to the attacker's workstation. Running 'strings' is a zero-cost first pass that frequently reveals leads days before deeper reverse engineering would. It is the forensic equivalent of 'grep for anything that looks like words'.",
    feedsInto: ["file", "sha256sum"],
    consumesFrom: ["binwalk", "7-Zip"],
    reference: "https://www.gnu.org/software/binutils/",
    environmentSetup: [
      "`strings` is part of GNU Binutils and is pre-installed on Kali Linux. Verify with: `strings --version`",
      "If missing, install with: `sudo apt-get install -y binutils`",
    ],
    reproductionSteps: [
      "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. The `strings` output is deterministic for a given input — any difference in the file changes the output.",
      "2. Run the original command exactly: `{command}`. The typical form is `strings {input_file} > {output_file}`. Common flags to replicate: `-n <min_length>` (default 4), `-e` for encoding (`-e l` for 16-bit little-endian Unicode, `-e b` for big-endian), `-a` to scan the whole file (not just loaded sections for ELF/PE).",
      "3. If the original command did not include `-n`, the default minimum length is 4 characters. Shorter strings (e.g., `-n 8`) produce less noise but may miss evidence — replicate the original flag exactly.",
      "4. Confirm output file size is in the expected range: `wc -l {output_file}`. A much smaller or larger line count than the original run usually means a flag or encoding difference.",
      "5. Pitfall: on ELF/PE executables, `strings` by default only scans the data section. Use `-a` if the original examiner did — omitting it on a binary can miss strings in non-data sections by a large margin.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Confirm the line count (`wc -l {output_file}`) matches the original run — a significant difference indicates a flag mismatch.",
      "Spot-check 5-10 key strings the original examiner highlighted (URLs, paths, email addresses) and confirm they appear at the same relative positions in the output.",
      "If hashes do not match, diff the outputs: `diff <(sort {output_file}) <(sort original_output.txt)` to identify added or missing strings, then trace back to the flag or encoding difference.",
    ],
  },
  {
    name: "xxd",
    aliases: ["xxd", "xxd.exe"],
    category: "hex",
    description:
      "A hex dump utility that shows the raw bytes of a file alongside their ASCII representation. Used for low-level inspection — examining file headers, confirming magic bytes, spotting patterns in encrypted data, and hand-editing binary files. Also performs the reverse (hex → binary) to reconstruct files.",
    typicalFindings: [
      "Magic bytes and file signatures at a file's start",
      "Padding patterns, cipher structure, and repeated blocks in encrypted data",
      "Anomalies in otherwise-normal binary structures",
      "Hidden content in file slack space or after end-of-file markers",
    ],
    whyItMatters:
      "When automated tools disagree about what a file is, xxd is how you settle it by reading the bytes yourself. It is also the last-resort tool when a file is so corrupted or unusual that no parser will touch it — you can still inspect the raw content and often recover enough to understand what happened. Essential for verifying the work of other tools: 'file said it is a JPEG, but xxd shows no FF D8 magic bytes — the extension is wrong, something is up.'",
    feedsInto: ["file", "strings", "sha256sum"],
    consumesFrom: ["binwalk", "7-Zip"],
    reference: "https://linux.die.net/man/1/xxd",
    environmentSetup: [
      "`xxd` ships with the vim package on Kali Linux and is pre-installed. Verify with: `xxd --version 2>&1 | head -1`",
      "If missing, install with: `sudo apt-get install -y xxd` (or `sudo apt-get install -y vim-common`)",
    ],
    reproductionSteps: [
      "1. Verify the input file is unchanged: `sha256sum {input_file}`. Must equal {input_sha256}. xxd output is byte-for-byte deterministic — any change to the file changes the dump.",
      "2. Run the original command exactly: `{command}`. The standard full-file form is `xxd {input_file} > {output_file}`. Replicate any flags: `-l <n>` (limit to first n bytes), `-s <offset>` (start at offset), `-c <cols>` (columns per line, default 16), `-p` (plain hex without ASCII column), `-e` (little-endian word groups).",
      "3. If only a header region was dumped (e.g., `xxd -l 64 {input_file}`), reproduce exactly that byte range — inspecting the wrong region is the most common reproduction mistake.",
      "4. For binary reconstruction (reverse mode, `xxd -r`), confirm the input hex file matches the original before running — a single garbled hex nibble will corrupt the output binary.",
      "5. Confirm output line count with `wc -l {output_file}`. Default format produces one line per 16 bytes, so a 512-byte file produces 32 lines.",
    ],
    verificationSteps: [
      "Compute SHA-256 of the output file: `sha256sum {output_file}` and compare with {output_sha256}.",
      "Confirm the first and last hex dump lines match the original examiner's ({operator}) recorded output — these anchor the byte-range and catch off-by-one errors in offset flags.",
      "Verify the magic bytes shown in the first line match the expected file type signature (e.g., `7z` archives start with `37 7a bc af 27 1c`, JPEG starts with `ff d8 ff`).",
      "If comparing a partial dump, confirm the `-l` and `-s` values match exactly — even a one-byte difference in start offset shifts every subsequent address and ASCII column.",
    ],
  },

  // ───── Additional common forensic tools (for future use) ─────
  {
    name: "Autopsy",
    aliases: ["autopsy"],
    category: "filesystem",
    description:
      "An open-source digital forensics platform with a graphical interface that runs on top of The Sleuth Kit. Provides filesystem analysis, keyword search, timeline generation, registry parsing, web history, and much more from a single integrated UI. The de facto free alternative to commercial suites like EnCase and FTK.",
    typicalFindings: [
      "Recoverable deleted files",
      "Full filesystem timeline of creation/modification/access events",
      "Browser history, email, chat artifacts",
      "Keyword hits across the entire drive",
    ],
    whyItMatters:
      "Most cases start by pointing Autopsy at a disk image and letting it run overnight. It gives you a broad baseline across every standard artifact type before you pick which ones to drill into with specialized tools.",
    feedsInto: ["exiftool", "strings", "sha256sum"],
    consumesFrom: ["FTK Imager", "dd"],
    reference: "https://www.autopsy.com",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Volatility",
    aliases: ["volatility", "vol.py", "vol"],
    category: "memory",
    description:
      "An open-source memory forensics framework for analyzing RAM dumps from Windows, Linux, and Mac systems. Extracts running processes, network connections, loaded DLLs, registry hives in memory, command history, and in-memory malware that never touched disk.",
    typicalFindings: [
      "Running processes including hidden or injected code",
      "Network connections at the time of the dump",
      "Cleartext passwords and encryption keys in memory",
      "In-memory-only malware payloads",
    ],
    whyItMatters:
      "A memory dump captures what was happening at a single moment — processes the user killed, network connections they closed, and passwords never written to disk. If you have a live system suspected of compromise, memory is often where the evidence is because mature attackers go to great lengths to leave nothing on disk.",
    feedsInto: ["strings", "sha256sum"],
    consumesFrom: [],
    reference: "https://www.volatilityfoundation.org",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Wireshark",
    aliases: ["wireshark", "tshark"],
    category: "network",
    description:
      "The standard open-source network protocol analyzer. Captures live network traffic or opens saved .pcap/.pcapng files and dissects every packet at every protocol layer. Includes follow-stream views, statistics, and a Lua scripting engine for custom dissectors.",
    typicalFindings: [
      "Reconstructed HTTP/FTP/SMTP conversations including file transfers",
      "DNS queries revealing domains visited",
      "TLS handshakes and SNI fields showing destination even when payload is encrypted",
      "Beaconing patterns consistent with C2 traffic",
    ],
    whyItMatters:
      "Network captures are the only evidence that tells you what actually traversed the wire. Host-based artifacts can be altered; a pcap from an out-of-band collector cannot. Wireshark turns raw packets into a reconstructed narrative of what the suspect's machine talked to, when, and with what content.",
    feedsInto: ["sha256sum", "strings"],
    consumesFrom: [],
    reference: "https://www.wireshark.org",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "FTK Imager",
    aliases: ["ftk imager", "ftkimager", "ftk_imager"],
    category: "disk-imaging",
    description:
      "A free disk imaging and triage tool from AccessData (now Exterro). Creates forensically-sound bit-for-bit images of physical disks and logical volumes in E01 or raw .dd format with automatic MD5/SHA-1 hashing for integrity verification. Also mounts images read-only for preview.",
    typicalFindings: [
      "Complete bit-for-bit disk image in E01 or .dd format",
      "MD5 and SHA-1 hashes computed during acquisition",
      "Preview of filesystem contents including deleted files",
    ],
    whyItMatters:
      "Every on-disk investigation begins with imaging. Working from an image rather than the live disk is a fundamental forensic principle: it is repeatable, preserves the original, and protects chain of custody. FTK Imager is the most commonly-used free tool for this step.",
    feedsInto: ["Autopsy", "sha256sum"],
    consumesFrom: [],
    reference: "https://www.exterro.com/ftk-imager",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "dd",
    aliases: ["dd", "dcfldd", "dc3dd"],
    category: "disk-imaging",
    description:
      "A Unix utility that copies data byte-for-byte between files or devices. The forensic variants dcfldd and dc3dd add on-the-fly hashing, logging, and progress reporting. Used to create raw (.dd) disk images from physical media.",
    typicalFindings: [
      "Raw disk image identical to the source device",
      "SHA-256 hash of the captured data (when using forensic variants)",
      "Acquisition log with timestamps and block counts",
    ],
    whyItMatters:
      "When you need a raw image and cannot boot a GUI imager, dd is the fallback that always works. It is the most portable imaging tool in existence, runs on any Unix-like system, and is the format most other tools accept without complaint.",
    feedsInto: ["Autopsy", "sha256sum"],
    consumesFrom: [],
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "hashcat",
    aliases: ["hashcat"],
    category: "password",
    description:
      "A GPU-accelerated password recovery tool. Supports 300+ hash formats and executes dictionary, mask, rule-based, and hybrid attacks on NVIDIA or AMD hardware. Generally faster than John the Ripper for raw brute-forcing; both tools use the same .hash-format input.",
    typicalFindings: [
      "Cleartext passwords recovered via GPU-accelerated attack",
      "Attack-mode timing and candidate-throughput statistics",
    ],
    whyItMatters:
      "When John is too slow, hashcat is the upgrade: a modern consumer GPU can test tens of billions of candidates per second against a fast hash. It is the tool of choice for large wordlists or long password spaces.",
    feedsInto: ["7-Zip"],
    consumesFrom: ["7z2john"],
    reference: "https://hashcat.net",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Sleuth Kit",
    aliases: ["sleuthkit", "sleuth kit", "tsk", "fls", "icat", "fsstat", "mmls", "tsk_recover"],
    category: "filesystem",
    description:
      "A command-line suite of filesystem analysis tools (fls, icat, fsstat, mmls, tsk_recover, etc.) that form the engine Autopsy is built on. Works at the file, inode, and block level to recover deleted files, parse filesystems, and extract timeline data.",
    typicalFindings: [
      "Deleted file recovery from unallocated space",
      "Full MAC-time timeline of every filesystem entry",
      "File content recovered directly from inode/block references",
    ],
    whyItMatters:
      "When Autopsy's GUI is too slow or the system is headless, the underlying Sleuth Kit commands do the same work from a shell and can be scripted. Essential for scripted or large-scale filesystem analysis.",
    feedsInto: ["exiftool", "sha256sum", "strings"],
    consumesFrom: ["FTK Imager", "dd"],
    reference: "https://www.sleuthkit.org",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "RegRipper",
    aliases: ["regripper", "rip.pl", "rip.exe"],
    category: "registry",
    description:
      "An open-source Windows registry parser written in Perl. Runs a library of plugins against NTUSER.DAT, SOFTWARE, SYSTEM, and SECURITY hives to extract user activity, installed software, USB device history, run/runonce entries, and hundreds of other artifacts.",
    typicalFindings: [
      "USB devices plugged into the system and when",
      "Recently opened documents and typed paths",
      "Installed software and autorun entries",
      "Network configuration and wireless SSIDs",
    ],
    whyItMatters:
      "The Windows registry is a rich, often-underused evidence source. RegRipper turns raw hive files into human-readable reports and is one of the fastest ways to answer 'what did this user do on this machine?'",
    feedsInto: [],
    consumesFrom: ["Autopsy", "FTK Imager"],
    reference: "https://github.com/keydet89/RegRipper3.0",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "plaso / log2timeline",
    aliases: ["plaso", "log2timeline", "log2timeline.py", "psort"],
    category: "timeline",
    description:
      "A Python-based super-timeline engine that extracts timestamped events from hundreds of artifact types (filesystem, registry, browser history, Windows event logs, etc.) and merges them into a single unified timeline stored in a Plaso database file.",
    typicalFindings: [
      "Merged timeline across filesystem, registry, browser, and event-log sources",
      "Event correlation revealing what happened in what order",
      "Gaps suggesting log deletion or time manipulation",
    ],
    whyItMatters:
      "A super-timeline is often the only view where the story of an incident becomes visible — a filesystem event on its own means nothing, but seeing it next to a registry write, a browser visit, and a PowerShell launch a second later tells you exactly what happened.",
    feedsInto: [],
    consumesFrom: ["Autopsy", "Sleuth Kit", "RegRipper"],
    reference: "https://plaso.readthedocs.io",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "YARA",
    aliases: ["yara"],
    category: "malware",
    description:
      "A pattern-matching engine for malware identification. Rules describe byte sequences, strings, and structural features; YARA scans files, processes, or memory dumps and reports every match. The de facto standard for sharing malware signatures between analysts.",
    typicalFindings: [
      "Matches against known malware families",
      "Custom indicators of compromise defined per-case",
      "Suspicious strings and code patterns in unknown binaries",
    ],
    whyItMatters:
      "YARA is how you go from 'I think this might be malware' to 'this is tracked as APT28 sample X from 2022'. The rule ecosystem is enormous and the scan is fast — running a YARA pass on every binary in an image is cheap and high-signal.",
    feedsInto: ["strings"],
    consumesFrom: [],
    reference: "https://virustotal.github.io/yara/",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "steghide",
    aliases: ["steghide"],
    category: "stego",
    description:
      "A steganography tool that embeds and extracts hidden payloads inside JPEG, BMP, WAV, and AU files. Uses a password to encrypt the payload before embedding.",
    typicalFindings: [
      "Hidden payloads inside otherwise-innocent media files",
      "Password-protected extraction candidates",
    ],
    whyItMatters:
      "When exfiltrated data is not in the obvious places, suspects sometimes hide it inside images or audio files using steganography. Steghide is the first tool to try because it is the most commonly-used implementation.",
    feedsInto: ["file", "exiftool", "strings"],
    consumesFrom: [],
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },

  // ───── OSINT tools (Persons + Agent Zero OSINT feature) ─────
  {
    name: "Sherlock",
    aliases: ["sherlock", "sherlock.py"],
    category: "osint",
    description:
      "A Python tool that hunts a given username across 300+ social network, forum, and web service sites. For each site it checks whether an account with the username exists and returns the full profile URL if found. The de facto standard for OSINT username enumeration.",
    typicalFindings: [
      "Social media profiles matching a suspect's username",
      "Forum and developer community accounts (GitHub, Reddit, Stack Overflow, etc.)",
      "Dating, shopping, gaming, and other niche site accounts",
      "Username reuse patterns across unrelated services",
    ],
    whyItMatters:
      "People reuse usernames across dozens of services without realizing it. A single handle often opens the door to a suspect's entire online footprint — personal email addresses, employer info, public posts, photographs, friend networks, even real names. Sherlock is the fastest way to turn a username into a complete OSINT pivot.",
    feedsInto: ["WhatsMyName", "theHarvester", "SpiderFoot"],
    consumesFrom: [],
    reference: "https://github.com/sherlock-project/sherlock",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "holehe",
    aliases: ["holehe"],
    category: "osint",
    description:
      "A Python OSINT tool that takes an email address and checks which of 120+ major websites have an account registered with it — without sending any login attempts or password-reset emails. Uses site-specific APIs and silent existence checks so the target never learns they were looked up.",
    typicalFindings: [
      "Websites where an email is registered (Instagram, Twitter, Imgur, Spotify, etc.)",
      "Unexpected account presence suggesting hidden online activity",
      "Confirmation or denial of email ownership across major services",
    ],
    whyItMatters:
      "Holehe answers the question 'what does this person use this email for?' without tipping them off. Because it never sends password-reset emails or login attempts, the suspect does not receive any notification. Essential for covert OSINT where operational security matters.",
    feedsInto: ["Sherlock", "WhatsMyName", "theHarvester", "SpiderFoot"],
    consumesFrom: [],
    reference: "https://github.com/megadose/holehe",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "theHarvester",
    aliases: ["theharvester", "theharvester.py", "harvester"],
    category: "osint",
    description:
      "An open-source reconnaissance tool that gathers emails, subdomains, hosts, employee names, open ports, and banners from public sources (search engines, LinkedIn, Shodan, DuckDuckGo, crt.sh, Bing, Yahoo, VirusTotal, and many more). One of the oldest and most reliable OSINT collection tools.",
    typicalFindings: [
      "Email addresses associated with a target domain",
      "Subdomains discoverable via passive DNS + certificate transparency",
      "Employees named on LinkedIn and public company pages",
      "Host fingerprints and open ports from Shodan",
    ],
    whyItMatters:
      "Given a domain or company name, theHarvester returns an entire starting OSINT map: who works there, what external-facing assets exist, and what their email patterns look like. This is the foundation for social engineering reconnaissance, phishing investigations, and understanding an organization's attack surface.",
    feedsInto: ["Amass", "Recon-ng", "SpiderFoot", "holehe"],
    consumesFrom: [],
    reference: "https://github.com/laramies/theHarvester",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "SpiderFoot",
    aliases: ["spiderfoot", "sf.py", "spiderfoot-cli"],
    category: "osint",
    description:
      "An open-source OSINT automation framework with over 200 modules for gathering information from 100+ public data sources. Accepts any target type (IP, domain, email, name, username, phone, BTC address) and automatically runs relevant modules to build a full intelligence profile. The most comprehensive OSINT tool in the Kali ecosystem.",
    typicalFindings: [
      "Full intelligence profile across every relevant OSINT source",
      "Cross-source correlation (e.g. email → breach database → username → social)",
      "Threat-intelligence hits against malware, botnet, and blocklist feeds",
      "Certificate transparency, DNS history, and web archive records",
      "Dark-web mentions and paste-site leaks (when configured with API keys)",
    ],
    whyItMatters:
      "SpiderFoot is the orchestrator of OSINT tools. Rather than running Sherlock, holehe, theHarvester, Amass, etc. individually and correlating the output by hand, SpiderFoot runs them together and pivots from any finding to the next logical query automatically. For a serious OSINT investigation this is the tool that ties every other source together.",
    feedsInto: [],
    consumesFrom: ["Sherlock", "holehe", "theHarvester", "Amass"],
    reference: "https://www.spiderfoot.net",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Recon-ng",
    aliases: ["recon-ng", "recon-ng.py"],
    category: "osint",
    description:
      "A full-featured web-reconnaissance framework written in Python. Modular like Metasploit — hundreds of modules are organized by data type (hosts, contacts, credentials, leaked accounts) and the user loads them one at a time to build up a SQLite workspace of OSINT findings.",
    typicalFindings: [
      "Structured workspace linking hosts, contacts, vulnerabilities, and credentials",
      "Domain enumeration, whois records, and DNS history",
      "Employee contact scraping from LinkedIn and other social sources",
      "Leaked credentials from public breach databases",
    ],
    whyItMatters:
      "When an investigation is going to produce a lot of OSINT data, Recon-ng's structured workspace is where you keep it organized. Unlike single-purpose tools, it accumulates findings into a database you can query, export, and hand off. Preferred by investigators who want an auditable trail of every OSINT query they ran.",
    feedsInto: ["SpiderFoot"],
    consumesFrom: ["theHarvester"],
    reference: "https://github.com/lanmaster53/recon-ng",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "WhatsMyName",
    aliases: ["whatsmyname", "whatsmyname.py", "wmn"],
    category: "osint",
    description:
      "A community-maintained username enumeration tool that checks 500+ websites for account existence. Larger site list than Sherlock, updated more frequently, and maintained with direct contributions from the OSINT community.",
    typicalFindings: [
      "Account presence across a broader site list than Sherlock covers",
      "Newly-added niche sites that other tools have not caught up to",
      "Cross-corroboration of Sherlock results",
    ],
    whyItMatters:
      "Running WhatsMyName AFTER Sherlock is standard OSINT practice — the lists overlap but each catches sites the other misses. Together they produce the broadest possible username enumeration.",
    feedsInto: ["SpiderFoot"],
    consumesFrom: ["Sherlock"],
    reference: "https://github.com/WebBreacher/WhatsMyName",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Amass",
    aliases: ["amass"],
    category: "osint",
    description:
      "OWASP's in-depth network-mapping and attack-surface discovery tool. Performs passive and active DNS enumeration, ASN discovery, certificate transparency scraping, and subdomain brute-forcing to map the full external footprint of an organization.",
    typicalFindings: [
      "Complete subdomain list via certificate transparency, DNS brute-force, and passive scraping",
      "ASN and IP range ownership attribution",
      "Related domains sharing the same SSL certificate or registrant",
      "DNS history showing how an organization's infrastructure evolved",
    ],
    whyItMatters:
      "For any investigation of an organization or domain, Amass is the authoritative subdomain enumerator. Knowing every public-facing host an organization owns is the foundation for every subsequent network or application-layer investigation.",
    feedsInto: ["SpiderFoot"],
    consumesFrom: ["theHarvester"],
    reference: "https://github.com/owasp-amass/amass",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Maltego CE",
    aliases: ["maltego", "maltego ce", "maltego-ce"],
    category: "osint",
    description:
      "A graphical link-analysis tool for OSINT. Represents entities (people, emails, domains, companies, phone numbers) as nodes and runs 'Transforms' that query public and commercial data sources to enrich them. The Community Edition is free and ships in Kali.",
    typicalFindings: [
      "Visual link graphs showing relationships between people, domains, and emails",
      "Enrichment from public WHOIS, DNS, social, and corporate registries",
      "Pivot paths that reveal hidden connections (same phone number, shared addresses, etc.)",
    ],
    whyItMatters:
      "Some OSINT findings are only obvious visually — a cluster of three people sharing an address, a phone number used by two companies, a domain registered to a shell entity that links back to the suspect. Maltego's graph view surfaces these patterns in ways text-output tools cannot.",
    feedsInto: [],
    consumesFrom: ["theHarvester", "Sherlock"],
    reference: "https://www.maltego.com",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Photon",
    aliases: ["photon", "photon.py"],
    category: "osint",
    description:
      "A fast web crawler designed for OSINT. Crawls a target domain and extracts URLs, email addresses, JavaScript files, external links, social media handles, and document files. Much faster than general-purpose crawlers because it knows what OSINT investigators want.",
    typicalFindings: [
      "Every internal URL on a target website",
      "Email addresses embedded in pages, comments, and mailto: links",
      "Document file URLs (PDF, DOCX, XLS) for metagoofil follow-up",
      "External links pointing to social media profiles",
    ],
    whyItMatters:
      "Manual browsing of a target website misses most of the OSINT-relevant content. Photon sweeps the whole site in seconds and produces a structured list of every email, document, and external link — far more than an investigator could find by clicking.",
    feedsInto: ["metagoofil", "theHarvester", "holehe"],
    consumesFrom: [],
    reference: "https://github.com/s0md3v/Photon",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "metagoofil",
    aliases: ["metagoofil", "metagoofil.py"],
    category: "osint",
    description:
      "An OSINT tool that uses search engines to find public documents on a target domain (PDF, DOC, XLS, PPT, ODT, etc.), downloads them, and extracts embedded metadata via ExifTool. Effectively weaponizes document metadata for open-source investigation.",
    typicalFindings: [
      "Author names embedded in published PDFs and Office documents",
      "Internal usernames and workstation identifiers in file metadata",
      "Software versions used by the organization",
      "Network paths and printer names revealing internal infrastructure",
    ],
    whyItMatters:
      "Every PDF and Word document published on a company's website leaks metadata about the person who created it. Metagoofil automates what would otherwise be a tedious manual process and often produces the single most valuable OSINT data point in an investigation: a real employee's username or internal network path.",
    feedsInto: ["ExifTool", "Recon-ng"],
    consumesFrom: ["Photon"],
    reference: "https://github.com/opsdisk/metagoofil",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "dnsrecon",
    aliases: ["dnsrecon", "dnsrecon.py"],
    category: "osint",
    description:
      "A DNS enumeration tool that queries a target domain's DNS records through multiple techniques: standard record lookups, zone transfers, brute-force subdomain discovery from a wordlist, reverse lookups on IP ranges, and SRV record probes.",
    typicalFindings: [
      "Complete DNS record set (A, AAAA, MX, NS, SOA, TXT, SPF, DMARC)",
      "Subdomains discovered via wordlist brute-force",
      "Mail server infrastructure and spam-filter configuration",
      "Historical DNS records via reverse lookup",
    ],
    whyItMatters:
      "DNS is often the most revealing public record about an organization. dnsrecon pulls every interesting DNS artifact in a single run and is the baseline for any subdomain or mail-infrastructure investigation.",
    feedsInto: ["Amass", "Recon-ng", "SpiderFoot"],
    consumesFrom: [],
    reference: "https://github.com/darkoperator/dnsrecon",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "fierce",
    aliases: ["fierce", "fierce.pl"],
    category: "osint",
    description:
      "A DNS reconnaissance tool focused on locating non-contiguous IP space owned by a target. Walks DNS records, tries zone transfers, and scans surrounding IPs to find hosts that would otherwise be missed by standard enumeration.",
    typicalFindings: [
      "IP ranges owned by the target not discoverable via ASN lookup alone",
      "Hosts on adjacent IPs sharing naming conventions",
      "Hidden or internal subdomains exposed via zone transfer",
    ],
    whyItMatters:
      "Complements dnsrecon and Amass — where those focus on name-based discovery, fierce finds IP-based neighbors. Together they produce the most complete network-layer footprint of a target.",
    feedsInto: ["Amass"],
    consumesFrom: [],
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "FinalRecon",
    aliases: ["finalrecon", "finalrecon.py"],
    category: "osint",
    description:
      "An all-in-one web reconnaissance tool combining header inspection, WHOIS, DNS lookup, SSL certificate analysis, crawler, traceroute, directory enumeration, subdomain scan, and WAF fingerprinting into a single command. Useful when you want a fast baseline picture of any website.",
    typicalFindings: [
      "HTTP headers revealing web server, framework, and security posture",
      "WHOIS registration details",
      "SSL certificate chain and validity",
      "Detected WAF and CDN",
      "Site directory structure (common paths)",
    ],
    whyItMatters:
      "When an investigator needs a quick snapshot of an unknown target website, FinalRecon produces in 30 seconds what would take five separate tools and a lot of manual correlation. Not deep, but fast and complete enough to decide which areas deserve deeper follow-up.",
    feedsInto: ["Amass", "theHarvester"],
    consumesFrom: [],
    reference: "https://github.com/thewhiteh4t/FinalRecon",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "Shodan CLI",
    aliases: ["shodan", "shodan-cli"],
    category: "osint",
    description:
      "The command-line client for Shodan, the search engine for internet-connected devices. Queries Shodan's index of IoT, industrial, and server devices by IP, port, service banner, location, or CVE. Requires an API key (free tier available, paid for heavier use).",
    typicalFindings: [
      "Exposed services and open ports on a target IP",
      "Running software versions and known vulnerabilities",
      "Geolocation and ISP attribution",
      "Historical service banners showing when vulnerabilities were present",
      "Related devices on the same network or owned by the same organization",
    ],
    whyItMatters:
      "Shodan is the ground-truth source for what is actually reachable from the public internet at a given IP or organization. For any investigation involving an IP address, Shodan reveals exposed infrastructure the target may not even know they have running.",
    feedsInto: ["SpiderFoot"],
    consumesFrom: [],
    reference: "https://cli.shodan.io",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "EagleEye",
    aliases: ["eagleeye"],
    category: "osint",
    description:
      "A reverse image search tool that takes a photo of a person and searches for matching faces across Facebook, Instagram, Twitter, VK, and other public profile sources. Combines facial recognition with OSINT scraping to identify people from a single photograph.",
    typicalFindings: [
      "Social media profiles containing the same person's face",
      "Name associated with a previously anonymous photograph",
      "Related profile URLs and aliases",
    ],
    whyItMatters:
      "When an investigation starts with a photograph of an unknown person, EagleEye is the tool that turns that image into a name and a social profile. High-impact, but also requires careful use — facial-recognition OSINT is ethically and legally sensitive and investigators must verify jurisdiction-specific rules before running it.",
    feedsInto: ["Sherlock", "holehe"],
    consumesFrom: ["ExifTool"],
    reference: "https://github.com/ThoughtfulDev/EagleEye",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
  {
    name: "OSINT-SPY",
    aliases: ["osint-spy", "osintspy"],
    category: "osint",
    description:
      "A Python OSINT tool that aggregates searches across email, domain, IP, device, and bitcoin-address data sources into a single command. Useful for quick lookups when you don't need the full depth of SpiderFoot or Recon-ng.",
    typicalFindings: [
      "Quick summary intel about an email, domain, or IP",
      "Malware and bitcoin-address reputation",
      "Associated accounts from breached databases",
    ],
    whyItMatters:
      "A lightweight 'middle ground' between running a single specialized tool and running SpiderFoot's full orchestration. Good for quick triage when you're not sure whether a target deserves deeper investigation.",
    feedsInto: ["SpiderFoot"],
    consumesFrom: [],
    reference: "https://github.com/SharadKumar97/OSINT-SPY",
    environmentSetup: [],
    reproductionSteps: [],
    verificationSteps: [],
  },
];

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/** Normalize a tool name for fuzzy matching — lowercase, trim, strip .exe. */
function normalize(name: string): string {
  return name.trim().toLowerCase().replace(/\.exe$/i, "").replace(/\s+/g, " ");
}

/**
 * Case-insensitive, alias-aware lookup. Returns the matching ForensicTool or
 * null if nothing matches. Tries exact, then alias, then startsWith (for
 * matches like "exiftool-13.50").
 */
export function lookupTool(name: string): ForensicTool | null {
  if (!name) return null;
  const n = normalize(name);

  // 1. Exact name match
  for (const t of TOOLS) {
    if (normalize(t.name) === n) return t;
  }
  // 2. Alias match
  for (const t of TOOLS) {
    if (t.aliases.some((a) => normalize(a) === n)) return t;
  }
  // 3. Prefix match — handles "exiftool-13.50", "john-1.9.0", etc.
  for (const t of TOOLS) {
    if (n.startsWith(normalize(t.name))) return t;
    if (t.aliases.some((a) => n.startsWith(normalize(a)))) return t;
  }
  return null;
}

/**
 * Given a ForensicTool and the list of tool_name strings present in the
 * current case, return the subset of case tools this tool feeds into —
 * each resolved to its own ForensicTool (or null if unknown).
 *
 * Matching is strict: two tools match only if they resolve to the SAME
 * canonical KB entry via lookupTool(), or (for unknown tools) if their
 * normalized strings are equal. Prefix matching is deliberately NOT used
 * here — it lives only in lookupTool() for one-tool-to-one-KB resolution.
 * Allowing prefix matches at this layer causes false positives like
 * "7z2john".startsWith("7z") matching "7z" as its own dependent.
 *
 * Used to render dependency chips: "Feeds into: exiftool, john".
 */
export function findDependentsInCase(
  tool: ForensicTool,
  caseToolNames: string[],
): Array<{ name: string; tool: ForensicTool | null }> {
  return resolveChain(tool.feedsInto, caseToolNames);
}

/**
 * Same as findDependentsInCase but walks the "consumes from" relationship —
 * which tools in the case this one takes input from.
 */
export function findPrerequisitesInCase(
  tool: ForensicTool,
  caseToolNames: string[],
): Array<{ name: string; tool: ForensicTool | null }> {
  return resolveChain(tool.consumesFrom, caseToolNames);
}

/** Shared dependency-chain resolver — see findDependentsInCase docs. */
function resolveChain(
  targets: string[],
  caseToolNames: string[],
): Array<{ name: string; tool: ForensicTool | null }> {
  const seen = new Set<string>();
  const out: Array<{ name: string; tool: ForensicTool | null }> = [];
  for (const target of targets) {
    const targetTool = lookupTool(target);
    const targetNorm = normalize(target);
    for (const caseName of caseToolNames) {
      if (seen.has(caseName)) continue;
      const caseTool = lookupTool(caseName);
      const caseNorm = normalize(caseName);
      const isMatch =
        targetTool && caseTool
          ? targetTool.name === caseTool.name
          : caseNorm === targetNorm;
      if (isMatch) {
        seen.add(caseName);
        out.push({ name: caseName, tool: caseTool });
      }
    }
  }
  return out;
}
