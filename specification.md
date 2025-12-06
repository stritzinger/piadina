<!--
SPDX-FileCopyrightText: 2024 Dipl.Phys. Peer Stritzinger GmbH
SPDX-License-Identifier: Apache-2.0
-->

## Piadina / Azdora – Planning and Specification (v0.1)

### 0. Glossary

- **Piadina**: The overall project name and the **launcher executable**. Piadina is the self-extracting binary’s entry program responsible for reading the footer and metadata, extracting the payload, and launching the target application.
- **Azdora**: The **packer executable** for the Piadina project. Azdora takes a Piadina launcher binary, a payload directory, and metadata, and produces a final self-extracting binary that Piadina can run.
- **Launcher**: The behavioral role implemented by the Piadina executable: read footer and metadata, manage caching and extraction, and `execve` the target application.
- **Packer**: The behavioral role implemented by the Azdora executable: assemble launcher, metadata, archive, and footer into a single binary.
- **Payload**: The directory tree that is tarred and compressed into the archive (e.g. an Erlang/OTP release). After extraction, it lives under `PAYLOAD_ROOT`.
- **Payload root (`PAYLOAD_ROOT`)**: The directory on disk where Piadina extracts (or reuses) the payload for a given archive (currently `{CACHE_ROOT}/{ARCHIVE_HASH}` until payload hashing is implemented).
- **Cache root (`CACHE_ROOT`)**: The top-level directory under which all cached payloads and auxiliary files (locks, temp dirs, ready markers) are stored (default `{HOME}/.piadina/cache`).
- **`PAYLOAD_HASH`**: SHA-256–based hash defined over the logical payload directory tree (paths, modes, contents, symlinks) before archiving. Used to key the cache and validate extracted payloads.
- **`ARCHIVE_HASH`**: SHA-256 hash over the exact tar+gzip byte stream embedded in the binary. Used to validate the integrity of the embedded archive.
- **Lock file (`LOCK_FILE`)**: A per-payload file used to coordinate extraction between concurrent launcher runs and to detect stale extractions.
- **Ready marker (`READY_MARKER`)**: A per-payload marker file indicating that a payload directory is fully extracted and ready for reuse.
- **Temporary extraction directory (`TEMP_DIR`)**: A scratch directory where extraction occurs before being atomically renamed into `PAYLOAD_ROOT`.
- **Footer**: The fixed-size structure at the end of the self-extracting binary that records offsets, sizes, layout version, hashes, and reserved bytes for future extensions.
- **`.piadina_env`**: A shell-friendly environment file written into the payload directory after extraction, capturing effective metadata and derived values in `KEY=VALUE` form.

### 1. Purpose and Scope

Piadina is a suite of two executables:

- **Piadina**: The **launcher**. A static C program that unpacks and runs an embedded payload (currently a gzip-compressed tarball).
- **Azdora**: The **packer**. A tool that takes a Piadina binary, a directory tree, and some metadata, and spits out a self-extracting executable.

**Why are we building this?**
We want a launcher that is:
1.  **Runtime-agnostic**: It shouldn't care if the payload is Erlang, Elixir, or a bash script. No BEAM dependencies in the launcher itself.
2.  **Reusable**: The same launcher binary works for any payload.
3.  **Portable**: Starts with Linux (x86_64, aarch64), aimed at `musl` for static linking. macOS and Windows are non-goals for v0.1 but on the radar.

Eventually, Piadina should fit nicely into `rebar3` and OTP releases. Azdora serves as the reference packer implementation (though in the future, `rebar3` might do the packing itself).

This spec covers the **functional requirements**, **binary format**, **metadata schema**, and **module design**. It's a draft (v0.1), so expect changes.

### 2. Prior Art & Inspiration

We're standing on the shoulders of:

- **Burrito** ([`burrito-elixir/burrito`](https://github.com/burrito-elixir/burrito)): specifically `src/wrapper.zig`. We liked:
  - Self-introspection to find the payload.
  - The footer layout.
  - Content-addressed caching (extraction keyed by hash).
  - Separating launcher args from app args.

- **Bakeware** ([`bake-bake-bake/bakeware`](https://github.com/bake-bake-bake/bakeware)):
  - The "single-file executable" concept.
  - Focus on a smooth CLI UX.

Piadina generalizes this: a **C-based launcher** for **any tarball payload**, not just BEAM apps.

### 3. Shared Binary Layout and Metadata

This section defines the contract between Azdora (the writer) and Piadina (the reader).

#### 3.1 On-Disk Binary Layout

The distributed binary is a concatenation of 4 parts:

1.  **Launcher executable** (ELF).
2.  **Archive** (gzip-compressed tarball).
3.  **Metadata** (CBOR).
4.  **Footer** (Fixed-size).

All offsets in the footer are relative to the start of the file.

##### 3.1.1 Overall Layout

From beginning to end, the file is:

- `[0 .. launcher_size-1]` – Launcher executable image.
- `[launcher_size .. launcher_size + archive_size - 1]` – Archive (tar+gzip, i.e. the compressed payload).
- `[launcher_size + archive_size .. launcher_size + archive_size + metadata_size - 1]` – CBOR metadata blob.
- `[end - FOOTER_SIZE .. end - 1]` – Footer with magic, offsets, sizes, hashes, format.

##### 3.1.2 Footer Structure (Conceptual)

The footer is a fixed-size, tightly-packed **192-byte** binary structure:

- **magic**: 8 bytes, `"PIADINA\0"`.
- **layout_version**: 32-bit unsigned integer.
- **metadata_offset**: 64-bit unsigned integer.
- **metadata_size**: 64-bit unsigned integer.
- **archive_offset**: 64-bit unsigned integer.
- **archive_size**: 64-bit unsigned integer.
- **metadata_hash**: 32-byte SHA-256 of the metadata block (as stored).
- **archive_hash**: 32-byte SHA-256 of the archive bytes (tar+gzip).
- **reserved**: 52 bytes, zeroed for layout version 1.
- **footer_hash**: 32-byte SHA-256 of the footer with `footer_hash` zeroed.

The exact C struct used in `footer.h` is the normative definition of the footer layout. All multi-byte integer fields are encoded as little-endian values, tightly packed with no padding between fields. For layout version `1`, the 52 `reserved` bytes MUST be set to zero; future layout versions MAY reinterpret them (or extend the footer) for features such as signature references or other metadata, but MUST do so in a way that is clearly distinguished via the `layout_version` field. At runtime, Piadina:

- Seeks to `file_size - FOOTER_SIZE`.
- Reads and validates the footer.
- Trusts offsets/sizes and uses them to find metadata and payload.

##### 3.1.3 Payload Hashing and Verification

Two different hashes are tracked:

- **`payload_hash`** in the metadata:
  - Computed by Azdora from the **directory tree** it packs (before tar/gzip).
  - Can be recomputed efficiently from the extracted directory structure, without re-reading or re-creating the tarball.
  - Used by Piadina to validate an existing extracted payload directory when `validate` behavior is enabled.
- **`archive_hash`** in the footer:
  - Computed by Azdora over the **exact archive bytes** written into the binary (tar+gzip).
  - Used to validate the integrity of the embedded archive stream itself.

###### 3.1.3.1 Payload Hash (`PAYLOAD_HASH`)

The payload hash is defined over the directory passed to Azdora as the payload root. The goal is a deterministic, content-sensitive hash that can be recomputed from the extracted directory alone.

Algorithm (conceptual):

1. **Input**:
   - A root directory `ROOT` provided to Azdora.
   - All regular files, directories, and symbolic links under `ROOT` are included.
   - Paths are considered relative to `ROOT` (no leading `/`).

2. **Enumerate entries**:
   - Recursively walk `ROOT`.
   - For each encountered entry:
     - Compute a **relative POSIX path** with `/` as separator and no `.` or `..` components.
     - Classify as:
       - `D` – directory.
       - `F` – regular file.
       - `L` – symbolic link.
   - Exclude:
     - The root directory itself as an entry.
     - Any entries that cannot be represented with a valid POSIX path (implementation-defined error handling).

3. **Sort entries**:
   - Build a list of entries sorted **lexicographically by relative path bytes** (UTF-8), with the convention that:
     - Directory paths are represented without a trailing `/` in the sort key (e.g. `dir` rather than `dir/`).

4. **Hash stream construction**:
   - Initialize a SHA-256 context `C`.
   - For each entry in sorted order:
     - Let `P` be the relative path bytes (no leading `/`).
     - Let `M` be the file mode (e.g. `st_mode`) encoded as an ASCII octal string without leading `0` padding (implementation detail).
     - For a **directory** `D`:
       - Feed into `C` in order:
         - Byte `"D"` (0x44).
         - Byte `0x00`.
         - Bytes of `P`.
         - Byte `0x00`.
         - Bytes of `M`.
         - Byte `0x00`.
     - For a **regular file** `F`:
       - Feed into `C`:
         - Byte `"F"` (0x46).
         - Byte `0x00`.
         - Bytes of `P`.
         - Byte `0x00`.
         - Bytes of `M`.
         - Byte `0x00`.
         - The **file contents**, read in order from byte 0 to end.
         - Byte `0x00`.
     - For a **symbolic link** `L`:
       - Let `T` be the link target path bytes exactly as stored.
       - Feed into `C`:
         - Byte `"L"` (0x4c).
         - Byte `0x00`.
         - Bytes of `P`.
         - Byte `0x00`.
         - Bytes of `M`.
         - Byte `0x00`.
         - Bytes of `T`.
         - Byte `0x00`.
   - After processing all entries, finalize `C` to produce 32 bytes: this is `payload_hash`.

5. **Properties**:
   - The hash is **order-independent** with respect to OS directory traversal order (paths are sorted).
   - It is sensitive to:
     - File contents, file modes, relative paths, and link targets.
   - It can be recomputed by Piadina from an extracted directory tree using the same algorithm.

###### 3.1.3.2 Archive Hash (`ARCHIVE_HASH`)

The archive hash is simpler:

- Azdora computes `ARCHIVE_HASH` as SHA-256 over the exact sequence of bytes that constitute the archive (the tar+gzip stream) written into the final binary, in the order they are written.
- Piadina may recompute this hash if it needs to validate the embedded archive stream (e.g. for diagnostics), but normal directory validation uses `payload_hash`.

#### 3.2 Metadata Schema (CBOR)

Metadata is a CBOR map with string keys and simple values. Piadina and Azdora implement only a **small subset of CBOR** for this schema:

- Unsigned integers.
- Boolean values.
- Text strings.
- Byte strings.
- Arrays.
- Maps with string keys.

All **metadata field names and map keys** (including keys inside `"ENV"`) MUST respect the identifier pattern:

- First character: `[a-zA-Z-_]`
- Subsequent characters: `[a-zA-Z0-9-_]*`

Metadata decoding (in Piadina and Azdora) MUST reject any metadata whose keys do not satisfy this pattern.

##### 3.2.1 Top-Level Metadata Map

The top-level map should contain at least:

- **`"VERSION"`** (uint): metadata schema version (e.g. `1`).
  - This value is set by the builder tools (e.g. Azdora) based on the supported schema/tool version.
  - User-provided metadata (including Azdora’s `--meta` CLI) MUST NOT be allowed to override `"VERSION"`; attempts to do so MUST result in a clear error.
- **`"APP_NAME"`** (text, optional): human-readable name used in logging.
- **`"APP_VER"`** (text, optional): human-readable version used in logging.
- **`"ARCHIVE_HASH"`** (text): archive hash, the same as in the footer.
- **`"ARCHIVE_FORMAT"`** (text, optional): archive format identifier; Piadina MUST currently support only `"tar+gzip"` and MUST reject any other value. Default if absent: `"tar+gzip"`.
- **`"PAYLOAD_HASH"`** (byte string): the payload (directory tree) hash.


Execution configuration:

- **`"ENTRY_POINT"`** (text, required):
  - Path to executable relative to the payload directory (e.g. `"bin/my_app"`).
- **`"ENTRY_ARGS"`** (array of text, optional):
  - Arguments inserted immediately after `argv[0]`, before any launcher-provided extra arguments.
- **`"ENTRY_ARGS_POST"`** (array of text, optional):
  - Arguments appended after launcher-provided extra arguments.
- **`"ENV"`**:
  - A map from text to text.
  - Specifies environment variables to add or override for the child process.
  - Keys MUST also be shell-safe for export: after uppercasing, they must match
    `[A-Za-z_][A-Za-z0-9_]*` (hyphens are not permitted).

Extraction/cache configuration:

- **`"CACHE_ROOT"`** (text, optional):
  - Template for the cache root directory.
  - Default if absent: `"{HOME}/.piadina/cache"`.
- **`"PAYLOAD_ROOT"`** (text, optional):
  - Template for the payload directory name relative to cache root.
  - Default if absent: `"{PAYLOAD_HASH}"`.
- **`"CLEANUP_POLICY"`** (text, optional):
  - One of `"never"`, `"oncrash"`, `"always"`.
  - Default if absent: `"oncrash"`.
- **`"VALIDATE"`** (bool, optional):
  - If `true`, existing cached payloads are validated against `PAYLOAD_HASH` by default.
  - Default if absent: `false`.

The builder tools (Azdora and any future alternatives) are responsible for producing this CBOR metadata according to the schema.

##### 3.2.2 Template Substitution

Some metadata string fields are **templates** which support `{VAR}` substitution:

- Typical variables from system env:
  - `{HOME}` – from the `HOME` environment variable (or fallback).
  - `{TMPDIR}` – from `TMPDIR` or default `/tmp`.
  - `{UID}`, `{GID}` – numeric UID/GID.

Supported template fields from metadata:

- `{PAYLOAD_HASH}` – hex representation of the payload (directory tree) hash from the metadata.
- `{ARCHIVE_HASH}` – hex representation of the archive hash from the footer.
- `{CACHE_ROOT}` - The root directory of the piadina cache.
- `{PAYLOAD_ROOT}` - The root directory of the payload.
- `{RANDOM}` - a random string on each launcher run.

Templating evaluation order:

1. **Initial variable set**:
   - Start from the current process environment: for each `NAME=VALUE` pair, define a template variable `{NAME}` with value `VALUE`, alongside `PAYLOAD_HASH` and `ARCHIVE_HASH`.
2. **Resolve cache root**:
   - Take the metadata field `"CACHE_ROOT"` (or its default `"{HOME}/.piadina/cache"`).
   - Apply template substitution using the initial variable set.
   - The result is the **cache root** and is also exported as variable `{CACHE_ROOT}`.
3. **Resolve payload root**:
   - Take the metadata field `"PAYLOAD_ROOT"` (or its default value defined later on).
   - Apply template substitution using the variable set extended with `{CACHE_ROOT}`.
   - The result is the **payload root directory** and is also exported as variable `{PAYLOAD_ROOT}`.
4. **Resolve arguments**:
   - Apply template substitution to each element of `"ENTRY_ARGS"` and `"ENTRY_ARGS_POST"`.
   - This allows these fields to reference variables like `{PAYLOAD_ROOT}` or `{CACHE_ROOT}`.
   - Note: `"ENTRY_POINT"` does **not** support template substitution; it must be a valid relative path within the payload.
5. **Resolve metadata environment variables**:
   - For each entry in metadata `"ENV"`, apply template substitution using all previously defined fields.
   - The resulting key/value pairs are then applied to the child’s environment.

The templating language is intentionally simple:

- No conditionals or loops.
- String substitution only:
  - Unknown variables should cause an error.

### 4. Piadina Launcher – Functional Specification

#### 4.1 High-Level Behavior

Here is the lifecycle of a Piadina run:

1.  **Parse configuration**: Environment vars, `--launcher-...` args, and locate the `--` separator.
2.  **Self-discovery**: Find our own executable path and open it.
3.  **Footer check**: Jump to the end, verify magic/version, read offsets.
4.  **Metadata load**: Read and decode the CBOR block.
5.  **Resolve config**: Merge defaults < environment < CLI args. Determine `CACHE_ROOT`, `PAYLOAD_ROOT`, etc.
6.  **Extraction (with locking)**:
    -   Calculate the **payload hash**.
    -   Grab the lock.
    -   Check if `READY_MARKER` exists.
    -   If missing or invalid: extract to `TEMP_DIR`, rename to `PAYLOAD_ROOT`, touch `READY_MARKER`.
7.  **Launch prep**:
    -   Template substitution.
    -   Build `argv` (Launcher args + App args).
    -   Build `envp` (Clean env + Metadata ENV).
8.  **Exec**: `fork` + `execve`. Parent waits.
9.  **Cleanup**: If policy says so (e.g. `oncrash`), wipe the directory.

#### 4.2 Configuration Interface: CLI and Environment

Piadina configuration comes from three sources:

1. **Metadata defaults** (embedded in the binary).
2. **Environment variables** (prefixed with `PIADINA_`).
3. **Command-line options** (prefixed with `--launcher-`).

Precedence:

- **Command-line options** override **environment variables**, which override **metadata defaults**.

All launcher-specific options are *consumed* by the launcher and not passed through to the application as arguments. Similarly, launcher-specific environment variables can optionally be filtered out before launching the child.

##### 4.2.1 Command-Line Options

Launcher-specific options (initial set):

- **`--launcher-cache-root=PATH`**
  - Override the cache root directory (after template processing).

- **`--launcher-cleanup=never|oncrash|always`**
  - Override cleanup policy:
    - `never`: never delete the payload directory automatically.
    - `oncrash`: delete if the child exits with non-zero status or via a signal.
    - `always`: delete payload directory after the child exits, regardless of status.

- **`--launcher-validate[=true|false]`**
  - Control whether an existing “ready” payload directory is validated against the payload hash.
  - If provided without value, treated as `true`.
- **`--launcher-force-extract[=true|false]`**
  - Force a fresh extraction of the embedded archive even if a cache entry is already marked ready.
  - When enabled, the launcher MUST still follow the standard locking protocol so that it never deletes or overwrites a payload currently being prepared by another process.
  - If provided without value, treated as `true`.

- **`--launcher-log-level=debug|info|warn|error`**
  - Override log verbosity.

- **`--launcher-verbose`**
  - Convenience alias for `--launcher-log-level=debug` (exact behavior to be defined).

- **`--launcher-print-metadata`**
  - Decode and dump metadata to stderr (or stdout) and exit without launching the application.

- **`--launcher-print-footer`**
  - Dump footer fields for debugging and exit.

- **`--launcher-help`**
  - Print launcher usage and exit.

- **`--launcher-version`**
  - Print launcher version and exit.

Argument separation:

- **`--`**:
  - All arguments after `--` are treated as application arguments and are not interpreted by the launcher.

##### 4.2.2 Environment Variables

Environment variables mirror many CLI options:

- **`PIADINA_CACHE_ROOT`**
  - Equivalent to `--launcher-cache-root`.

- **`PIADINA_CLEANUP_POLICY`**
  - Values: `never`, `oncrash`, `always`.
  - Equivalent to `--launcher-cleanup`.

- **`PIADINA_VALIDATE`**
  - Values: `true`, `false`.
  - Equivalent to `--launcher-validate`.
- **`PIADINA_FORCE_EXTRACT`**
  - Values: `true`, `false`.
  - Equivalent to `--launcher-force-extract`.
- **`PIADINA_LOG_LEVEL`**
  - Values: `debug`, `info`, `warn`, `error`.
  - Equivalent to `--launcher-log-level`.

The launcher will:

- Read these variables for configuration.
- Optionally remove them from the environment before launching the application to avoid leaking internal configuration (exact behavior to be finalized).

#### 4.3 Extraction, Locking, and Crash Recovery

##### 4.3.1 Directory Layout

Given:

- `PAYLOAD_HASH` = hex SHA-256 of the payload directory tree (from the metadata and recomputable from the extracted directory).
- `CACHE_ROOT` resolved from metadata/defaults and CLI/env.

Suggested defaults on Linux:

- `CACHE_ROOT = {HOME}/.piadina/cache` (or a fallback in `/tmp` if `HOME` is not set).
- `PAYLOAD_ROOT = {CACHE_ROOT}/{ARCHIVE_HASH}` (until payload hashing is implemented).
- `TEMP_DIR = {CACHE_ROOT}/.{PAYLOAD_HASH}.tmp`.
- `LOCK_FILE = {CACHE_ROOT}/.{PAYLOAD_HASH}.lock`.
- `READY_MARKER = {CACHE_ROOT}/.{PAYLOAD_HASH}.ready`.

##### 4.3.2 Lock Acquisition

Locking is implemented with a simple file-based protocol:

- Attempt to create the lock file with `O_CREAT | O_EXCL`.
- On success:
  - The current process owns the lock and is responsible for extraction.
  - Write identifying info into the file:
    - PID.
    - Timestamp.
    - Optional hostname.
- On failure (lock file exists):
  - Read and parse existing lock file.
  - Check if the PID is still alive (e.g. using `kill(pid, 0)` on Unix).
    - If alive, either wait and retry (with backoff) or fail fast with a user-friendly error.
    - If not alive, treat the lock as stale:
      - Remove lock file and attempt to acquire it again.

This protocol provides:

- Mutual exclusion for extraction.
- Recovery from crash or abrupt termination of the extracting process.

##### 4.3.3 Extraction Algorithm

Under the lock:

1. If `PAYLOAD_ROOT` exists and `READY_MARKER` exists:
   - If validation is disabled:
     - Assume payload is valid and skip extraction.
   - If validation is enabled:
     - Recompute the directory tree hash using the algorithm in §3.1.3.1 and compare it to `PAYLOAD_HASH`.
     - If validation fails, remove or move aside `PAYLOAD_ROOT` and proceed to re-extract.
   - If the effective configuration sets `force_extract=true`:
     - Treat the existing payload as stale regardless of validation outcome and continue with the re-extraction flow below.

2. If `PAYLOAD_ROOT` does not exist, validation failed, or `force_extract=true`:
   - Verify that the decoded metadata’s `"ARCHIVE_FORMAT"` is supported:
     - For v0.1, Piadina MUST accept only `"tar+gzip"` (default when field is absent) and MUST fail with a clear error for any other value.
   - Remove `TEMP_DIR` if it exists (leftovers from previous crash).
   - Create `TEMP_DIR`.
   - Open the launcher file and seek to `archive_offset`.
   - Stream (`read`) the archive bytes through gzip and tar extraction code into `TEMP_DIR`.
   - On successful extraction (still under the lock):
     - Atomically `rename(TEMP_DIR, PAYLOAD_ROOT)`.
     - Write or refresh the exported metadata file inside `PAYLOAD_ROOT` (see §4.3.4).
     - Create or update `READY_MARKER`.

3. Release lock:
   - Close lock file descriptor.
   - Unlink the lock file so future runs can reuse the cached directory.

##### 4.3.4 Exported Metadata File

After a successful extraction (either a fresh extraction or reuse of an already validated `PAYLOAD_ROOT`), and **while still holding the extraction lock**, Piadina will write (or refresh) a **human-readable metadata file** inside the payload directory to capture effective launcher and payload configuration in a form that can be reused by other tools or inspected by users.

- **Location**:
  - The file is created at `{PAYLOAD_ROOT}/.piadina_env`.
- **Purpose**:
  - Provide a stable, shell-friendly view of relevant metadata and derived values (e.g. `PAYLOAD_HASH`, `ARCHIVE_HASH`, `CACHE_ROOT`, `PAYLOAD_ROOT`, `ENTRY_POINT`, etc.).
  - Allow advanced users or scripts to `source` this file in `bash` (or compatible shells) to inspect or reuse metadata.
  - Ensure that environment variables defined in the `"ENV"` metadata map, when sourced from `.piadina_env`, take precedence over any conflicting metadata-derived variables by writing their **unprefixed** forms at the end of the file.

File format:

- Text file, UTF-8 encoded.
- Each non-empty, non-comment line has the form:
  - `KEY=VALUE`
- Lines beginning with `#` are comments and ignored when sourcing.
- Keys:
  - Must match the shell identifier pattern `[A-Z_][A-Z0-9_]*`.
  - All keys defined by Piadina (e.g. `APP_NAME`, `APP_VER`, `PAYLOAD_HASH`, `ARCHIVE_HASH`, `CACHE_ROOT`, `PAYLOAD_ROOT`, `ENTRY_POINT`, etc.) MUST be **all uppercase**, to align with the template variable names and common shell conventions.
- Values:
  - If `VALUE` contains only characters safe for unquoted shell assignment (no spaces, tabs, quotes, backslashes, `$`, backticks, `#`, or control characters), it MAY be written literally:
    - `FOO=bar`
  - Otherwise, values MUST be written as a double-quoted shell string:
    - `FOO="some value with spaces and \"quotes\""`
  - Special characters inside double quotes MUST be backslash-escaped, at minimum:
    - `"` as `\"`
    - `\` as `\\`
    - Newline as `\n`
    - Tab as `\t`

Multiline and binary values:

- **Multiline text values**:
  - Represented using `\n` escape sequences inside the double-quoted string, e.g.:
    - `LONG_TEXT="line one\nline two\nline three"`
  - When `bash` (or a compatible shell) sources this file, the resulting environment variable will contain literal newline characters at those positions.
- **Binary values**:
  - Piadina MUST NOT attempt to emit raw binary in this file.
  - Instead, binary metadata (if any) MUST be encoded in **Base64** (RFC 4648) and written as:
    - `KEY=base64:ENCODED`
  - `ENCODED` is a Base64 string with no embedded whitespace or newlines.

Arrays and maps:

- The `.piadina_env` file MUST represent arrays and maps in a **bash-compatible, purely environment-variable-based way** (no bash-specific array syntax is required to consume it, but it SHOULD be easy to use from bash).
- For metadata that is conceptually a **scalar** (single value), Piadina will export a single `KEY=VALUE` pair, e.g.:
  - `APP_NAME="my_app"`
  - `APP_VER="1.2.3"`
- For metadata that is conceptually an **array** under logical name `X`:
  - Piadina will export:
    - `X_COUNT=N` (number of elements).
    - `X_0=...`, `X_1=...`, …, `X_{N-1}=...`.
  - Example for `ENTRY_ARGS`:
    - `ENTRY_ARGS_COUNT=3`
    - `ENTRY_ARGS_0="--foo"`
    - `ENTRY_ARGS_1="--bar"`
    - `ENTRY_ARGS_2="--baz"`
  - A bash script can then consume this as:
    - `for ((i=0; i<ENTRY_ARGS_COUNT; i++)); do ARGS+=("${!("ENTRY_ARGS_"$i)}"); done`
- For metadata that is conceptually a **map** under logical name `X`:
  - Piadina will export one **prefixed** variable per key, uppercasing and sanitizing the original key after a fixed prefix:
    - The prefixed variable name is `X_` followed by the map key converted to:
      - All letters uppercased.
      - Hyphens `-` converted to underscores `_`.
      - (Other characters are already forbidden by validation; see `"ENV"` in §3.2.1.)
  - For the special metadata map `"ENV"` **only**, Piadina will additionally export **unprefixed** environment variables so that sourcing `.piadina_env` sets the intended environment directly:
    - The unprefixed variable name is just the uppercased-and-sanitized key (no `ENV_` prefix).
    - If an unprefixed `ENV` variable name collides with a metadata-derived key (e.g. `APP_NAME`, `PAYLOAD_ROOT`), Piadina MUST:
      - Write both variables (metadata-derived and prefixed forms first, and the unprefixed `ENV` key later in the file) so the `ENV` value wins when sourced.
      - Emit a warning (to stderr or logs) indicating that an `ENV` key is overriding a metadata key.
  - Example for metadata `ENV`:
    - Metadata keys: `"DB_HOST"`, `"db_port"`, `"secret-key"`.
    - Exported variables:
      - Prefixed:
        - `ENV_DB_HOST="localhost"`
        - `ENV_DB_PORT="5432"`
        - `ENV_SECRET_KEY="s3cr3t"`
      - Unprefixed (ENV only):
        - `DB_HOST="localhost"`
        - `DB_PORT="5432"`
        - `SECRET_KEY="s3cr3t"`
  - Exact naming for each logical metadata map (e.g. `ENV`) SHOULD be documented when that map is introduced, but MUST follow this “prefix + uppercased-and-sanitized key” pattern for the prefixed form. Only `"ENV"` gets the additional unprefixed environment variables, which MUST be written **after all metadata-derived and prefixed variables** so that they override any earlier definitions when the file is sourced.

Generation order:

- The variables written to `.piadina_env` are derived **exclusively from metadata** (fields defined in §3.2) plus a small set of fixed launcher identifiers. Piadina MUST NOT copy arbitrary OS environment variables into this file.
  - For each metadata field, Piadina exports either the value explicitly provided in the CBOR metadata or its **default value** if the field is omitted (for example, `ARCHIVE_FORMAT="tar+gzip"` will still appear in `.piadina_env` even if `"ARCHIVE_FORMAT"` is not present in the metadata).
  - Template placeholders in metadata use the `{VAR}` syntax (e.g. `{HOME}`, `{PAYLOAD_ROOT}`) and are **not** expanded when writing `.piadina_env`. Instead, each `{VAR}` placeholder SHOULD be rendered as the bash-compatible form `${VAR}` in the exported value so that expansion happens at shell runtime when the file is sourced.
- Piadina MUST order assignments in `.piadina_env` so that any variable used in another value is defined **before** its first use:
  - Metadata- and launcher-derived variables such as `PAYLOAD_HASH`, `CACHE_ROOT`, and `PAYLOAD_ROOT` MUST be written before variables that reference `${PAYLOAD_HASH}`, `${CACHE_ROOT}`, or `${PAYLOAD_ROOT}`.
  - Prefixed map variables (e.g. `ENV_FOO`, `CUSTOM_SETTINGS_BAR`) MUST be written before any unprefixed `ENV` variables, and all unprefixed `ENV` variables MUST appear at the very end of the file so that they can safely override earlier definitions when sourced.
  - The exact set of exported keys is:
  - One uppercase `KEY=VALUE` assignment for each top-level metadata field defined in §3.2.1 (e.g. `VERSION`, `APP_NAME`, `APP_VER`, `ARCHIVE_HASH`, `ARCHIVE_FORMAT`, `PAYLOAD_HASH`, `CACHE_ROOT`, `PAYLOAD_ROOT`, `CLEANUP_POLICY`, `VALIDATE`, `ENTRY_POINT`), whether explicitly provided in metadata or filled in by defaults.
  - The array and map expansions described above (e.g. `ENTRY_ARGS_COUNT`/`ENTRY_ARGS_N`, prefixed `ENV_*`, and similar for any user-defined maps following the same pattern).
  - For the special `"ENV"` map only, the additional unprefixed variables corresponding to each key, written last as described above, so that they override earlier definitions when the file is sourced.
  - No other keys derived from the ambient OS environment or internal launcher state MAY be exported into `.piadina_env`.
  - The file format and escaping rules above MUST be followed so that:
    - `bash -c 'source .piadina_env; exec "$ENTRY_POINT" "$@"'` is safe and behaves as expected.

Example:

Below is a **realistic `.piadina_env` example** for an Erlang/OTP release with defaulted top-level metadata fields, an `ENV` map, and a user-defined map named `CUSTOM_SETTINGS`, plus an `ENTRY_ARGS` array configured in metadata. Assume:

- `"VERSION" = 1`
- `"APP_NAME" = "my_app"`, `"APP_VER" = "1.2.3"`.
- `"ARCHIVE_HASH"` and `"PAYLOAD_HASH"` are 64-character hex SHA-256 strings.
- `"ARCHIVE_FORMAT"` omitted, so it defaults to `"tar+gzip"`.
- `"CACHE_ROOT" = "{HOME}/.piadina/cache"`, `"PAYLOAD_ROOT" = "{CACHE_ROOT}/{ARCHIVE_HASH}"`.
- `"CLEANUP_POLICY"` omitted, so it defaults to `"oncrash"`.
- `"VALIDATE"` omitted, so it defaults to `false`.
- `"ENTRY_POINT" = "bin/my_app"`.
- `"ENTRY_ARGS" = ["console", "--no-halt"]`.
- `"ENV"` contains (Erlang release-related variables):
  - `"RELEASE_ROOT"` = "{PAYLOAD_ROOT}"
  - `"ERL_CRASH_DUMP"` = "{PAYLOAD_ROOT}/log/erl_crash.dump"
  - `"RELX_REPLACE_OS_VARS"` = "true"
- A user-defined map `"CUSTOM_SETTINGS"` contains:
  - `"support_email"` = "support@example.com"
  - `"feature-flag"` = "on"

The resulting `.piadina_env` might look like:

```bash
# Top-level metadata
VERSION=1
APP_NAME="my_app"
APP_VER="1.2.3"
ARCHIVE_HASH="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ARCHIVE_FORMAT="tar+gzip"
PAYLOAD_HASH="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

# Derived paths (note: metadata templates {FOO} become bash-style ${FOO})
CACHE_ROOT="${HOME}/.piadina/cache"
PAYLOAD_ROOT="${CACHE_ROOT}/${PAYLOAD_HASH}"

# Defaulted behavioral settings
CLEANUP_POLICY="oncrash"
VALIDATE="false"

# Entry point and arguments
ENTRY_POINT="${PAYLOAD_ROOT}/bin/my_app"
ENTRY_ARGS_COUNT=2
ENTRY_ARGS_0="console"
ENTRY_ARGS_1="--no-halt"

# Environment map exported from ENV (prefixed)
ENV_RELEASE_ROOT="${PAYLOAD_ROOT}"
ENV_ERL_CRASH_DUMP="${PAYLOAD_ROOT}/log/erl_crash.dump"
ENV_RELX_REPLACE_OS_VARS="true"

# User-defined map exported with prefix only
CUSTOM_SETTINGS_SUPPORT_EMAIL="support@example.com"
CUSTOM_SETTINGS_FEATURE_FLAG="on"

# Unprefixed ENV variables written last so they override any earlier definitions
RELEASE_ROOT="${PAYLOAD_ROOT}"
ERL_CRASH_DUMP="${PAYLOAD_ROOT}/log/erl_crash.dump"
RELX_REPLACE_OS_VARS="true"
```

When a user runs:

```bash
source .piadina_env
exec "$ENTRY_POINT" "${ENTRY_ARGS[@]}"
```

the `${HOME}`, `${CACHE_ROOT}`, and `${PAYLOAD_ROOT}` references are resolved by the shell at that time, ensuring that `.piadina_env` itself is independent of the OS environment at the moment Piadina generated it.

#### 4.4 Process Launch and Monitoring

- Build the target executable path:
  - Join `PAYLOAD_ROOT` and `ENTRY_POINT`.
- Construct `argv`:
  - `argv[0]`: Set to the **filename** (basename) of the `ENTRY_POINT`, not the full path.
    - The full path constructed above is used as the `filename` argument to `execve`, but `argv[0]` identifies the program name to the running process.
  - Followed by:
    - Metadata `ENTRY_ARGS`.
    - CLI arguments after `--` (application arguments).
    - Metadata `ENTRY_ARGS_POST`.
- Construct `envp`:
  - Start from current process environment.
  - Optionally strip `PIADINA_*` variables.
  - Apply metadata `ENV` map:
    - Add or override entries.

Launch and monitor:

- **Signal Handling**:
  - The launcher MUST install signal handlers for at least `SIGINT` and `SIGTERM`.
  - Upon receiving these signals, the launcher MUST forward them to the child process (e.g. using `kill(child_pid, signum)`).
  - This ensures the child application can perform graceful shutdown (e.g. an Erlang node stopping cleanly) rather than being abruptly killed when the launcher terminates.
  - The `process` module is responsible for setting up this forwarding before launching the child.

- Use `fork` + `execve` on Unix-like systems.
- Parent process waits with `waitpid`:
  - If `WIFEXITED(status)`:
    - Capture `exit_code = WEXITSTATUS(status)`.
  - If `WIFSIGNALED(status)`:
    - Capture `signum = WTERMSIG(status)`.
    - Map to an appropriate exit code (often `128 + signum`).
- Apply cleanup policy based on:
  - Exit code.
  - Whether a signal terminated the process.
- Parent process exits with a code reflecting child outcome (see §4.5).

#### 4.5 Piadina Exit Codes

To avoid ambiguity between "the launcher failed" and "the application failed", Piadina uses a specific range of exit codes for its own internal failures. These are chosen to be distinct from standard shell exit codes (0, 1, 126, 127) and common Erlang/BEAM exit codes (typically 0 or 1).

**Launcher Internal Error Codes (Range 111-119):**

- **`111`**: **Usage Error**. Invalid command-line arguments provided to the launcher itself (e.g. unknown `--launcher-*` flag).
- **`112`**: **Footer/Binary Error**. The binary is corrupted, the footer is missing or invalid, or the magic bytes do not match.
- **`113`**: **Metadata Error**. The metadata blob could not be decoded, the schema version is unsupported, or required fields are missing.
- **`114`**: **Extraction Error**. Failed to acquire the lock, failed to write files to the temporary directory, or the archive stream was corrupted (hash mismatch).
- **`115`**: **Launch Error**. `execve` failed (e.g. entry point not found or not executable). Note: if the child launches and then crashes, it will return its own exit code, not this one.
- **`116`**: **Signal/System Error**. Failed to setup signal handlers or other critical system resource failure.

If the child process is successfully launched, Piadina exits with the **exact exit code** of the child process (0-255), preserving the application's status.

### 5. Azdora Packer – Functional Specification

#### 5.1 Overview and Responsibilities

In addition to the Piadina launcher, the project includes a **second executable**, called **Azdora**: a **reference packer** which assembles the final self-extracting binary by combining:

- A prebuilt Piadina launcher executable.
- A directory tree (payload root) which Azdora will tar/gzip.
- Metadata constructed from a flexible command-line interface.

Azdora is conceptually separate from the launcher and may live in a different directory and/or repository, especially if only the launcher is upstreamed to `rebar3` or OTP.

Azdora’s responsibilities are to:

- Accept:
  - Path to the Piadina launcher executable.
  - Path to a **directory tree** that will be packed as the payload root.
  - Command-line options describing the metadata to encode (maps, arrays, scalars).
  - Output path (or default naming convention) for the resulting self-extracting binary.
- Compute:
  - The **payload hash** (`PAYLOAD_HASH`) from the input directory, using the algorithm in §3.1.3.1.
  - A **tar+gzip archive** stream built from the same directory tree.
  - The **archive hash** (`ARCHIVE_HASH`) over the generated archive stream, as described in §3.1.3.2.
  - Metadata structure according to the schema defined in this document.
  - CBOR encoding of the metadata (the **encoding half** of CBOR).
- Produce:
  - A final binary whose layout matches §3.1 for Piadina:
    - Launcher executable.
    - CBOR metadata.
    - Archive (tar+gzip) generated from the input directory.
    - Footer with offsets, sizes, `ARCHIVE_HASH`, and format.

The packer is a **reference implementation**; other tooling (e.g. rebar3 plugins, build systems) may reimplement its logic in other languages.

#### 5.2 Naming and Placement

- Name: **Azdora** (the Piadina packer), fitting the naming motif already used (e.g. the `cassone` rebar3 plugin).
- Source layout:
  - The repository is organized by **executable name**, not by role:
    - `piadina/` – sources for the Piadina launcher executable.
    - `azdora/` – sources for the Azdora packer executable.
  - Terms like “launcher” and “packer” describe **behaviour/roles**, not directory names.

#### 5.3 Azdora Inputs and CLI Requirements

Azdora needs a **rich but easy-to-use command-line interface** to express metadata, including nested maps and arrays with typed values (integer, string, binary), without requiring separate configuration files.

Core inputs:

- **Launcher path**:
  - Options: `--launcher FILE_PATH` or `-l FILE_PATH`.
- **Payload root directory**:
  - Options: `--payload DIR_PATH` or `-p DIR_PATH`.
  - Azdora will walk this directory tree to compute `PAYLOAD_HASH` and to construct the tar+gzip archive.
- **Output path**:
  - Options: `--output FILE_PATH` or `-o FILE_PATH`.
  - Defaults will be generated from the given meta data app-name and app-ver, if provided or 'output' if not.

Metadata specification:

- All metadata is provided via repeated `--meta` options:
  - General form: `--meta PATH=VALUE` (short form: `-m PATH=VALUE`).
  - `PATH` is a key path that identifies a scalar, array element, or map entry.
  - `VALUE` is a string by default, with optional lightweight type prefixes.

Key paths:

- **Top-level fields** (from the shared schema in §3.2.1):
  - Examples: `APP_NAME`, `APP_VER`, `ENTRY_POINT`, `CACHE_ROOT`, `PAYLOAD_ROOT`,
    `CLEANUP_POLICY`, `VALIDATE`, `ARCHIVE_HASH`, `PAYLOAD_HASH`.
  - The `VERSION` field is reserved and set automatically by Azdora; specifying `--meta VERSION=...` MUST be rejected with an error.
- **Map entries**:
  - `MAP.KEY` form, where `MAP` is a top-level map and `KEY` is the user key.
  - Examples:
    - `ENV.DB_HOST`
    - `ENV.secret-key`
    - `CUSTOM_SETTINGS.support_email`
- **Array elements**:
  - Indexed form: `ARRAY[INDEX]`
    - Example: `ENTRY_ARGS[0]`, `ENTRY_ARGS[1]`
  - Append form: `ARRAY[]`
    - Example: `ENTRY_ARGS[]`

Array index rules:

- Arrays are conceptually dense and 0-based.
- Using `ARRAY[]` appends an element at the end.
- Using `ARRAY[INDEX]` sets the element at a specific index.
- It is an **error** to create holes:
  - If `ENTRY_ARGS[10]` is specified while `ENTRY_ARGS[0]..ENTRY_ARGS[9]` are unset,
    Azdora MUST fail with a clear error rather than implicitly filling gaps.

Typed values:

- By default, `VALUE` is treated as a text string.
- For non-string types, a short prefix is used:
  - Unsigned integer: `u:VALUE`
    - Example: `--meta VERSION=u:1`
  - Boolean: `b:true` or `b:false`
    - Example: `--meta VALIDATE=b:true`
  - Byte strings (for hashes or opaque data):
    - Hex: `hex:012345...`
    - Base64: `b64:AAECAwQ=`

Examples:

- **Top-level scalars**:
  - `--meta VERSION=u:1`
  - `--meta APP_NAME="my_app"`
  - `--meta APP_VER="1.2.3"`
  - `--meta ENTRY_POINT=bin/my_app`
  - `--meta CACHE_ROOT="{HOME}/.piadina/cache"`
  - `--meta PAYLOAD_ROOT="{CACHE_ROOT}/{ARCHIVE_HASH}"`
  - `--meta CLEANUP_POLICY=oncrash`
  - `--meta VALIDATE=b:true`

- **Arrays**:
  - Append:
    - `--meta ENTRY_ARGS[]=console`
    - `--meta ENTRY_ARGS[]=--no-halt`
  - Indexed:
    - `--meta ENTRY_ARGS[0]=console`
    - `--meta ENTRY_ARGS[1]=--no-halt`

- **ENV map**:
  - `--meta ENV.RELEASE_ROOT="{PAYLOAD_ROOT}"`
  - `--meta ENV.ERL_CRASH_DUMP="{PAYLOAD_ROOT}/log/erl_crash.dump"`
  - `--meta ENV.RELX_REPLACE_OS_VARS=true`

- **User-defined map example**:
  - `--meta CUSTOM_SETTINGS.support_email=support@example.com`
  - `--meta CUSTOM_SETTINGS.feature-flag=on`

Help and discoverability:

- Azdora MUST provide:
  - `--help` / `-h`:
    - Prints usage, including:
      - Core options (`--launcher`/`-l`, `--payload`/`-p`, `--output`/`-o`, `--meta`/`-m`).
      - A brief summary of the `PATH=VALUE` format and examples for:
        - Top-level scalars.
        - Arrays (`ARRAY[]`, `ARRAY[INDEX]`).
        - Maps (`MAP.KEY`).
      - A short description of type prefixes (`u:`, `b:`, `hex:`, `b64:`).
    - Exits without producing any output binaries.

This key-path based syntax balances:

- Expressiveness for complex/nested metadata.
- Simplicity and usability from the command line.
- A direct, deterministic mapping to the CBOR schema in this document.

#### 5.4 Azdora CBOR Encoding Responsibilities

Whereas the launcher implements a **CBOR decoder** for the metadata, Azdora must implement the **CBOR encoder**:

- Support encoding of:
  - Unsigned integers.
  - Booleans.
  - Text strings.
  - Byte strings.
  - Arrays.
  - Maps with text keys.
- Enforce the same key naming rules as the launcher:
  - All top-level field names and map keys MUST match the identifier pattern `[a-zA-Z-_][a-zA-Z0-9-_]*`.
  - Azdora MUST refuse to encode metadata that violates this constraint.
- Produce CBOR output that is compatible with the launcher’s decoder.
- Ideally use a shared internal representation (e.g. small metadata DOM or direct encoding from parsed CLI commands) to simplify both encoder and decoder.

The encoder should be minimal and self-contained, mirroring the decoder’s subset of CBOR and avoiding external libraries.

### 6. Implementation Details

#### 6.1 Dependencies, Toolchain, and Testing

##### 6.1.1 Dependencies

Piadina aims for **minimal external dependencies**:

- C standard library + POSIX APIs.
- **Compression**:
  - `zlib` (or a compatible gzip implementation) is required for handling the gzip-compressed archive.
  - The tar format handling itself will be implemented in-tree as a small, self-contained C module (no external tar/archive library).
- A **minimal CBOR implementation** in C:
  - Implement only what is required by the metadata schema.
  - No external CBOR library if avoidable.

Implementation note (non-normative, for early prototypes only):

- For the **first implementation stage**, Piadina and Azdora may use external libraries to accelerate initial prototype delivery:
  - `libarchive` (with gzip support) for tar+gzip handling.
  - `libcbor` for metadata encoding/decoding.
- These libraries MUST be used in a way that preserves the on-disk formats defined in this specification and are always accessed via the internal abstraction layers.
- In later roadmap milestones (15 and 16), in-tree tar and CBOR implementations become the **default**, while support for building against `libarchive` and `libcbor` MAY be retained behind configure-time options.
- The choice between the in-tree implementations and the external libraries is **conditional and driven by the Autotools `configure` script**, which sets feature macros in `piadina_config.h` that control which backend each module delegates to at build time.

No Erlang/Elixir-specific dependencies are required at runtime.

##### 6.1.2 Toolchain and Build System

Targets:

- First phase:
  - Linux (x86_64, aarch64), statically linked against `musl` where possible.
- Future phases (out of scope for v0.1):
  - macOS and Windows support will be investigated later.

Build system:

- Use a **single Autotools-based configuration** for both Piadina and Azdora:
  - Top-level `configure.ac`:
    - Detects compiler (`CC`), `CFLAGS`, `LDFLAGS`.
    - Detects availability of a musl toolchain (e.g. `musl-gcc`) and sets a feature macro (e.g. `HAVE_MUSL`).
    - Detects presence of static `zlib` (or equivalent) and sets `HAVE_ZLIB`.
    - Detects presence of static `libarchive` (or equivalent) and sets `HAVE_LIBARCHIVE`; for the initial prototype, this is treated as **required** unless a configure-time option explicitly disables the vendored/system tar backend.
    - Detects presence of static `libcbor` and sets `HAVE_LIBCBOR`; for the initial prototype this is also treated as **required**, with the option to fall back to an in-tree implementation in later milestones.
    - Determines host/target triple (CPU and OS), e.g. `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`.
    - Generates a shared header (e.g. `piadina_config.h`) with feature macros used by both executables (Piadina and Azdora).
  - Top-level `Makefile.am` (or equivalent):
    - Builds both executables by default:
      - `piadina/piadina`
      - `azdora/azdora`
    - Provides configure-time switches to enable/disable individual components, e.g.:
      - `--disable-piadina` (build only Azdora).
      - `--disable-azdora` (build only Piadina; useful when integrating just the launcher into rebar3/OTP).
    - Supports optional targets such as `make check` / `make test` for unit and integration tests.
  - Source layout:
    - `piadina/` – sources for the Piadina launcher executable, using common headers like `piadina_config.h`.
    - `azdora/` – sources for the Azdora packer executable.
    - `common/` – shared code and definitions (e.g. footer structures, hash helpers, CBOR schema definitions) used by both.

This approach keeps toolchain and feature detection centralized, ensures that both Piadina and Azdora share a consistent view of the environment and configuration, and fits well with existing tooling that expects a `./configure && make` flow (including potential future OTP integration).

##### 6.1.3 Testing Strategy

Testing for both Piadina and Azdora will rely on a **vendored C unit test framework** plus simple integration tests:

- **Unit tests (C)**:
  - The project will vendor the **Unity** C test framework (single C file + header) under `tests/unity/` (or similar).
  - Unit test suites will live under `tests/unit/` and cover, at minimum:
    - Tar/archive handling (creation/extraction).
    - CBOR encoding/decoding and schema validation.
    - Templating engine (`{VAR}` substitution and error cases).
    - Footer parsing and validation.
    - Locking and crash-recovery logic.
    - Path computations and cache directory layout.
    - Process spawning/monitoring helpers (as far as practical in unit tests).
  - Each `test_*.c` file will build into a small test binary linked with Unity and the relevant project modules.
- **Integration tests**:
  - Additional tests (shell scripts or small C/Erlang drivers) will verify end-to-end behavior:
    - Azdora building a self-extracting binary from a sample payload directory.
    - Piadina extracting, validating, launching, and cleaning up that payload.
    - Concurrent launcher runs and lock behavior.
    - `.piadina_env` generation and sourcing semantics.
- **`make check`**:
  - The Autotools setup MUST wire all unit and integration tests into the standard `make check` target.
  - A successful `make check` run MUST validate all core components of the project (launcher, packer, tar handling, CBOR, templating, locking, process management, and metadata export).

#### 6.2 Shared C Modules (`common/`)

These modules live under a shared `common/` directory (plus the Autotools-generated header) and are used by both the Piadina launcher and the Azdora packer:

- **`piadina_config.h`**
  - Autotools-generated configuration header.
  - Provides feature macros (e.g. `HAVE_MUSL`, `HAVE_ZLIB`, `HAVE_LIBCRYPTO`) and platform information shared by all C modules.

- **`cbor_core.{c,h}`**
  - Low-level CBOR primitives shared by encoder and decoder:
    - Types and constants.
    - Reading/writing of integers, text strings, byte strings, arrays, and maps with text keys.

- **`metadata_core.{c,h}`**
  - Shared metadata schema definitions and helpers:
    - Constants and enumerations for well-known fields and maps (e.g. `VERSION`, `APP_NAME`, `ENTRY_POINT`, `ENV`).
    - Shared validation helpers for key naming, allowed value sets (e.g. `CLEANUP_POLICY`, `ARCHIVE_FORMAT`), and required/optional fields.
    - Utilities to apply defaults and to map between CBOR keys and internal field identifiers.

- **`footer.{c,h}`**
  - Shared definition of the footer structure and helpers for:
    - Interpreting offsets, sizes, and hashes in Piadina.
    - Constructing the footer in Azdora.

- **`tar_decoder.{c,h}`**
  - Shared tar **reader/decoder interface**:
    - Defines the abstraction for iterating over entries in a decompressed tar stream and extracting them under a specified root directory.
    - The eventual in-tree implementation (introduced in roadmap milestone 15) MUST:
      - Create directories, regular files, and symbolic links under the target root.
      - Apply basic metadata such as file modes and timestamps to the extent required by the runtime.
      - Enforce safety constraints so that extraction cannot escape the intended payload root (e.g. via `..` or symlink tricks).
    - Before milestone 15, Piadina uses `extractor_tar_gzip` backed by `libarchive` to realize these semantics.

- **`tar_encoder.{c,h}`**
  - Shared tar **writer/encoder interface**:
    - Defines the abstraction for producing a tar stream from a directory tree.
    - The eventual in-tree implementation (introduced in roadmap milestone 15) MUST:
      - Produce a deterministic ordering (e.g. lexicographic by path) so that hashing and reproducible builds behave as expected.
      - Cooperate with shared hashing helpers so that `PAYLOAD_HASH` and `ARCHIVE_HASH` can be computed consistently from the same directory traversal.
      - NOT follow or dereference symbolic links whose resolved target lies **outside** the payload root directory; encountering such a link SHOULD result in a clear, user-facing error rather than silently including external files.
      - For symbolic links whose target is an **absolute path** that canonically resolves **inside** the payload root, MAY rewrite the stored link target to an equivalent **relative path** within the root to improve portability, while preserving the fact that the entry is a symbolic link.
    - Before milestone 15, Azdora uses `packer_tar_gzip` backed by `libarchive` to implement archive creation in a way that is compatible with these requirements.

- **`log.{c,h}`**
  - Simple logging abstraction with log levels.
  - Select output stream (stderr) and formatting.

- **`platform.{c,h}`**
  - Encapsulate OS-specific behavior:
    - Resolve the path to the running executable:
      - Linux: `/proc/self/exe` or `argv[0]` fallback.
      - (macOS/Windows not in scope).
    - Provide any additional platform abstractions needed over time (signal handling quirks, path separators, etc.).

#### 6.3 Piadina Launcher Implementation

This section lists the planned C modules for the **Piadina launcher** and their responsibilities. The exact file naming may evolve, but the separation of concerns should remain.

- **`main.c`**
  - Entry point.
  - Orchestrates configuration parsing, footer+metadata reading, context resolution, extraction, process launch, cleanup, and `.piadina_env` export.

- **`config.{c,h}`**
  - Parse launcher CLI arguments and environment variables into a `struct piadina_config`.
  - Apply precedence rules with metadata defaults.
  - Handle `--` separator and flexible `--launcher-opt=value` / `--launcher-opt value` forms.

- **`cbor_decode.{c,h}`**
  - Schema-aware CBOR decoder for the launcher:
    - Uses `cbor_core` and `metadata_core` to parse the metadata blob into a `struct piadina_metadata`.
    - Applies defaults and validates required fields according to the shared schema helpers.
    - Verifies that the decoded `"VERSION"` field is **compatible** with the launcher:
      - For v0.1, Piadina MUST accept **only** the single hard-coded schema version it was built with.
      - Any other `"VERSION"` value (missing, lower, or higher) MUST cause a clear error and prevent launching the payload.

- **`metadata.{c,h}`**
  - Define `struct piadina_metadata` as the launcher-specific in-memory representation of decoded metadata.
  - Provide launcher-oriented helpers to query effective values (after defaults and overrides), building on the shared rules in `metadata_core`.

- **`template.{c,h}`**
  - Implement `{VAR}` substitution for template strings.
  - Read variables from:
    - The process environment (for `{HOME}`, `{TMPDIR}`, etc.).
    - A launcher-defined dictionary (e.g. `PAYLOAD_HASH`, `ARCHIVE_HASH`, `RANDOM`).

- **`context.{c,h}`**
  - Central “resolved context” for the launcher:
    - Combines:
      - Metadata defaults and values.
      - CLI options.
      - Environment variables (read-only).
      - Template expansion via `template.{c,h}`.
    - Produces a `struct piadina_context` with:
      - Effective `CACHE_ROOT`, `PAYLOAD_ROOT`, `TEMP_DIR`, `LOCK_FILE`, `READY_MARKER`.
      - Effective `ENTRY_POINT`, `ENTRY_ARGS` (resolved array), `CLEANUP_POLICY`, `VALIDATE`.
      - Resolved `ENV` map and any user-defined maps.
    - Provides both:
      - Fully expanded values used at runtime, and
      - Access to original template strings for use by the `.piadina_env` writer (which rewrites `{VAR}` to `${VAR}`).

- **`lock.{c,h}`**
  - File-based locking logic:
    - Acquire, detect stale locks, release.
  - Store and parse PID and timestamp into/from lock files.

- **`archive.{c,h}`**
  - Abstract interface for archive backends, used on the **read/extract** side by Piadina:
    - Resolve whether a given `"ARCHIVE_FORMAT"` (from metadata) is supported.
    - Given an open file descriptor and `ARCHIVE_OFFSET`/`ARCHIVE_SIZE`, dispatch to the appropriate concrete extractor with the target directory and context.
  - v0.1 provides a single backend for the `"tar+gzip"` format, but the interface MUST be designed so that:
    - Adding a new backend (e.g. `"tar+zstd"`, `"zip"`) does not require changes in higher-level modules such as `context.c`, `main.c`, or `process.c`.
    - Selection of the backend is driven by metadata/format identifiers rather than hard-coded branches scattered throughout the codebase.

- **`extractor_tar_gzip.{c,h}`**
  - Concrete implementation of the `"tar+gzip"` archive backend:
    - Uses `zlib` (or equivalent) to decompress the archive stream.
    - Uses the shared tar decoder module to interpret tar headers and extract files.
    - Extracts into the directory specified in the `piadina_context` (e.g. `PAYLOAD_ROOT` via `context.{c,h}`).

- **`process.{c,h}`**
  - Construct `argv` and `envp` for the target process.
  - **Signal Handling**:
    - Setup handlers for `SIGINT` and `SIGTERM` to forward signals to the child.
    - Ensure signal masks are correctly managed before `execve`.
  - Launch and monitor the child process (via `fork` + `execve`).
  - Report termination status.

- **`cleanup.{c,h}`**
  - Encapsulate cleanup policy and directory deletion:
    - Evaluate `CLEANUP_POLICY` (`never`, `oncrash`, `always`) and child exit status/signal.
    - Perform safe recursive deletion of `PAYLOAD_ROOT` when required.
  - Keeping cleanup in its own module isolates policy logic and deletion mechanics from extraction and process management, making it easier to test and evolve independently.

#### 6.4 Azdora Implementation

At a high level, Azdora will require:

- **`main.c`**
  - Entry point for the Azdora executable (typically located under the `azdora/` directory).
  - Parses arguments for launcher path, payload root directory, output path, and metadata entries.
  - Orchestrates payload hashing, archive creation, metadata construction, CBOR encoding, and final binary assembly.

- **`config.{c,h}`**
  - Command-line and configuration parser for Azdora:
    - Parses core options (launcher path, payload directory, output path).
    - Parses metadata key-paths (e.g. `ENV.DB_HOST`, `ENTRY_ARGS[0]`).
    - Parses value types (string, integer, binary).
    - Builds an internal metadata representation (maps/arrays).

- **`metadata.{c,h}`**
  - Azdora-specific internal representation of metadata (e.g. tree of maps and arrays) tailored for encoding.
  - Uses `metadata_core` for shared schema rules, but focuses on:
    - Incremental construction from CLI (`--meta` / `-m`) and other inputs.
    - Validation errors and diagnostics expressed in terms of user-facing key paths.

- **`cbor_encode.{c,h}`**
  - CBOR encoding routines for the required types and container structures.
  - Complementary to the launcher’s `cbor_decode.{c,h}` and built on top of `cbor_core`.

- **`packer_tar_gzip.{c,h}`**
  - Libarchive-based tar+gzip packer module:
    - Uses `libarchive` (with gzip support) to walk a payload directory tree and produce a tar+gzip archive stream.
    - Applies the same safety and path-normalization rules required by the tar abstractions (no escaping the payload root, deterministic ordering where practical).
    - Translates `libarchive` status and error codes into Azdora’s project-specific error model.
  - For the first implementation stage, this module is the sole implementation used by Azdora to create the archive block for `"tar+gzip"`.
  - In roadmap milestone 15, `packer_tar_gzip` will be updated to delegate to the in-tree `tar_encoder` implementation (rather than calling `libarchive` directly), so that archive creation goes through the shared tar abstraction layer.

- **`assembler.{c,h}`**
  - Binary assembler:
    - Reads launcher binary and payload root directory.
    - For the `"tar+gzip"` format, invokes `packer_tar_gzip` to create the archive stream from the payload directory.
    - Computes `PAYLOAD_HASH` and `ARCHIVE_HASH` as specified in §3.1.3 (typically via shared hashing helpers in `common/`).
    - Encodes metadata to CBOR.
    - Computes footer fields and hashes.
    - Writes final layout to output file.

The packer and launcher will share common definitions where appropriate (e.g. footer structure, hash constants, metadata schema) but remain **separate executables** with independent lifecycles.

#### 6.5 Memory Management Strategy

We need to be strict about memory to avoid leaks and use-after-free bugs.

- **Lifetimes**:
  - **Process**: Globals/config (lives forever).
  - **Run**: Metadata, context, tar buffers (lives for `main`).
  - **Scope**: Scratch buffers (freed before return).

- **Ownership**:
  - Use **owner structs** with explicit `*_destroy()` functions (e.g. `piadina_context_destroy`).
  - `*_destroy` must handle partially-init structs safely (for error paths).

- **Arenas**:
  - Consider simple arena/region allocators for the CBOR/Metadata tree. One free to rule them all.

- **Naming Contracts**:
  - `*_new`/`*_dup` -> Caller owns it.
  - `*_get`/`*_peek` -> Borrowed.
  - `*_init(struct *out)` -> Caller provides memory, function inits. `*_destroy` must still work if init fails halfway.

- **Error Handling**:
  - Use the `goto cleanup;` pattern. One exit point per function to guarantee resource release.

- **Documentation**:
  - Every public function MUST document ownership and lifetime expectations in its header comment:
    - State explicitly which side allocates and which side frees any buffers or structs referenced by the API.
    - When no allocation occurs, say so clearly so future readers know the lifecycle is purely caller-managed.
  - Treat these comments as part of the contract; update them whenever ownership rules change.

- **Tools**:
  - ASan (`-fsanitize=address`) in CI.
  - Valgrind for leak checks.

#### 6.6 Code Documentation Standard

To ensure maintainability and clarity, all exported functions and public module interfaces must be documented using **Doxygen-style** comments. This applies to all headers in `common/`, `piadina/`, and `azdora/`.

**Format:**

```c
/**
 * @brief Short description of the function.
 *
 * Detailed description explaining what the function does, its side effects,
 * and any important context.
 *
 * @param[in]  param_name  Description of the parameter.
 * @param[out] out_param   Description of the output parameter.
 * @return                 Description of the return value (e.g., 0 on success).
 *
 * @note Memory Management:
 *       Explicitly state who owns the memory for parameters and return values.
 *       - "Caller retains ownership of..."
 *       - "Caller must free the returned string using..."
 *       - "Function creates a copy..."
 */
```

**Requirements:**

1.  **@brief**: Mandatory 1-line summary.
2.  **@param**: Document every parameter with `[in]`, `[out]`, or `[in,out]`.
3.  **@return**: Document return values, including specific error codes if applicable.
4.  **Memory Management**: Every function that handles pointers must explicitly state ownership rules (who allocates, who frees) in a `@note` or detailed description.
5.  **Module Documentation**: Each header file should start with a `@file` block describing the module's purpose.

#### 6.7 Licensing Compliance

To ensure SPDX and REUSE compliance:

1.  **SPDX Headers**: All source files (`.c`, `.h`, `.am`, `.ac`, `.sh`, etc.) MUST include a standard SPDX header at the very top:
    ```c
    /*
     * SPDX-License-Identifier: Apache-2.0
     * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
     */
    ```
    Use the appropriate comment style for the file type (`#` for shell/make/python).

2.  **Vendored Code**:
    - External code in `tests/unity/` retains its original license headers.
    - The `.reuse/dep5` file may be used to declare licenses for files that cannot be modified, though adding headers directly is preferred where possible.

3.  **License Files**:
    - The repository MUST contain a `LICENSES/` directory with the full text of all used licenses (e.g., `Apache-2.0.txt`, `MIT.txt`).

### 7. Roadmap and Milestones

Planned development phases for Piadina and Azdora as a combined project. Each milestone is intended to be small, **compiling**, and **covered by tests** before moving on.

1. **Project scaffolding and build/test infrastructure**
   - **Implementation**:
     - Create repository layout: `piadina/`, `azdora/`, `common/`, `tests/` (with `tests/unit/` and `tests/integration/`), `m4/` (for Autoconf macros).
     - Add initial `configure.ac` and top-level `Makefile.am`, with subdirectory `Makefile.am` files for `piadina/`, `azdora/`, `common/`, and `tests/`.
     - Vendor Unity under `tests/unity/` and add a minimal test runner wired into `make check`.
     - Add minimal `piadina/main.c` and `azdora/main.c` that print version information and exit with status `0`.
   - **Expected output**:
     - `./configure && make` successfully builds both `piadina/piadina` and `azdora/azdora`.
     - `make check` runs and reports at least one passing test.
   - **Testing**:
     - Unit test that verifies both executables can be invoked and exit with status `0`.
     - CI (if present) configured to run `./configure && make && make check`.

2. **Core shared utilities: logging, platform, footer skeleton**
   - **Implementation**:
     - Implement `common/log.{c,h}` with log levels and consistent formatting to `stderr`.
     - Implement minimal `common/platform.{c,h}`:
       - Stubbed but compiling platform-specific `platform_get_self_exe_path()` for Linux (macOS/Windows can return clearly-marked “not yet implemented” errors).
     - Implement `common/footer.{c,h}`:
       - Define the footer struct matching §3.1.2.
       - Provide helpers to append a footer when assembling binaries and to seek/read/validate it at runtime, ensuring metadata/archive ranges are sane for the current file size.
       - Provide basic error codes (bad magic, bad layout version, short/failed IO, bad ranges, etc.).
     - Expose a convenience initializer so callers (and tests) can prepare zeroed footer structs with the correct magic/version before filling offsets/sizes.
   - **Expected output**:
     - A small test program under `tests/unit/` can construct a fake file with a footer and successfully read/validate it.
   - **Testing**:
     - Unit tests for `log` (at least ensure functions are callable and don’t crash).
     - Unit tests for `platform_get_self_exe_path()` on Linux (using `argv[0]` or `/proc/self/exe`).
     - Unit tests for `footer_read()`:
       - Valid footer → success.
       - Wrong magic or layout version → explicit error.
       - Truncated file → explicit error.

3. **Shared CBOR and metadata core primitives**
   - **Implementation**:
     - Implement `common/cbor_core.{c,h}` with the minimal CBOR subset from §3.2:
       - Unsigned integers, booleans, text strings, byte strings, arrays, and maps with string keys.
        - For this milestone these functions are **thin wrappers around `libcbor`**, so no custom encoder is written yet; all callers see only the `cbor_core` API so the backend can be swapped later without touching higher layers.
     - Implement `common/metadata_core.{c,h}`:
       - Enumerations/constants for well-known metadata entries (`VERSION`, `APP_NAME`, `ENTRY_POINT`, `ENV`, etc.).
       - Validation helpers for key naming and allowed values (`CLEANUP_POLICY`, `ARCHIVE_FORMAT`, etc.).
       - Defaulting helpers for metadata fields that carry defaults (e.g. archive format, cache root).
   - **Expected output**:
     - Standalone unit tests can:
       - Encode/decode small CBOR fragments and confirm round-trips.
       - Validate metadata key names and constants match the spec.
   - **Testing**:
     - Unit tests for `cbor_core` covering each supported major type and nested maps/arrays.
     - Unit tests for `metadata_core`:
       - Key naming acceptance/rejection.
       - Enforcement of enumerated values and defaults.

4. **Static build support**
   - **Implementation**:
     - Make fully static builds the default: configure should attempt to produce statically linked `piadina`/`azdora` (musl or glibc `-static`) without extra flags.
     - Detect the presence of static variants of required libraries (`libc`, `libcbor`, `libarchive`, `libz`, etc.) and fail configure early with actionable guidance if any are missing.
     - Provide an opt-out flag such as `--disable-static-build` that falls back to dynamic linking when engineers need it.
     - Update the README/developer docs to describe the default static behavior, prerequisites (e.g. musl toolchain), and how to opt out when static builds aren’t possible.
   - **Testing**:
     - Extend CI (or add a scripted check) that runs `./configure && make && make check`, then verifies `ldd piadina/piadina` and `ldd azdora/azdora` report “not a dynamic executable”.
     - Ensure the static build still runs the full unit/integration test suite so regressions are caught early.

5. **Minimal Piadina launcher skeleton (no tar yet)**
   - **Implementation**:
     - Implement `piadina/config.{c,h}`:
       - Parse launcher CLI options (`--launcher-*`) and `PIADINA_*` environment variables into a `struct piadina_config`.
       - Honor precedence: CLI > env > hard-coded defaults.
     - Extend `piadina/main.c` to:
       - Resolve its own executable path via `platform_get_self_exe_path()`.
       - Open itself, read and validate a footer using `footer_read()`.
       - For now, skip actual metadata decoding and tar extraction; instead, use a static test `ENTRY_POINT` and `ENTRY_ARGS` from a hard-coded struct.
       - `fork` + `execve` a simple system command (e.g. `/bin/echo`) to validate process launching and exit-code forwarding.
   - **Expected output**:
     - A manually-constructed, small test binary (launcher + fake footer) can be run and will:
       - Read the footer.
       - Launch `/bin/echo` and return its exit status.
   - **Testing**:
     - Unit tests for `config` (CLI parsing, env overrides).
     - Unit tests for `process` (once stubbed in) that verify exit codes are propagated correctly for normal exits and signaled exits (using small helper programs).
     - Integration test that runs the launcher against a test file with a valid footer and checks that `/bin/echo` is executed and that the launcher’s exit status matches.

6. **Minimal Azdora skeleton: assembling a minimal binary**
   - **Implementation**:
     - Implement `azdora/config.{c,h}`:
       - Parse `--launcher`/`-l`, `--payload`/`-p`, `--output`/`-o`, and first `--meta`/`-m` flags into an internal configuration structure (even if metadata handling is partial at this stage).
     - Implement `azdora/metadata.{c,h}`:
       - A minimal internal representation of metadata using `metadata_core`:
         - Enough to set `VERSION`, `APP_NAME`, `APP_VER`, `ENTRY_POINT`, and hashes to placeholder values.
     - Implement `azdora/cbor_encode.{c,h}` as a thin wrapper over `cbor_core`/`libcbor` with just enough functionality to encode the minimal metadata map.
     - Implement `azdora/assembler.{c,h}`:
       - Read the launcher binary.
       - Append a small CBOR metadata block produced via `cbor_core`/`libcbor` and an empty (or placeholder) archive block.
       - Construct a correct footer pointing to those regions.
   - **Expected output**:
     - Running Azdora on a test payload tree produces a self-extracting binary whose footer and CBOR metadata can be read correctly by unit tests and by a small diagnostic tool.
   - **Testing**:
     - Unit tests for `azdora/config` CLI parsing.
     - Unit tests for `azdora/metadata` building a minimal metadata struct from a small set of `--meta` calls.
     - Unit tests for `cbor_encode` that match `cbor_core` expectations while using `libcbor` underneath.
     - Integration test:
       - Run Azdora on a sample payload.
       - Verify the resulting binary has the expected layout and that `footer_read` and CBOR decoding succeed.

7. **Tar integration via libarchive (skipping payload hashing for now)**
   - **Implementation**:
     - Implement `piadina/extractor_tar_gzip.{c,h}` to:
       - Use `libarchive` to read tar+gzip streams from the launcher file and extract them into a target directory.
       - Map `libarchive` errors to project-specific error codes.
     - Implement `azdora/packer_tar_gzip.{c,h}` to:
       - Use `libarchive` to create tar+gzip archives from a payload directory tree.
       - Integrate with `azdora/assembler.{c,h}` so that the archive block in the final binary is produced via `libarchive`.
     - The shared tar abstraction (`common/tar_encoder` / `common/tar_decoder`) is deferred to milestone 15, when the in-tree tar implementation will land. No interface is frozen in milestone 7.
   - **Expected output**:
     - Azdora can now produce binaries whose archive stream matches the spec, and Piadina can extract those archives using `libarchive` through the `extractor_tar_gzip` module.
   - **Testing**:
     - Unit tests for `extractor_tar_gzip` and `packer_tar_gzip` round-tripping simple directory trees using `libarchive`.
     - Integration test:
       - Create a payload on disk, pack it with Azdora, and assert the archive is valid tar+gzip and can be extracted by Piadina.

8. **Full metadata decoding/encoding and templating (via libcbor)**
   - **Implementation**:
     - Implement `common/cbor_core.{c,h}`, `piadina/cbor_decode.{c,h}`, and `azdora/cbor_encode.{c,h}` as abstraction layers over `libcbor` that fully support the schema in §3.2, including maps and arrays (`ENTRY_ARGS`, `ENV`, and user-defined maps).
     - Extend Azdora’s `metadata` and `cbor_encode` to build/encode all fields from `--meta` input using these abstractions.
     - Implement `piadina/template.{c,h}` and integrate templating into `context.{c,h}`:
       - Resolve `CACHE_ROOT`, `PAYLOAD_ROOT`, and metadata `ENV` values using the templating rules.
   - **Expected output**:
     - Arbitrary metadata that conforms to the schema can be encoded by Azdora (via `libcbor` and `cbor_core`) and decoded by Piadina with consistent defaults and validation.
   - **Testing**:
     - Unit tests for all metadata fields, including error cases (invalid keys, bad enum values, missing required fields).
     - Unit tests for templating substitution (correct order and failure on unknown variables).
     - Integration tests where Azdora generates metadata for several scenarios (different `CACHE_ROOT`, `PAYLOAD_ROOT`, `ENV`) and Piadina resolves them as expected.

9. **Extraction and basic caching (single-process)**
   - **Implementation**:
     - Complete `archive.{c,h}`, `extractor_tar_gzip.{c,h}`, and the portions of `context.{c,h}` needed to compute `TEMP_DIR` and `PAYLOAD_ROOT` and drive archive extraction, following §4.3 but without full lock/ready-marker semantics.
     - Implement extraction of tar+gzip archives into `TEMP_DIR` and atomic promotion to `PAYLOAD_ROOT` for the single-process case.
     - Allow subsequent launcher runs to reuse an existing `PAYLOAD_ROOT` on a best-effort basis without relying on `LOCK_FILE`/`READY_MARKER`; concurrent invocations are not yet considered safe.
   - **Expected output**:
     - Piadina and Azdora can, together, build a self-extracting binary and run a real payload end-to-end in a **single-launcher-process** scenario (no concurrent invocations).
     - The **minimal feature set** required for this first runnable prototype consists of:
       - A single archive format (`"tar+gzip"`) as specified in §3.2.1 (`"ARCHIVE_FORMAT"` defaults to `"tar+gzip"`).
       - A subset of metadata sufficient to locate and start the payload (`ENTRY_POINT`, optional `ENTRY_ARGS`, cache and payload layout via `CACHE_ROOT`/`PAYLOAD_ROOT` and their templating, and basic `ENV` overrides).
       - Footer handling that provides correct offsets and sizes, without payload validation (`VALIDATE`) or cleanup policies beyond a simple default behavior.
       - No `.piadina_env` export (introduced later in milestone 11).
   - **Testing**:
     - Integration tests:
       - Azdora packs a small Erlang/OTP release‑like payload.
       - Piadina extracts it and launches the payload once.
       - Re-run Piadina sequentially to confirm it reuses the cache without re-extracting.

10. **Lock management and ready markers**
   - **Implementation**:
     - Complete `lock.{c,h}` and integrate file-based lock acquisition and stale-lock detection as in §4.3.2.
     - Extend `context.{c,h}` and extraction logic to use `TEMP_DIR`, `LOCK_FILE`, and `READY_MARKER` as in §4.3.1 and §4.3.3.
     - Ensure that all extraction and cache-reuse decisions are made **under the lock**, so concurrent launcher runs coordinate safely without clobbering each other’s payload directories.
   - **Expected output**:
     - Piadina’s extraction and caching become robust under concurrent invocations; a minimal single-process launcher was already functional after milestone 8, and this milestone hardens it for multi-process use.
   - **Testing**:
     - Unit tests for locking (concurrent attempts and stale lock clean-up, as far as practical).
     - Integration tests:
       - Multiple concurrent Piadina runs for the same payload coordinate via the lock and do not corrupt the cache.
       - Re-run Piadina to confirm it reuses the cache across concurrent and sequential runs.

11. **Process lifecycle, exit codes, and cleanup policies**
   - **Implementation**:
     - Finalize `process.{c,h}`:
       - Correct `argv` assembly (`ENTRY_POINT`, `ENTRY_ARGS`, CLI args after `--`, `ENTRY_ARGS_POST`).
       - Environment setup: stripping `PIADINA_*` and applying `ENV` overrides.
     - Finalize `cleanup.{c,h}`:
       - Apply `CLEANUP_POLICY` based on exit code and signals as in §4.4.
     - Implement signal forwarding from launcher to child (e.g. SIGINT, SIGTERM) in `process.{c,h}`.
   - **Expected output**:
     - Launching a payload entry point behaves as expected:
       - Exit codes from the child are propagated unchanged (or via `128 + signum` for signals).
       - Cleanup behavior matches `CLEANUP_POLICY`.
   - **Testing**:
     - Unit tests for `process` to verify argument ordering and environment contents.
     - Unit tests for `cleanup` covering `never`, `oncrash`, and `always`.
     - Integration tests:
       - Pack an escript-like payload that exits with `0` and non-`0` and assert Piadina’s exit code matches.
       - Verify that `oncrash` only deletes the cache on non-zero exits or signals.

12. **Exported Metadata File (`.piadina_env`)**
    - **Implementation**:
      - Implement the `.piadina_env` writer and integrate it under the extraction lock, as in §4.3.4.
      - Ensure environment variables defined in `ENV` are exported in unprefixed form at the end of the file.
    - **Expected output**:
      - Piadina writes a correct `.piadina_env` file inside `PAYLOAD_ROOT` after extraction or validation.
      - The file can be sourced by `bash` to run the app with the correct environment.
      - Earlier milestones (in particular the first runnable prototype reached after milestone 8) MAY omit `.piadina_env` entirely; no user-facing behavior MUST depend on its presence before this milestone.
    - **Testing**:
      - Unit tests for `.piadina_env` formatting (escaping, arrays/maps, override ordering).
       - Integration tests:
         - Verify that sourcing the generated file sets the expected variables.

13. **Payload Hashing and Verification**
    - **Implementation**:
      - Implement shared payload/archive hashing helpers that use the tar traversal to compute `PAYLOAD_HASH` and `ARCHIVE_HASH`.
      - Integrate hashing into `assembler` (Azdora) to populate the real hash values.
      - Integrate hashing into `Piadina` (validation logic) to support the `VALIDATE` flag.
    - **Expected output**:
      - Full end-to-end integrity checks are available.
    - **Testing**:
      - Unit tests for hashing:
        - Two identical trees → identical `PAYLOAD_HASH`.
        - Small changes in content, mode, or path → changed hash.
      - Integration test:
        - Create two identical payloads on disk, pack each, and assert their `PAYLOAD_HASH` and `ARCHIVE_HASH` match.
        - Verify that `Piadina` detects modified payloads when `VALIDATE` is on.

14. **Extended integration (Linux)**
    - **Implementation**:
      - Refine any Linux-specific behaviors.
      - Add any small Azdora/launcher enhancements that arise from initial real-world use (e.g. additional diagnostics, `--launcher-print-*` improvements).
    - **Expected output**:
      - Piadina and Azdora build and pass tests on Linux.
    - **Testing**:
      - Update CI matrix (when available) to run `make check` on all supported platforms, including at least one configuration built with AddressSanitizer enabled.
      - Periodically run `make check` under a memory checker (such as Valgrind) to detect leaks and invalid memory accesses.
      - Add integration tests for OS-specific behaviors as they are implemented.

15. **In-tree tar implementation (replacing vendored tar backend)**
    - **Implementation**:
      - Treat `common/tar_encoder.{c,h}` and `common/tar_decoder.{c,h}` as the **stable tar abstraction layer** used by Azdora and Piadina.
      - Replace any internal use of `libarchive` within these modules with a minimal, self-contained tar encoder/decoder that:
        - Produces deterministic, spec-compliant tar streams for payloads (directories, regular files, symlinks).
        - Safely extracts tar streams into directories, respecting the security and correctness rules in §3.1.3 and §4.3.
      - Keep the public interface of `tar_encoder` / `tar_decoder` unchanged so higher-level modules (`archive`, `assembler`, tests) do not need to change.
      - Optionally retain `libarchive` support behind a configure-time flag (e.g. `--with-system-tar`), defaulting build configurations to the in-tree implementation.
    - **Expected output**:
      - Binaries produced and consumed using the in-tree tar implementation are compatible with those produced when using `libarchive` via the same interfaces.
      - The project no longer depends on a third-party tar implementation by default.
    - **Testing**:
      - Golden-file tests comparing archives created with the old `libarchive`-backed implementation versus the new in-tree implementation.
      - Round-trip tests encoding and decoding directories using only the in-tree tar code.
      - Re-running the full integration test suite with the vendored tar backend disabled.

16. **In-tree CBOR implementation (replacing vendored CBOR backend)**
    - **Implementation**:
      - Treat `common/cbor_core.{c,h}`, `piadina/cbor_decode.{c,h}`, and `azdora/cbor_encode.{c,h}` as the **stable CBOR abstraction layer** for all metadata encoding/decoding.
      - Replace any internal use of `libcbor` inside these modules with a minimal, self-contained encoder/decoder that supports only the CBOR subset required by the metadata schema (§3.2).
      - Preserve the public interfaces of `cbor_core` / `cbor_encode` / `cbor_decode` so callers in Piadina and Azdora remain unchanged.
      - Optionally retain support for building against a system CBOR library behind a configure-time flag (e.g. `--with-system-cbor`), defaulting build configurations to the in-tree implementation.
    - **Expected output**:
      - Metadata encoded by Azdora using the in-tree CBOR implementation can be decoded by Piadina exactly as before.
      - The on-disk CBOR format remains compatible with earlier binaries produced using the vendored CBOR library.
    - **Testing**:
      - Golden-encoding tests comparing CBOR blobs produced with the previous library-backed implementation versus the in-tree implementation, where practical.
      - Round-trip tests of representative metadata structures through Azdora encode → Piadina decode.
      - Robustness tests feeding malformed CBOR to the decoder, ensuring correct error reporting and no crashes.

### 8. Non-Goals and Out-of-Scope Items for v0.1

The following topics are explicitly **out of scope** for this initial version of the Piadina project and may be considered in future layout or schema versions:

- **Additional platforms**:
  - Native macOS and Windows support (beyond basic investigation for future phases).
- **Signatures and trust management**:
  - Cryptographic signatures over the launcher, metadata, or archive payload.
  - Certificate or key management, trust stores, or signature policy enforcement.
  - Future layout versions (e.g. a `layout_version` > 1) MAY reuse the footer’s reserved bytes and/or add new sections to carry signature-related metadata, but no concrete scheme is defined here.
- **Encryption at rest**:
  - Encrypting the embedded archive or the extracted payload on disk.
  - Key management and secure storage mechanisms for such encryption.
- **Library usage / embedding**:
  - Shipping Piadina or Azdora as a stable, documented C library API for third-party embedding.
  - Language bindings (e.g. NIFs, FFI wrappers) beyond what is needed for internal tests and tools.
- **Advanced packaging features**:
  - Auto-update or self-update mechanisms for the launcher or payload.
  - Multiple archive formats beyond `"tar+gzip"` (e.g. `tar+zstd`, `zip`) in v0.1.
  - Rich diagnostics UX beyond the basic `--launcher-print-*` and `--help`-style commands described in this document.
