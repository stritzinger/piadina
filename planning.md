## Piadina / Azdora – Roadmap Implementation Checklist

This document breaks down the roadmap from `specification.md` into a trackable checklist.

Legend:
- **[ ]** Not started
- **[~]** In progress
- **[x]** Done

Mark items as you complete them.

---

## Milestone 1 – Project Scaffolding and Build/Test Infrastructure

### Repository layout and build basics

- [x] **Repo setup**
  - [x] Create `piadina/` (launcher sources).
  - [x] Create `azdora/` (packer sources).
  - [x] Create `common/` (shared C modules).
  - [x] Create `tests/` with `unit/` and `integration/` subdirs.
  - [x] Create `m4/` (Autoconf macros).

- [x] **Autotools bootstrap**
  - [x] `configure.ac`:
    - [x] Init project (name, version, bug-report).
    - [x] Check for ANSI C compiler (`AC_PROG_CC`).
    - [x] Default `CFLAGS` / `LDFLAGS`.
    - [x] `AM_INIT_AUTOMAKE`.
    - [x] `AC_CONFIG_HEADERS([piadina_config.h])`.
    - [x] `AC_CONFIG_FILES` (Makefiles for root, dirs, tests).
    - [x] `AC_OUTPUT`.

  - [x] `Makefile.am` (root):
    - [x] `SUBDIRS = common piadina azdora tests`.
    - [x] Wire `check` to recurse.

  - [x] `piadina/Makefile.am`:
    - [x] `bin_PROGRAMS = piadina`.
    - [x] Minimal source list (`main.c`).

  - [x] `azdora/Makefile.am`:
    - [x] `bin_PROGRAMS = azdora`.
    - [x] Minimal source list (`main.c`).

  - [x] `common/Makefile.am`:
    - [x] `noinst_LIBRARIES` or `libcommon_a`.

  - [x] `tests/Makefile.am`:
    - [x] `SUBDIRS = unity unit integration`.
    - [x] Wire unit tests into `TESTS`.

- [x] **Helper scripts**
  - [x] Add `autogen.sh` (`autoreconf -i`).

### Skeleton executables and Unity test framework

- [x] **Minimal `piadina/main.c`**
  - [x] Implement `main()` that:
    - [x] Prints Piadina version information (hard-coded string or macro).
    - [x] Returns exit status `0`.

- [x] **Minimal `azdora/main.c`**
  - [x] Implement `main()` that:
    - [x] Prints Azdora version information (hard-coded string or macro).
    - [x] Returns exit status `0`.

- [x] **Vendor Unity test framework**
  - [x] Add `tests/unity/` directory.
  - [x] Vendor Unity source files:
    - [x] `unity.c`.
    - [x] `unity.h`.
  - [x] Add a simple Unity-based test runner in `tests/unit/` (e.g. `test_smoke.c`):
    - [x] Includes `unity.h`.
    - [x] Has at least one basic test (e.g. `TEST_ASSERT_EQUAL_INT(1, 1);`).
    - [x] Integrates with Automake test harness (listed in `TESTS`).

### Build and test verification

- [x] **Build flow**
  - [x] Run `./autogen.sh` (or `autoreconf -i`) successfully.
  - [x] Run `./configure` successfully.
  - [x] Run `make` successfully:
    - [x] `piadina/piadina` binary is built.
    - [x] `azdora/azdora` binary is built.

- [x] **Test flow**
  - [x] Run `make check` successfully:
    - [x] Unity tests in `tests/unit/` run and pass.
    - [x] At least one test asserts that `piadina` and `azdora` can be executed and exit with status `0` (can be done via small C driver or shell script).

---

## Milestone 2 – Core Shared Utilities: Logging, Platform, Footer Skeleton

### `common/log.{c,h}`

- [ ] **Design log API**
  - [ ] Define log levels enum (e.g. `LOG_DEBUG`, `LOG_INFO`, `LOG_WARN`, `LOG_ERROR`).
  - [ ] Define functions:
    - [ ] `log_set_level(...)` to set current minimum log level.
    - [ ] `log_get_level()` accessor.
    - [ ] `log_debug(...)`, `log_info(...)`, `log_warn(...)`, `log_error(...)` (or a generic `log_log(level, ...)`).
  - [ ] Decide on formatting convention (e.g. `[LEVEL] message`).

- [ ] **Implementation**
  - [ ] Implement logging functions, writing to `stderr`.
  - [ ] Ensure functions are safe to call before configuration is fully initialized (sane defaults).

### `common/platform.{c,h}`

- [ ] **API definition**
  - [ ] Define a function to get the current executable path:
    - [ ] `int platform_get_self_exe_path(char *buf, size_t buf_size);`
  - [ ] Define basic error codes or return conventions.

- [ ] **Linux implementation**
  - [ ] Implement using `/proc/self/exe` when available:
    - [ ] Use `readlink` to read the symlink.
    - [ ] Null-terminate the result.
    - [ ] Handle truncation and errors cleanly.
  - [ ] Provide a fallback using `argv[0]` if `/proc/self/exe` is unavailable (design decision: may be done later or via helper).

- [ ] **Non-Linux stubs**
  - [ ] Provide stubs for other platforms (macOS/Windows) that:
    - [ ] Compile but return clear “not implemented” error codes.

### `common/footer.{c,h}`

- [ ] **Struct definition**
  - [ ] Define a packed C struct matching §3.1.2:
    - [ ] `magic[8]`.
    - [ ] `uint32_t layout_version`.
    - [ ] `uint64_t metadata_offset`.
    - [ ] `uint64_t metadata_size`.
    - [ ] `uint64_t archive_offset`.
    - [ ] `uint64_t archive_size`.
    - [ ] `uint8_t archive_hash[32]`.
    - [ ] `uint8_t footer_hash[32]`.
    - [ ] `uint8_t reserved[12]`.
  - [ ] Ensure struct layout is tightly packed and little-endian (use static asserts if available).

- [ ] **Constants**
  - [ ] Define `FOOTER_MAGIC = "PIADINA\0"`.
  - [ ] Define `FOOTER_LAYOUT_VERSION = 1`.
  - [ ] Define `FOOTER_SIZE` constant as `sizeof(struct footer)` and assert equals 64 bytes.

- [ ] **Footer read/validate API**
  - [ ] Declare functions:
    - [ ] `int footer_read(int fd, struct footer *out_footer);`
    - [ ] `int footer_validate(const struct footer *footer);`
  - [ ] Define error codes for:
    - [ ] Bad magic.
    - [ ] Unsupported layout version.
    - [ ] Short read / file too small.
    - [ ] Footer checksum mismatch (if implemented at this stage or reserved for later).

- [ ] **Implementation**
  - [ ] Implement `footer_read`:
    - [ ] Use `lseek` to position at `file_size - FOOTER_SIZE`.
    - [ ] Read into `out_footer`.
    - [ ] Handle errors and partial reads.
  - [ ] Implement `footer_validate`:
    - [ ] Verify `magic`.
    - [ ] Verify `layout_version`.
    - [ ] Optionally verify `reserved` bytes are zero for version 1.

### Tests for milestone 2

- [ ] **Unit tests for `log`**
  - [ ] Verify each log-level function is callable without crashing.
  - [ ] Optionally capture `stderr` to confirm formatting and level filtering.

- [ ] **Unit tests for `platform_get_self_exe_path()` (Linux)**
  - [ ] Test successful path resolution on Linux.
  - [ ] Test buffer too small case returns an appropriate error.

- [ ] **Unit tests for `footer_read()` and `footer_validate()`**
  - [ ] Create a temporary file with a valid footer and assert:
    - [ ] `footer_read` succeeds.
    - [ ] `footer_validate` succeeds.
  - [ ] Create a file with wrong magic and assert:
    - [ ] `footer_validate` returns “bad magic” error.
  - [ ] Create a truncated file and assert:
    - [ ] `footer_read` reports explicit error.

---

## Milestone 3 – Shared CBOR and Metadata Core Primitives

### `common/cbor_core.{c,h}`

- [ ] **Type and constant definitions**
  - [ ] Define basic CBOR type tags/constants for:
    - [ ] Unsigned integers.
    - [ ] Booleans.
    - [ ] Text strings.
    - [ ] Byte strings.
    - [ ] Arrays.
    - [ ] Maps with string keys.

- [ ] **Encoding primitives**
  - [ ] Design function signatures for encoding:
    - [ ] Unsigned integers.
    - [ ] Booleans (`true`/`false`).
    - [ ] Text strings (length + UTF-8 bytes).
    - [ ] Byte strings.
    - [ ] Array headers (length + items encoded by callers).
    - [ ] Map headers with string keys.
  - [ ] Provide an internal abstraction that can be backed by a vendored CBOR library (`libcbor`) for the initial prototype.

- [ ] **Decoding primitives**
  - [ ] Design function signatures for decoding:
    - [ ] Unsigned integers.
    - [ ] Booleans.
    - [ ] Text strings (pointer/length).
    - [ ] Byte strings.
    - [ ] Array headers and iterating items.
    - [ ] Map headers and iterating over string-key entries.
  - [ ] Implement these functions initially as thin wrappers over the chosen CBOR library, translating between its API and the `cbor_core` abstraction.
  - [ ] Provide clear error codes for malformed CBOR or unsupported types, independent of the underlying library’s error representation.

### `common/metadata_core.{c,h}`

- [ ] **Schema constants and enums**
  - [ ] Define constants/enums for top-level fields:
    - [ ] `VERSION`, `APP_NAME`, `APP_VER`, `ARCHIVE_HASH`, `ARCHIVE_FORMAT`,
      `PAYLOAD_HASH`, `ENTRY_POINT`, `ENTRY_ARGS`, `ENTRY_ARGS_POST`, `CACHE_ROOT`,
      `PAYLOAD_ROOT`, `CLEANUP_POLICY`, `VALIDATE`, `LOG_LEVEL`, `ENV`, `EXTRA`, etc.

- [ ] **Key naming validation**
  - [ ] Implement function to verify key names match `[a-zA-Z-_][a-zA-Z0-9-_]*`.
  - [ ] Ensure usage in both encoder and decoder paths.

- [ ] **Enum value validation**
  - [ ] Implement validators for:
    - [ ] `CLEANUP_POLICY` (values `never`, `oncrash`, `always`).
    - [ ] `LOG_LEVEL` (values `debug`, `info`, `warn`, `error`).
    - [ ] `ARCHIVE_FORMAT` (must be `"tar+gzip"` in v0.1).

- [ ] **Defaults and helpers**
  - [ ] Implement helpers to:
    - [ ] Apply default `ARCHIVE_FORMAT="tar+gzip"` when absent.
    - [ ] Apply default `CLEANUP_POLICY="oncrash"`.
    - [ ] Apply default `VALIDATE=false`.
    - [ ] Apply default `LOG_LEVEL="info"`.
  - [ ] Provide API to map between CBOR keys (strings) and internal identifiers.

### Tests for milestone 3

- [ ] **Unit tests for `cbor_core`**
  - [ ] Round-trip tests using the `cbor_core` API (backed by the vendored CBOR library) for:
    - [ ] Unsigned integers (various values).
    - [ ] Booleans.
    - [ ] Text strings (ASCII and UTF-8).
    - [ ] Byte strings.
    - [ ] Arrays and nested arrays/maps.
  - [ ] Negative tests for malformed encodings, ensuring the abstraction returns consistent error codes regardless of the underlying library’s behavior.

- [ ] **Unit tests for `metadata_core`**
  - [ ] Key naming tests:
    - [ ] Accept valid identifiers.
    - [ ] Reject invalid ones.
  - [ ] Enum value tests:
    - [ ] Accept allowed values.
    - [ ] Reject unknown values with clear errors.
  - [ ] Defaults tests:
    - [ ] Confirm default values are applied when fields are missing.

---

## Milestone 4 – Minimal Piadina Launcher Skeleton (No Tar Yet)

### `piadina/config.{c,h}`

- [ ] **Config structure definition**
  - [ ] Define `struct piadina_config` including:
    - [ ] Cache root override.
    - [ ] Cleanup policy override.
    - [ ] Validate flag override.
    - [ ] Force-extract flag override.
    - [ ] Log level override.
    - [ ] Other launcher-specific flags (`print-metadata`, `print-footer`, `help`, `version`).
    - [ ] Collection of non-launcher arguments (application args after `--`).

- [ ] **CLI parsing**
  - [ ] Implement parser for `--launcher-*` options:
    - [ ] `--launcher-cache-root=PATH`.
    - [ ] `--launcher-cleanup=never|oncrash|always`.
    - [ ] `--launcher-validate[=true|false]`.
    - [ ] `--launcher-force-extract[=true|false]`.
    - [ ] `--launcher-log-level=debug|info|warn|error`.
    - [ ] `--launcher-verbose`.
    - [ ] `--launcher-print-metadata`.
    - [ ] `--launcher-print-footer`.
    - [ ] `--launcher-help`.
    - [ ] `--launcher-version`.
  - [ ] Support both `--opt=value` and `--opt value` forms.
  - [ ] Implement `--` separator handling:
    - [ ] All arguments after `--` stored as application arguments, not parsed as launcher options.

- [ ] **Environment variable parsing**
  - [ ] Read `PIADINA_CACHE_ROOT`, `PIADINA_CLEANUP_POLICY`, `PIADINA_VALIDATE`,
    `PIADINA_FORCE_EXTRACT`, `PIADINA_LOG_LEVEL`.
  - [ ] Map environment values to the same internal representation as CLI.

- [ ] **Precedence rules**
  - [ ] Implement logic: CLI overrides env, env overrides hard-coded defaults.

### `piadina/main.c` (extended)

- [ ] **Self path resolution and footer handling**
  - [ ] Use `platform_get_self_exe_path()` to determine launcher path.
  - [ ] Open the executable file for reading.
  - [ ] Use `footer_read()` and `footer_validate()` to:
    - [ ] Read footer from the executable.
    - [ ] Fail with internal error code (112) on invalid or missing footer.

- [ ] **Temporary process launch (no tar/metadata yet)**
  - [ ] Define a test configuration with hard-coded `ENTRY_POINT` (e.g. `/bin/echo`) and arguments.
  - [ ] Implement a minimal `process` helper (or inline logic) to:
    - [ ] `fork` + `execve` `/bin/echo` with test arguments.
    - [ ] Return child exit status as launcher exit code.

### Tests for milestone 4

- [ ] **Unit tests for `piadina/config`**
  - [ ] Test various combinations of CLI options and environment variables for correct precedence.
  - [ ] Test `--` separation behavior.
  - [ ] Test boolean parsing for `--launcher-validate` / `PIADINA_VALIDATE`.

- [ ] **Unit / integration tests for `process` or `main`**
  - [ ] Test successful execution of `/bin/echo` and exit-code forwarding.
  - [ ] Test behavior when `execve` fails (e.g. non-existent program) → launcher returns `115`.
  - [ ] Integration test:
    - [ ] Construct a test binary with a valid footer and run it.
    - [ ] Verify:
      - [ ] Footer is read.
      - [ ] `/bin/echo` is invoked.
      - [ ] Launcher exit status matches child exit status.

---

## Milestone 5 – Minimal Azdora Skeleton: Assembling a Minimal Binary

### `azdora/config.{c,h}`

- [ ] **Config structure**
  - [ ] Define configuration struct with:
    - [ ] Launcher path (`--launcher` / `-l`).
    - [ ] Payload directory path (`--payload` / `-p`).
    - [ ] Output file path (`--output` / `-o`).
    - [ ] Collection of `--meta` / `-m` entries (as raw strings for now).

- [ ] **CLI parsing**
  - [ ] Implement parsing for:
    - [ ] `--launcher FILE_PATH` / `-l`.
    - [ ] `--payload DIR_PATH` / `-p`.
    - [ ] `--output FILE_PATH` / `-o`.
    - [ ] Repeated `--meta PATH=VALUE` / `-m PATH=VALUE`.
  - [ ] Implement default naming behavior for output when `--output` is omitted (basic initial behavior is acceptable here).

### `azdora/metadata.{c,h}` (minimal)

- [ ] **Metadata representation**
  - [ ] Define a minimal metadata struct sufficient for:
    - [ ] `VERSION`.
    - [ ] `APP_NAME`.
    - [ ] `APP_VER`.
    - [ ] `ENTRY_POINT`.
    - [ ] Placeholder hash fields.

- [ ] **Metadata construction**
  - [ ] Implement functions to:
    - [ ] Initialize metadata with default schema version.
    - [ ] Apply parsed `--meta` entries (initial limited subset).
    - [ ] Enforce that `VERSION` cannot be overridden by user input.

### `azdora/cbor_encode.{c,h}` (minimal, via `libcbor`)

- [ ] **Encoding minimal map**
  - [ ] Implement functions that use `cbor_core` / `libcbor` to encode a top-level metadata map containing:
    - [ ] `VERSION` (uint).
    - [ ] `APP_NAME` (text, optional).
    - [ ] `APP_VER` (text, optional).
    - [ ] `ENTRY_POINT` (text, optional).
    - [ ] Placeholder hashes, if desired at this stage.

### `azdora/assembler.{c,h}`

- [ ] **Launcher + metadata + placeholder archive assembly**
  - [ ] Read launcher binary from disk.
  - [ ] Encode minimal metadata to CBOR using `cbor_encode`.
  - [ ] Decide representation for a placeholder archive block (empty or fixed placeholder).
  - [ ] Compute offsets and sizes:
    - [ ] `launcher_size`.
    - [ ] `metadata_offset` = `launcher_size`.
    - [ ] `metadata_size`.
    - [ ] `archive_offset` = `launcher_size + metadata_size`.
    - [ ] `archive_size` (placeholder).
  - [ ] Construct footer struct with:
    - [ ] Fill offsets and sizes.
    - [ ] Set `ARCHIVE_HASH` to placeholder or zero value for now.
  - [ ] Write final layout to output file:
    - [ ] Launcher bytes.
    - [ ] Metadata block.
    - [ ] Placeholder archive block.
    - [ ] Footer.

### Tests for milestone 5

- [ ] **Unit tests for `azdora/config`**
  - [ ] CLI parsing tests for each of `--launcher`, `--payload`, `--output`, `--meta`.
  - [ ] Test error cases (missing required options).

- [ ] **Unit tests for `azdora/metadata`**
  - [ ] Test `--meta` handling for minimal fields.
  - [ ] Test rejection of attempts to override `VERSION`.

- [ ] **Unit tests for `azdora/cbor_encode`**
  - [ ] Verify that encoded CBOR matches expectations from `cbor_core`.

- [ ] **Integration test**
  - [ ] Run Azdora on a test payload directory:
    - [ ] Verify resulting binary layout:
      - [ ] Footer can be read and validated using `footer_read`/`footer_validate`.
      - [ ] CBOR metadata can be decoded by a simple reader or unit test.

---

## Milestone 6 – Tar Integration via `libarchive` (Deferring Payload Hashing)

### `common/tar_encoder.{c,h}` and `common/tar_decoder.{c,h}`

- [ ] **Interface design only (no in-tree implementation yet)**
  - [ ] Define C APIs for:
    - [ ] Creating a tar stream from a directory tree (`tar_encoder`).
    - [ ] Extracting a decompressed tar stream into a target directory (`tar_decoder`).
  - [ ] Define shared error codes and basic invariants (e.g. path normalization, safety rules) that will be honored by the future in-tree implementation.
  - [ ] Ensure these interfaces will be suitable for being implemented without `libarchive` in milestone 14.

### `piadina/extractor_tar_gzip.{c,h}` (via `libarchive`)

- [ ] **Implementation**
  - [ ] Implement an `extractor_tar_gzip` module that:
    - [ ] Uses `libarchive` to read a tar+gzip stream from an open file descriptor and offset/size.
    - [ ] Extracts entries into a target directory, honoring safety checks (no escape outside target root).
    - [ ] Translates `libarchive` errors into project-specific error codes.
  - [ ] Integrate this module into `piadina/archive.{c,h}` as the concrete backend for `"tar+gzip"`.

### `azdora/packer_tar_gzip.{c,h}` (via `libarchive`)

- [ ] **Implementation**
  - [ ] Implement a `packer_tar_gzip` module that:
    - [ ] Uses `libarchive` to walk a payload directory and emit a tar+gzip archive.
    - [ ] Writes the archive bytes to the output file in the layout expected by `assembler.{c,h}`.
    - [ ] Translates `libarchive` errors into project-specific error codes.
  - [ ] Integrate this module into `azdora/assembler.{c,h}` so the archive block is produced via `libarchive`.

### Integration into Azdora

- [ ] **Tar + gzip pipeline for Azdora**
  - [ ] Ensure `packer_tar_gzip` is invoked from `azdora/assembler` to:
    - [ ] Walk the payload directory and produce a tar+gzip archive using `libarchive`.
    - [ ] Write the resulting tar+gzip stream into the archive block region of the final binary.
  - [ ] For now, continue to use placeholder or zeroed hashes in footer/metadata (until hashing is implemented in milestone 12).
### Tests for milestone 6

- [ ] **Unit tests for `extractor_tar_gzip` and `packer_tar_gzip`**
  - [ ] Create simple directory trees (files, dirs, symlinks).
  - [ ] Pack them with `packer_tar_gzip` (using `libarchive`), then extract with `extractor_tar_gzip`.
  - [ ] Verify:
    - [ ] Paths.
    - [ ] File modes (to the extent recorded).
    - [ ] Contents.
    - [ ] Symlink behavior and safety checks (no extraction outside target root).

- [ ] **Integration tests**
  - [ ] Azdora + Piadina:
    - [ ] Create a payload directory.
    - [ ] Pack it using Azdora.
    - [ ] Run the resulting binary with Piadina and confirm that extraction and launch succeed.
    - [ ] Optionally, use an external tar tool to verify the embedded archive is a valid tar+gzip stream.

---

## Milestone 7 – Full Metadata Decoding/Encoding and Templating

### Piadina metadata decode (`piadina/cbor_decode.{c,h}` and `piadina/metadata.{c,h}`)

- [ ] **Launcher-side metadata struct**
  - [ ] Define `struct piadina_metadata` with fields for:
    - [ ] All top-level scalars (`VERSION`, `APP_NAME`, etc.).
    - [ ] Arrays (`ENTRY_ARGS`, `ENTRY_ARGS_POST`).
    - [ ] Maps (`ENV`, `EXTRA`, etc.).

- [ ] **CBOR decode implementation**
  - [ ] Implement schema-aware decoder:
    - [ ] Decode top-level map.
    - [ ] Validate field names via `metadata_core`.
    - [ ] Enforce presence/absence of required/optional fields.
    - [ ] Apply defaults for missing optional fields.
  - [ ] Enforce `"VERSION"` compatibility:
    - [ ] Accept only the schema version compiled into the launcher.
    - [ ] Reject missing, lower, or higher versions with a clear error.

### Azdora metadata build/encode (`azdora/metadata.{c,h}`, `azdora/cbor_encode.{c,h}`)

- [ ] **Metadata representation (builder side)**
  - [ ] Extend Azdora’s metadata structure to fully represent:
    - [ ] Top-level fields.
    - [ ] Arrays (`ENTRY_ARGS`, `ENTRY_ARGS_POST`).
    - [ ] Maps (`ENV`, `EXTRA`, and future maps).

- [ ] **`--meta` key-path parsing**
  - [ ] Implement parsing for:
    - [ ] Top-level scalars: `KEY=VALUE`.
    - [ ] Maps: `MAP.KEY=VALUE`.
    - [ ] Arrays:
      - [ ] Indexed: `ARRAY[INDEX]=VALUE`.
      - [ ] Append: `ARRAY[]=VALUE`.
  - [ ] Enforce dense 0-based indexing for arrays:
    - [ ] Reject configurations with holes (e.g. `ENTRY_ARGS[10]` without 0–9).

- [ ] **Typed values support**
  - [ ] Implement value-type prefixes:
    - [ ] Unsigned integer: `u:VALUE`.
    - [ ] Boolean: `b:true` / `b:false`.
    - [ ] Byte strings: `hex:...` and `b64:...`.
  - [ ] Map them to correct CBOR types in `cbor_encode`.

### Templating in Piadina (`piadina/template.{c,h}` and `piadina/context.{c,h}`)

- [ ] **Template engine**
  - [ ] Implement `{VAR}` substitution:
    - [ ] Gather initial variable set from process environment (`{HOME}`, `{TMPDIR}`, `{UID}`, `{GID}`).
    - [ ] Add metadata-based variables (`{PAYLOAD_HASH}`, `{ARCHIVE_HASH}`).
  - [ ] Implement substitution function that:
    - [ ] Replaces `{VAR}` with value.
    - [ ] Fails on unknown variables.

- [ ] **Context resolution**
  - [ ] Define `struct piadina_context` containing:
    - [ ] Effective `CACHE_ROOT`, `PAYLOAD_ROOT`, `TEMP_DIR`, `LOCK_FILE`, `READY_MARKER`.
    - [ ] Effective `ENTRY_POINT`, `ENTRY_ARGS`, `CLEANUP_POLICY`, `VALIDATE`, `LOG_LEVEL`.
    - [ ] Resolved `ENV` and user-defined maps.
    - [ ] Both:
      - [ ] Fully expanded runtime values.
      - [ ] Original template values for `.piadina_env` (for later milestones).
  - [ ] Implement evaluation order:
    - [ ] Resolve `CACHE_ROOT` first (from metadata or default `"{HOME}/.piadina/cache"`).
    - [ ] Export `{CACHE_ROOT}` to template variables.
    - [ ] Resolve `PAYLOAD_ROOT` next (from metadata or default `"{PAYLOAD_HASH}"` combined with cache root).
    - [ ] Apply substitution in `ENV` entries last, using all known variables.

### Tests for milestone 7

- [ ] **Unit tests for metadata decode/encode**
  - [ ] Round-trip tests for full metadata structures through Azdora encode → Piadina decode.
  - [ ] Error tests:
    - [ ] Invalid keys.
    - [ ] Invalid enum values.
    - [ ] Missing required fields.
    - [ ] Version mismatch.

- [ ] **Unit tests for templating**
  - [ ] Verify `{VAR}` substitution with system env variables.
  - [ ] Verify `CACHE_ROOT` and `PAYLOAD_ROOT` resolution order.
  - [ ] Verify error on unknown variables.

- [ ] **Integration tests**
  - [ ] Use Azdora to create binaries with various `CACHE_ROOT`, `PAYLOAD_ROOT`, and `ENV` configurations.
  - [ ] Confirm Piadina resolves them as expected.

---

## Milestone 8 – Extraction and Basic Caching (Single-Process)

### Archive abstraction (`piadina/archive.{c,h}` and `piadina/extractor_tar_gzip.{c,h}`)

- [ ] **Archive interface**
  - [ ] Define a generic archive extraction interface:
    - [ ] Function to check if a given `ARCHIVE_FORMAT` is supported.
    - [ ] Function to extract from a file descriptor + offset/size into target directory.

- [ ] **tar+gzip backend**
  - [ ] Implement `extractor_tar_gzip`:
    - [ ] Accept file descriptor and offset/size for the archive.
    - [ ] Use `lseek` to position at `archive_offset`.
    - [ ] Decompress gzip stream with `zlib`.
    - [ ] Feed decompressed stream into `tar_decoder`.

### Basic extraction logic (no locking/ready markers yet)

- [ ] **Context integration**
  - [ ] Use `piadina_context` to compute:
    - [ ] `CACHE_ROOT`.
    - [ ] `PAYLOAD_ROOT`.
    - [ ] Temporary extraction directory (`TEMP_DIR`).

- [ ] **Extraction path**
  - [ ] If `PAYLOAD_ROOT` exists:
    - [ ] Optionally reuse it without validation (simplified for this milestone).
  - [ ] If `PAYLOAD_ROOT` does not exist:
    - [ ] Remove any existing `TEMP_DIR`.
    - [ ] Create `TEMP_DIR`.
    - [ ] Extract archive into `TEMP_DIR` via archive backend.
    - [ ] Atomically rename `TEMP_DIR` to `PAYLOAD_ROOT`.

### Providing a minimal runnable prototype

- [ ] **Launcher behavior**
  - [ ] Combine:
    - [ ] Footer read/validate.
    - [ ] Metadata decode.
    - [ ] Context resolution.
    - [ ] Archive extraction.
    - [ ] Process launch with a real payload.
  - [ ] Ensure:
    - [ ] Single-process, sequential runs reuse existing `PAYLOAD_ROOT` where possible.
    - [ ] No `.piadina_env` or validation/cleanup policies beyond a simple default.

### Tests for milestone 8

- [ ] **Integration tests**
  - [ ] Use Azdora to pack a small payload (e.g. simple shell script or small program).
  - [ ] Run Piadina:
    - [ ] Confirm extraction into cache.
    - [ ] Confirm payload launches successfully.
  - [ ] Re-run Piadina:
    - [ ] Confirm payload is re-used without re-extraction (as observed via logs or timestamps).

---

## Milestone 9 – Lock Management and Ready Markers

### Locking (`piadina/lock.{c,h}`)

- [ ] **API and data structures**
  - [ ] Define lock operations:
    - [ ] `lock_acquire(...)`.
    - [ ] `lock_release(...)`.
  - [ ] Define lock file content format:
    - [ ] PID.
    - [ ] Timestamp.
    - [ ] Optional hostname.

- [ ] **Lock acquisition logic**
  - [ ] Attempt to create lock file with `O_CREAT | O_EXCL`.
  - [ ] On success:
    - [ ] Write identifying info to lock file.
  - [ ] On failure:
    - [ ] Read lock file contents.
    - [ ] Check whether PID is alive (e.g. `kill(pid, 0)`).
      - [ ] If alive: decide to wait with retry or return error.
      - [ ] If dead: treat as stale, remove lock file, retry acquisition.

### Ready marker and extraction integration

- [ ] **Context extensions**
  - [ ] Extend `piadina_context` with:
    - [ ] `LOCK_FILE`.
    - [ ] `READY_MARKER`.

- [ ] **Extraction under lock**
  - [ ] Wrap extraction logic with lock acquisition/release:
    - [ ] Under lock:
      - [ ] If `PAYLOAD_ROOT` and `READY_MARKER` exist:
        - [ ] Reuse payload (validation behavior deferred to milestone 12).
      - [ ] Otherwise:
        - [ ] Clean up `TEMP_DIR`.
        - [ ] Extract into `TEMP_DIR`.
        - [ ] Atomically rename to `PAYLOAD_ROOT`.
        - [ ] Create/update `READY_MARKER`.
    - [ ] Release lock and unlink lock file when done.

### Tests for milestone 9

- [ ] **Unit tests for `lock`**
  - [ ] Single process lock acquire/release.
  - [ ] Simulated concurrent acquire (e.g. via fork or threads).
  - [ ] Stale lock handling when PID is not alive.

- [ ] **Integration tests**
  - [ ] Start multiple Piadina processes for same payload concurrently:
    - [ ] Verify that only one process performs extraction.
    - [ ] Others wait and then reuse ready payload.
    - [ ] No cache corruption occurs.

---

## Milestone 10 – Process Lifecycle, Exit Codes, and Cleanup Policies

### Process management (`piadina/process.{c,h}`)

- [ ] **Argument assembly**
  - [ ] Build `argv` for child process as:
    - [ ] `argv[0]` = basename of `ENTRY_POINT`.
    - [ ] Followed by:
      - [ ] Metadata `ENTRY_ARGS`.
      - [ ] CLI arguments after `--`.
      - [ ] Metadata `ENTRY_ARGS_POST`.

- [ ] **Environment construction**
  - [ ] Start from current environment.
  - [ ] Optionally strip `PIADINA_*` variables.
  - [ ] Apply metadata `ENV` map overrides (add or override).

- [ ] **Signal handling**
  - [ ] Install handlers for `SIGINT` and `SIGTERM`:
    - [ ] Forward these signals to the child using `kill(child_pid, signum)`.
  - [ ] Ensure proper signal mask management around `fork`/`execve`.

- [ ] **Child lifecycle**
  - [ ] `fork` + `execve` the target executable path (`PAYLOAD_ROOT` + `ENTRY_POINT`).
  - [ ] In parent:
    - [ ] Wait with `waitpid`.
    - [ ] On normal exit:
      - [ ] Capture `exit_code = WEXITSTATUS(status)`.
    - [ ] On signal:
      - [ ] Capture `signum = WTERMSIG(status)`.
      - [ ] Map to exit code `128 + signum`.

### Cleanup policy (`piadina/cleanup.{c,h}`)

- [ ] **Policy evaluation**
  - [ ] Implement handling for:
    - [ ] `never`.
    - [ ] `oncrash`.
    - [ ] `always`.
  - [ ] Decide crash definition (non-zero exit code or termination by signal).

- [ ] **Directory deletion**
  - [ ] Implement safe recursive deletion for `PAYLOAD_ROOT`:
    - [ ] Avoid following symlinks out of tree.
    - [ ] Handle partial failures (e.g. permissions) with logging.

### Exit codes and error handling

- [ ] **Launcher internal error codes**
  - [ ] Ensure Piadina uses codes 111–116 appropriately:
    - [ ] `111` – usage error.
    - [ ] `112` – footer/binary error.
    - [ ] `113` – metadata error.
    - [ ] `114` – extraction error.
    - [ ] `115` – launch error.
    - [ ] `116` – signal/system error.

### Tests for milestone 10

- [ ] **Unit tests for `process`**
  - [ ] Verify `argv` ordering.
  - [ ] Verify environment contents and `PIADINA_*` stripping.
  - [ ] Verify signal forwarding (using a helper child program that logs signals).

- [ ] **Unit tests for `cleanup`**
  - [ ] Confirm behavior for:
    - [ ] `never`: cache never removed.
    - [ ] `oncrash`: cache removed on non-zero exit or signal; retained on success.
    - [ ] `always`: cache removed regardless of exit status.

- [ ] **Integration tests**
  - [ ] Pack payloads that exit with `0` and non-`0`:
    - [ ] Confirm Piadina’s exit code matches child outcome.
    - [ ] Confirm `CLEANUP_POLICY` behavior via presence/absence of payload directory.

---

## Milestone 11 – Exported Metadata File (`.piadina_env`)

### `.piadina_env` writer

- [ ] **API and data model**
  - [ ] Implement module (e.g. `piadina/env_export.{c,h}` or part of `context`):
    - [ ] Accepts `piadina_context` and decoded metadata.
    - [ ] Writes `.piadina_env` file into `PAYLOAD_ROOT`.

- [ ] **File format implementation**
  - [ ] Ensure output:
    - [ ] Is UTF-8, text, `KEY=VALUE` lines.
    - [ ] Uses shell-safe key names `[A-Z_][A-Z0-9_]*`.
  - [ ] Implement value escaping rules:
    - [ ] Write bare `VALUE` when safe.
    - [ ] Otherwise, double-quote and escape `"`, `\`, newlines (`\n`), tabs (`\t`).
  - [ ] Encode binary metadata as `KEY=base64:ENCODED`.

- [ ] **Arrays and maps**
  - [ ] Scalar values:
    - [ ] Export as single `KEY=VALUE`.
  - [ ] Arrays:
    - [ ] Export `X_COUNT` and `X_0`, `X_1`, ….
  - [ ] Maps:
    - [ ] Export as `PREFIX_KEY="..."` where `PREFIX` is map name (e.g. `ENV_`).
    - [ ] For `ENV` only:
      - [ ] Also export unprefixed `KEY` names, uppercased and sanitized.
      - [ ] Ensure unprefixed `ENV` variants appear after all metadata-derived and prefixed variables.

- [ ] **Ordering and template placeholders**
  - [ ] Ensure:
    - [ ] Variables used by others are defined first (`PAYLOAD_HASH`, `CACHE_ROOT`, `PAYLOAD_ROOT`, etc.).
    - [ ] Metadata templates `{VAR}` are converted to `${VAR}` in output values (no eager substitution).

- [ ] **Integration into extraction**
  - [ ] Under extraction lock:
    - [ ] After successful extraction or validated reuse:
      - [ ] Write or refresh `.piadina_env`.

### Tests for milestone 11

- [ ] **Unit tests for `.piadina_env` writer**
  - [ ] Verify correct formatting and escaping for:
    - [ ] Simple scalars.
    - [ ] Arrays and maps.
    - [ ] Binary values.
  - [ ] Verify correct ordering of variables and `{VAR}` → `${VAR}` conversion.
  - [ ] Verify collision behavior where `ENV` overrides metadata keys.

- [ ] **Integration tests**
  - [ ] Pack a payload with `ENV`, `EXTRA`, and `ENTRY_ARGS`.
  - [ ] Run Piadina and inspect `.piadina_env`:
    - [ ] `source` the file in a shell.
    - [ ] Confirm the environment matches expectations and application runs correctly.

---

## Milestone 12 – Payload Hashing and Verification

### Shared hashing helpers

- [ ] **Hashing API**
  - [ ] Implement shared module (e.g. `common/hash.{c,h}`) for:
    - [ ] Computing `PAYLOAD_HASH` as defined in §3.1.3.1:
      - [ ] Directory walk, entry classification (`D`, `F`, `L`).
      - [ ] Lexicographic sorting by path.
      - [ ] Feeding type, path, mode, contents/targets into SHA-256.
    - [ ] Computing `ARCHIVE_HASH` over tar+gzip stream as in §3.1.3.2.

- [ ] **Integration into Azdora**
  - [ ] During assembly:
    - [ ] Use payload tree traversal to compute `PAYLOAD_HASH`.
    - [ ] Use archive bytes to compute `ARCHIVE_HASH`.
  - [ ] Populate:
    - [ ] Metadata `PAYLOAD_HASH`.
    - [ ] Footer `archive_hash`.
    - [ ] Metadata `ARCHIVE_HASH`.

### Validation in Piadina

- [ ] **Validate existing payloads**
  - [ ] Implement validation path when `VALIDATE=true`:
    - [ ] If `PAYLOAD_ROOT` and `READY_MARKER` exist:
      - [ ] Recompute directory hash using the same algorithm.
      - [ ] Compare to `PAYLOAD_HASH` from metadata.
      - [ ] If mismatch:
        - [ ] Remove or move aside `PAYLOAD_ROOT`.
        - [ ] Proceed with re-extraction.
  - [ ] Honor `force_extract` configuration:
    - [ ] When `force_extract=true`, re-extract regardless of validation result.

### Tests for milestone 12

- [ ] **Unit tests for hashing**
  - [ ] Two identical trees produce identical `PAYLOAD_HASH`.
  - [ ] Small changes in content, mode, or path change the hash.
  - [ ] `ARCHIVE_HASH` matches independent hashing of archive bytes.

- [ ] **Integration tests**
  - [ ] Create two identical payloads:
    - [ ] Verify their `PAYLOAD_HASH` and `ARCHIVE_HASH` match.
  - [ ] Modify a file in an existing extracted payload:
    - [ ] With `VALIDATE=true`, Piadina detects mismatch and re-extracts.

---

## Milestone 13 – Extended Integration (Linux)

### Linux-specific refinements

- [ ] **Platform behavior**
  - [ ] Review and refine Linux-specific behaviors in `platform`, `process`, `lock`, and filesystem handling.
  - [ ] Ensure robust handling of:
    - [ ] `/proc/self/exe` nuances.
    - [ ] Signal semantics.
    - [ ] Filesystem permissions and edge cases.

### CI and tooling

- [ ] **CI setup**
  - [ ] Configure CI to run:
    - [ ] `./configure && make && make check` on at least one Linux environment.
    - [ ] At least one configuration built with AddressSanitizer (`-fsanitize=address`).

- [ ] **Memory checking**
  - [ ] Periodically run `make check` under Valgrind (or equivalent):
    - [ ] Ensure no leaks or invalid memory accesses in unit and integration tests.

### Additional integration tests

- [ ] **End-to-end scenarios**
  - [ ] Add integration tests for:
    - [ ] Concurrent launcher runs with real payloads.
    - [ ] Different cache roots and cleanup policies.
    - [ ] Realistic Erlang/OTP release-like payloads.
  - [ ] Document any observed OS-specific behaviors and ensure they are stable across runs.

---

## Milestone 14 – In-Tree Tar Implementation (Replacing Vendored Tar Backend)

> Goal: Replace the interim vendored tar implementation (via `libarchive`) with a minimal, self-contained tar encoder/decoder while preserving the existing `tar_encoder` / `tar_decoder` abstraction.

### Design and preparation

- [ ] **Confirm abstraction boundaries**
  - [ ] Review existing `common/tar_encoder.{c,h}` and `common/tar_decoder.{c,h}` interfaces.
  - [ ] Ensure no callers reach directly into the vendored tar library APIs (all usage must go through these modules).
  - [ ] Document supported tar subset (file types, metadata fields, ordering, size limits).

- [ ] **Reference behavior capture**
  - [ ] Create small, representative payload trees (files, dirs, symlinks, edge cases).
  - [ ] Using the current vendored tar backend:
    - [ ] Generate tar+gzip archives for each test tree.
    - [ ] Save these archives as “golden” fixtures for regression comparison.

### Implement in-tree tar encoder

- [ ] **Header encoding**
  - [ ] Implement functions to:
    - [ ] Build tar headers (e.g. ustar/POSIX format) from internal entry struct.
    - [ ] Encode path, mode, size, mtime, type flag, linkname, and basic ownership fields.
  - [ ] Implement block padding and end-of-archive markers.

- [ ] **Directory walk and ordering**
  - [ ] Reuse or refine directory-walk logic used for payload hashing to:
    - [ ] Traverse payload root.
    - [ ] Classify entries as directory, regular file, symlink.
    - [ ] Produce a lexicographically sorted list of paths.
  - [ ] For each entry in sorted order:
    - [ ] Emit a header block.
    - [ ] For regular files, stream file contents and padding blocks.

- [ ] **Safety rules**
  - [ ] Enforce that symlinks whose canonical target is outside the payload root are rejected with a clear error.
  - [ ] Optionally rewrite absolute symlink targets that resolve inside the root to relative ones while preserving link semantics.

### Implement in-tree tar decoder

- [ ] **Header parsing**
  - [ ] Implement functions to:
    - [ ] Parse tar header blocks into an internal entry struct.
    - [ ] Validate checksums and basic fields.
  - [ ] Handle end-of-archive markers correctly.

- [ ] **Extraction**
  - [ ] For each entry:
    - [ ] Create directories as needed.
    - [ ] Create regular files and stream contents from input.
    - [ ] Create symlinks with stored target.
    - [ ] Apply file modes and basic metadata where required.

### Swap implementation and deprecate vendored tar

- [ ] **Wire in-tree tar under existing interface**
  - [ ] Replace calls to the vendored tar backend inside `tar_encoder` / `tar_decoder` with calls to the new in-tree implementation.
  - [ ] Keep the public C API of `tar_encoder` / `tar_decoder` unchanged so higher layers (`archive`, `assembler`, tests) do not need modification.
  - [ ] Update `azdora/packer_tar_gzip.{c,h}` so that:
    - [ ] It delegates tar stream creation to `tar_encoder` instead of calling `libarchive` directly.
    - [ ] It remains the single integration point for assembling a `"tar+gzip"` archive in Azdora, now backed by the in-tree tar implementation by default.

- [ ] **Optional fallback/removal**
  - [ ] Decide whether to:
    - [ ] Remove vendored tar library entirely, or
    - [ ] Keep it compiled-out behind a configure flag (e.g. `--with-system-tar`), defaulting to the in-tree implementation.

### Tests for milestone 14

- [ ] **Golden-file comparisons**
  - [ ] For each reference payload tree:
    - [ ] Generate a tar+gzip archive with the new in-tree encoder.
    - [ ] Compare structure and semantics against the original vendored-output fixtures (using external `tar`/`cmp` tools as needed).

- [ ] **Round-trip tests**
  - [ ] Encode a payload tree with the in-tree encoder and decode it with the in-tree decoder:
    - [ ] Verify contents, paths, and modes.
    - [ ] Verify symlink behavior and safety constraints.

- [ ] **End-to-end integration**
  - [ ] Build Azdora + Piadina with vendored tar disabled (if applicable).
  - [ ] Re-run existing integration tests:
    - [ ] Verify no regressions in packing, extraction, and launch behavior.

---

## Milestone 15 – In-Tree CBOR Implementation (Replacing Vendored CBOR Backend)

> Goal: Replace the interim vendored CBOR implementation (`libcbor`) with a minimal, self-contained encoder/decoder behind the existing `cbor_core` / `cbor_encode` / `cbor_decode` abstractions.

### Design and preparation

- [ ] **Confirm abstraction boundaries**
  - [ ] Review `common/cbor_core.{c,h}`, `piadina/cbor_decode.{c,h}`, and `azdora/cbor_encode.{c,h}`.
  - [ ] Ensure all external CBOR usage is routed through these modules (no direct calls to the vendored CBOR API).
  - [ ] Enumerate the exact subset of CBOR types and container patterns used by the metadata schema.

- [ ] **Reference behavior capture**
  - [ ] For a set of representative metadata structures:
    - [ ] Use the current vendored CBOR implementation to encode them.
    - [ ] Save encoded CBOR blobs as “golden” fixtures.
  - [ ] Decode these fixtures through the existing decoder and record expected in-memory structures for comparison.

### Implement in-tree CBOR core

- [ ] **Encoding primitives**
  - [ ] Implement minimal encoding for:
    - [ ] Unsigned integers.
    - [ ] Booleans.
    - [ ] Text strings.
    - [ ] Byte strings.
    - [ ] Array headers (fixed-size).
    - [ ] Map headers with text keys.
  - [ ] Implement buffer management strategy (growable buffer or explicit size checks with error codes).

- [ ] **Decoding primitives**
  - [ ] Implement minimal decoding for the same subset of types:
    - [ ] Properly handle major types and additional-info values.
    - [ ] Enforce definite-length containers (no need to support indefinite-length for v0.1).
  - [ ] Provide clear error codes for malformed input or unsupported features.

### Integrate with launcher and packer

- [ ] **Azdora encoding path**
  - [ ] Reimplement `azdora/cbor_encode` to use only the in-tree `cbor_core` primitives.
  - [ ] Ensure output for typical metadata structures is byte-for-byte compatible with the previous vendored implementation where feasible, or at least semantically equivalent and schema-compliant.

- [ ] **Piadina decoding path**
  - [ ] Reimplement `piadina/cbor_decode` to use only the in-tree `cbor_core` primitives.
  - [ ] Ensure all validation and defaulting logic in `metadata_core` continues to work unchanged.

- [ ] **Remove / gate vendored CBOR**
  - [ ] Remove direct dependencies on the external CBOR library, or
    - [ ] Make it optional via a configure flag (e.g. `--with-system-cbor`), defaulting to the in-tree implementation.

### Tests for milestone 15

- [ ] **Golden encoding tests**
  - [ ] For each golden metadata structure:
    - [ ] Encode with the new in-tree encoder.
    - [ ] Compare against previously captured blobs or check via decode + structural comparison.

- [ ] **Round-trip tests**
  - [ ] Azdora encode → Piadina decode for:
    - [ ] Simple metadata.
    - [ ] Full metadata with maps, arrays, and typed values.
  - [ ] Verify that all fields, defaults, and validation behavior match expectations.

- [ ] **Failure-mode tests**
  - [ ] Feed truncated or malformed CBOR to the decoder:
    - [ ] Confirm robust error reporting and no crashes.

- [ ] **End-to-end integration**
  - [ ] Build Azdora + Piadina with vendored CBOR disabled (if applicable).
  - [ ] Re-run the full `make check` suite:
    - [ ] Confirm no regressions relative to the vendored-CBOR configuration.
