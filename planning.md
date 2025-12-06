<!--
SPDX-FileCopyrightText: 2024 Dipl.Phys. Peer Stritzinger GmbH
SPDX-License-Identifier: Apache-2.0
-->

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

- [x] **Design log API**
  - [x] Define log levels enum (e.g. `LOG_DEBUG`, `LOG_INFO`, `LOG_WARN`, `LOG_ERROR`).
  - [x] Define functions:
    - [x] `log_set_level(...)` to set current minimum log level.
    - [x] `log_get_level()` accessor.
    - [x] `log_debug(...)`, `log_info(...)`, `log_warn(...)`, `log_error(...)` (or a generic `log_log(level, ...)`).
  - [x] Decide on formatting convention (e.g. `[LEVEL] message`).

- [x] **Implementation**
  - [x] Implement logging functions, writing to `stderr`.
  - [x] Ensure functions are safe to call before configuration is fully initialized (sane defaults).

### `common/platform.{c,h}`

- [x] **API definition**
  - [x] Define a function to get the current executable path:
    - [x] `int platform_get_self_exe_path(char *buf, size_t buf_size);`
  - [x] Define basic error codes or return conventions.

- [x] **Linux implementation**
  - [x] Implement using `/proc/self/exe` when available:
    - [x] Use `readlink` to read the symlink.
    - [x] Null-terminate the result.
    - [x] Handle truncation and errors cleanly.
  - [x] Provide a fallback using `argv[0]` if `/proc/self/exe` is unavailable (design decision: may be done later or via helper).

- [x] **Non-Linux stubs**
  - [x] Provide stubs for other platforms (macOS/Windows) that:
    - [x] Compile but return clear “not implemented” error codes.

### `common/footer.{c,h}`

- [x] **Struct definition**
  - [x] Define a packed C struct matching §3.1.2:
    - [x] `magic[8]`.
    - [x] `uint32_t layout_version`.
    - [x] `uint64_t metadata_offset`.
    - [x] `uint64_t metadata_size`.
    - [x] `uint64_t archive_offset`.
    - [x] `uint64_t archive_size`.
    - [x] `uint8_t archive_hash[32]`.
    - [x] `uint8_t footer_hash[32]`.
    - [x] `uint8_t reserved[12]`.
  - [x] Ensure struct layout is tightly packed and little-endian (use static asserts if available).

- [x] **Constants**
  - [x] Define `FOOTER_MAGIC = "PIADINA\0"`.
  - [x] Define `FOOTER_LAYOUT_VERSION = 1`.
  - [x] Define `FOOTER_SIZE` constant as `sizeof(struct footer)` and assert equals 64 bytes.

- [x] **Footer read/validate API**
  - [x] Declare functions:
    - [x] `int footer_read(int fd, struct footer *out_footer);`
    - [x] `int footer_validate(const struct footer *footer);`
  - [x] Define error codes for:
    - [x] Bad magic.
    - [x] Unsupported layout version.
    - [x] Short read / file too small.
    - [x] Footer checksum mismatch (if implemented at this stage or reserved for later).

- [x] **Implementation**
  - [x] Implement `footer_read`:
    - [x] Use `lseek` to position at `file_size - FOOTER_SIZE`.
    - [x] Read into `out_footer`.
    - [x] Handle errors and partial reads.
  - [x] Implement `footer_validate`:
    - [x] Verify `magic`.
    - [x] Verify `layout_version`.
    - [x] Optionally verify `reserved` bytes are zero for version 1.

### Tests for milestone 2

- [x] **Unit tests for `log`**
  - [x] Verify each log-level function is callable without crashing.
  - [x] Optionally capture `stderr` to confirm formatting and level filtering.

- [x] **Unit tests for `platform_get_self_exe_path()` (Linux)**
  - [x] Test successful path resolution on Linux.
  - [x] Test buffer too small case returns an appropriate error.

- [x] **Unit tests for `footer_read()` and `footer_validate()`**
  - [x] Create a temporary file with a valid footer and assert:
    - [x] `footer_read` succeeds.
    - [x] `footer_validate` succeeds.
  - [x] Create a file with wrong magic and assert:
    - [x] `footer_validate` returns "bad magic" error.
  - [x] Create a file with wrong layout version and assert:
    - [x] `footer_validate` returns "bad version" error.
  - [x] Create a file with non-zero reserved bytes and assert:
    - [x] `footer_validate` returns "reserved non-zero" error.
  - [x] Create a truncated file and assert:
    - [x] `footer_read` reports explicit error.

---

## Milestone 3 – Shared CBOR and Metadata Core Primitives

> For this milestone, all CBOR helpers are thin wrappers around `libcbor`. The goal is to finalize the abstraction (`cbor_core`, encoder, decoder, metadata helpers) so that swapping the backend later requires no API changes elsewhere in the project.

### `common/cbor_core.{c,h}`

- [x] **Type and constant definitions**
  - [x] Define basic CBOR type tags/constants for:
    - [x] Unsigned integers.
    - [x] Booleans.
    - [x] Text strings.
    - [x] Byte strings.
    - [x] Arrays.
    - [x] Maps with string keys.

- [x] **Encoding primitives**
  - [x] Design function signatures for encoding:
    - [x] Unsigned integers.
    - [x] Booleans (`true`/`false`).
    - [x] Text strings (length + UTF-8 bytes).
    - [x] Byte strings.
    - [x] Array headers (length + items encoded by callers).
    - [x] Map headers with string keys.
  - [x] Provide an internal abstraction that can be backed by a vendored CBOR library (`libcbor`) for the initial prototype.

- [x] **Decoding primitives**
  - [x] Design function signatures for decoding:
    - [x] Unsigned integers.
    - [x] Booleans.
    - [x] Text strings (pointer/length).
    - [x] Byte strings.
    - [x] Array headers and iterating items.
    - [x] Map headers and iterating over string-key entries.
  - [x] Implement these functions initially as thin wrappers over the chosen CBOR library, translating between its API and the `cbor_core` abstraction.
  - [x] Provide clear error codes for malformed CBOR or unsupported types, independent of the underlying library’s error representation.

### `common/metadata_core.{c,h}`

- [x] **Schema constants and enums**
  - [x] Define constants/enums for top-level fields:
    - [x] `VERSION`, `APP_NAME`, `APP_VER`, `ARCHIVE_HASH`, `ARCHIVE_FORMAT`,
      `PAYLOAD_HASH`, `ENTRY_POINT`, `ENTRY_ARGS`, `ENTRY_ARGS_POST`, `CACHE_ROOT`,
      `PAYLOAD_ROOT`, `CLEANUP_POLICY`, `VALIDATE`, `LOG_LEVEL`, `ENV`, and user-defined maps, etc.

- [x] **Key naming validation**
  - [x] Implement function to verify key names match `[a-zA-Z-_][a-zA-Z0-9-_]*`.
  - [x] Ensure usage in both encoder and decoder paths.

- [x] **Enum value validation**
  - [x] Implement validators for:
    - [x] `CLEANUP_POLICY` (values `never`, `oncrash`, `always`).
    - [x] `LOG_LEVEL` (values `debug`, `info`, `warn`, `error`).
    - [x] `ARCHIVE_FORMAT` (must be `"tar+gzip"` in v0.1).

- [x] **Defaults and helpers**
  - [x] Implement helpers to:
    - [x] Apply default `ARCHIVE_FORMAT="tar+gzip"` when absent.
    - [x] Apply default `CLEANUP_POLICY="oncrash"`.
    - [x] Apply default `VALIDATE=false`.
    - [x] Apply default `LOG_LEVEL="info"`.
  - [x] Provide API to map between CBOR keys (strings) and internal identifiers.

### Tests for milestone 3

- [x] **Unit tests for `cbor_core`**
  - [x] Round-trip tests using the `cbor_core` API (backed by the vendored CBOR library) for:
    - [x] Unsigned integers (various values).
    - [x] Booleans.
    - [x] Text strings (ASCII and UTF-8).
    - [x] Byte strings.
    - [x] Arrays and nested arrays/maps.
  - [x] Negative tests for malformed encodings, ensuring the abstraction returns consistent error codes regardless of the underlying library’s behavior.

- [x] **Unit tests for `metadata_core`**
  - [x] Key naming tests:
    - [x] Accept valid identifiers.
    - [x] Reject invalid ones.
  - [x] Enum value tests:
    - [x] Accept allowed values.
    - [x] Reject unknown values with clear errors.
  - [x] Defaults tests:
    - [x] Confirm default values are applied when fields are missing.

---

## Milestone 4 – Static Build Support

### Configure / Toolchain detection

- [x] **Static-by-default**
  - [x] Make static builds the default: `configure` should attempt to produce fully static binaries (musl or glibc `-static`) without extra flags.
  - [x] Add `--disable-static-build` for situations where developers need dynamic binaries.

- [x] **Dependency verification**
  - [x] During `configure`, detect whether static variants of required libraries (`libc`, `libcbor`, `libarchive`, `libz`, etc.) are available; fail early with a clear error if any are missing.

- [x] **Musl toolchain support**
  - [x] Auto-detect `musl-gcc` and use it by default for static builds when available.
  - [x] Add `--with-musl` option to force musl usage (error if not available).
  - [x] Add `--without-musl` option to disable musl even when available.

### Linking + docs

- [x] **Static linkage plumbing**
  - [x] When the static flag is enabled, ensure both `piadina` and `azdora` pass `-static` (or equivalent) and link against the static archives.
  - [x] Update the README/developer notes describing how to perform a static build locally and what prerequisites (musl toolchain, static libs) are needed.

- [x] **Package requirements documentation**
  - [x] Document required packages: `libcbor-dev`, `libarchive-dev`.
  - [x] Document optional packages for portable builds: `musl-dev`, `musl-tools`.
  - [x] Add troubleshooting section for common build errors.

### Validation

- [x] **CI/test hook**
  - [x] Add a scripted test (can be optional) that runs the default (static) build (`./configure && make && make check`) and asserts `ldd piadina/piadina` and `ldd azdora/azdora` report "not a dynamic executable".

---

## Milestone 5 – Minimal Piadina Launcher Skeleton (No Tar Yet)

### `piadina/config.{c,h}`

- [x] **Config structure definition**
  - [x] Define `struct piadina_config` including:
    - [x] Cache root override.
    - [x] Cleanup policy override.
    - [x] Validate flag override.
    - [x] Force-extract flag override.
    - [x] Log level override.
    - [x] Other launcher-specific flags (`print-metadata`, `print-footer`, `help`, `version`).
    - [x] Collection of non-launcher arguments (application args after `--`).

- [x] **CLI parsing**
  - [x] Implement parser for `--launcher-*` options:
    - [x] `--launcher-cache-root=PATH`.
    - [x] `--launcher-cleanup=never|oncrash|always`.
    - [x] `--launcher-validate[=true|false]`.
    - [x] `--launcher-force-extract[=true|false]`.
    - [x] `--launcher-log-level=debug|info|warn|error`.
    - [x] `--launcher-verbose`.
    - [x] `--launcher-print-metadata`.
    - [x] `--launcher-print-footer`.
    - [x] `--launcher-help`.
    - [x] `--launcher-version`.
  - [x] Support both `--opt=value` and `--opt value` forms.
  - [x] Implement `--` separator handling:
    - [x] All arguments after `--` stored as application arguments, not parsed as launcher options.

- [x] **Environment variable parsing**
  - [x] Read `PIADINA_CACHE_ROOT`, `PIADINA_CLEANUP_POLICY`, `PIADINA_VALIDATE`,
    `PIADINA_FORCE_EXTRACT`, `PIADINA_LOG_LEVEL`.
  - [x] Map environment values to the same internal representation as CLI.

- [x] **Precedence rules**
  - [x] Implement logic: CLI overrides env, env overrides hard-coded defaults.

### `piadina/main.c` (extended)

- [x] **Self path resolution and footer handling**
  - [x] Use `platform_get_self_exe_path()` to determine launcher path.
  - [x] Open the executable file for reading.
  - [x] Use `footer_read()` and `footer_validate()` to:
    - [x] Read footer from the executable.
    - [x] Fail with internal error code (112) on invalid or missing footer.

- [x] **Temporary process launch (no tar/metadata yet)**
  - [x] Define a test configuration with hard-coded `ENTRY_POINT` (e.g. `/bin/echo`) and arguments.
  - [x] Implement a minimal `process` helper (or inline logic) to:
    - [x] `fork` + `execve` `/bin/echo` with test arguments.
    - [x] Return child exit status as launcher exit code.

### Tests for milestone 5

- [x] **Unit tests for `piadina/config`**
  - [x] Test various combinations of CLI options and environment variables for correct precedence.
  - [x] Test `--` separation behavior.
  - [x] Test boolean parsing for `--launcher-validate` / `PIADINA_VALIDATE`.

- [x] **Unit / integration tests for `process` or `main`**
  - [x] Test successful execution of `/bin/echo` and exit-code forwarding.
  - [x] Test behavior when `execve` fails (e.g. non-existent program) → launcher returns `115`.
  - [x] Integration test:
    - [x] Construct a test binary with a valid footer and run it.
    - [x] Verify:
      - [x] Footer is read.
      - [x] `/bin/echo` is invoked.
      - [x] Launcher exit status matches child exit status.

---

## Milestone 6 – Minimal Azdora Skeleton: Assembling a Minimal Binary

### `azdora/config.{c,h}`

- [x] **Config structure**
  - [x] Define configuration struct with:
    - [x] Launcher path (`--launcher` / `-l`).
    - [x] Payload directory path (`--payload` / `-p`).
    - [x] Output file path (`--output` / `-o`).
    - [x] Collection of `--meta` / `-m` entries (as raw strings for now).

- [x] **CLI parsing**
  - [x] Implement parsing for:
    - [x] `--launcher FILE_PATH` / `-l`.
    - [x] `--payload DIR_PATH` / `-p`.
    - [x] `--output FILE_PATH` / `-o`.
    - [x] Repeated `--meta PATH=VALUE` / `-m PATH=VALUE`.
  - [x] Implement default naming behavior for output when `--output` is omitted (basic initial behavior is acceptable here).

### `azdora/metadata.{c,h}` (minimal)

- [x] **Metadata representation**
  - [x] Define a minimal metadata struct sufficient for:
    - [x] `VERSION`.
    - [x] `APP_NAME`.
    - [x] `APP_VER`.
    - [x] `ENTRY_POINT`.
    - [x] Placeholder hash fields.

- [x] **Metadata construction**
  - [x] Implement functions to:
    - [x] Initialize metadata with default schema version.
    - [x] Apply parsed `--meta` entries (initial limited subset).
    - [x] Enforce that `VERSION` cannot be overridden by user input.

### `azdora/cbor_encode.{c,h}` (minimal, via `libcbor`)

- [x] **Encoding minimal map**
  - [x] Implement functions that use `cbor_core` / `libcbor` to encode a top-level metadata map containing:
    - [x] `VERSION` (uint).
    - [x] `APP_NAME` (text, optional).
    - [x] `APP_VER` (text, optional).
    - [x] `ENTRY_POINT` (text, optional).
    - [x] Placeholder hashes, if desired at this stage.

### `azdora/assembler.{c,h}`

- [x] **Launcher + metadata + placeholder archive assembly**
  - [x] Read launcher binary from disk.
  - [x] Encode minimal metadata to CBOR using `cbor_encode`.
  - [x] Decide representation for a placeholder archive block (empty or fixed placeholder).
  - [x] Compute offsets and sizes:
    - [x] `launcher_size`.
    - [x] `metadata_offset` = `launcher_size`.
    - [x] `metadata_size`.
    - [x] `archive_offset` = `launcher_size + metadata_size`.
    - [x] `archive_size` (placeholder).
  - [x] Construct footer struct with:
    - [x] Fill offsets and sizes.
    - [x] Set `ARCHIVE_HASH` to placeholder or zero value for now.
  - [x] Write final layout to output file:
    - [x] Launcher bytes.
    - [x] Metadata block.
    - [x] Placeholder archive block.
    - [x] Footer.

### Tests for milestone 6

- [x] **Unit tests for `azdora/config`**
  - [x] CLI parsing tests for each of `--launcher`, `--payload`, `--output`, `--meta`.
  - [x] Test error cases (missing required options).

- [x] **Unit tests for `azdora/metadata`**
  - [x] Test `--meta` handling for minimal fields.
  - [x] Test rejection of attempts to override `VERSION`.

- [x] **Unit tests for `azdora/cbor_encode`**
  - [x] Verify that encoded CBOR matches expectations from `cbor_core`.

- [x] **Integration test**
  - [x] Run Azdora on a test payload directory:
    - [x] Verify resulting binary layout:
      - [x] Footer can be read and validated using `footer_read`/`footer_validate`.
      - [x] CBOR metadata can be decoded by a simple reader or unit test.

---

### Milestone 6.5 – Documentation and Licensing Consistency

- [x] **Define documentation style**
  - [x] Adopt a uniform Doxygen-style block for all exported functions across azdora, piadina, and common headers.
  - [x] Specify required fields per function comment: brief, ownership/lifetime notes, parameter descriptions, and return/value semantics (including error handling and caller cleanup).
- [x] **Apply documentation pass**
  - [x] Update exported functions in azdora (metadata, assembler, config, cbor encoder) to the agreed style.
  - [x] Update exported functions in common (cbor_core, metadata_core, footer, log, platform) to the same style.
  - [x] Update exported functions in piadina headers as applicable.
- [x] **Clarify specification**
  - [x] Amend `specification.md` to state the chosen documentation style and the expectation that all exported APIs include ownership/cleanup details.
- [x] **Setup Doxygen**
  - [x] Create `Doxyfile.in` template.
  - [x] Update `configure.ac` to check for doxygen and generate `Doxyfile`.
  - [x] Add `doc` target to `Makefile.am`.
- [x] **SPDX Headers**
  - [x] Add SPDX-License-Identifier and Copyright headers to all source files.
  - [x] Use correct comment style for each file type.
- [x] **License Files**
  - [x] Create `LICENSES/` directory.
  - [x] Add `Apache-2.0.txt` and `MIT.txt`.
- [x] **REUSE Compliance**
  - [x] Create `.reuse/dep5` for vendored code exceptions (if any) or defaults.
  - [x] Verify compliance with `reuse lint`.

---

## Milestone 7 – Tar Integration via `libarchive` (Deferring Payload Hashing)

### `common/tar_encoder.{c,h}` and `common/tar_decoder.{c,h}`

- [ ] **Deferred to milestone 15**
  - These shared tar interfaces are not introduced in milestone 7 to avoid locking the API early. They will be designed and added alongside the in-tree tar implementation in milestone 15.

### `piadina/extractor_tar_gzip.{c,h}` (via `libarchive`)

- [x] **Implementation**
  - [x] Implement an `extractor_tar_gzip` module that:
    - [x] Uses `libarchive` to read a tar+gzip stream from an open file descriptor and offset/size.
    - [x] Extracts entries into a target directory, honoring safety checks (no escape outside target root).
    - [x] Translates `libarchive` errors into project-specific error codes.
  - [x] Integrate this module into `piadina/archive.{c,h}` as the concrete backend for `"tar+gzip"`.

### `azdora/packer_tar_gzip.{c,h}` (via `libarchive`)

- [x] **Implementation**
  - [x] Implement a `packer_tar_gzip` module that:
    - [x] Uses `libarchive` to walk a payload directory and emit a tar+gzip archive.
    - [x] Writes the archive bytes to the output file in the layout expected by `assembler.{c,h}`.
    - [x] Translates `libarchive` errors into project-specific error codes.
  - [x] Integrate this module into `azdora/assembler.{c,h}` so the archive block is produced via `libarchive`.

### Integration into Azdora

- [x] **Tar + gzip pipeline for Azdora**
  - [x] Ensure `packer_tar_gzip` is invoked from `azdora/assembler` to:
    - [x] Walk the payload directory and produce a tar+gzip archive using `libarchive`.
    - [x] Write the resulting tar+gzip stream into the archive block region of the final binary.
  - [x] For now, continue to use placeholder or zeroed hashes in footer/metadata (until hashing is implemented in milestone 12).

### Tests for milestone 7

- [x] **Unit tests for `extractor_tar_gzip` and `packer_tar_gzip`**
  - [x] Create simple directory trees (files, dirs, symlinks).
  - [x] Pack them with `packer_tar_gzip` (using `libarchive`), then extract with `extractor_tar_gzip`.
  - [x] Verify:
    - [x] Paths.
    - [x] File modes (to the extent recorded).
    - [x] Contents.
    - [x] Symlink behavior and safety checks (no extraction outside target root).

- [x] **Integration tests**
  - [x] Azdora + Piadina:
    - [x] Create a payload directory.
    - [x] Pack it using Azdora.
    - [x] Run the resulting binary with Piadina and confirm that extraction and launch succeed.
    - [x] Optionally, use an external tar tool to verify the embedded archive is a valid tar+gzip stream.

---

## Milestone 8 – Full Metadata Decoding/Encoding and Templating

### Piadina metadata decode (`piadina/cbor_decode.{c,h}` and `piadina/metadata.{c,h}`)

- [ ] **Launcher-side metadata struct**
  - [ ] Define `struct piadina_metadata` with fields for:
    - [ ] All top-level scalars (`VERSION`, `APP_NAME`, etc.).
    - [ ] Arrays (`ENTRY_ARGS`, `ENTRY_ARGS_POST`).
    - [ ] Maps (`ENV`, user-defined maps, etc.).

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
  - [ ] Maps (`ENV`, user-defined maps, and future maps).

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

### Tests for milestone 8

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

## Milestone 9 – Extraction and Basic Caching (Single-Process)

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

### Tests for milestone 9

- [ ] **Integration tests**
  - [ ] Use Azdora to pack a small payload (e.g. simple shell script or small program).
  - [ ] Run Piadina:
    - [ ] Confirm extraction into cache.
    - [ ] Confirm payload launches successfully.
  - [ ] Re-run Piadina:
    - [ ] Confirm payload is re-used without re-extraction (as observed via logs or timestamps).

---

## Milestone 10 – Lock Management and Ready Markers

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

### Tests for milestone 10

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

## Milestone 11 – Process Lifecycle, Exit Codes, and Cleanup Policies

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

### Tests for milestone 11

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

## Milestone 12 – Exported Metadata File (`.piadina_env`)

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

### Tests for milestone 12

- [ ] **Unit tests for `.piadina_env` writer**
  - [ ] Verify correct formatting and escaping for:
    - [ ] Simple scalars.
    - [ ] Arrays and maps.
    - [ ] Binary values.
  - [ ] Verify correct ordering of variables and `{VAR}` → `${VAR}` conversion.
  - [ ] Verify collision behavior where `ENV` overrides metadata keys.

- [ ] **Integration tests**
- [ ] Pack a payload with `ENV`, a user-defined map, and `ENTRY_ARGS`.
  - [ ] Run Piadina and inspect `.piadina_env`:
    - [ ] `source` the file in a shell.
    - [ ] Confirm the environment matches expectations and application runs correctly.

---

## Milestone 13 – Payload Hashing and Verification

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

### Tests for milestone 13

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

## Milestone 14 – Extended Integration (Linux)

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

## Milestone 15 – In-Tree Tar Implementation (Replacing Vendored Tar Backend)

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

### Tests for milestone 15

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

## Milestone 16 – In-Tree CBOR Implementation (Replacing Vendored CBOR Backend)

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

### Tests for milestone 16

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
