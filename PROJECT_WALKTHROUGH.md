# LogGuard Project Walkthrough

This document explains the complete LogGuard project: its purpose, architecture,
database model, execution flow, security decisions, configuration, commands,
tests, and every Python source file. Line numbers refer to the repository state
documented on 2026-09-02. Blank lines only separate logical blocks and are not
listed; contiguous lines that form one Python statement are explained together.

The editable diagrams are in [`LogGuard_Architecture.drawio`](LogGuard_Architecture.drawio):

1. **ER Diagram** — the exact SQLite schema and its only foreign-key relation.
2. **Project Flow** — CLI routing, components, files, database, and output.
3. **Verification Decision Flow** — the exact status-decision precedence.

## 1. What the project does

LogGuard is a command-line file-integrity monitor. It creates a trusted snapshot
(a *baseline*) of a regular file, stores that snapshot in SQLite, signs the
important baseline fields with HMAC-SHA256, and later compares the live file
with the saved baseline.

The baseline records:

- canonical absolute path;
- SHA-256 content digest;
- file size;
- owner UID and group GID;
- permission bits;
- inode;
- modification timestamp;
- HMAC-SHA256 signature over the identity/security fields.

Verification can report `SAFE`, `MODIFIED`, `DELETED`, `PERMISSION_CHANGED`,
`OWNER_CHANGED`, `REPLACED`, or `BASELINE_TAMPERED`. Non-safe results are
recorded as alerts. Baseline creation, removal, and verification are also
recorded in the audit log.

LogGuard reads monitored files but never edits or deletes them. The `remove`
command only deletes their database registration.

## 2. End-to-end execution flow

1. `main.py` parses the command and optional configuration path.
2. `config.py` loads YAML, validates supported values, and resolves relative
   database/log paths relative to the configuration file.
3. `main.py` configures logging, initializes SQLite, reads the HMAC secret from
   `LOGGUARD_HMAC_KEY`, and constructs the services.
4. The selected command is dispatched:
   - `add`/`remove` use `BaselineManager`;
   - `verify` uses `Verifier`;
   - `scan` uses `Scanner`, which calls the same verifier for every row;
   - `monitor` uses watchdog and calls the same verifier after file events;
   - `status`, `alerts`, and `history` query the database;
   - `Reporter` formats query and verification results for the terminal.
5. `Database.connect()` commits successful work, rolls back failed work, and
   always closes the SQLite connection.

This shared-verifier design is important: manual, batch, and real-time checks
all apply the same security rules and create the same status/audit/alert data.

## 3. Verification decision precedence

After finding the baseline, the verifier evaluates checks in this exact order:

| Priority | Condition | Result | Severity |
|---:|---|---|---|
| 1 | Saved baseline HMAC is invalid | `BASELINE_TAMPERED` | `CRITICAL` |
| 2 | Registered path does not exist | `DELETED` | `HIGH` |
| 3 | Path is a symlink or is not a regular file | `REPLACED` | `HIGH` |
| 4 | Current inode differs from baseline | `REPLACED` | `HIGH` |
| 5 | Owner UID or group GID differs | `OWNER_CHANGED` | `MEDIUM` |
| 6 | Permission bits differ | `PERMISSION_CHANGED` | `MEDIUM` |
| 7 | SHA-256 differs | `MODIFIED` | `HIGH` |
| 8 | No check failed | `SAFE` | `INFO` |

The first matching condition wins. For example, a file whose inode and content
both changed is classified as `REPLACED`, not merely `MODIFIED`.

Every completed verification updates `monitored_files.status` and
`last_checked`, then inserts an audit row. Every non-`SAFE` completion also
inserts an alert and optionally prints it to the console.

## 4. Database model

### `monitored_files`

One row represents one registered file and its trusted baseline. `file_path` is
unique. `baseline_hmac` authenticates the path, digest, size, owner, group,
permissions, and inode. `modification_time` is stored but is not included in the
HMAC payload and is not compared during verification.

### `alerts`

One row represents one detected integrity violation. `file_id` is a required
foreign key to `monitored_files.id`; one monitored file can have zero or many
alerts. `ON DELETE CASCADE` removes those alerts when registration is removed.

### `audit_logs`

One row represents an auditable action and its outcome. It deliberately has no
foreign key: `target` is a textual snapshot, allowing audit history to remain
after a monitored file row is removed.

## 5. Command reference

| Command | Main action | Success/error exit behavior |
|---|---|---|
| `add PATH` | Hash, sign, and save a new baseline | `0`; duplicate/invalid file gives `1` |
| `remove PATH` | Remove registration only | `0` if found, `1` if not monitored |
| `verify PATH` | Verify one registered file | `0` if safe, `2` for a violation, `1` for ordinary error |
| `scan` | Verify every registered file | `0` unless an exception interrupts the scan |
| `status` | List current stored statuses | `0` |
| `alerts` | List alerts newest first | `0` |
| `history` | List audit rows newest first | `0` |
| `monitor` | Watch parent directories until interrupted | `130` on Ctrl+C |

All commands require a valid `LOGGUARD_HMAC_KEY` of at least 32 encoded bytes,
including read-only reporting commands, because service composition happens
before command dispatch.

## 6. Configuration and external dependencies

`config.yaml` selects SHA-256, a 60-second scan/debounce value, SQLite and log
paths, and console alerts. `monitor_paths` and `exclude_patterns` are present as
future-facing settings but current Python code does not consume them. Likewise,
the loaded `Config.realtime` flag is retained but command routing does not use
it; real-time operation is explicitly selected with `monitor`.

`requirements.txt` contains:

- `PyYAML` for parsing configuration;
- `watchdog` for the optional real-time monitor command;
- `pytest` for the test suite.

## 7. Python files, line by line

### `main.py` — CLI entry point and dependency composition

| Lines | Explanation |
|---:|---|
| 1 | Module docstring identifies this as the LogGuard command-line entry point. |
| 2 | Enables postponed annotation evaluation for modern typing behavior. |
| 3–6 | Import argument parsing, logging, process/system access, and `Path`. |
| 7–15 | Import all application services, error types, status enum, scanner, watcher, reporter, and HMAC manager used to compose the program. |
| 18 | Declares `build_parser()` and its `ArgumentParser` return type. |
| 19 | Creates the top-level parser and its help description. |
| 20 | Adds global `--config`; its default is `config.yaml`. |
| 21 | Creates a required subcommand group and stores the selected name in `args.command`. |
| 22 | Iterates over the three commands that require a file path. |
| 23 | Creates each `add`, `remove`, and `verify` parser with generated help text. |
| 24 | Adds the positional path and converts it directly to `Path`. |
| 25–29 | Defines the five no-path commands and their help descriptions. |
| 30 | Adds each no-path subparser. |
| 31 | Returns the completed parser. |
| 34 | Declares logging setup for a requested filesystem path. |
| 35 | Creates the log directory tree when needed. |
| 36–37 | Configures file logging at INFO level with timestamp, severity, logger name, and message. |
| 40 | Declares the main command dispatcher, returning a process exit code. |
| 41 | Loads configuration from the parsed config path. |
| 42 | Activates application file logging. |
| 43 | Creates the SQLite access object. |
| 44 | Creates missing tables and index. |
| 45 | Builds the HMAC service from the environment secret. |
| 46 | Builds the alert service and applies the console-alert preference. |
| 47 | Builds the baseline lifecycle service. |
| 48 | Builds the shared verifier. |
| 49 | Builds the terminal reporter. |
| 50–53 | `add`: create a baseline and print its normalized path and SHA-256 digest. |
| 54–57 | `remove`: unregister the path, print found/not-found feedback, and return `0` or `1`. |
| 58–61 | `verify`: verify one path, render the result, and return `0` only for `SAFE`; violations return `2`. |
| 62–63 | `scan`: list all baselines, verify each, and render a batch summary. |
| 64–65 | `status`: query monitored rows and render current statuses. |
| 66–67 | `alerts`: query alerts and render them. |
| 68–69 | `history`: query audit rows and render them. |
| 70–71 | `monitor`: start watchdog monitoring using `scan_interval` as the debounce interval. |
| 72 | Returns normal success when a branch did not already return a special code. |
| 75 | Declares the thin top-level exception boundary. |
| 76–77 | Parses CLI arguments, dispatches the command, and returns its exit code. |
| 78–80 | Converts Ctrl+C into a friendly message and standard interrupt exit code `130`. |
| 81–84 | Handles expected configuration, key, validation, filesystem, and watcher errors; logs details and returns `1`. |
| 85–88 | Handles any unexpected exception similarly, preventing a terminal traceback while retaining one in the log. |
| 91–92 | When executed as a script, exits the process with `main()`'s integer result. |

### `config.py` — YAML loading and validation

| Lines | Explanation |
|---:|---|
| 1 | States the module's configuration responsibility. |
| 2–5 | Import immutable dataclasses, filesystem paths, flexible input typing, and PyYAML. |
| 7–8 | Define the public validation exception used by the CLI boundary. |
| 10–16 | Define immutable `Config`: database/log paths, positive scan interval, retained realtime flag, and console-alert flag. |
| 18 | Declares the loader from a YAML `Path`. |
| 19 | Computes the resolution base from the config's parent and starts with empty data. |
| 20 | Makes a missing config valid, allowing defaults. |
| 21–24 | Reads UTF-8 YAML safely and wraps I/O/YAML failures as `ConfigError`. |
| 25–26 | Requires a mapping at the YAML root when content is present. |
| 27 | Replaces YAML `null` with an empty mapping. |
| 28–29 | Rejects every hashing algorithm except `sha256`. |
| 30–31 | Extracts and validates the four nested configuration mappings. |
| 32 | Reads the interval with a default of 60 seconds. |
| 33–34 | Requires a positive numeric interval and explicitly rejects booleans. |
| 35–38 | Creates `Config`, resolving paths, normalizing interval to float, and coercing the two flags to bool. |
| 40 | Declares a helper for nested mapping validation. |
| 41 | Reads a named section or supplies `{}`. |
| 42–43 | Rejects a non-dictionary section. |
| 44 | Returns the validated section. |
| 46 | Declares path-value validation/resolution. |
| 47–48 | Requires a non-empty string. |
| 49 | Expands a leading user-home marker. |
| 50 | Leaves absolute paths intact; otherwise anchors them to the config directory. |

### `alerts/__init__.py`

| Line | Explanation |
|---:|---|
| 1 | Package docstring marks `alerts` as the integrity-alert package. |

### `alerts/alert_manager.py` — alert side effects

| Lines | Explanation |
|---:|---|
| 1 | Describes persistent and optional console alerting. |
| 2–4 | Import logging, nullable typing, and database access. |
| 6 | Declares `AlertManager`. |
| 7–8 | Save the database dependency and console-output preference. |
| 10–11 | Define alert creation inputs, including optional old/new hashes. |
| 12 | Persist the alert through `Database.add_alert()`. |
| 13 | Write a WARNING record to the application log. |
| 14–15 | Print severity/message only when console alerts are enabled. |

### `core/__init__.py`

| Line | Explanation |
|---:|---|
| 1 | Package docstring identifies the core integrity layer. |

### `core/hasher.py` — race-aware streaming SHA-256

| Lines | Explanation |
|---:|---|
| 1 | Describes streaming SHA-256. |
| 2–4 | Import hashing, descriptor-stat support, and `Path`. |
| 6–7 | Define the specific error for a file changing during hashing. |
| 9 | Declare hashing with a default 1 MiB chunk size. |
| 10–11 | Reject zero or negative chunk sizes. |
| 12 | Capture pre-read metadata without following symlinks and create SHA-256 state. |
| 13 | Open the file in binary read-only mode. |
| 14–15 | Read until EOF in bounded chunks and feed each chunk into the digest. |
| 16 | Capture post-read metadata from the already-open file descriptor. |
| 17–19 | Compare device, inode, size, and nanosecond mtime before/after; raise if any changed. |
| 20 | Return the lowercase 64-character hexadecimal digest. |

### `core/metadata.py` — path safety and filesystem metadata

| Lines | Explanation |
|---:|---|
| 1 | Describes safe path and metadata handling. |
| 2–4 | Import file-mode helpers, dataclass support, and `Path`. |
| 6–14 | Define immutable `FileMetadata` containing canonical path, size, ownership, permissions, inode, and nanosecond modification time. |
| 16 | Declare normalization with an optional existence requirement. |
| 17 | Expand a user-home marker in the supplied path. |
| 18–19 | Reject a supplied path that is currently a symbolic link. |
| 20–23 | Resolve the path (strictly by default) and translate filesystem/loop failures to `ValueError`. |
| 24–25 | When existence is required, enforce a regular-file path. |
| 26 | Return the canonical `Path`. |
| 28 | Declare metadata collection. |
| 29 | Normalize and require the path. |
| 30 | Stat it without symlink following. |
| 31–32 | Defensively confirm that the mode represents a regular file. |
| 33–34 | Build immutable metadata, masking the mode down to permission bits. |

### `core/baseline.py` — trusted baseline lifecycle

| Lines | Explanation |
|---:|---|
| 1 | Describes trusted baseline creation/removal. |
| 2–8 | Import dataclass/path support and hashing, metadata, persistence, model, and HMAC dependencies. |
| 10–18 | Define the exact subset of baseline fields that will be signed. |
| 20 | Declare `BaselineManager`. |
| 21–22 | Store database and HMAC dependencies. |
| 24 | Declare baseline registration from a path. |
| 25 | Capture trusted pre-hash metadata and canonical path. |
| 26 | Hash that canonical path. |
| 27–28 | Collect metadata again and reject any difference during baseline creation. |
| 29–31 | Construct the signable baseline payload, excluding modification time. |
| 32–33 | Sign the payload and insert the complete baseline row. |
| 34 | Record successful baseline creation in audit history. |
| 35 | Return the persisted `MonitoredFile`. |
| 37 | Declare registration removal. |
| 38 | Canonicalize the path without requiring the target to still exist. |
| 39 | Delete only the matching database row. |
| 40–41 | Audit either `SUCCESS` or `NOT_FOUND`. |
| 42 | Return whether a row was deleted. |

### `core/verifier.py` — integrity classification

| Lines | Explanation |
|---:|---|
| 1 | Describes baseline verification. |
| 2–10 | Import immutable result support, enums, paths, optional typing, alerts, hashing, metadata, database, and HMAC. |
| 12–19 | Define every allowed string-valued integrity status. |
| 21–28 | Define immutable `VerificationResult` for reporting and scans. |
| 30 | Declare `Verifier`. |
| 31–35 | Inject and retain database, HMAC, and alert services. |
| 37 | Declare verification of one supplied path. |
| 38 | Canonicalize without requiring existence, permitting deleted-file detection. |
| 39 | Look up the exact canonical path in `monitored_files`. |
| 40–41 | Reject unregistered paths. |
| 42–44 | Validate baseline HMAC before trusting other saved fields; finish as critical tampering on failure. |
| 45 | Recreate a `Path` from the authenticated saved path. |
| 46–48 | Classify a missing target as `DELETED/HIGH`. |
| 49–51 | Classify symlinks or non-regular replacements as `REPLACED/HIGH`. |
| 52 | Collect current metadata. |
| 53 | Compute the current content digest. |
| 54–56 | Give inode replacement highest priority among live-file comparisons. |
| 57–60 | Next, detect owner or group changes. |
| 61–63 | Next, detect permission changes. |
| 64–66 | Next, detect content changes. |
| 67–69 | If all comparisons match, classify the file as safe. |
| 70 | Delegate persistence/alert work and return the result. |
| 72–73 | Declare the common completion helper. |
| 74 | Persist status and `last_checked`. |
| 75 | Choose normal or violation audit action. |
| 76 | Insert the audit row. |
| 77–79 | Insert/log/optionally print an alert for every non-safe result. |
| 80–81 | Return the complete immutable verification result. |

### `database/__init__.py`

| Line | Explanation |
|---:|---|
| 1 | Package docstring marks the SQLite persistence layer. |

### `database/models.py` — typed database rows

| Lines | Explanation |
|---:|---|
| 1 | Describes persistence models. |
| 2–3 | Import immutable dataclass support and nullable typing. |
| 5–19 | Define `MonitoredFile`; field names exactly match `SELECT *` column names so rows can be unpacked by keyword. |
| 21–31 | Define `Alert`, including the joined `file_path` plus nullable hash values. |
| 33–39 | Define `AuditLog` with action, textual target, outcome, and timestamp. |

### `database/database.py` — transactional SQLite persistence

| Lines | Explanation |
|---:|---|
| 1 | Describes parameterized SQLite persistence. |
| 2–7 | Import SQLite, context-manager support, paths/types, metadata, and row models. |
| 9 | Declare `Database`. |
| 10–11 | Store the configured SQLite file path. |
| 13 | Turn `connect()` into a context manager. |
| 14 | Declare that it yields a SQLite connection. |
| 15 | Create the database parent directory when necessary. |
| 16 | Open SQLite with a 10-second lock wait. |
| 17 | Make fetched rows accessible by column name. |
| 18 | Enable foreign-key enforcement for this connection. |
| 19–21 | Yield to the operation and commit when it finishes successfully. |
| 22–24 | Roll back and re-raise any failure. |
| 25–26 | Always close the connection. |
| 28 | Declare idempotent schema initialization. |
| 29–30 | Open a transaction and execute the multi-statement schema script. |
| 31–39 | Create `monitored_files` with unique path, trusted metadata, timestamps/status, and HMAC. |
| 40–45 | Create `alerts` and its cascading foreign key to `monitored_files`. |
| 46–48 | Create standalone `audit_logs`. |
| 49 | Create an index for newest-first alert retrieval. |
| 50 | End the schema script. |
| 52 | Declare monitored-file insertion and typed return. |
| 53 | Begin duplicate-constraint translation. |
| 54–61 | Insert metadata, digest, and signature using SQL parameters. |
| 62 | Fetch the inserted row by generated primary key. |
| 63 | Convert the row mapping into immutable `MonitoredFile`. |
| 64–65 | Translate path uniqueness failure into a domain-level `ValueError`. |
| 67 | Declare exact-path lookup with an optional result. |
| 68–69 | Execute the parameterized single-row query. |
| 70 | Convert a found row or return `None`. |
| 72 | Declare sorted monitored-file listing. |
| 73–74 | Fetch all rows alphabetically by path. |
| 75 | Convert all rows to typed models. |
| 77 | Declare registration deletion. |
| 78–79 | Delete the exact parameterized path. Cascading alerts are also deleted. |
| 80 | Report whether SQLite deleted at least one row. |
| 82 | Declare status/timestamp update. |
| 83–85 | Update status and set `last_checked` to the current SQLite timestamp. |
| 87–88 | Declare alert insertion and nullable hash parameters. |
| 89–93 | Insert alert values using SQL parameters. |
| 95 | Declare alert listing. |
| 96–99 | Join alerts to monitored files for `file_path`, newest and highest ID first. |
| 100 | Convert rows to `Alert` models. |
| 102 | Declare audit insertion. |
| 103–105 | Insert action, target, and result using parameters. |
| 107 | Declare audit listing. |
| 108–109 | Retrieve newest audit rows first, using ID as a tie-breaker. |
| 110 | Convert rows to `AuditLog` models. |

### `monitoring/__init__.py`

| Line | Explanation |
|---:|---|
| 1 | Package docstring identifies batch and real-time monitoring. |

### `monitoring/scanner.py` — batch verification

| Lines | Explanation |
|---:|---|
| 1 | Describes the batch scanner. |
| 2–4 | Import paths, verification result/service, and database access. |
| 6 | Declare `Scanner`. |
| 7–8 | Store database and verifier dependencies. |
| 10 | Declare scanning of all registered rows. |
| 11–12 | List monitored files and synchronously verify every saved path, preserving database sort order. |

### `monitoring/watcher.py` — real-time event monitoring

| Lines | Explanation |
|---:|---|
| 1 | Describes debounced watchdog monitoring. |
| 2–5 | Import time/path support and verifier/database dependencies. |
| 7–8 | Define a clear error for a missing optional watchdog installation. |
| 10–11 | Declare monitoring with a default one-second debounce. |
| 12–17 | Lazily import watchdog only for this command and translate absence into installation guidance. |
| 18 | Snapshot currently registered canonical path strings into a set. |
| 19–20 | Refuse to start when nothing is registered. |
| 21 | Create per-path last-event timestamps. |
| 23 | Define a local handler that closes over registration/debounce state. |
| 24 | Handle every watchdog event type. |
| 25 | Canonicalize the event source path without requiring existence. |
| 26–27 | Include a destination path for move/rename events when present. |
| 28 | Read a monotonic timestamp suitable for elapsed-time comparisons. |
| 29 | Keep only event paths that are explicitly registered. |
| 30–31 | Ignore a path when it is still inside its debounce window. |
| 32 | Save the accepted event time. |
| 33 | Briefly wait for a write to settle, capped at one second. |
| 34–36 | Verify the path and print its resulting status immediately. |
| 37–38 | Report filesystem verification errors without stopping the observer. |
| 40 | Construct the observer and handler. |
| 41–42 | Schedule each unique registered parent directory non-recursively. |
| 43 | Start watchdog's observer thread. |
| 44 | Tell the operator how many files are watched and how to stop. |
| 45–47 | Keep the main thread alive until interruption. |
| 48–50 | Always stop and join the observer during exit. |

### `reports/__init__.py`

| Line | Explanation |
|---:|---|
| 1 | Package docstring marks terminal-reporting functionality. |

### `reports/reporter.py` — terminal presentation

| Lines | Explanation |
|---:|---|
| 1 | Describes human-readable terminal output. |
| 2–3 | Import status counting and the verification result type. |
| 5 | Declare stateless `Reporter`. |
| 6–7 | Define static single-result rendering. |
| 8 | Print a titled separator. |
| 9 | Print path and status. |
| 10 | Print expected SHA-256. |
| 11 | Print current SHA-256 or `Unavailable`. |
| 12 | Print severity. |
| 14–15 | Define static batch rendering. |
| 16 | Print file/status columns. |
| 17–18 | Print one row per verification result. |
| 19 | Count results by status string. |
| 20 | Print total count. |
| 21–22 | Print sorted, humanized status counts. |
| 24–25 | Define monitored-status rendering for generic record iterables. |
| 26 | Print status column headings. |
| 27–28 | Print each path, stored status, and timestamp or `Never`. |
| 30–31 | Define alert rendering. |
| 32 | Print alert column headings. |
| 33–35 | Print each detection time, severity, event, path, and message. |
| 37–38 | Define audit-history rendering. |
| 39 | Print audit column headings. |
| 40–41 | Print each timestamp, action, result, and target. |

### `security/__init__.py`

| Line | Explanation |
|---:|---|
| 1 | Package docstring identifies security helpers. |

### `security/hmac_manager.py` — baseline authentication

| Lines | Explanation |
|---:|---|
| 1 | Describes HMAC-SHA256 signing and verification. |
| 2–6 | Import digest/HMAC, deterministic JSON, environment access, and structural typing. |
| 8–15 | Define the fields any signable baseline-like object must expose. |
| 17–18 | Define the public key-configuration exception. |
| 20 | Declare `HMACManager`. |
| 21 | Accept raw key bytes. |
| 22–23 | Require at least 32 bytes. |
| 24 | Store the key privately. |
| 26 | Mark the environment constructor as a class method. |
| 27 | Declare that constructor's return type. |
| 28 | Read `LOGGUARD_HMAC_KEY`. |
| 29–31 | Reject a missing/empty value and provide a safe generation hint. |
| 32 | UTF-8 encode the environment string and delegate validation to `__init__`. |
| 34 | Mark deterministic payload generation as static. |
| 35 | Accept any object satisfying `BaselineLike`. |
| 36–39 | Build the authenticated field mapping; modification time and status are intentionally absent. |
| 40 | Serialize with sorted keys and compact separators, then encode to bytes. |
| 42–43 | Compute and return hexadecimal HMAC-SHA256. |
| 45–46 | Recompute and compare signatures in constant time. |

### `tests/__init__.py`

| Line | Explanation |
|---:|---|
| 1 | Package docstring identifies the LogGuard test suite. |

### `tests/conftest.py` — shared isolated services

| Lines | Explanation |
|---:|---|
| 1–7 | Import paths, pytest, and all services needed by the fixture. |
| 9 | Register a pytest fixture. |
| 10 | Declare `services`, receiving pytest's isolated temporary directory. |
| 11 | Point SQLite at a disposable per-test database. |
| 12 | Initialize its schema. |
| 13 | Create a deterministic valid 32-byte test key. |
| 14–15 | Return database, baseline manager, and verifier with console alerts disabled. |

### `tests/test_hashing.py`

| Lines | Explanation |
|---:|---|
| 1–4 | Import reference SHA-256, paths, pytest, and the production hasher. |
| 6–9 | Parameterize empty, spaced-name, and multi-megabyte cases. |
| 10 | Declare the parameterized hashing test. |
| 11–12 | Create the requested temporary file and bytes. |
| 13 | Assert chunked production output equals Python's reference SHA-256. |
| 15 | Declare missing-path behavior test. |
| 16–17 | Assert a missing file raises `FileNotFoundError`. |

### `tests/test_monitoring.py`

| Lines | Explanation |
|---:|---|
| 1–3 | Import paths, statuses, and the batch scanner. |
| 5 | Declare the multi-file scan test. |
| 6 | Unpack shared services. |
| 7–8 | Define safe and changed test paths. |
| 9–10 | Create their original contents. |
| 11–12 | Register both baselines. |
| 13 | Modify only the second file. |
| 14 | Scan all registered rows. |
| 15–16 | Assert the result set contains one safe and one modified status. |

### `tests/test_baseline.py`

| Lines | Explanation |
|---:|---|
| 1–2 | Import paths and pytest. |
| 4 | Declare successful creation plus duplicate rejection test. |
| 5 | Unpack database and baseline service. |
| 6–7 | Create a temporary file whose name contains spaces. |
| 8 | Register its baseline. |
| 9 | Assert canonical path storage. |
| 10 | Assert SHA-256 hexadecimal length. |
| 11 | Assert database round-trip equality. |
| 12–13 | Assert duplicate registration raises the intended message. |
| 15 | Declare missing-file rejection test. |
| 16–18 | Attempt to register a missing path and expect `ValueError`. |
| 20 | Declare symbolic-link rejection test. |
| 21–25 | Create a real target and a symlink to it. |
| 26–27 | Assert registration rejects the link with a symbolic-link message. |

### `tests/test_config.py`

| Lines | Explanation |
|---:|---|
| 1–3 | Import paths, pytest, and configuration API. |
| 5 | Declare missing-config default behavior test. |
| 6 | Load a path that does not exist. |
| 7 | Assert the 60-second default interval. |
| 8 | Assert the database default is anchored to the config's parent directory. |
| 10 | Declare malformed nested-section test. |
| 11–12 | Write YAML where `monitoring` is a list instead of a mapping. |
| 13–14 | Assert `ConfigError` is raised. |

### `tests/test_database.py`

| Lines | Explanation |
|---:|---|
| 1–3 | Import path, production metadata collection, and HMAC manager. |
| 5 | Declare database insert/update/read/audit test. |
| 6 | Unpack the isolated database. |
| 7–9 | Create a file and collect its real metadata. |
| 10 | Create a valid deterministic HMAC manager. |
| 11–18 | Define a minimal class satisfying the signable baseline protocol. |
| 19 | Sign and insert the baseline row. |
| 20 | Change its stored status. |
| 21 | Assert the updated status round-trips. |
| 22 | Insert an audit row. |
| 23 | Assert it can be listed. |
| 25 | Declare removal-safety test. |
| 26–29 | Create and register a temporary file. |
| 30 | Assert registration removal succeeds. |
| 31 | Assert the physical file still exists. |
| 32 | Assert no monitored rows remain. |

### `tests/test_verifier.py`

| Lines | Explanation |
|---:|---|
| 1–3 | Import atomic replacement support, paths, and integrity statuses. |
| 5 | Declare a helper that registers a path. |
| 6–8 | Obtain services, add the baseline, and return the verifier. |
| 10 | Declare safe-to-modified behavior and alert creation test. |
| 11–14 | Create/register original file and retain database/verifier. |
| 15 | Assert unchanged verification is `SAFE`. |
| 16–17 | Modify content and assert `MODIFIED`. |
| 18 | Load persisted alerts. |
| 19–21 | Assert exactly one HIGH `MODIFIED` alert; the safe check produced none. |
| 23 | Declare deletion classification test. |
| 24–27 | Create/register then unlink the disposable file. |
| 28 | Assert `DELETED`. |
| 30 | Declare permission classification test. |
| 31–35 | Create a file, baseline mode `0600`, then change mode to `0640`. |
| 36 | Assert `PERMISSION_CHANGED`. |
| 38 | Declare inode replacement test. |
| 39–44 | Register an original path, create another file, and atomically replace the original. |
| 45 | Assert `REPLACED` even though replacement content is identical. |
| 47 | Declare baseline-tampering test. |
| 48–51 | Create/register a valid baseline. |
| 52–53 | Directly corrupt authenticated `file_size` in SQLite. |
| 54 | Verify the live path. |
| 55–56 | Assert `BASELINE_TAMPERED` with `CRITICAL` severity. |

## 8. Test coverage and uncovered edges

The suite directly covers hashing, missing hash input, baseline creation,
duplicates, missing files, symlinks, configuration defaults/errors, database
insert/update/read/audit/removal, batch scanning, and verifier states for safe,
modified, deleted, permissions, inode replacement, and tampered HMAC.

Important behavior that exists but has no direct test in the current suite:

- `OWNER_CHANGED` classification;
- replacement by symlink or non-regular file during verification;
- file-changing-during-hash detection;
- watcher debounce/move behavior and missing-watchdog error;
- reporter formatting and CLI exit codes;
- invalid HMAC key length/missing environment key;
- alert cascade deletion and transaction rollback;
- malformed root YAML, invalid paths, and invalid/non-positive interval variants.

These are coverage gaps, not claims that the implementation is incorrect.

## 9. Security and operational notes

- Keep `LOGGUARD_HMAC_KEY` stable and outside the repository/database. Changing
  it makes every existing baseline fail authentication.
- HMAC authenticates baseline fields but does not stop deletion of the whole
  database, alert deletion, audit deletion, or row reordering.
- Active logs normally grow. Under this static-snapshot design, legitimate
  growth is still `MODIFIED`; LogGuard does not prove malicious intent.
- Log rotation commonly changes inode/path identity and may be reported as
  `REPLACED` or `DELETED`.
- The scanner stops on the first uncaught per-file failure; it does not currently
  isolate a failing row and continue through the remaining baselines.
- Real-time monitoring snapshots registrations at startup. Files added or
  removed from the database after startup do not change the watcher's in-memory
  registered set until it is restarted.
- Run the tool as a dedicated, unprivileged user with only the file access it
  needs, and separately protect the database, application log, and key source.

## 10. Repository map

```text
Log_Monitoring_Tool/
├── main.py                    CLI, service construction, exit codes
├── config.py                  YAML validation and path resolution
├── config.yaml                Default runtime settings
├── alerts/                    Alert persistence/logging/console output
├── core/                      Metadata, hashing, baseline, verification
├── database/                  SQLite schema, queries, typed row models
├── monitoring/                Batch scanner and watchdog observer
├── reports/                   Terminal formatting
├── security/                  HMAC-SHA256 baseline authentication
├── tests/                     Isolated pytest suite
├── docs/
│   └── logguard-architecture.svg  GitHub-renderable architecture preview
├── requirements.txt           Runtime/test dependencies
├── README.md                  Installation and operator documentation
├── PROJECT_WALKTHROUGH.md     This full technical explanation
└── LogGuard_Architecture.drawio  Editable ER and flow diagrams
```
