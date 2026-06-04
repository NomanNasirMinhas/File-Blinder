# FileBlinder


**FileBlinder** is a Windows process instrumentation and file-access manipulation toolkit for authorized red-team labs, malware-analysis simulations, application resilience testing, and defensive detection engineering.

It injects a user-mode DLL into a target process and selectively changes how that process sees specific files, DLLs, and runtime resources. This allows researchers to study Windows loader behavior, file-access assumptions, process-child propagation, user-mode API hooking, and anti-evasion behavior around `ntdll.dll`.

![FileBlinder banner](banner.png)
> FileBlinder is intended for controlled environments where you own the system, have explicit authorization, or are conducting internal security validation.

---



## Responsible Use Disclaimer

FileBlinder is dual-use security tooling.

It can be used by defenders, researchers, and red teams to understand how Windows applications behave when file access is manipulated inside a process. However, the same concepts can be misused if applied to systems without permission.

By using this project, you agree that:

- You will only use it on systems you own or are explicitly authorized to test.
- You will not use it to hide malware, bypass security controls, steal data, or maintain unauthorized access.
- You are responsible for complying with applicable laws, contracts, policies, and rules of engagement.
- The authors and contributors are not responsible for misuse, damage, data loss, or legal consequences caused by unauthorized use.

Use FileBlinder for research, validation, education, and defensive improvement.

---

## Key Capabilities

FileBlinder can:

- Inject into an existing Windows process
- Spawn a new process in a suspended state, inject, then resume it
- Hide selected file paths from the injected process
- Simulate missing DLLs, configuration files, plugins, or runtime resources
- Study DLL search-order behavior
- Test application behavior when expected files disappear
- Propagate instrumentation into child processes
- Intercept attempts to read a clean `ntdll.dll`
- Protect the hooked `ntdll.dll` view inside the instrumented process
- Capture telemetry from selected file, process, DLL-loading, HTTP, TLS, and socket APIs

---

## Example Research Scenarios

FileBlinder is not limited to DLL search-order hijacking. It can be used in multiple authorized research and engineering workflows.

---

### 1. DLL Search-Order Research

Windows applications sometimes load DLLs by name instead of using a full absolute path.

Example:

```c
LoadLibraryW(L"version.dll");
```

When this happens, Windows searches several locations in order. FileBlinder can make a specific DLL appear missing to the target process, allowing researchers to observe how the loader behaves when the expected DLL cannot be found.

Useful for:

- Studying unsafe DLL loading behavior
- Testing whether applications resolve DLLs from unexpected paths
- Reproducing DLL search-order issues in a controlled lab
- Validating detections for suspicious DLL resolution
- Understanding how applications behave when system DLL access fails

Example:

```powershell
.\file_blinder_injector.exe --spawn notepad.exe --block "C:\Windows\System32\version.dll"
```

---

### 2. Application Resilience Testing

Applications often assume that configuration files, plugins, databases, cache files, or runtime resources always exist.

FileBlinder can simulate missing files without deleting or modifying anything on disk.

Useful for testing:

- Missing configuration files
- Missing plugins or modules
- Missing license files
- Missing cache files
- Missing update metadata
- Broken installer or updater assumptions
- Graceful error handling

Example:

```powershell
.\file_blinder_injector.exe --spawn app.exe --block "C:\ProgramData\Vendor\App\config.json"
```

The file remains present on disk, but the instrumented process sees it as missing.

---

### 3. Security Detection Engineering

Blue teams and detection engineers can use FileBlinder to generate controlled telemetry for suspicious file-access and DLL-loading patterns.

Useful for validating detections around:

- Unusual DLL search behavior
- Repeated `NAME NOT FOUND` events before DLL loading
- User-writable directories involved in DLL resolution
- Unexpected file-access failures
- Child-process inheritance of suspicious behavior
- Attempts to read or remap `ntdll.dll`

Example:

```powershell
.\file_blinder_injector.exe --spawn target.exe --block "C:\Windows\System32\example.dll" --child
```

The `--child` option is useful when testing applications that spawn helpers, plugin hosts, crash handlers, or updater processes.

---

### 4. Malware-Analysis Simulation

In a malware-analysis lab, FileBlinder can simulate process-local file hiding and anti-evasion behaviors without using live malware.

Useful for:

- Training analysts
- Testing sandbox visibility
- Testing EDR behavior
- Generating controlled telemetry
- Studying user-mode hook visibility
- Observing process behavior under manipulated file-access conditions

Example:

```powershell
.\file_blinder_injector.exe --pid 3660 --block "C:\Path\To\watched_file.dat"
```

---

### 5. Anti-Evasion Research Around `ntdll.dll`

Many offensive tools and malware families attempt to read a clean copy of `ntdll.dll` from disk or from `KnownDlls` to bypass user-mode hooks.

FileBlinder can intercept some of these attempts inside the instrumented process and return the already-hooked in-memory view instead.

Research areas:

- Clean `ntdll.dll` reload attempts
- `KnownDlls` access behavior
- Image-section mapping behavior
- Hook visibility
- User-mode hook bypass attempts
- Process-local memory protection assumptions

---

### 6. Child Process Instrumentation

Many applications spawn helper processes, update processes, plugin hosts, crash reporters, or background workers.

FileBlinder can optionally inject into child processes so the same instrumentation follows the process tree.

Useful for:

- Multi-process application analysis
- Browser helper-process testing
- Updater behavior research
- Parent-child telemetry validation
- Process-tree behavior simulation

Example:

```powershell
.\file_blinder_injector.exe --spawn app.exe --block "C:\Path\To\File.dll" --child
```

---

## Build

### Windows PowerShell

```powershell
.\build.ps1
```

### Windows CMD

```cmd
build.bat
```

### Linux / Cross-Compile

```bash
./build.sh
```

### Manual Build

```bash
cargo build --release --manifest-path file_blinder_dll\Cargo.toml
cargo build --release --manifest-path file_blinder_injector\Cargo.toml
```

Build outputs:

```text
file_blinder_dll.dll
file_blinder_injector.exe
```

The build scripts copy the final binaries to the project root.

---

## Usage

```powershell
file_blinder_injector.exe --pid <PID> [--dll <DllPath>] [--block <Path>] [--child]

file_blinder_injector.exe --spawn <ExePath> [--dll <DllPath>] [--block <Path>] [--child] [--cmdline <args>]
```

---

## Options

| Flag | Description |
|---|---|
| `--pid <pid>` | Inject into an existing process |
| `--spawn <exe>` | Start a process suspended, inject FileBlinder, then resume it |
| `--dll <path>` | Path to `file_blinder_dll.dll`; defaults to `.\file_blinder_dll.dll` |
| `--block <path>` | File path that should appear missing to the target process |
| `--child` | Also inject into child processes created by the target |
| `--cmdline <args>` | Command-line arguments for the spawned process; used with `--spawn` |

---

## Basic Examples

Inject into a running process:

```powershell
.\file_blinder_injector.exe --pid 3660
```

Inject into a running process and hide a file:

```powershell
.\file_blinder_injector.exe --pid 3660 --block "C:\Path\To\file.txt"
```

Spawn a target process and hide a DLL:

```powershell
.\file_blinder_injector.exe --spawn notepad.exe --block "C:\Windows\System32\version.dll"
```

Spawn a process, hide a file, and instrument child processes:

```powershell
.\file_blinder_injector.exe --spawn app.exe --block "C:\ProgramData\App\config.json" --child
```

Pass command-line arguments to a spawned process:

```powershell
.\file_blinder_injector.exe --spawn app.exe --cmdline "--debug --profile test" --block "C:\Path\To\file.dat"
```

---

## How It Works

FileBlinder injects a DLL into the target process and installs user-mode API hooks using MinHook.

When the target process tries to access a configured blocked path, FileBlinder makes that path appear unavailable to the process. The file is not deleted, modified, or hidden globally. The behavior only applies inside the instrumented process.

The blocked path configuration is stored at:

```text
C:\Users\Public\file_blinder_block.cfg
```

Child-injection behavior is configured through:

```text
C:\Users\Public\file_blinder_child.cfg
```

---

## Hooked API Categories

FileBlinder hooks APIs across several categories.

| Category | Purpose |
|---|---|
| File visibility | Make selected paths appear missing |
| DLL loading | Observe and influence DLL-resolution behavior |
| Process creation | Support child-process instrumentation |
| `ntdll.dll` read protection | Intercept attempts to read a clean disk copy of `ntdll.dll` |
| Memory protection | Reduce simple in-process attempts to overwrite hooked pages |
| HTTP/TLS/socket APIs | Capture lab telemetry from instrumented processes |

---

## File Visibility Hooks

FileBlinder intercepts common file and path APIs, including:

```text
NtOpenFile
NtCreateFile
NtQueryAttributesFile
NtQueryFullAttributesFile
GetFileAttributesW
GetFileAttributesExW
CreateFileW
FindFirstFileW
FindFirstFileExW
SearchPathW
LoadLibraryW
LoadLibraryExW
PathFileExistsW
_waccess
_wstat64
_wfopen
```

When a blocked path is requested, the target process receives a result equivalent to the file not existing.

---

## DLL Search-Order Research

When an application calls:

```c
LoadLibraryW(L"example.dll");
```

without a fully qualified path, Windows searches multiple locations in order.

Typical locations include:

1. Known DLLs
2. Application directory
3. System directory
4. Windows directory
5. Current working directory
6. Directories in `%PATH%`

If a DLL is found in a higher-priority location, lower-priority locations are not normally checked.

FileBlinder can make a selected DLL appear missing to the target process, allowing researchers to observe fallback behavior in a controlled lab.

Example:

```powershell
.\file_blinder_injector.exe --spawn target.exe --block "C:\Windows\System32\version.dll"
```

This is useful for studying whether the application safely loads DLLs or whether it may resolve DLLs from unexpected locations.

---

## `ntdll.dll` Protection Research

After injection, FileBlinder snapshots the in-memory `ntdll.dll` view and attempts to prevent the instrumented process from loading or reading a clean copy from disk.

This is useful for studying common user-mode hook bypass behavior.

Examples of intercepted behavior include:

| Behavior | FileBlinder Response |
|---|---|
| Reading `C:\Windows\System32\ntdll.dll` | Returns the hooked in-memory copy |
| Opening `\KnownDlls\ntdll.dll` | Blocks access |
| Creating an image section from `ntdll.dll` | Redirects to a controlled section |
| Attempting to overwrite hooked `ntdll.dll` pages | Blocks or neutralizes the write inside the instrumented process |

---

## Network and Plaintext Telemetry

FileBlinder can hook selected HTTP, TLS, and socket APIs to collect lab telemetry from the instrumented process.

Hook categories include:

```text
EncryptMessage
DecryptMessage
InitializeSecurityContextW

WinHttpSendRequest
WinHttpWriteData
WinHttpReadData

HttpSendRequestW
HttpSendRequestA

InternetReadFile
InternetWriteFile

send
recv
WSASend
WSARecv
```

This is useful for controlled research and visibility testing inside lab environments.

---

## Limitations

FileBlinder is a user-mode instrumentation tool. It is not a kernel security boundary.

Important limitations:

- It only affects processes where the FileBlinder DLL is injected.
- It does not globally hide files from the operating system.
- It does not protect against all external process tampering.
- Kernel-mode components or privileged tools may bypass user-mode hooks.
- Some applications may crash if expected DLL exports or files are missing.
- EDRs, AVs, or system hardening tools may detect or block injection behavior.
- Behavior may vary across Windows versions and process architectures.

For stronger memory protection or tamper resistance, kernel-mode enforcement or platform security features are required.

---

## Recommended Lab Workflow

1. Use a disposable virtual machine.
2. Take a snapshot before testing.
3. Pick a known target process.
4. Choose one file or DLL path to block.
5. Run FileBlinder with `--spawn` or `--pid`.
6. Observe behavior using Process Monitor, ETW, Sysmon, EDR telemetry, or custom logging.
7. Revert the VM snapshot after testing.

---

## Safety Notes

- Do not test on production systems unless explicitly authorized.
- Do not inject into security-sensitive or critical business processes unless your rules of engagement allow it.
- Do not use this tool to conceal unauthorized payloads or bypass security monitoring.
- Prefer isolated lab machines, snapshots, and disposable test data.
- Document your test scope before running experiments.

---

## Project Status

FileBlinder is experimental research tooling.

Expect rough edges, version-specific behavior, and possible crashes in some target processes. Contributions, bug reports, and defensive research feedback are welcome.

---
