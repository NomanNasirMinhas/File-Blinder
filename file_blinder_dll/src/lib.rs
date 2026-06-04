use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use minhook::MinHook;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Pipes::WaitNamedPipeA;
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx,
    PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_EXECUTE_READ,
};
use windows_sys::Win32::System::Diagnostics::Debug::{OutputDebugStringA, WriteProcessMemory};

// CreateRemoteThread is not in windows-sys 0.52 Threading; declare manually.
extern "system" {
    fn CreateRemoteThread(
        hProcess: HANDLE,
        lpThreadAttributes: *const c_void,
        dwStackSize: usize,
        lpStartAddress: *mut c_void,
        lpParameter: *mut c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> HANDLE;
}

// --- Shared Constants ---
const GENERIC_WRITE: u32 = 0x40000000;

// Bound on DLL_LOAD / PROC_SPAWN string payloads. TLS payloads are NOT capped
// by this — they are sliced straight from the SChannel SECBUFFER_DATA buffer.
const STR_BUF: usize = 4096;

// Max payload bytes per single frame.  Larger TLS records are split into
// several frames sharing the same stream_id with consecutive seq numbers,
// which the reader concatenates by (stream_id, seq) order.
const MAX_FRAME_PAYLOAD: usize = 65536;

// --- Frame protocol (must match reader.cpp's FrameHeader) ---
const FRAME_MAGIC: u32      = 0x4641_474E; // 'NGAF' little-endian on disk
const EV_DLL_LOAD: u32      = 1;
const EV_PROC_SPAWN: u32    = 2;
const EV_TLS_OUT_PLAIN: u32 = 3;
const EV_TLS_IN_PLAIN: u32  = 4;
const EV_AGENT_ONLINE: u32  = 5;
const EV_TLS_HOST: u32      = 6;
// Non-TLS application data taps.  Each is a {stream_id, seq, bytes} event
// just like TLS_OUT/IN — the reader hex-encodes payload for JSON.
// stream_id is the per-API handle: HINTERNET for WinHttp/WinInet, SOCKET
// for Winsock.  These hooks WILL double-cover HTTPS that flows through
// the same process (you'll see plaintext at WinHttp/WinInet *and* again
// at SChannel) — that is intentional, since either path may carry data
// the other doesn't (plain HTTP via WinHttp, non-HTTP via raw sockets).
const EV_WINHTTP_OUT: u32   = 7;
const EV_WINHTTP_IN: u32    = 8;
const EV_WININET_OUT: u32   = 9;
const EV_WININET_IN: u32    = 10;
const EV_SOCKET_OUT: u32    = 11;
const EV_SOCKET_IN: u32     = 12;

// --- File Blocking Constants ---
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFFu32;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034u32 as i32;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const CREATE_SUSPENDED: u32 = 0x00000004;

// Access mask constants for CreateFileW filtering
const FILE_GENERIC_READ: u32 = 0x80000000; // same as GENERIC_READ

#[repr(C, packed)]
struct FrameHeader {
    magic: u32,
    event: u32,
    stream_id: u64,
    seq: u64,
    payload_len: u32,
    reserved: u32,
}

// --- Globals ---
static mut G_PIPE_HANDLE: HANDLE = INVALID_HANDLE_VALUE;
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
static PIPE_BROKEN: AtomicBool = AtomicBool::new(false);
// Monotonic per-process counter — every frame's `seq` is unique within the
// agent.  Reader sorts (stream_id, seq) to reconstruct ordered conversations.
static SEQ: AtomicU64 = AtomicU64::new(1);

// One-shot flags for hook-fire diagnostics (avoid flooding DebugView).
static DBG_WINHTTP_SEND: AtomicBool = AtomicBool::new(false);
static DBG_WINHTTP_READ: AtomicBool = AtomicBool::new(false);
static DBG_WINHTTP_WRITE: AtomicBool = AtomicBool::new(false);
static DBG_WININET_SEND: AtomicBool = AtomicBool::new(false);
static DBG_WININET_READ: AtomicBool = AtomicBool::new(false);
static DBG_WININET_WRITE: AtomicBool = AtomicBool::new(false);
static DBG_SEND: AtomicBool = AtomicBool::new(false);
static DBG_RECV: AtomicBool = AtomicBool::new(false);
static DBG_WSASEND: AtomicBool = AtomicBool::new(false);
static DBG_WSARECV: AtomicBool = AtomicBool::new(false);
static DBG_ENCRYPT: AtomicBool = AtomicBool::new(false);
static DBG_DECRYPT: AtomicBool = AtomicBool::new(false);

// --- File Blocking State ---
static mut G_BLOCKED_PATH_NORMALIZED: Vec<u16> = Vec::new();
static mut G_SELF_MODULE_PATH: Vec<u16> = Vec::new();
static mut G_DEVICE_PREFIXES: Vec<(Vec<u16>, Vec<u16>)> = Vec::new();
static mut G_DLL_HINSTANCE: HANDLE = 0;
static INJECT_CHILDREN: AtomicBool = AtomicBool::new(false);
static mut G_CHILD_TARGET: Vec<u16> = Vec::new(); // specific child exe name, or empty = all

// --- ntdll Protection State ---
static mut G_NTDLL_MODIFIED_BYTES: Vec<u8> = Vec::new();
static mut G_NTDLL_PATHS: Vec<Vec<u16>> = Vec::new();
static mut G_NTDLL_HANDLES: Vec<HANDLE> = Vec::new();
static mut G_NTDLL_BASE: *const u8 = std::ptr::null();
static mut G_NTDLL_SIZE: usize = 0;

// --- Windows Internal Structs ---
#[repr(C)]
#[allow(non_camel_case_types)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

// NT kernel structs for file API hooks
#[repr(C)]
struct OBJECT_ATTRIBUTES {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IO_STATUS_BLOCK {
    status: NTSTATUS,
    information: usize,
}

#[repr(C)]
struct FILE_BASIC_INFORMATION {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
}

#[repr(C)]
struct FILE_NETWORK_OPEN_INFORMATION {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    allocation_size: i64,
    end_of_file: i64,
    file_attributes: u32,
}

// PE header structs for reading module SizeOfImage
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u16; 29],
    e_lfanew: i32,
}
#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    _pad1: [u8; 60],
    size_of_image: u32,
}

// --- SSPI / TLS Cryptography Structs ---
#[repr(C)]
struct SecBuffer {
    cbBuffer: u32,
    BufferType: u32,
    pvBuffer: *mut u8,
}

#[repr(C)]
struct SecBufferDesc {
    ulVersion: u32,
    cBuffers: u32,
    pBuffers: *mut SecBuffer,
}
const SECBUFFER_DATA: u32 = 1; // The buffer type that holds actual application plaintext

// --- Hook Signatures ---
type FnLdrLoadDll = unsafe extern "system" fn(*mut u16, *const u32, *const UNICODE_STRING, *mut *mut c_void) -> NTSTATUS;
static mut ORIG_LDRLOADDLL: Option<FnLdrLoadDll> = None;

type FnCreateProcessInternalW = unsafe extern "system" fn(
    HANDLE, *const u16, *mut u16, *mut c_void, *mut c_void, BOOL, u32, *mut c_void, *const u16, *mut c_void, *mut c_void, *mut c_void
) -> BOOL;
static mut ORIG_CREATEPROCESSINTERNALW: Option<FnCreateProcessInternalW> = None;

// SSPI Hook Signatures
type FnEncryptMessage = unsafe extern "system" fn(*mut c_void, u32, *mut SecBufferDesc, u32) -> i32;
static mut ORIG_ENCRYPTMESSAGE: Option<FnEncryptMessage> = None;

type FnDecryptMessage = unsafe extern "system" fn(*mut c_void, *mut SecBufferDesc, u32, *mut u32) -> i32;
static mut ORIG_DECRYPTMESSAGE: Option<FnDecryptMessage> = None;

type FnInitSecCtxW = unsafe extern "system" fn(
    *mut c_void,   // phCredential
    *mut c_void,   // phContext (may be NULL on first call)
    *const u16,    // pszTargetName  ← SNI hostname (wide)
    u32, u32, u32,
    *mut c_void,   // pInput
    u32,
    *mut c_void,   // phNewContext
    *mut c_void,   // pOutput
    *mut u32,
    *mut i64,
) -> i32;
static mut ORIG_INITSECCTXW: Option<FnInitSecCtxW> = None;

// --- WinHttp ---
type FnWinHttpSendRequest = unsafe extern "system" fn(
    *mut c_void,   // hRequest
    *const u16,    // pwszHeaders (wide; or NULL)
    u32,           // dwHeadersLength (chars, or 0xFFFFFFFF for NUL-terminated)
    *mut c_void,   // lpOptional (body bytes, or NULL)
    u32,           // dwOptionalLength (bytes)
    u32,           // dwTotalLength
    usize,         // dwContext
) -> i32;
static mut ORIG_WINHTTPSENDREQUEST: Option<FnWinHttpSendRequest> = None;

type FnWinHttpWriteData = unsafe extern "system" fn(
    *mut c_void,   // hRequest
    *const c_void, // lpBuffer
    u32,           // dwNumberOfBytesToWrite
    *mut u32,      // lpdwNumberOfBytesWritten
) -> i32;
static mut ORIG_WINHTTPWRITEDATA: Option<FnWinHttpWriteData> = None;

type FnWinHttpReadData = unsafe extern "system" fn(
    *mut c_void,   // hRequest
    *mut c_void,   // lpBuffer
    u32,           // dwNumberOfBytesToRead
    *mut u32,      // lpdwNumberOfBytesRead
) -> i32;
static mut ORIG_WINHTTPREADDATA: Option<FnWinHttpReadData> = None;

// --- WinInet ---
type FnHttpSendRequestW = unsafe extern "system" fn(
    *mut c_void,   // hRequest
    *const u16,    // lpszHeaders (wide; or NULL)
    u32,           // dwHeadersLength (chars, or 0xFFFFFFFF)
    *mut c_void,   // lpOptional
    u32,           // dwOptionalLength
) -> i32;
static mut ORIG_HTTPSENDREQUESTW: Option<FnHttpSendRequestW> = None;

type FnHttpSendRequestA = unsafe extern "system" fn(
    *mut c_void,   // hRequest
    *const u8,     // lpszHeaders (narrow; or NULL)
    u32,           // dwHeadersLength
    *mut c_void,   // lpOptional
    u32,           // dwOptionalLength
) -> i32;
static mut ORIG_HTTPSENDREQUESTA: Option<FnHttpSendRequestA> = None;

type FnInternetReadFile = unsafe extern "system" fn(
    *mut c_void,   // hFile
    *mut c_void,   // lpBuffer
    u32,           // dwNumberOfBytesToRead
    *mut u32,      // lpdwNumberOfBytesRead
) -> i32;
static mut ORIG_INTERNETREADFILE: Option<FnInternetReadFile> = None;

type FnInternetWriteFile = unsafe extern "system" fn(
    *mut c_void,   // hFile
    *const c_void, // lpBuffer
    u32,           // dwNumberOfBytesToWrite
    *mut u32,      // lpdwNumberOfBytesWritten
) -> i32;
static mut ORIG_INTERNETWRITEFILE: Option<FnInternetWriteFile> = None;

// --- Winsock (ws2_32) ---
//
// SOCKET is a UINT_PTR.  send/recv use C int returns where -1 == SOCKET_ERROR.
// WSASend/WSARecv use scatter-gather WSABUF arrays and return 0 on success.
//
// For recv/WSARecv we MUST call original first then read the populated
// buffer; for send/WSASend the buffer is caller-supplied so we can read it
// before delegating.  Overlapped WSARecv (lp_overlapped != NULL) has its
// completion happen asynchronously — we deliberately skip capture in that
// case rather than read stale buffer contents.
#[repr(C)]
struct WsaBuf {
    len: u32,
    buf: *mut u8,
}

type FnSend = unsafe extern "system" fn(usize, *const u8, i32, i32) -> i32;
static mut ORIG_SEND: Option<FnSend> = None;

type FnRecv = unsafe extern "system" fn(usize, *mut u8, i32, i32) -> i32;
static mut ORIG_RECV: Option<FnRecv> = None;

type FnWSASend = unsafe extern "system" fn(
    usize,             // s (SOCKET)
    *const WsaBuf,     // lpBuffers
    u32,               // dwBufferCount
    *mut u32,          // lpNumberOfBytesSent
    u32,               // dwFlags
    *mut c_void,       // lpOverlapped
    *mut c_void,       // lpCompletionRoutine
) -> i32;
static mut ORIG_WSASEND: Option<FnWSASend> = None;

type FnWSARecv = unsafe extern "system" fn(
    usize,             // s (SOCKET)
    *mut WsaBuf,       // lpBuffers
    u32,               // dwBufferCount
    *mut u32,          // lpNumberOfBytesRecvd
    *mut u32,          // lpFlags
    *mut c_void,       // lpOverlapped
    *mut c_void,       // lpCompletionRoutine
) -> i32;
static mut ORIG_WSARECV: Option<FnWSARecv> = None;

// --- File API Hook Signatures (ntdll) ---
type FnNtQueryAttributesFile = unsafe extern "system" fn(*mut OBJECT_ATTRIBUTES, *mut FILE_BASIC_INFORMATION) -> NTSTATUS;
static mut ORIG_NTQUERYATTRIBUTESFILE: Option<FnNtQueryAttributesFile> = None;

type FnNtQueryFullAttributesFile = unsafe extern "system" fn(*mut OBJECT_ATTRIBUTES, *mut FILE_NETWORK_OPEN_INFORMATION) -> NTSTATUS;
static mut ORIG_NTQUERYFULLATTRIBUTESFILE: Option<FnNtQueryFullAttributesFile> = None;

type FnNtOpenFile = unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut IO_STATUS_BLOCK, u32, u32) -> NTSTATUS;
static mut ORIG_NTOPENFILE: Option<FnNtOpenFile> = None;

type FnNtCreateFile = unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut IO_STATUS_BLOCK, *mut i64, u32, u32, u32, u32, HANDLE, u32) -> NTSTATUS;
static mut ORIG_NTCREATEFILE: Option<FnNtCreateFile> = None;

// --- ntdll Protection Hook Signatures ---
const SEC_IMAGE: u32 = 0x01000000;
const CURRENT_PROCESS: HANDLE = -1isize as HANDLE;
const PAGE_WRITABLE_FLAGS: u32 = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

// Read-side hooks
type FnNtReadFile = unsafe extern "system" fn(
    HANDLE, HANDLE, *mut c_void, *mut c_void,
    *mut IO_STATUS_BLOCK, *mut c_void, u32, *mut i64, *mut u32,
) -> NTSTATUS;
static mut ORIG_NTREADFILE: Option<FnNtReadFile> = None;

type FnNtReadFileScatter = unsafe extern "system" fn(
    HANDLE, HANDLE, *mut c_void, *mut c_void,
    *mut IO_STATUS_BLOCK, *mut c_void, u32, *mut i64, *mut u32,
) -> NTSTATUS;
static mut ORIG_NTREADFILESCATTER: Option<FnNtReadFileScatter> = None;

type FnNtCreateSection = unsafe extern "system" fn(
    *mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut i64, u32, u32, HANDLE,
) -> NTSTATUS;
static mut ORIG_NTCREATESECTION: Option<FnNtCreateSection> = None;

type FnNtOpenSection = unsafe extern "system" fn(
    *mut HANDLE, u32, *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS;
static mut ORIG_NTOPENSECTION: Option<FnNtOpenSection> = None;

// Write-side hooks
type FnNtWriteVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut c_void, *const c_void, usize, *mut usize,
) -> NTSTATUS;
static mut ORIG_NTWRITEVIRTUALMEMORY: Option<FnNtWriteVirtualMemory> = None;

type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32,
) -> NTSTATUS;
static mut ORIG_NTPROTECTVIRTUALMEMORY: Option<FnNtProtectVirtualMemory> = None;

type FnNtMapViewOfSection = unsafe extern "system" fn(
    HANDLE, HANDLE, *mut *mut c_void, usize, usize,
    *mut i64, *mut usize, u32, u32, u32,
) -> NTSTATUS;
static mut ORIG_NTMAPVIEWOFSECTION: Option<FnNtMapViewOfSection> = None;

type FnNtUnmapViewOfSection = unsafe extern "system" fn(
    HANDLE, *mut c_void,
) -> NTSTATUS;
static mut ORIG_NTUNMAPVIEWOFSECTION: Option<FnNtUnmapViewOfSection> = None;

// --- File API Hook Signatures (kernelbase) ---
type FnGetFileAttributesW = unsafe extern "system" fn(*const u16) -> u32;
static mut ORIG_GETFILEATTRIBUTESW: Option<FnGetFileAttributesW> = None;

type FnGetFileAttributesExW = unsafe extern "system" fn(*const u16, u32, *mut c_void) -> BOOL;
static mut ORIG_GETFILEATTRIBUTESEXW: Option<FnGetFileAttributesExW> = None;

type FnCreateFileWFn = unsafe extern "system" fn(*const u16, u32, u32, *mut c_void, u32, u32, HANDLE) -> HANDLE;
static mut ORIG_CREATEFILEW_HOOK: Option<FnCreateFileWFn> = None;

type FnFindFirstFileW = unsafe extern "system" fn(*const u16, *mut c_void) -> HANDLE;
static mut ORIG_FINDFIRSTFILEW: Option<FnFindFirstFileW> = None;

type FnFindFirstFileExW = unsafe extern "system" fn(*const u16, u32, *mut c_void, u32, *mut c_void, u32) -> HANDLE;
static mut ORIG_FINDFIRSTFILEEXW: Option<FnFindFirstFileExW> = None;

type FnSearchPathW = unsafe extern "system" fn(*const u16, *const u16, *const u16, u32, *mut u16, *mut *mut u16) -> u32;
static mut ORIG_SEARCHPATHW: Option<FnSearchPathW> = None;

type FnLoadLibraryW = unsafe extern "system" fn(*const u16) -> HANDLE;
static mut ORIG_LOADLIBRARYW: Option<FnLoadLibraryW> = None;

type FnLoadLibraryExW = unsafe extern "system" fn(*const u16, HANDLE, u32) -> HANDLE;
static mut ORIG_LOADLIBRARYEXW: Option<FnLoadLibraryExW> = None;

// --- File API Hook Signatures (shlwapi) ---
type FnPathFileExistsW = unsafe extern "system" fn(*const u16) -> BOOL;
static mut ORIG_PATHFILEEXISTSW: Option<FnPathFileExistsW> = None;

// --- File API Hook Signatures (ucrtbase CRT) ---
type FnWaccess = unsafe extern "system" fn(*const u16, i32) -> i32;
static mut ORIG_WACCESS: Option<FnWaccess> = None;

type FnWstat64 = unsafe extern "system" fn(*const u16, *mut c_void) -> i32;
static mut ORIG_WSTAT64: Option<FnWstat64> = None;

type FnWfopen = unsafe extern "system" fn(*const u16, *const u16) -> *mut c_void;
static mut ORIG_WFOPEN: Option<FnWfopen> = None;


// --- Utility: Protected Process Check ---
const PROTECTED_PROCESSES: &[&[u8]] = &[
    b"smss.exe", b"csrss.exe", b"wininit.exe", b"services.exe",
    b"lsass.exe", b"winlogon.exe", b"dwm.exe", b"system",
];

fn ascii_lower(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        if (b'A'..=b'Z').contains(b) { *b += 0x20; }
    }
}

unsafe fn host_process_is_protected() -> bool {
    let mut wbuf: [u16; 260] = [0; 260];
    let n = GetModuleFileNameW(0, wbuf.as_mut_ptr(), wbuf.len() as u32);
    if n == 0 { return true; }
    let mut start = 0usize;
    for i in 0..(n as usize) {
        if wbuf[i] == b'\\' as u16 || wbuf[i] == b'/' as u16 { start = i + 1; }
    }
    let mut name = [0u8; 64];
    let mut len = 0usize;
    for i in start..(n as usize) {
        if len >= name.len() { break; }
        let u = wbuf[i];
        name[len] = if u < 0x80 { u as u8 } else { b'?' };
        len += 1;
    }
    ascii_lower(&mut name[..len]);
    PROTECTED_PROCESSES.iter().any(|&p| p == &name[..len])
}

// --- Path Normalization and Matching Utilities ---

/// Normalize a wide path: uppercase, / -> \, trim trailing backslashes, NUL terminate.
fn normalize_wpath(input: &[u16]) -> Vec<u16> {
    let mut out: Vec<u16> = input.iter().map(|&c| {
        if c == b'/' as u16 { b'\\' as u16 }
        else if (b'a' as u16..=b'z' as u16).contains(&c) { c - 0x20 }
        else { c }
    }).collect();
    while out.last() == Some(&(b'\\' as u16)) { out.pop(); }
    if out.last() != Some(&0) { out.push(0); }
    out
}

/// Case-insensitive compare of two normalized paths, ignoring trailing NUL.
fn paths_eq(a: &[u16], b: &[u16]) -> bool {
    let a_end = if a.last() == Some(&0) { a.len() - 1 } else { a.len() };
    let b_end = if b.last() == Some(&0) { b.len() - 1 } else { b.len() };
    a_end == b_end && a[..a_end] == b[..b_end]
}

/// Check if a candidate wide path matches the blocked file path.
/// Handles DOS prefixes, NT namespace (\??\, \\?\, \\.\), and NT device translations.
unsafe fn is_blocked_file(candidate: *const u16) -> bool {
    if candidate.is_null() { return false; }
    if G_BLOCKED_PATH_NORMALIZED.is_empty() { return false; }

    let mut len = 0usize;
    while *candidate.add(len) != 0 {
        len += 1;
        if len > 32767 { return false; }
    }
    let raw: Vec<u16> = std::slice::from_raw_parts(candidate, len).to_vec();
    let norm = normalize_wpath(&raw);

    if paths_eq(&norm, &G_BLOCKED_PATH_NORMALIZED) { return true; }

    // Strip NT namespace prefixes
    for prefix in [&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16] as &[u16],
                    &[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16],
                    &[b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16]] {
        if norm.len() > prefix.len() && &norm[..prefix.len()] == prefix {
            let stripped = &norm[prefix.len()..];
            let mut candidate = stripped.to_vec();
            if candidate.last() != Some(&0) { candidate.push(0); }
            if paths_eq(&candidate, &G_BLOCKED_PATH_NORMALIZED) { return true; }
        }
    }

    // Translate NT device path -> DOS path
    for (nt_prefix, dos_prefix) in &G_DEVICE_PREFIXES {
        if norm.len() >= nt_prefix.len() && &norm[..nt_prefix.len()] == nt_prefix.as_slice() {
            let mut translated = dos_prefix.clone();
            translated.extend_from_slice(&norm[nt_prefix.len()..]);
            while translated.last() == Some(&(b'\\' as u16)) { translated.pop(); }
            if translated.last() != Some(&0) { translated.push(0); }
            if paths_eq(&translated, &G_BLOCKED_PATH_NORMALIZED) { return true; }
        }
    }

    false
}

/// Read the SizeOfImage from a loaded PE module's headers.
unsafe fn get_module_image_size(base: *const u8) -> usize {
    if base.is_null() { return 0; }
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D { return 0; }
    if dos.e_lfanew <= 0 { return 0; }
    let nt = &*(base.add(dos.e_lfanew as usize) as *const ImageNtHeaders64);
    if nt.signature != 0x00004550 { return 0; }
    nt.size_of_image as usize
}

/// Snapshot the in-memory ntdll.dll (already patched by MinHook) into G_NTDLL_MODIFIED_BYTES.
unsafe fn snapshot_ntdll() {
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll == 0 { return; }
    let base = ntdll as *const u8;
    let size = get_module_image_size(base);
    if size == 0 { return; }
    G_NTDLL_BASE = base;
    G_NTDLL_SIZE = size;
    G_NTDLL_MODIFIED_BYTES = std::slice::from_raw_parts(base, size).to_vec();
}

/// Build the set of normalized paths that identify ntdll.dll on disk.
unsafe fn build_ntdll_paths() {
    G_NTDLL_PATHS.clear();
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll == 0 { return; }

    // 1. Actual loaded path from GetModuleFileNameW
    let mut buf = [0u16; 520];
    let n = GetModuleFileNameW(ntdll, buf.as_mut_ptr(), buf.len() as u32);
    if n > 0 && (n as usize) < buf.len() {
        G_NTDLL_PATHS.push(normalize_wpath(&buf[..n as usize]));
    }

    // 2. SysWOW64 variant (replace \System32\ with \SysWOW64\)
    if let Some(first) = G_NTDLL_PATHS.first() {
        let syswow64 = first.iter().enumerate().position(|(i, _)| {
            i + 10 <= first.len() && first[i..i+10] == [b'\\' as u16, b'S' as u16, b'Y' as u16, b'S' as u16, b'T' as u16, b'E' as u16, b'M' as u16, b'3' as u16, b'2' as u16, b'\\' as u16]
        });
        if let Some(pos) = syswow64 {
            let mut variant = first[..pos].to_vec();
            variant.extend_from_slice(&[
                b'\\' as u16, b'S' as u16, b'Y' as u16, b'S' as u16,
                b'W' as u16, b'O' as u16, b'W' as u16, b'6' as u16,
                b'4' as u16, b'\\' as u16,
            ]);
            variant.extend_from_slice(&first[pos + 10..]);
            G_NTDLL_PATHS.push(variant);
        }
    }

    // 3. KnownDlls path
    let known_dlls: Vec<u16> = b"\\\0K\0n\0o\0w\0n\0D\0l\0l\0s\0\\\0n\0t\0d\0l\0l\0.\0d\0l\0l\0\0".iter()
        .map(|&b| b as u16).collect();
    G_NTDLL_PATHS.push(normalize_wpath(&known_dlls[..known_dlls.len()-1]));
}

/// Check if a candidate wide path refers to ntdll.dll.
/// Uses the same normalization + prefix translation logic as is_blocked_file().
unsafe fn is_ntdll_file(candidate: *const u16) -> bool {
    if candidate.is_null() { return false; }
    if G_NTDLL_PATHS.is_empty() { return false; }

    let mut len = 0usize;
    while *candidate.add(len) != 0 {
        len += 1;
        if len > 32767 { return false; }
    }
    let raw: Vec<u16> = std::slice::from_raw_parts(candidate, len).to_vec();
    let norm = normalize_wpath(&raw);

    for ntdll_path in &G_NTDLL_PATHS {
        if paths_eq(&norm, ntdll_path) { return true; }
    }

    // Strip NT namespace prefixes
    for prefix in [&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16] as &[u16],
                    &[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16],
                    &[b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16]] {
        if norm.len() > prefix.len() && &norm[..prefix.len()] == prefix {
            let stripped = &norm[prefix.len()..];
            let mut candidate = stripped.to_vec();
            if candidate.last() != Some(&0) { candidate.push(0); }
            for ntdll_path in &G_NTDLL_PATHS {
                if paths_eq(&candidate, ntdll_path) { return true; }
            }
        }
    }

    // Translate NT device path -> DOS path
    for (nt_prefix, dos_prefix) in &G_DEVICE_PREFIXES {
        if norm.len() >= nt_prefix.len() && &norm[..nt_prefix.len()] == nt_prefix.as_slice() {
            let mut translated = dos_prefix.clone();
            translated.extend_from_slice(&norm[nt_prefix.len()..]);
            while translated.last() == Some(&(b'\\' as u16)) { translated.pop(); }
            if translated.last() != Some(&0) { translated.push(0); }
            for ntdll_path in &G_NTDLL_PATHS {
                if paths_eq(&translated, ntdll_path) { return true; }
            }
        }
    }

    false
}

/// Read the blocked file path from config file.
unsafe fn read_blocked_path() -> Vec<u16> {
    let cfg_path = b"C:\\Users\\Public\\file_blinder_block.cfg\0";
    let h = CreateFileA(
        cfg_path.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        std::ptr::null(),
        OPEN_EXISTING,
        0,
        0,
    );
    if h != INVALID_HANDLE_VALUE {
        let mut buf = [0u8; 1040];
        let mut bytes: u32 = 0;
        if ReadFile(h, buf.as_mut_ptr() as _, buf.len() as u32, &mut bytes, std::ptr::null_mut()) != 0 && bytes > 0 {
            CloseHandle(h);
            // Trim trailing CR/LF/whitespace, convert ASCII bytes -> wide chars
            let mut end = bytes as usize;
            while end > 0 && (buf[end - 1] == b'\r' || buf[end - 1] == b'\n' || buf[end - 1] == b' ') {
                end -= 1;
            }
            let v: Vec<u16> = buf[..end].iter().map(|&b| b as u16).chain(std::iter::once(0)).collect();
            return v;
        }
        CloseHandle(h);
    }
    Vec::new()
}

/// Populate G_DEVICE_PREFIXES with DOS drive letter -> NT device mappings for A-Z.
unsafe fn init_device_prefixes() {
    G_DEVICE_PREFIXES.clear();
    for drive in b'A'..=b'Z' {
        let dos_name = [drive as u16, b':' as u16, 0u16];
        let mut nt_buf = [0u16; 256];
        let len = QueryDosDeviceW(dos_name.as_ptr(), nt_buf.as_mut_ptr(), nt_buf.len() as u32);
        if len > 0 && len < nt_buf.len() as u32 {
            let dos_prefix = vec![drive as u16, b':' as u16];
            let nt_prefix: Vec<u16> = nt_buf[..len as usize].iter().take_while(|&&c| c != 0).copied().collect();
            G_DEVICE_PREFIXES.push((nt_prefix, dos_prefix));
        }
    }
}

// --- Telemetry Core: framed binary protocol ---
//
// Header (32 bytes, little-endian) + payload of payload_len bytes.
// One Encrypt/DecryptMessage SECBUFFER_DATA chunk may exceed 64KB only in
// theory (TLS record cap is ~16KB); we chunk it across frames just in case.
// Reader splices chunks by (stream_id, seq) order.
unsafe fn send_frame(event: u32, stream_id: u64, payload: &[u8]) {
    if SHUTTING_DOWN.load(Ordering::Acquire) { return; }
    if PIPE_BROKEN.load(Ordering::Acquire) { return; }
    if G_PIPE_HANDLE == INVALID_HANDLE_VALUE { return; }

    // Empty payload (AGENT_ONLINE) still emits one header frame so the reader
    // sees the event.
    let mut offset = 0usize;
    let len = payload.len();
    loop {
        let take = if len == 0 { 0 } else { core::cmp::min(MAX_FRAME_PAYLOAD, len - offset) };
        let hdr = FrameHeader {
            magic: FRAME_MAGIC,
            event,
            stream_id,
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
            payload_len: take as u32,
            reserved: 0,
        };
        let mut written = 0u32;
        let ok = WriteFile(
            G_PIPE_HANDLE,
            &hdr as *const _ as _,
            core::mem::size_of::<FrameHeader>() as u32,
            &mut written, std::ptr::null_mut());
        if ok == 0 {
            PIPE_BROKEN.store(true, Ordering::Release);
            OutputDebugStringA(b"FileBlinder: Pipe write FAILED (header) - marking broken\0".as_ptr());
            return;
        }
        if take > 0 {
            let ok = WriteFile(
                G_PIPE_HANDLE,
                payload[offset..offset + take].as_ptr() as _,
                take as u32,
                &mut written, std::ptr::null_mut());
            if ok == 0 {
                PIPE_BROKEN.store(true, Ordering::Release);
                OutputDebugStringA(b"FileBlinder: Pipe write FAILED (payload) - marking broken\0".as_ptr());
                return;
            }
        }
        offset += take;
        if len == 0 || offset >= len { break; }
    }
}

// --- Hook: LdrLoadDll ---
unsafe extern "system" fn hooked_ldr_load_dll(p: *mut u16, f: *const u32, name: *const UNICODE_STRING, h: *mut *mut c_void) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) && !name.is_null() && !(*name).buffer.is_null() {
        let mut buf = [0u8; STR_BUF];
        let mut pos = 0usize;
        let wchars = (*name).length as usize / 2;
        let src = std::slice::from_raw_parts((*name).buffer, wchars);
        for &u in src {
            if pos >= buf.len() { break; }
            buf[pos] = if u < 0x80 { u as u8 } else { b'?' };
            pos += 1;
        }
        send_frame(EV_DLL_LOAD, 0, &buf[..pos]);
    }
    match ORIG_LDRLOADDLL { Some(orig) => orig(p, f, name, h), None => 0 }
}

// --- Hook: CreateProcessInternalW ---
unsafe extern "system" fn hooked_create_process(ht: HANDLE, an: *const u16, cl: *mut u16, pa: *mut c_void, ta: *mut c_void, ih: BOOL, cf: u32, env: *mut c_void, cd: *const u16, si: *mut c_void, pi: *mut c_void, rt: *mut c_void) -> BOOL {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) && !cl.is_null() {
        let mut buf = [0u8; STR_BUF];
        let mut pos = 0usize;
        let mut len = 0usize;
        while *cl.add(len) != 0 { len += 1; }
        let src = std::slice::from_raw_parts(cl, len);
        for &u in src {
            if pos >= buf.len() { break; }
            buf[pos] = if u < 0x80 { u as u8 } else { b'?' };
            pos += 1;
        }
        send_frame(EV_PROC_SPAWN, 0, &buf[..pos]);
    }

    // Decide whether to inject into this child (only when child-injection enabled)
    let should_inject = INJECT_CHILDREN.load(Ordering::Acquire) && !G_SELF_MODULE_PATH.is_empty();
    let target_matches = if should_inject && !G_CHILD_TARGET.is_empty() {
        // Match child command-line against the target exe name (case-insensitive)
        !cl.is_null() && {
            let mut i = 0usize;
            while *cl.add(i) != 0 { i += 1; }
            let cmd = std::slice::from_raw_parts(cl, i);
            // Check if target name appears anywhere in command line (case-insensitive)
            let tgt_len = G_CHILD_TARGET.len() - 1; // exclude NUL
            i >= tgt_len && cmd.windows(tgt_len).any(|w| {
                w.iter().zip(G_CHILD_TARGET.iter()).all(|(&c, &t)| {
                    let cl = if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 0x20 } else { c };
                    cl == t
                })
            })
        }
    } else {
        should_inject // no target filter → inject all
    };
    let do_inject = target_matches;

    let was_suspended = (cf & CREATE_SUSPENDED) != 0;
    let new_cf = if do_inject { cf | CREATE_SUSPENDED } else { cf };

    let result = match ORIG_CREATEPROCESSINTERNALW {
        Some(orig) => orig(ht, an, cl, pa, ta, ih, new_cf, env, cd, si, pi, rt),
        None => 0,
    };

    // Inject into child if it matched the target filter
    if do_inject && result != 0 && !pi.is_null() {
        #[repr(C)]
        struct ProcInfo { hProcess: HANDLE, hThread: HANDLE, dwProcessId: u32, dwThreadId: u32 }
        let info = &*(pi as *const ProcInfo);

        let dll_path_bytes = G_SELF_MODULE_PATH.len() * 2;
        let alloc = VirtualAllocEx(
            info.hProcess, std::ptr::null(), dll_path_bytes,
            0x00001000 | 0x00002000, 0x04,
        );
        if !alloc.is_null() {
            let mut written: usize = 0;
            WriteProcessMemory(
                info.hProcess, alloc,
                G_SELF_MODULE_PATH.as_ptr() as _, dll_path_bytes,
                &mut written,
            );

            let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
            if k32 != 0 {
                let loadlib = GetProcAddress(k32, b"LoadLibraryW\0".as_ptr());
                if loadlib.is_some() {
                    let remote_thread = CreateRemoteThread(
                        info.hProcess, std::ptr::null(), 0,
                        loadlib.unwrap() as *mut c_void,
                        alloc, 0, std::ptr::null_mut(),
                    );
                    if remote_thread != 0 {
                        WaitForSingleObject(remote_thread, 10000);
                        CloseHandle(remote_thread);
                    }
                }
            }
            VirtualFreeEx(info.hProcess, alloc, 0, 0x00008000);
        }
    }

    // Resume child's main thread if we suspended it and caller didn't want it suspended
    if do_inject && result != 0 && !was_suspended && !pi.is_null() {
        #[repr(C)]
        struct ProcInfo { hProcess: HANDLE, hThread: HANDLE, dwProcessId: u32, dwThreadId: u32 }
        let info = &*(pi as *const ProcInfo);
        if info.hThread != 0 {
            ResumeThread(info.hThread);
        }
    }

    result
}

// Read the CtxtHandle's `dwLower` (first ULONG_PTR of the 16-byte struct)
// as the stream correlation key.
//
// Why dwLower instead of the pointer-to-CtxtHandle: CtxtHandle is a
// caller-owned 16-byte struct, and high-level wrappers (.NET SslStream,
// WinHttp, etc.) routinely *copy* the struct between handshake and bulk
// I/O — same logical TLS session, but the `phContext` pointer we see in
// EncryptMessage / DecryptMessage is at a different memory address than
// what InitializeSecurityContextW filled in.  SChannel writes its real
// session identifier into dwLower, and that survives memcpys of the
// outer struct, so it correctly correlates copies of the same session.
#[inline]
unsafe fn ctxt_handle_id(p: *const c_void) -> u64 {
    if p.is_null() { return 0; }
    // Use read_unaligned to avoid UB if the caller's CtxtHandle isn't
    // 8-byte aligned (unlikely on x64, but defensive).
    core::ptr::read_unaligned(p as *const u64)
}

// --- Hook: EncryptMessage (OUTBOUND PLAINTEXT) ---
//
// Send the SECBUFFER_DATA chunk to the reader IN RAW form (no escaping, no
// length cap, no printable filtering).  The reader hex-encodes for JSON.
unsafe extern "system" fn hooked_encrypt_message(
    ph_context: *mut c_void, f_qop: u32, p_message: *mut SecBufferDesc, msg_seq: u32
) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) && !p_message.is_null() {
        if !DBG_ENCRYPT.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook EncryptMessage fired\0".as_ptr());
        }
        let sid = ctxt_handle_id(ph_context);
        let desc = &*p_message;
        if !desc.pBuffers.is_null() {
            let buffers = std::slice::from_raw_parts(desc.pBuffers, desc.cBuffers as usize);
            for buf in buffers {
                if buf.BufferType == SECBUFFER_DATA && !buf.pvBuffer.is_null() && buf.cbBuffer > 0 {
                    let slice = std::slice::from_raw_parts(buf.pvBuffer, buf.cbBuffer as usize);
                    send_frame(EV_TLS_OUT_PLAIN, sid, slice);
                }
            }
        }
    }
    match ORIG_ENCRYPTMESSAGE {
        Some(orig) => orig(ph_context, f_qop, p_message, msg_seq),
        None => -1,
    }
}

// --- Hook: DecryptMessage (INBOUND PLAINTEXT) ---
unsafe extern "system" fn hooked_decrypt_message(
    ph_context: *mut c_void, p_message: *mut SecBufferDesc, msg_seq: u32, pf_qop: *mut u32
) -> i32 {
    // 1. Call original first so SChannel decrypts the ciphertext buffer.
    let status = match ORIG_DECRYPTMESSAGE {
        Some(orig) => orig(ph_context, p_message, msg_seq, pf_qop),
        None => return -1,
    };

    // 2. On SEC_E_OK, snapshot the now-plaintext SECBUFFER_DATA chunks.
    if status == 0 && INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) && !p_message.is_null() {
        if !DBG_DECRYPT.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook DecryptMessage fired\0".as_ptr());
        }
        let sid = ctxt_handle_id(ph_context);
        let desc = &*p_message;
        if !desc.pBuffers.is_null() {
            let buffers = std::slice::from_raw_parts(desc.pBuffers, desc.cBuffers as usize);
            for buf in buffers {
                if buf.BufferType == SECBUFFER_DATA && !buf.pvBuffer.is_null() && buf.cbBuffer > 0 {
                    let slice = std::slice::from_raw_parts(buf.pvBuffer, buf.cbBuffer as usize);
                    send_frame(EV_TLS_IN_PLAIN, sid, slice);
                }
            }
        }
    }
    status
}

// --- Hook: InitializeSecurityContextW (HOST CAPTURE) ---
//
// SChannel calls this several times during the TLS handshake. The
// pszTargetName argument is the SNI hostname the application requested.
// We snapshot it BEFORE delegating, then key it under the resulting
// CtxtHandle's `dwLower` field — that is what EncryptMessage /
// DecryptMessage will see as `*phContext`'s first ULONG_PTR for this
// session, even if the high-level wrapper (.NET SslStream, WinHttp, ...)
// copies the 16-byte CtxtHandle struct to a different memory address
// between handshake and bulk I/O.  Keying under the pointer-to-CtxtHandle
// breaks in exactly that case → bulk PNG bytes show up under an
// `unknown-host` stream id because they came through a copy of the same
// SChannel session at a different address.
unsafe extern "system" fn hooked_init_sec_ctx_w(
    ph_cred: *mut c_void, ph_ctx: *mut c_void, target: *const u16,
    f_req: u32, r1: u32, tdr: u32, p_in: *mut c_void, r2: u32,
    ph_new_ctx: *mut c_void, p_out: *mut c_void, p_attr: *mut u32, p_exp: *mut i64
) -> i32 {
    // Snapshot the hostname BEFORE the call — caller-owned, stable across
    // the delegate.
    let mut host_buf = [0u8; 256];
    let mut host_len = 0usize;
    if !target.is_null() {
        let mut i = 0usize;
        loop {
            let u = *target.add(i);
            if u == 0 || host_len >= host_buf.len() { break; }
            host_buf[host_len] = if u < 0x80 { u as u8 } else { b'?' };
            host_len += 1; i += 1;
        }
    }

    let status = match ORIG_INITSECCTXW {
        Some(orig) => orig(ph_cred, ph_ctx, target, f_req, r1, tdr, p_in, r2, ph_new_ctx, p_out, p_attr, p_exp),
        None => return -1,
    };

    // Prefer phNewContext (SChannel writes the new session's dwLower into
    // its first ULONG_PTR), fall back to phContext (reused on subsequent
    // handshake round-trips).  Reading dwLower (not the pointer-to-handle)
    // means a downstream memcpy of the CtxtHandle by a wrapper layer still
    // joins back to this host record.
    if host_len > 0 {
        let mut sid = ctxt_handle_id(ph_new_ctx);
        if sid == 0 { sid = ctxt_handle_id(ph_ctx); }
        if sid != 0 {
            send_frame(EV_TLS_HOST, sid, &host_buf[..host_len]);
        }
    }
    status
}


// --- Buffer helpers for the HTTP hooks ---
//
// WinHttp / WinInet headers come in either pre-counted (chars) or NUL-
// terminated (length == 0xFFFFFFFF).  Convert to a UTF-8-ish byte buffer
// for the wire; non-ASCII codepoints get '?' to keep the line printable.
// Cap at 16 KB to avoid runaway in case of a corrupted length.
unsafe fn wide_headers_to_bytes(p: *const u16, char_len_or_neg1: u32) -> Vec<u8> {
    if p.is_null() { return Vec::new(); }
    let len = if char_len_or_neg1 == u32::MAX {
        let mut n = 0usize;
        while *p.add(n) != 0 && n < 16384 { n += 1; }
        n
    } else {
        core::cmp::min(char_len_or_neg1 as usize, 16384)
    };
    let mut out = Vec::with_capacity(len);
    let src = std::slice::from_raw_parts(p, len);
    for &w in src {
        out.push(if w < 0x80 { w as u8 } else { b'?' });
    }
    out
}

unsafe fn ascii_headers_to_bytes(p: *const u8, len_or_neg1: u32) -> Vec<u8> {
    if p.is_null() { return Vec::new(); }
    let len = if len_or_neg1 == u32::MAX {
        let mut n = 0usize;
        while *p.add(n) != 0 && n < 16384 { n += 1; }
        n
    } else {
        core::cmp::min(len_or_neg1 as usize, 16384)
    };
    std::slice::from_raw_parts(p, len).to_vec()
}

// --- Hook: WinHttpSendRequest ---
//
// Captures the headers + optional body the application is about to send.
// stream_id is the HINTERNET request handle.  For HTTPS this fires BEFORE
// SChannel's EncryptMessage too, so analysts see the plaintext at both
// layers — useful when one path is buggy / mis-attributed.
unsafe extern "system" fn hooked_winhttp_send_request(
    h_request: *mut c_void,
    pwsz_headers: *const u16,
    dw_headers_length: u32,
    lp_optional: *mut c_void,
    dw_optional_length: u32,
    dw_total_length: u32,
    dw_context: usize,
) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if !DBG_WINHTTP_SEND.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook WinHttpSendRequest fired\0".as_ptr());
        }
        let sid = h_request as u64;
        let hdrs = wide_headers_to_bytes(pwsz_headers, dw_headers_length);
        if !hdrs.is_empty() {
            send_frame(EV_WINHTTP_OUT, sid, &hdrs);
        }
        if !lp_optional.is_null() && dw_optional_length > 0 {
            let body = std::slice::from_raw_parts(lp_optional as *const u8, dw_optional_length as usize);
            send_frame(EV_WINHTTP_OUT, sid, body);
        }
    }
    match ORIG_WINHTTPSENDREQUEST {
        Some(orig) => orig(h_request, pwsz_headers, dw_headers_length, lp_optional, dw_optional_length, dw_total_length, dw_context),
        None => 0,
    }
}

unsafe extern "system" fn hooked_winhttp_write_data(
    h_request: *mut c_void,
    lp_buffer: *const c_void,
    dw_num_bytes_to_write: u32,
    lpdw_num_bytes_written: *mut u32,
) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire)
        && !lp_buffer.is_null() && dw_num_bytes_to_write > 0 {
        if !DBG_WINHTTP_WRITE.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook WinHttpWriteData fired\0".as_ptr());
        }
        let slice = std::slice::from_raw_parts(lp_buffer as *const u8, dw_num_bytes_to_write as usize);
        send_frame(EV_WINHTTP_OUT, h_request as u64, slice);
    }
    match ORIG_WINHTTPWRITEDATA {
        Some(orig) => orig(h_request, lp_buffer, dw_num_bytes_to_write, lpdw_num_bytes_written),
        None => 0,
    }
}

// WinHttpReadData fills lpBuffer; we must call original FIRST, then read
// the actual byte count from lpdwNumberOfBytesRead.
unsafe extern "system" fn hooked_winhttp_read_data(
    h_request: *mut c_void,
    lp_buffer: *mut c_void,
    dw_num_bytes_to_read: u32,
    lpdw_num_bytes_read: *mut u32,
) -> i32 {
    let rv = match ORIG_WINHTTPREADDATA {
        Some(orig) => orig(h_request, lp_buffer, dw_num_bytes_to_read, lpdw_num_bytes_read),
        None => return 0,
    };
    if rv != 0 && INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire)
        && !lp_buffer.is_null() && !lpdw_num_bytes_read.is_null() {
        if !DBG_WINHTTP_READ.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook WinHttpReadData fired\0".as_ptr());
        }
        let got = *lpdw_num_bytes_read;
        if got > 0 {
            let slice = std::slice::from_raw_parts(lp_buffer as *const u8, got as usize);
            send_frame(EV_WINHTTP_IN, h_request as u64, slice);
        }
    }
    rv
}

// --- Hook: HttpSendRequestW / HttpSendRequestA (WinInet) ---
unsafe extern "system" fn hooked_http_send_request_w(
    h_request: *mut c_void,
    lpsz_headers: *const u16,
    dw_headers_length: u32,
    lp_optional: *mut c_void,
    dw_optional_length: u32,
) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if !DBG_WININET_SEND.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook HttpSendRequestW fired\0".as_ptr());
        }
        let sid = h_request as u64;
        let hdrs = wide_headers_to_bytes(lpsz_headers, dw_headers_length);
        if !hdrs.is_empty() {
            send_frame(EV_WININET_OUT, sid, &hdrs);
        }
        if !lp_optional.is_null() && dw_optional_length > 0 {
            let body = std::slice::from_raw_parts(lp_optional as *const u8, dw_optional_length as usize);
            send_frame(EV_WININET_OUT, sid, body);
        }
    }
    match ORIG_HTTPSENDREQUESTW {
        Some(orig) => orig(h_request, lpsz_headers, dw_headers_length, lp_optional, dw_optional_length),
        None => 0,
    }
}

unsafe extern "system" fn hooked_http_send_request_a(
    h_request: *mut c_void,
    lpsz_headers: *const u8,
    dw_headers_length: u32,
    lp_optional: *mut c_void,
    dw_optional_length: u32,
) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        let sid = h_request as u64;
        let hdrs = ascii_headers_to_bytes(lpsz_headers, dw_headers_length);
        if !hdrs.is_empty() {
            send_frame(EV_WININET_OUT, sid, &hdrs);
        }
        if !lp_optional.is_null() && dw_optional_length > 0 {
            let body = std::slice::from_raw_parts(lp_optional as *const u8, dw_optional_length as usize);
            send_frame(EV_WININET_OUT, sid, body);
        }
    }
    match ORIG_HTTPSENDREQUESTA {
        Some(orig) => orig(h_request, lpsz_headers, dw_headers_length, lp_optional, dw_optional_length),
        None => 0,
    }
}

unsafe extern "system" fn hooked_internet_read_file(
    h_file: *mut c_void,
    lp_buffer: *mut c_void,
    dw_num_bytes_to_read: u32,
    lpdw_num_bytes_read: *mut u32,
) -> i32 {
    let rv = match ORIG_INTERNETREADFILE {
        Some(orig) => orig(h_file, lp_buffer, dw_num_bytes_to_read, lpdw_num_bytes_read),
        None => return 0,
    };
    if rv != 0 && INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire)
        && !lp_buffer.is_null() && !lpdw_num_bytes_read.is_null() {
        if !DBG_WININET_READ.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook InternetReadFile fired\0".as_ptr());
        }
        let got = *lpdw_num_bytes_read;
        if got > 0 {
            let slice = std::slice::from_raw_parts(lp_buffer as *const u8, got as usize);
            send_frame(EV_WININET_IN, h_file as u64, slice);
        }
    }
    rv
}

unsafe extern "system" fn hooked_internet_write_file(
    h_file: *mut c_void,
    lp_buffer: *const c_void,
    dw_num_bytes_to_write: u32,
    lpdw_num_bytes_written: *mut u32,
) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire)
        && !lp_buffer.is_null() && dw_num_bytes_to_write > 0 {
        if !DBG_WININET_WRITE.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook InternetWriteFile fired\0".as_ptr());
        }
        let slice = std::slice::from_raw_parts(lp_buffer as *const u8, dw_num_bytes_to_write as usize);
        send_frame(EV_WININET_OUT, h_file as u64, slice);
    }
    match ORIG_INTERNETWRITEFILE {
        Some(orig) => orig(h_file, lp_buffer, dw_num_bytes_to_write, lpdw_num_bytes_written),
        None => 0,
    }
}

// --- Hook: send / recv / WSASend / WSARecv (Winsock) ---
//
// `s` (the SOCKET) is the stream_id.  Note that Winsock will see the
// CIPHERTEXT of an HTTPS connection — those bytes are useful only for
// flow accounting (sizes, timing), not content.  Plain HTTP, FTP, SMTP,
// custom TCP protocols and the like show their actual payload here.
unsafe extern "system" fn hooked_send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire)
        && !buf.is_null() && len > 0 {
        if !DBG_SEND.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook send fired\0".as_ptr());
        }
        let slice = std::slice::from_raw_parts(buf, len as usize);
        send_frame(EV_SOCKET_OUT, s as u64, slice);
    }
    match ORIG_SEND {
        Some(orig) => orig(s, buf, len, flags),
        None => -1,
    }
}

unsafe extern "system" fn hooked_recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32 {
    let rv = match ORIG_RECV {
        Some(orig) => orig(s, buf, len, flags),
        None => return -1,
    };
    if rv > 0 && INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) && !buf.is_null() {
        if !DBG_RECV.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook recv fired\0".as_ptr());
        }
        let slice = std::slice::from_raw_parts(buf, rv as usize);
        send_frame(EV_SOCKET_IN, s as u64, slice);
    }
    rv
}

unsafe extern "system" fn hooked_wsa_send(
    s: usize,
    lp_buffers: *const WsaBuf,
    dw_buffer_count: u32,
    lp_num_bytes_sent: *mut u32,
    dw_flags: u32,
    lp_overlapped: *mut c_void,
    lp_completion_routine: *mut c_void,
) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire)
        && !lp_buffers.is_null() && dw_buffer_count > 0 {
        if !DBG_WSASEND.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook WSASend fired\0".as_ptr());
        }
        let bufs = std::slice::from_raw_parts(lp_buffers, dw_buffer_count as usize);
        for b in bufs {
            if !b.buf.is_null() && b.len > 0 {
                let slice = std::slice::from_raw_parts(b.buf, b.len as usize);
                send_frame(EV_SOCKET_OUT, s as u64, slice);
            }
        }
    }
    match ORIG_WSASEND {
        Some(orig) => orig(s, lp_buffers, dw_buffer_count, lp_num_bytes_sent, dw_flags, lp_overlapped, lp_completion_routine),
        None => -1,
    }
}

// Skip overlapped WSARecv (lpOverlapped != NULL) — the buffer is filled
// asynchronously via a completion port / event and the contents are not
// valid at function return.  Capturing them here would log uninitialised
// memory.  Sync WSARecv (lpOverlapped == NULL) fills buffers before
// returning, so we read post-call as with recv().
unsafe extern "system" fn hooked_wsa_recv(
    s: usize,
    lp_buffers: *mut WsaBuf,
    dw_buffer_count: u32,
    lp_num_bytes_recvd: *mut u32,
    lp_flags: *mut u32,
    lp_overlapped: *mut c_void,
    lp_completion_routine: *mut c_void,
) -> i32 {
    let rv = match ORIG_WSARECV {
        Some(orig) => orig(s, lp_buffers, dw_buffer_count, lp_num_bytes_recvd, lp_flags, lp_overlapped, lp_completion_routine),
        None => return -1,
    };
    if rv == 0 && lp_overlapped.is_null()
        && INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire)
        && !lp_buffers.is_null() && !lp_num_bytes_recvd.is_null() {
        if !DBG_WSARECV.swap(true, Ordering::Relaxed) {
            OutputDebugStringA(b"FileBlinder: hook WSARecv fired\0".as_ptr());
        }
        let mut remaining = *lp_num_bytes_recvd as usize;
        let bufs = std::slice::from_raw_parts(lp_buffers, dw_buffer_count as usize);
        for b in bufs {
            if remaining == 0 { break; }
            if !b.buf.is_null() && b.len > 0 {
                let take = core::cmp::min(b.len as usize, remaining);
                let slice = std::slice::from_raw_parts(b.buf, take);
                send_frame(EV_SOCKET_IN, s as u64, slice);
                remaining -= take;
            }
        }
    }
    rv
}

// --- File API Hooks ---
// Extract the file path from OBJECT_ATTRIBUTES -> ObjectName UNICODE_STRING.
unsafe fn objattr_path(oa: *mut OBJECT_ATTRIBUTES) -> *const u16 {
    if oa.is_null() { return std::ptr::null(); }
    let on = (*oa).object_name;
    if on.is_null() { return std::ptr::null(); }
    (*on).buffer
}

// --- ntdll hooks ---
unsafe extern "system" fn hooked_nt_query_attributes_file(
    oa: *mut OBJECT_ATTRIBUTES,
    fi: *mut FILE_BASIC_INFORMATION,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        let path = objattr_path(oa);
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    match ORIG_NTQUERYATTRIBUTESFILE { Some(orig) => orig(oa, fi), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

unsafe extern "system" fn hooked_nt_query_full_attributes_file(
    oa: *mut OBJECT_ATTRIBUTES,
    fi: *mut FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        let path = objattr_path(oa);
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    match ORIG_NTQUERYFULLATTRIBUTESFILE { Some(orig) => orig(oa, fi), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

unsafe extern "system" fn hooked_nt_open_file(
    fh: *mut HANDLE, access: u32, oa: *mut OBJECT_ATTRIBUTES,
    isb: *mut IO_STATUS_BLOCK, share: u32, opts: u32,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        let path = objattr_path(oa);
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if is_ntdll_file(path) {
            let result = ORIG_NTOPENFILE.map_or(STATUS_OBJECT_NAME_NOT_FOUND, |orig| orig(fh, access, oa, isb, share, opts));
            if result >= 0 && !fh.is_null() {
                G_NTDLL_HANDLES.push(*fh);
            }
            return result;
        }
    }
    match ORIG_NTOPENFILE { Some(orig) => orig(fh, access, oa, isb, share, opts), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

unsafe extern "system" fn hooked_nt_create_file(
    fh: *mut HANDLE, access: u32, oa: *mut OBJECT_ATTRIBUTES,
    isb: *mut IO_STATUS_BLOCK, alloc: *mut i64, attr: u32,
    share: u32, disp: u32, create: u32, edb: HANDLE, opts: u32,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        let path = objattr_path(oa);
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if is_ntdll_file(path) {
            let result = ORIG_NTCREATEFILE.map_or(STATUS_OBJECT_NAME_NOT_FOUND, |orig| orig(fh, access, oa, isb, alloc, attr, share, disp, create, edb, opts));
            if result >= 0 && !fh.is_null() {
                G_NTDLL_HANDLES.push(*fh);
            }
            return result;
        }
    }
    match ORIG_NTCREATEFILE { Some(orig) => orig(fh, access, oa, isb, alloc, attr, share, disp, create, edb, opts), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

// --- ntdll protection hooks (read-side) ---

fn is_ntdll_handle(handle: HANDLE) -> bool {
    unsafe { G_NTDLL_HANDLES.iter().any(|&h| h == handle) }
}

unsafe fn serve_ntdll_bytes(
    buffer: *mut c_void,
    length: u32,
    byte_offset: *const i64,
    io_status: *mut IO_STATUS_BLOCK,
) -> NTSTATUS {
    if buffer.is_null() || io_status.is_null() { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let offset = if !byte_offset.is_null() { *byte_offset as usize } else { 0 };
    let available = if offset < G_NTDLL_MODIFIED_BYTES.len() {
        G_NTDLL_MODIFIED_BYTES.len() - offset
    } else { 0 };
    let bytes = if (length as usize) < available { length as usize } else { available };
    if bytes > 0 {
        std::ptr::copy_nonoverlapping(G_NTDLL_MODIFIED_BYTES.as_ptr().add(offset), buffer as *mut u8, bytes);
    }
    (*io_status).status = 0;
    (*io_status).information = bytes;
    0
}

unsafe extern "system" fn hooked_nt_read_file(
    file_handle: HANDLE, event: HANDLE, apc_routine: *mut c_void,
    apc_context: *mut c_void, io_status: *mut IO_STATUS_BLOCK,
    buffer: *mut c_void, length: u32, byte_offset: *mut i64, key: *mut u32,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_ntdll_handle(file_handle) {
            return serve_ntdll_bytes(buffer, length, byte_offset, io_status);
        }
    }
    match ORIG_NTREADFILE { Some(orig) => orig(file_handle, event, apc_routine, apc_context, io_status, buffer, length, byte_offset, key), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

unsafe extern "system" fn hooked_nt_read_file_scatter(
    file_handle: HANDLE, event: HANDLE, apc_routine: *mut c_void,
    apc_context: *mut c_void, io_status: *mut IO_STATUS_BLOCK,
    segments: *mut c_void, length: u32, byte_offset: *mut i64, key: *mut u32,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_ntdll_handle(file_handle) {
            // The segments parameter is a FILE_SEGMENT_ELEMENT array (64-bit pointers).
            // For simplicity, serve the request as if it were a contiguous read.
            // The first segment element contains the buffer pointer.
            if !segments.is_null() && length > 0 {
                let seg = segments as *const usize;
                let buf = *seg as *mut c_void;
                if !buf.is_null() {
                    return serve_ntdll_bytes(buf, length, byte_offset, io_status);
                }
            }
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    match ORIG_NTREADFILESCATTER { Some(orig) => orig(file_handle, event, apc_routine, apc_context, io_status, segments, length, byte_offset, key), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

unsafe extern "system" fn hooked_nt_create_section(
    section_handle: *mut HANDLE, desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES, maximum_size: *mut i64,
    section_page_protection: u32, allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_ntdll_handle(file_handle) && (allocation_attributes & SEC_IMAGE) != 0 {
            // Create a pagefile-backed section and fill it with our modified bytes.
            let nt_map: unsafe extern "system" fn(HANDLE, HANDLE, *mut *mut c_void, usize, usize, *mut i64, *mut usize, u32, u32, u32) -> NTSTATUS =
                std::mem::transmute(GetProcAddress(GetModuleHandleA(b"ntdll.dll\0".as_ptr()), b"NtMapViewOfSection\0".as_ptr()));
            let nt_unmap: unsafe extern "system" fn(HANDLE, *mut c_void) -> NTSTATUS =
                std::mem::transmute(GetProcAddress(GetModuleHandleA(b"ntdll.dll\0".as_ptr()), b"NtUnmapViewOfSection\0".as_ptr()));

            match ORIG_NTCREATESECTION {
                Some(orig) => {
                    let status = orig(section_handle, desired_access, object_attributes,
                                      maximum_size, PAGE_EXECUTE_READWRITE,
                                      allocation_attributes & !SEC_IMAGE,
                                      INVALID_HANDLE_VALUE);
                    if status >= 0 && !section_handle.is_null() {
                        let mut base: *mut c_void = std::ptr::null_mut();
                        let mut view_size: usize = 0;
                        let s = nt_map(*section_handle, CURRENT_PROCESS, &mut base, 0, 0,
                                       std::ptr::null_mut(), &mut view_size, 0, 0,
                                       PAGE_READWRITE);
                        if s >= 0 && !base.is_null() {
                            let copy_len = if G_NTDLL_MODIFIED_BYTES.len() < view_size {
                                G_NTDLL_MODIFIED_BYTES.len() } else { view_size };
                            std::ptr::copy_nonoverlapping(G_NTDLL_MODIFIED_BYTES.as_ptr(), base as *mut u8, copy_len);
                            nt_unmap(CURRENT_PROCESS, base);
                        }
                    }
                    status
                }
                None => STATUS_OBJECT_NAME_NOT_FOUND,
            }
        } else {
            match ORIG_NTCREATESECTION { Some(orig) => orig(section_handle, desired_access, object_attributes, maximum_size, section_page_protection, allocation_attributes, file_handle), None => STATUS_OBJECT_NAME_NOT_FOUND }
        }
    } else {
        match ORIG_NTCREATESECTION { Some(orig) => orig(section_handle, desired_access, object_attributes, maximum_size, section_page_protection, allocation_attributes, file_handle), None => STATUS_OBJECT_NAME_NOT_FOUND }
    }
}

unsafe extern "system" fn hooked_nt_open_section(
    section_handle: *mut HANDLE, desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if !object_attributes.is_null() {
            let oa = &*object_attributes;
            if !oa.object_name.is_null() {
                let name = &*(oa.object_name);
                if is_ntdll_file(name.buffer) {
                    return 0xC000_0022u32 as i32; // STATUS_ACCESS_DENIED
                }
            }
        }
    }
    match ORIG_NTOPENSECTION { Some(orig) => orig(section_handle, desired_access, object_attributes), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

// --- ntdll protection hooks (write-side) ---

fn addr_in_ntdll(addr: *const c_void, len: usize) -> bool {
    let a = addr as usize;
    let base = unsafe { G_NTDLL_BASE as usize };
    let end = base.saturating_add(unsafe { G_NTDLL_SIZE });
    if len == 0 { return a >= base && a < end; }
    let a_end = a.saturating_add(len);
    a < end && a_end > base
}

unsafe extern "system" fn hooked_nt_write_virtual_memory(
    process_handle: HANDLE, base_address: *mut c_void,
    buffer: *const c_void, buffer_size: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if !base_address.is_null() && !G_NTDLL_BASE.is_null() && addr_in_ntdll(base_address, buffer_size) {
            if !number_of_bytes_written.is_null() {
                *number_of_bytes_written = buffer_size;
            }
            return 0;
        }
    }
    match ORIG_NTWRITEVIRTUALMEMORY { Some(orig) => orig(process_handle, base_address, buffer, buffer_size, number_of_bytes_written), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

unsafe extern "system" fn hooked_nt_protect_virtual_memory(
    process_handle: HANDLE, base_address: *mut *mut c_void,
    region_size: *mut usize, new_protect: u32, old_protect: *mut u32,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if !base_address.is_null() && !(*base_address).is_null() && !G_NTDLL_BASE.is_null() {
            let addr = *base_address;
            let size = if !region_size.is_null() { *region_size } else { 1 };
            if addr_in_ntdll(addr, size) && (new_protect & PAGE_WRITABLE_FLAGS) != 0 {
                // Silently succeed without changing protection.
                if !old_protect.is_null() {
                    *old_protect = PAGE_EXECUTE_READ;
                }
                return 0;
            }
        }
    }
    match ORIG_NTPROTECTVIRTUALMEMORY { Some(orig) => orig(process_handle, base_address, region_size, new_protect, old_protect), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

unsafe extern "system" fn hooked_nt_map_view_of_section(
    section_handle: HANDLE, process_handle: HANDLE,
    base_address: *mut *mut c_void, zero_bits: usize, commit_size: usize,
    section_offset: *mut i64, view_size: *mut usize, inherit_disposition: u32,
    allocation_type: u32, protect: u32,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        // Block if caller explicitly requested an address within ntdll range.
        if !base_address.is_null() && !(*base_address).is_null() && !G_NTDLL_BASE.is_null() {
            if addr_in_ntdll(*base_address, 0) {
                return 0xC000_0018u32 as i32; // STATUS_CONFLICTING_ADDRESSES
            }
        }
    }
    // Call original first, then check if the resulting mapping overlaps ntdll.
    let result = match ORIG_NTMAPVIEWOFSECTION {
        Some(orig) => orig(section_handle, process_handle, base_address, zero_bits,
                           commit_size, section_offset, view_size, inherit_disposition,
                           allocation_type, protect),
        None => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    if result >= 0 && INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        let mapped_addr = if !base_address.is_null() { *base_address } else { std::ptr::null_mut() };
        let mapped_size = if !view_size.is_null() { *view_size } else { 0 };
        if !mapped_addr.is_null() && !G_NTDLL_BASE.is_null() && addr_in_ntdll(mapped_addr, mapped_size) {
            // Undo the mapping.
            let nt_unmap: unsafe extern "system" fn(HANDLE, *mut c_void) -> NTSTATUS =
                std::mem::transmute(GetProcAddress(GetModuleHandleA(b"ntdll.dll\0".as_ptr()), b"NtUnmapViewOfSection\0".as_ptr()));
            nt_unmap(process_handle, mapped_addr);
            return 0xC000_0018u32 as i32; // STATUS_CONFLICTING_ADDRESSES
        }
    }
    result
}

unsafe extern "system" fn hooked_nt_unmap_view_of_section(
    process_handle: HANDLE, base_address: *mut c_void,
) -> NTSTATUS {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if !base_address.is_null() && base_address == G_NTDLL_BASE as *mut c_void {
            return 0; // silently block unmap of ntdll
        }
    }
    match ORIG_NTUNMAPVIEWOFSECTION { Some(orig) => orig(process_handle, base_address), None => STATUS_OBJECT_NAME_NOT_FOUND }
}

// --- kernelbase hooks ---
unsafe extern "system" fn hooked_get_file_attributes_w(path: *const u16) -> u32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_FILE_ATTRIBUTES;
        }
    }
    match ORIG_GETFILEATTRIBUTESW { Some(orig) => orig(path), None => INVALID_FILE_ATTRIBUTES }
}

unsafe extern "system" fn hooked_get_file_attributes_ex_w(
    path: *const u16, level: u32, info: *mut c_void,
) -> BOOL {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return 0;
        }
    }
    match ORIG_GETFILEATTRIBUTESEXW { Some(orig) => orig(path, level, info), None => 0 }
}

unsafe extern "system" fn hooked_create_file_w(
    path: *const u16, access: u32, share: u32,
    sa: *mut c_void, creation: u32, flags: u32, tmpl: HANDLE,
) -> HANDLE {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        // Only block READ_ATTRIBUTES or GENERIC_READ access
        let is_read = (access & FILE_GENERIC_READ) != 0;
        let is_attr = (access & FILE_READ_ATTRIBUTES) != 0;
        if (is_read || is_attr) && is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    match ORIG_CREATEFILEW_HOOK { Some(orig) => orig(path, access, share, sa, creation, flags, tmpl), None => INVALID_HANDLE_VALUE }
}

unsafe extern "system" fn hooked_find_first_file_w(path: *const u16, data: *mut c_void) -> HANDLE {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    match ORIG_FINDFIRSTFILEW { Some(orig) => orig(path, data), None => INVALID_HANDLE_VALUE }
}

unsafe extern "system" fn hooked_find_first_file_ex_w(
    path: *const u16, level: u32, data: *mut c_void,
    search_op: u32, filter: *mut c_void, flags: u32,
) -> HANDLE {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    match ORIG_FINDFIRSTFILEEXW { Some(orig) => orig(path, level, data, search_op, filter, flags), None => INVALID_HANDLE_VALUE }
}

unsafe extern "system" fn hooked_search_path_w(
    path: *const u16, name: *const u16, ext: *const u16,
    buf_len: u32, buf: *mut u16, file_part: *mut *mut u16,
) -> u32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        // SearchPathW searches for a file; check both path and name+ext combo
        if !path.is_null() && is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return 0;
        }
        if !name.is_null() && is_blocked_file(name) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return 0;
        }
    }
    match ORIG_SEARCHPATHW { Some(orig) => orig(path, name, ext, buf_len, buf, file_part), None => 0 }
}

unsafe extern "system" fn hooked_load_library_w(path: *const u16) -> HANDLE {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return 0;
        }
    }
    match ORIG_LOADLIBRARYW { Some(orig) => orig(path), None => 0 }
}

unsafe extern "system" fn hooked_load_library_ex_w(path: *const u16, file: HANDLE, flags: u32) -> HANDLE {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        // Only block when LOAD_LIBRARY_AS_DATAFILE or LOAD_LIBRARY_AS_IMAGE_RESOURCE
        if (flags & (LOAD_LIBRARY_AS_DATAFILE | 0x00000020)) != 0 && is_blocked_file(path) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return 0;
        }
    }
    match ORIG_LOADLIBRARYEXW { Some(orig) => orig(path, file, flags), None => 0 }
}

// --- shlwapi hook ---
unsafe extern "system" fn hooked_path_file_exists_w(path: *const u16) -> BOOL {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            return 0; // FALSE — file does not exist
        }
    }
    match ORIG_PATHFILEEXISTSW { Some(orig) => orig(path), None => 0 }
}

// --- ucrtbase CRT hooks ---
unsafe extern "system" fn hooked_waccess(path: *const u16, mode: i32) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return -1;
        }
    }
    match ORIG_WACCESS { Some(orig) => orig(path, mode), None => -1 }
}

unsafe extern "system" fn hooked_wstat64(path: *const u16, buf: *mut c_void) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return -1;
        }
    }
    match ORIG_WSTAT64 { Some(orig) => orig(path, buf), None => -1 }
}

unsafe extern "system" fn hooked_wfopen(path: *const u16, mode: *const u16) -> *mut c_void {
    if INITIALIZED.load(Ordering::Acquire) && !SHUTTING_DOWN.load(Ordering::Acquire) {
        if is_blocked_file(path) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return std::ptr::null_mut();
        }
    }
    match ORIG_WFOPEN { Some(orig) => orig(path, mode), None => std::ptr::null_mut() }
}


// --- Initialization ---
unsafe extern "system" fn init_worker(_: *mut c_void) -> u32 {
    OutputDebugStringA(b"FileBlinder: Worker Started\0".as_ptr());
    if host_process_is_protected() { return 0; }

    // --- File-blocking init ---
    // Read blocked path from config file, init device prefixes, store self path.
    let raw_path = read_blocked_path();
    if !raw_path.is_empty() {
        G_BLOCKED_PATH_NORMALIZED = normalize_wpath(&raw_path[..raw_path.len() - 1]); // strip NUL before normalize
        let mut debug_msg = [0u8; 512];
        let prefix = b"FileBlinder: blocking path: ";
        debug_msg[..prefix.len()].copy_from_slice(prefix);
        // Copy a few chars of blocked path for debug
        let mut di = prefix.len();
        for &c in raw_path.iter().take(400) {
            if c == 0 { break; }
            if di < debug_msg.len() - 2 {
                debug_msg[di] = if c < 0x80 { c as u8 } else { b'?' };
                di += 1;
            }
        }
        debug_msg[di] = 0;
        OutputDebugStringA(debug_msg.as_ptr());
    }
    init_device_prefixes();

    // Check if child-process injection is enabled and read target filter
    {
        let child_flag_path = b"C:\\Users\\Public\\file_blinder_child.cfg\0";
        let h = CreateFileA(child_flag_path.as_ptr(), GENERIC_READ, FILE_SHARE_READ, std::ptr::null(), OPEN_EXISTING, 0, 0);
        if h != INVALID_HANDLE_VALUE {
            let mut buf = [0u8; 260];
            let mut bytes: u32 = 0;
            if ReadFile(h, buf.as_mut_ptr() as _, buf.len() as u32, &mut bytes, std::ptr::null_mut()) != 0 && bytes > 0 {
                let mut end = bytes as usize;
                while end > 0 && (buf[end - 1] == b'\r' || buf[end - 1] == b'\n' || buf[end - 1] == b' ') { end -= 1; }
                let content = &buf[..end];
                if content == b"1" || content == b"*" {
                    INJECT_CHILDREN.store(true, Ordering::Release);
                    OutputDebugStringA(b"FileBlinder: child injection ENABLED (all)\0".as_ptr());
                } else if !content.is_empty() {
                    INJECT_CHILDREN.store(true, Ordering::Release);
                    // Convert ASCII target name to lowercase wide string for matching
                    G_CHILD_TARGET = content.iter().map(|&b| {
                        if (b'A'..=b'Z').contains(&b) { (b + 0x20) as u16 }
                        else { b as u16 }
                    }).chain(std::iter::once(0)).collect();
                    OutputDebugStringA(b"FileBlinder: child injection ENABLED (targeted)\0".as_ptr());
                }
            }
            CloseHandle(h);
        }
    }

    // Store own module path for child injection
    if G_DLL_HINSTANCE != 0 {
        let mut buf = [0u16; 520];
        let n = GetModuleFileNameW(G_DLL_HINSTANCE, buf.as_mut_ptr(), buf.len() as u32);
        if n > 0 && n < buf.len() as u32 {
            G_SELF_MODULE_PATH = buf[..n as usize].to_vec();
        }
    }

    // Build "\\.\pipe\FileBlinder_<pid>\0"
    let pid = GetCurrentProcessId();
    let mut name = [0u8; 64];
    let prefix = b"\\\\.\\pipe\\FileBlinder_";
    name[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();
    let mut digits = [0u8; 10]; let mut n = pid; let mut d = 0;
    if n == 0 { digits[0] = b'0'; d = 1; }
    while n > 0 { digits[d] = b'0' + (n % 10) as u8; n /= 10; d += 1; }
    for i in 0..d { name[pos] = digits[d - 1 - i]; pos += 1; }
    name[pos] = 0;

    // Wait up to 2 s for reader to have the pipe instance ready, then connect.
    // Pipe is optional; file blocking hooks work without it.
    let _ = WaitNamedPipeA(name.as_ptr(), 2000);
    G_PIPE_HANDLE = CreateFileA(name.as_ptr(), GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, 0, 0);
    if G_PIPE_HANDLE == INVALID_HANDLE_VALUE {
        OutputDebugStringA(b"FileBlinder: Pipe Connection Failed (continuing without telemetry)\0".as_ptr());
    }

    // 1. Hook Ntdll (DLL Loads + File APIs)
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll != 0 {
        if let Some(target) = GetProcAddress(ntdll, b"LdrLoadDll\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_ldr_load_dll as _) {
                ORIG_LDRLOADDLL = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtQueryAttributesFile\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_query_attributes_file as _) {
                ORIG_NTQUERYATTRIBUTESFILE = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtQueryFullAttributesFile\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_query_full_attributes_file as _) {
                ORIG_NTQUERYFULLATTRIBUTESFILE = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtOpenFile\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_open_file as _) {
                ORIG_NTOPENFILE = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtCreateFile\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_create_file as _) {
                ORIG_NTCREATEFILE = Some(std::mem::transmute(orig));
            }
        }
        // ntdll protection hooks (read-side)
        if let Some(target) = GetProcAddress(ntdll, b"NtReadFile\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_read_file as _) {
                ORIG_NTREADFILE = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtReadFileScatter\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_read_file_scatter as _) {
                ORIG_NTREADFILESCATTER = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtCreateSection\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_create_section as _) {
                ORIG_NTCREATESECTION = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtOpenSection\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_open_section as _) {
                ORIG_NTOPENSECTION = Some(std::mem::transmute(orig));
            }
        }
        // ntdll protection hooks (write-side)
        if let Some(target) = GetProcAddress(ntdll, b"NtWriteVirtualMemory\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_write_virtual_memory as _) {
                ORIG_NTWRITEVIRTUALMEMORY = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_protect_virtual_memory as _) {
                ORIG_NTPROTECTVIRTUALMEMORY = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtMapViewOfSection\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_map_view_of_section as _) {
                ORIG_NTMAPVIEWOFSECTION = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ntdll, b"NtUnmapViewOfSection\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_nt_unmap_view_of_section as _) {
                ORIG_NTUNMAPVIEWOFSECTION = Some(std::mem::transmute(orig));
            }
        }
    }

    // 2. Hook Kernelbase (Process Spawns + File APIs)
    let kbase = GetModuleHandleA(b"kernelbase.dll\0".as_ptr());
    if kbase != 0 {
        if let Some(target) = GetProcAddress(kbase, b"CreateProcessInternalW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_create_process as _) {
                ORIG_CREATEPROCESSINTERNALW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"GetFileAttributesW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_get_file_attributes_w as _) {
                ORIG_GETFILEATTRIBUTESW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"GetFileAttributesExW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_get_file_attributes_ex_w as _) {
                ORIG_GETFILEATTRIBUTESEXW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"CreateFileW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_create_file_w as _) {
                ORIG_CREATEFILEW_HOOK = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"FindFirstFileW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_find_first_file_w as _) {
                ORIG_FINDFIRSTFILEW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"FindFirstFileExW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_find_first_file_ex_w as _) {
                ORIG_FINDFIRSTFILEEXW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"SearchPathW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_search_path_w as _) {
                ORIG_SEARCHPATHW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"LoadLibraryW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_load_library_w as _) {
                ORIG_LOADLIBRARYW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(kbase, b"LoadLibraryExW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_load_library_ex_w as _) {
                ORIG_LOADLIBRARYEXW = Some(std::mem::transmute(orig));
            }
        }
    }

    // 3. Hook SSPI / Schannel (Plaintext TLS Traffic + Host capture)
    LoadLibraryA(b"sspicli.dll\0".as_ptr());
    let sspi = GetModuleHandleA(b"sspicli.dll\0".as_ptr());
    if sspi != 0 {
        if let Some(target) = GetProcAddress(sspi, b"EncryptMessage\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_encrypt_message as _) {
                ORIG_ENCRYPTMESSAGE = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(sspi, b"DecryptMessage\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_decrypt_message as _) {
                ORIG_DECRYPTMESSAGE = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(sspi, b"InitializeSecurityContextW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_init_sec_ctx_w as _) {
                ORIG_INITSECCTXW = Some(std::mem::transmute(orig));
            }
        }
    }

    // 4. Hook WinHttp (HINTERNET-based HTTP/S — used by Invoke-WebRequest,
    //    HttpClient, modern Windows binaries).  LoadLibrary because winhttp
    //    isn't always pre-loaded into a process.
    LoadLibraryA(b"winhttp.dll\0".as_ptr());
    let winhttp = GetModuleHandleA(b"winhttp.dll\0".as_ptr());
    if winhttp != 0 {
        if let Some(target) = GetProcAddress(winhttp, b"WinHttpSendRequest\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_winhttp_send_request as _) {
                ORIG_WINHTTPSENDREQUEST = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(winhttp, b"WinHttpWriteData\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_winhttp_write_data as _) {
                ORIG_WINHTTPWRITEDATA = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(winhttp, b"WinHttpReadData\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_winhttp_read_data as _) {
                ORIG_WINHTTPREADDATA = Some(std::mem::transmute(orig));
            }
        }
    }

    // 5. Hook WinInet (legacy IE-era HTTP/S — still used by older installers,
    //    .NET 2.0-style code, and `urlmon` consumers).
    LoadLibraryA(b"wininet.dll\0".as_ptr());
    let wininet = GetModuleHandleA(b"wininet.dll\0".as_ptr());
    if wininet != 0 {
        if let Some(target) = GetProcAddress(wininet, b"HttpSendRequestW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_http_send_request_w as _) {
                ORIG_HTTPSENDREQUESTW = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(wininet, b"HttpSendRequestA\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_http_send_request_a as _) {
                ORIG_HTTPSENDREQUESTA = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(wininet, b"InternetReadFile\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_internet_read_file as _) {
                ORIG_INTERNETREADFILE = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(wininet, b"InternetWriteFile\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_internet_write_file as _) {
                ORIG_INTERNETWRITEFILE = Some(std::mem::transmute(orig));
            }
        }
    }

    // 6. Hook Winsock (raw TCP/UDP — catches everything that bypasses the
    //    HTTP wrappers: custom protocols, FTP, SMTP plaintext, redis, etc.).
    LoadLibraryA(b"ws2_32.dll\0".as_ptr());
    let ws2 = GetModuleHandleA(b"ws2_32.dll\0".as_ptr());
    if ws2 != 0 {
        if let Some(target) = GetProcAddress(ws2, b"send\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_send as _) {
                ORIG_SEND = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ws2, b"recv\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_recv as _) {
                ORIG_RECV = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ws2, b"WSASend\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_wsa_send as _) {
                ORIG_WSASEND = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ws2, b"WSARecv\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_wsa_recv as _) {
                ORIG_WSARECV = Some(std::mem::transmute(orig));
            }
        }
    }

    // 7. Hook shlwapi (PathFileExistsW)
    LoadLibraryA(b"shlwapi.dll\0".as_ptr());
    let shlwapi = GetModuleHandleA(b"shlwapi.dll\0".as_ptr());
    if shlwapi != 0 {
        if let Some(target) = GetProcAddress(shlwapi, b"PathFileExistsW\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_path_file_exists_w as _) {
                ORIG_PATHFILEEXISTSW = Some(std::mem::transmute(orig));
            }
        }
    }

    // 8. Hook ucrtbase (CRT file functions)
    LoadLibraryA(b"ucrtbase.dll\0".as_ptr());
    let ucrt = GetModuleHandleA(b"ucrtbase.dll\0".as_ptr());
    if ucrt != 0 {
        if let Some(target) = GetProcAddress(ucrt, b"_waccess\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_waccess as _) {
                ORIG_WACCESS = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ucrt, b"_wstat64\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_wstat64 as _) {
                ORIG_WSTAT64 = Some(std::mem::transmute(orig));
            }
        }
        if let Some(target) = GetProcAddress(ucrt, b"_wfopen\0".as_ptr()) {
            if let Ok(orig) = MinHook::create_hook(target as _, hooked_wfopen as _) {
                ORIG_WFOPEN = Some(std::mem::transmute(orig));
            }
        }
    }

    let _ = MinHook::enable_all_hooks();
    // Snapshot the now-patched ntdll before hooks become active.
    snapshot_ntdll();
    build_ntdll_paths();
    INITIALIZED.store(true, Ordering::Release);
    send_frame(EV_AGENT_ONLINE, 0, &[]);
    0
}

#[no_mangle]
extern "system" fn DllMain(h: HINSTANCE, r: u32, _: *mut c_void) -> BOOL {
    if r == DLL_PROCESS_ATTACH {
        unsafe {
            G_DLL_HINSTANCE = h;
            DisableThreadLibraryCalls(h);
            let t = CreateThread(std::ptr::null(), 0, Some(init_worker), std::ptr::null_mut(), 0, std::ptr::null_mut());
            if t != 0 { CloseHandle(t); }
        }
    } else if r == DLL_PROCESS_DETACH {
        SHUTTING_DOWN.store(true, Ordering::Release);
    }
    1
}
