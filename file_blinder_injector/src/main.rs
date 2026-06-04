use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, ResumeThread, SuspendThread,
    WaitForSingleObject,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, PROCESS_VM_READ,
};

// CreateRemoteThread not exported by windows-sys 0.52; declare manually.
extern "system" {
    fn CreateRemoteThread(
        hProcess: HANDLE,
        lpThreadAttributes: *const core::ffi::c_void,
        dwStackSize: usize,
        lpStartAddress: *mut core::ffi::c_void,
        lpParameter: *mut core::ffi::c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> HANDLE;
}

// CreateProcessW — for spawning new processes suspended.
#[repr(C)]
struct ProcessInfo {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: u32,
    dwThreadId: u32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
}

extern "system" {
    fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut core::ffi::c_void,
        lpThreadAttributes: *mut core::ffi::c_void,
        bInheritHandles: i32,
        dwCreationFlags: u32,
        lpEnvironment: *mut core::ffi::c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut StartupInfoW,
        lpProcessInformation: *mut ProcessInfo,
    ) -> i32;
}

const THREAD_SUSPEND_RESUME: u32 = 0x0002;
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
const CREATE_SUSPENDED_FLAG: u32 = 0x00000004;

const DEFAULT_DLL: &str = r".\file_blinder_dll.dll";

fn print_usage(args: &[String]) {
    eprintln!("Usage:");
    eprintln!("  Inject into PID:   {} --pid <PID> [--dll <DllPath>] [--block <Path>] [--child]", args[0]);
    eprintln!("  Spawn and inject:  {} --spawn <ExePath> [--dll <DllPath>] [--block <Path>] [--child] [--cmdline <args>]", args[0]);
    eprintln!("");
    eprintln!("  --dll     Path to file_blinder_dll.dll (default: {})", DEFAULT_DLL);
    eprintln!("  --block   Full path of file to hide from target process");
    eprintln!("  --child   Also inject into child processes recursively");
    eprintln!("  --cmdline Command-line arguments for the spawned process (--spawn only)");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args);
        return;
    }

    let is_spawn = args[1] == "--spawn";
    let is_pid   = args[1] == "--pid";

    if !is_spawn && !is_pid {
        eprintln!("[-] Unknown option: {}", args[1]);
        print_usage(&args);
        return;
    }

    let mut i = 2; // start after --spawn or --pid

    // For --spawn, the first positional is the exe path
    // For --pid, the first positional is the PID
    let spawn_exe: Option<String> = if is_spawn {
        if args.len() <= i { eprintln!("[-] --spawn requires <ExePath>"); return; }
        let exe = args[i].clone();
        i += 1;
        Some(exe)
    } else {
        None
    };

    let pid: Option<u32> = if !is_spawn {
        if args.len() <= i { eprintln!("[-] --pid requires <PID>"); return; }
        let p = args[i].parse().expect("Invalid PID");
        i += 1;
        Some(p)
    } else {
        None
    };

    let (block, child, dll_override, cmdline) = parse_optional_args(&args, &mut i);
    let dll = dll_override.unwrap_or_else(|| DEFAULT_DLL.to_string());
    let dll_path = format!("{}\0", dll);

    if let Some(ref path) = block { write_block_config(path); }
    if child { write_child_flag(); }

    if is_spawn {
        let exe = spawn_exe.unwrap();
        println!("[*] Spawning '{}' suspended...", exe);
        match spawn_and_inject(&exe, &dll_path, cmdline.as_deref()) {
            Ok(child_pid) => println!("[+] Process spawned (PID {}) and injected successfully!", child_pid),
            Err(e) => eprintln!("[-] Spawn/inject failed: {}", e),
        }
    } else {
        let p = pid.unwrap();
        println!("[*] Injecting DLL '{}' into PID: {}", dll, p);
        match inject_dll_suspended(p, &dll_path) {
            Ok(()) => println!("[+] Injection successful!"),
            Err(e) => eprintln!("[-] Injection failed: {}", e),
        }
    }
}

fn parse_optional_args(args: &[String], i: &mut usize) -> (Option<String>, bool, Option<String>, Option<String>) {
    let mut block_path = None;
    let mut child = false;
    let mut dll_path = None;
    let mut cmdline = None;
    while *i < args.len() {
        if args[*i] == "--block" && *i + 1 < args.len() {
            block_path = Some(args[*i + 1].clone());
            *i += 2;
        } else if args[*i] == "--dll" && *i + 1 < args.len() {
            dll_path = Some(args[*i + 1].clone());
            *i += 2;
        } else if args[*i] == "--cmdline" && *i + 1 < args.len() {
            cmdline = Some(args[*i + 1].clone());
            *i += 2;
        } else if args[*i] == "--child" {
            child = true;
            *i += 1;
        } else {
            break;
        }
    }
    (block_path, child, dll_path, cmdline)
}

fn write_child_flag() {
    write_child_config("1");
}

fn write_child_config(target: &str) {
    let cfg_file = "C:\\Users\\Public\\file_blinder_child.cfg";
    std::fs::write(cfg_file, target).ok();
    if target == "1" {
        println!("[+] Child injection enabled (all children)");
    } else {
        println!("[+] Child injection enabled (target: {})", target);
    }
}

/// Spawn a new process in suspended state, inject the DLL, then resume.
fn spawn_and_inject(exe_path: &str, dll_path: &str, cmdline_args: Option<&str>) -> Result<u32, String> {
    unsafe {
        // Build the full command line: "exe_path cmdline_args"
        let cmd = if let Some(args) = cmdline_args {
            format!("\"{}\" {}", exe_path, args)
        } else {
            format!("\"{}\"", exe_path)
        };
        let cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

        let mut si: StartupInfoW = std::mem::zeroed();
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;

        let mut pi: ProcessInfo = std::mem::zeroed();

        let ok = CreateProcessW(
            std::ptr::null(),          // lpApplicationName
            cmd_wide.as_ptr() as *mut u16, // lpCommandLine (mutable)
            std::ptr::null_mut(),      // lpProcessAttributes
            std::ptr::null_mut(),      // lpThreadAttributes
            0,                         // bInheritHandles
            CREATE_SUSPENDED_FLAG,     // dwCreationFlags — suspended
            std::ptr::null_mut(),      // lpEnvironment
            std::ptr::null(),          // lpCurrentDirectory
            &mut si,                   // lpStartupInfo
            &mut pi,                   // lpProcessInformation
        );

        if ok == 0 {
            return Err(format!("CreateProcessW failed (error: {})", GetLastError()));
        }

        let child_pid = pi.dwProcessId;
        println!("[*] Child created suspended (PID {})", child_pid);

        // Inject DLL (process is already suspended, main thread is the only thread)
        inject_into_handle(pi.hProcess, dll_path)?;

        // Resume the main thread
        println!("[*] Resuming child process...");
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        Ok(child_pid)
    }
}

/// Inject DLL into an already-opened process handle.
unsafe fn inject_into_handle(h_process: HANDLE, dll_path: &str) -> Result<(), String> {
    let path_len = dll_path.len();
    let alloc_addr = VirtualAllocEx(
        h_process,
        ptr::null(),
        path_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if alloc_addr.is_null() {
        return Err("VirtualAllocEx failed".to_string());
    }

    let mut bytes_written: usize = 0;
    let write_ok = WriteProcessMemory(
        h_process,
        alloc_addr,
        dll_path.as_ptr() as _,
        path_len,
        &mut bytes_written,
    );
    if write_ok == 0 {
        VirtualFreeEx(h_process, alloc_addr, 0, MEM_RELEASE);
        return Err("WriteProcessMemory failed".to_string());
    }

    let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    let load_library = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr());
    if load_library.is_none() {
        VirtualFreeEx(h_process, alloc_addr, 0, MEM_RELEASE);
        return Err("GetProcAddress(LoadLibraryA) failed".to_string());
    }

    let h_thread = CreateRemoteThread(
        h_process,
        ptr::null(),
        0,
        load_library.unwrap() as *mut core::ffi::c_void,
        alloc_addr,
        0,
        ptr::null_mut(),
    );
    if h_thread == 0 {
        VirtualFreeEx(h_process, alloc_addr, 0, MEM_RELEASE);
        return Err("CreateRemoteThread failed".to_string());
    }

    println!("[*] Waiting for DLL initialization...");
    WaitForSingleObject(h_thread, 15000);
    CloseHandle(h_thread);
    VirtualFreeEx(h_process, alloc_addr, 0, MEM_RELEASE);
    Ok(())
}

/// Write the blocked file path to the well-known config location.
fn write_block_config(path: &str) {
    let cfg_dir = "C:\\Users\\Public";
    let cfg_file = format!("{}\\file_blinder_block.cfg", cfg_dir);

    // Ensure the directory exists
    std::fs::create_dir_all(cfg_dir).ok();

    match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&cfg_file)
    {
        Ok(mut f) => {
            f.write_all(path.as_bytes()).ok();
            f.write_all(b"\r\n").ok();
            println!("[+] Block config written: {}", cfg_file);
        }
        Err(e) => {
            eprintln!("[-] Failed to write block config: {}", e);
        }
    }
}

/// Inject DLL into an existing process using suspend/inject/resume pattern.
fn inject_dll_suspended(pid: u32, dll_path: &str) -> Result<(), String> {
    unsafe {
        let h_process = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
                | PROCESS_SUSPEND_RESUME,
            0,
            pid,
        );
        if h_process == 0 {
            return Err(format!("Failed to open process {} (error: {})", pid, GetLastError()));
        }

        // Enumerate and suspend all threads
        let thread_ids = enumerate_threads(pid)?;
        println!("[*] Suspending {} threads in PID {}", thread_ids.len(), pid);

        let mut thread_handles: Vec<HANDLE> = Vec::new();
        for &tid in &thread_ids {
            let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, tid);
            if h_thread != 0 {
                SuspendThread(h_thread);
                thread_handles.push(h_thread);
            }
        }

        // Inject
        let result = inject_into_handle(h_process, dll_path);

        // Resume all threads regardless of injection success/failure
        println!("[*] Resuming {} threads", thread_handles.len());
        cleanup_threads(&thread_handles);
        CloseHandle(h_process);

        result
    }
}

/// Enumerate thread IDs belonging to the target PID.
unsafe fn enumerate_threads(pid: u32) -> Result<Vec<u32>, String> {
    let snapshot = CreateToolhelp32Snapshot(0x00000004, 0); // TH32CS_SNAPTHREAD
    if snapshot == INVALID_HANDLE_VALUE {
        return Err("CreateToolhelp32Snapshot failed".to_string());
    }

    let mut ids = Vec::new();
    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    if Thread32First(snapshot, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == pid {
                ids.push(te.th32ThreadID);
            }
            if Thread32Next(snapshot, &mut te) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
    Ok(ids)
}

/// Resume all suspended threads and close their handles.
unsafe fn cleanup_threads(handles: &[HANDLE]) {
    for &h in handles {
        if h != 0 {
            ResumeThread(h);
            CloseHandle(h);
        }
    }
}
