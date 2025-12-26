use std::ffi::{c_void, CString};
use std::mem;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{BOOL, HINSTANCE, HANDLE};
use windows::Win32::Networking::WinSock::{SOCKET, SOCKADDR};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH};
use windows::Win32::Storage::FileSystem::{WriteFile, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ};
use windows::Win32::UI::WindowsAndMessaging::{HHOOK, HOOKPROC, WINDOWS_HOOK_ID};
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, WINEVENTPROC};

// Force linking to the minhook crate
extern crate minhook;

// Raw MinHook FFI (using C calling convention)
unsafe extern "C" {
    fn MH_Initialize() -> i32;
    fn MH_CreateHook(pTarget: *mut c_void, pDetour: *mut c_void, ppOriginal: *mut *mut c_void) -> i32;
    fn MH_EnableHook(pTarget: *mut c_void) -> i32;
}

// Global storage for original functions
static mut ORIGINAL_CONNECT: Option<unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32> = None;
static mut ORIGINAL_SET_WINDOWS_HOOK_EX: Option<unsafe extern "system" fn(WINDOWS_HOOK_ID, HOOKPROC, HINSTANCE, u32) -> HHOOK> = None;
static mut ORIGINAL_SET_WIN_EVENT_HOOK: Option<unsafe extern "system" fn(u32, u32, HINSTANCE, WINEVENTPROC, u32, u32, u32) -> HWINEVENTHOOK> = None;

// Helper: Send log to firewall pipe
unsafe fn send_log(msg: String) {
    let pipe_name = windows::core::s!("\\\\.\\pipe\\HydraDragonFirewall");
    
    // Explicitly use windows-rs types to avoid inference issues (HANDLE.0 check)
    unsafe {
        let handle_res = windows::Win32::Storage::FileSystem::CreateFileA(
            pipe_name,
            windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default()
        );
        
        if let Ok(handle) = handle_res {
            // INVALID_HANDLE_VALUE is -1, null handle is 0. Accessing .0 for comparison.
            if handle.0 != 0 && handle.0 != -1 {
                let msg_c = CString::new(msg).unwrap_or_default();
                let bytes = msg_c.as_bytes();
                let mut written = 0;
                let _ = WriteFile(handle, Some(bytes), Some(&mut written), None);
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
    }
}

// Detours
unsafe extern "system" fn connect_detour(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    unsafe {
        send_log(format!("🛡️ Connect call detected! Socket: {:?} Len: {}", s, namelen));
        if let Some(original) = ORIGINAL_CONNECT { original(s, name, namelen) } else { -1 }
    }
}

unsafe extern "system" fn set_windows_hook_ex_detour(id: WINDOWS_HOOK_ID, proc: HOOKPROC, hmod: HINSTANCE, tid: u32) -> HHOOK {
    unsafe {
        send_log(format!("🛡️ SetWindowsHookEx detected! ID: {:?} TID: {}", id, tid));
        if let Some(original) = ORIGINAL_SET_WINDOWS_HOOK_EX { original(id, proc, hmod, tid) } else { HHOOK::default() }
    }
}

unsafe extern "system" fn set_win_event_hook_detour(event_min: u32, event_max: u32, hmod: HINSTANCE, proc: WINEVENTPROC, pid: u32, tid: u32, flags: u32) -> HWINEVENTHOOK {
    unsafe {
        send_log(format!("🛡️ SetWinEventHook detected! PID: {} TID: {}", pid, tid));
        if let Some(original) = ORIGINAL_SET_WIN_EVENT_HOOK { original(event_min, event_max, hmod, proc, pid, tid, flags) } else { HWINEVENTHOOK::default() }
    }
}

fn initialize_hooks() {
    unsafe {
        if MH_Initialize() != 0 { return; }

        // 1. Hook Winsock Connect
        if let Ok(ws2) = LoadLibraryA(windows::core::s!("ws2_32.dll")) {
            if let Some(target) = GetProcAddress(ws2, windows::core::s!("connect")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, connect_detour as _, &mut original) == 0 {
                    ORIGINAL_CONNECT = mem::transmute::<*mut c_void, Option<unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32>>(original);
                    MH_EnableHook(target as _);
                }
            }
        }

        // 2. Hook SetWindowsHookExW
        if let Ok(user32) = LoadLibraryA(windows::core::s!("user32.dll")) {
            if let Some(target) = GetProcAddress(user32, windows::core::s!("SetWindowsHookExW")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, set_windows_hook_ex_detour as _, &mut original) == 0 {
                    let opt: Option<unsafe extern "system" fn(WINDOWS_HOOK_ID, HOOKPROC, HINSTANCE, u32) -> HHOOK> = mem::transmute(original);
                    ORIGINAL_SET_WINDOWS_HOOK_EX = opt;
                    MH_EnableHook(target as _);
                }
            }
            
            // 3. Hook SetWinEventHook
            if let Some(target) = GetProcAddress(user32, windows::core::s!("SetWinEventHook")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, set_win_event_hook_detour as _, &mut original) == 0 {
                    let opt: Option<unsafe extern "system" fn(u32, u32, HINSTANCE, WINEVENTPROC, u32, u32, u32) -> HWINEVENTHOOK> = mem::transmute(original);
                    ORIGINAL_SET_WIN_EVENT_HOOK = opt;
                    MH_EnableHook(target as _);
                }
            }
        }
        
        send_log("🛡️ EDR Hooks (Connect, HookEx, EventHook) active!".into());
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, reserved: *mut c_void) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| {
            thread::sleep(Duration::from_millis(500));
            initialize_hooks();
        });
    }
    BOOL::from(true)
}
