use std::ffi::{c_void, CString};
use std::mem;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{BOOL, HINSTANCE, HANDLE};
use windows::Win32::Networking::WinSock::{SOCKET, SOCKADDR};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH};
use windows::Win32::Storage::FileSystem::{CreateFileA, WriteFile, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ};

// Raw MinHook FFI
// We link to the minhook static library provided by the crate
#[link(name = "minhook")]
extern "system" {
    fn MH_Initialize() -> i32;
    fn MH_CreateHook(pTarget: *mut c_void, pDetour: *mut c_void, ppOriginal: *mut *mut c_void) -> i32;
    fn MH_EnableHook(pTarget: *mut c_void) -> i32;
}

// Global storage for original function
static mut ORIGINAL_CONNECT: Option<unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32> = None;

// Helper: Send log to firewall pipe
unsafe fn send_log(msg: String) {
    let pipe_name = windows::core::s!("\\\\.\\pipe\\HydraDragonFirewall");
    // Connect to pipe
    
    let handle_res: windows::core::Result<HANDLE> = CreateFileA(
        pipe_name,
        FILE_GENERIC_WRITE,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None
    );
    
    if let Ok(handle) = handle_res {
        if !handle.is_invalid() {
            let msg_c = CString::new(msg).unwrap_or_default();
            let bytes = msg_c.as_bytes();
            let mut written = 0;
            let _ = WriteFile(handle, Some(bytes), Some(&mut written), None);
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }
}

// Detour function for 'connect'
unsafe extern "system" fn connect_detour(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    send_log(format!("Connect call detected! Socket: {:?} Len: {}", s, namelen));
    
    // Call original
    if let Some(original) = ORIGINAL_CONNECT {
        original(s, name, namelen)
    } else {
        -1 
    }
}

fn initialize_hooks() {
    unsafe {
        // Initialize MinHook
        if MH_Initialize() != 0 {
             send_log("MH_Initialize failed".into());
             return;
        }

        let ws2_name = windows::core::s!("ws2_32.dll");
        if let Ok(ws2) = LoadLibraryA(ws2_name) {
            let connect_name = windows::core::s!("connect");
            if let Some(target) = GetProcAddress(ws2, connect_name) {
                let target_ptr = target as *mut c_void;
                let detour_ptr = connect_detour as *mut c_void;
                let mut original_ptr: *mut c_void = ptr::null_mut();
                
                // Create Hook
                if MH_CreateHook(target_ptr, detour_ptr, &mut original_ptr) == 0 {
                    if !original_ptr.is_null() {
                        ORIGINAL_CONNECT = Some(mem::transmute(original_ptr));
                    }
                    
                    // Enable Hook
                    MH_EnableHook(target_ptr);
                    
                    send_log("Connect hook installed successfully".into());
                } else {
                    send_log("MH_CreateHook failed".into());
                }
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn DllMain(_dll_module: HINSTANCE, call_reason: u32, _reserved: *mut c_void) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            thread::spawn(|| {
                // Sleep to avoid Loader Lock deadlocks
                thread::sleep(Duration::from_millis(100));
                initialize_hooks();
            });
        }
        _ => {}
    }
    BOOL::from(true)
}
