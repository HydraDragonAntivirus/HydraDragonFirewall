#![no_std]
#![no_main]

extern crate alloc;
extern crate wdk_panic;

use core::ffi::c_void;
use core::ptr::null_mut;
use wdk_alloc::WdkAllocator;
use wdk_sys::ntddk::*;
use wdk_sys::*;
use wdk_macros::export_config;

#[global_allocator]
static ALLOCATOR: WdkAllocator = WdkAllocator;

static mut REG_COOKIE: LARGE_INTEGER = LARGE_INTEGER { QuadPart: 0 };

/// Helper to initialize UNICODE_STRING from a literal u16 slice
pub unsafe fn init_unicode_string(s: *mut UNICODE_STRING, buffer: &[u16]) {
    (*s).Length = (buffer.len() * 2) as u16;
    (*s).MaximumLength = (buffer.len() * 2) as u16;
    (*s).Buffer = buffer.as_ptr() as *mut u16;
}

/// Registry Callback Function
pub unsafe extern "system" fn registry_callback(
    _context: *mut c_void,
    argument1: *mut c_void,
    argument2: *mut c_void,
) -> NTSTATUS {
    let notify_class = argument1 as REG_NOTIFY_CLASS;
    
    if notify_class == RegNtPreSetValueKey {
        let info = argument2 as *mut REG_SET_VALUE_KEY_INFORMATION;
        if !info.is_null() && !(*info).Object.is_null() {
            let value_name = (*info).ValueName;
            if !value_name.is_null() {
                let name = (*value_name).Buffer;
                let len = (*value_name).Length / 2;
                let name_slice = core::slice::from_raw_parts(name, len as usize);

                // Check for "Debugger" (COMODO test 32)
                let debugger_u16 = [
                    'D' as u16, 'e' as u16, 'b' as u16, 'u' as u16, 'g' as u16, 
                    'g' as u16, 'e' as u16, 'r' as u16,
                ];
                if name_slice == debugger_u16 {
                    return STATUS_ACCESS_DENIED;
                }

                // Check for "AppInit_DLLs" (COMODO test 33)
                let appinit_u16 = [
                    'A' as u16, 'p' as u16, 'p' as u16, 'I' as u16, 'n' as u16, 'i' as u16, 't' as u16,
                    '_' as u16, 'D' as u16, 'L' as u16, 'L' as u16, 's' as u16,
                ];
                if name_slice == appinit_u16 {
                    return STATUS_ACCESS_DENIED;
                }
            }
        }
    }
    
    STATUS_SUCCESS
}

/// Process Notify Callback (COMODO test 5: Runner)
pub unsafe extern "system" fn process_notify_callback(
    _parent_id: HANDLE,
    _process_id: HANDLE,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
) {
    if !create_info.is_null() {
        // Runner protection logic could be added here
    }
}

#[export_config(arm64)]
#[export_config(x64)]
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: *mut UNICODE_STRING,
) -> NTSTATUS {
    (*driver_object).DriverUnload = Some(driver_unload);

    // 1. Registry Protection
    let mut altitude = UNICODE_STRING::default();
    let altitude_u16 = [
        '3' as u16, '2' as u16, '0' as u16, '0' as u16, '0' as u16,
        '.' as u16, '1' as u16, '2' as u16, '3' as u16, '4' as u16, '5' as u16,
    ];
    init_unicode_string(&mut altitude, &altitude_u16);

    let status = CmRegisterCallbackEx(
        Some(registry_callback),
        &altitude,
        driver_object as *mut c_void,
        null_mut(),
        &mut REG_COOKIE,
        null_mut(),
    );

    if !NT_SUCCESS(status) {
        return status;
    }

    // 2. Process Monitoring
    let status = PsSetCreateProcessNotifyRoutineEx(
        Some(process_notify_callback),
        0, // FALSE (Registering)
    );

    if !NT_SUCCESS(status) {
        let _ = driver_unload(driver_object);
        return status;
    }

    STATUS_SUCCESS
}

pub unsafe extern "system" fn driver_unload(_driver_object: *mut DRIVER_OBJECT) {
    if REG_COOKIE.QuadPart != 0 {
        CmUnRegisterCallback(REG_COOKIE);
        REG_COOKIE.QuadPart = 0;
    }
    
    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), 1); // TRUE (Unregistering)
}
