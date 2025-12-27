pub mod engine;
pub mod injector;
pub mod web_filter;
pub mod windivert_api;

use std::sync::Arc;

// use crate::engine::FirewallEngine;
use tauri::{AppHandle, Manager};

#[tauri::command]
async fn add_whitelist_entry(
    _item: String,
    _reason: String,
    _category: String,
    _handle: AppHandle
) -> Result<(), String> {
    // Mock
    Ok(())
}

#[tauri::command]
async fn resolve_app_decision(
    _name: String,
    _decision: String,
    _handle: AppHandle
) -> Result<(), String> {
    // Mock
    Ok(())
}

#[tauri::command]
async fn get_settings(
    _handle: AppHandle
) -> Result<(), String> {
    // Mock
    Err("Not implemented".to_string())
}

pub fn run() {
    println!("DEBUG: hydradragonfirewall::run() entered");
    println!("--- HydraDragon Firewall Booting (Tauri 2.0) ---");

    println!("DEBUG: Initializing tauri::Builder...");
    let builder = tauri::Builder::default();
    println!("DEBUG: tauri::Builder created.");

    builder
        .setup(|app| {
            println!("DEBUG: Entering setup closure...");
            // let handle = app.handle().clone();
            
            // Engine init commented out for isolation
            /*
            std::thread::Builder::new()
                .name("engine_init".to_string())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                     // ...
                })
                .expect("Failed to spawn engine_init thread");
            */

            println!("DEBUG: setup closure finished.");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            add_whitelist_entry,
            resolve_app_decision,
            get_settings
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
