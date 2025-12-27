pub mod engine;
pub mod injector;
pub mod web_filter;
pub mod windivert_api;

use std::sync::Arc;
use crate::engine::FirewallEngine;
use tauri::{AppHandle, Manager, Runtime};

#[tauri::command]
async fn add_whitelist_entry(
    item: String,
    reason: String,
    category: String,
    handle: AppHandle
) -> Result<(), String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        engine.add_whitelist_entry(item, reason, category);
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn resolve_app_decision(
    name: String,
    decision: String,
    handle: AppHandle
) -> Result<(), String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        engine.resolve_app_decision(name, decision);
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_settings<R: Runtime>(
    handle: AppHandle<R>
) -> Result<crate::engine::FirewallSettings, String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        Ok(engine.get_settings())
    } else {
        Err("Engine not initialized".to_string())
    }
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
            let handle = app.handle().clone();
            
            // Re-enabling Engine Initialization
            std::thread::Builder::new()
                .name("engine_init".to_string())
                .spawn(move || {
                    println!("DEBUG: FirewallEngine::new() starting...");
                    let engine = Arc::new(FirewallEngine::new());
                    println!("DEBUG: FirewallEngine::new() finished.");
                    
                    engine.start(handle.clone());
                    handle.manage(engine);
                    println!("DEBUG: FirewallEngine managed and started.");
                })
                .expect("Failed to spawn engine_init thread");

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
