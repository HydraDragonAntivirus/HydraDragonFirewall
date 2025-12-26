pub mod engine;
pub mod injector;
pub mod web_filter;

use std::sync::Arc;

use crate::engine::FirewallEngine;
use tauri::{AppHandle, Manager};

pub fn run() {
    println!("--- HydraDragon Firewall Booting (Tauri 2.0) ---");

    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            
            // Move engine initialization to a background thread to prevent main-thread stack overflow
            // and ensure the UI starts up immediately.
            std::thread::Builder::new()
                .name("engine_init".to_string())
                .stack_size(16 * 1024 * 1024) // 16MB for init thread
                .spawn(move || {
                    println!("DEBUG: Initializing Firewall Engine on background thread...");
                    let engine = Arc::new(FirewallEngine::new());
                    println!("DEBUG: Engine initialized successfully.");
                    
                    // Manage the engine state on the handle
                    handle.manage(engine.clone());
                    
                    // Start the engine loops
                    engine.start(handle);
                })
                .expect("Failed to spawn engine_init thread");

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
        Err("Firewall engine is still initializing...".to_string())
    }
}

#[tauri::command]
async fn resolve_app_decision(
    name: String,
    decision: String,
    handle: AppHandle
) -> Result<(), String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        use crate::engine::AppDecision;
        let d = match decision.to_lowercase().as_str() {
            "allow" => AppDecision::Allow,
            "block" => AppDecision::Block,
            _ => AppDecision::Pending,
        };
        
        engine.app_manager.decisions.write().unwrap().insert(name.to_lowercase(), d);
        engine.save_settings();
        Ok(())
    } else {
        Err("Firewall engine is still initializing...".to_string())
    }
}

#[tauri::command]
async fn get_settings(
    handle: AppHandle
) -> Result<crate::engine::FirewallSettings, String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        let s = engine.settings.read().unwrap();
        Ok(s.clone())
    } else {
        Err("Firewall engine is still initializing...".to_string())
    }
}
