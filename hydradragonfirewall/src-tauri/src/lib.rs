pub mod engine;
pub mod injector;
pub mod web_filter;

use crate::engine::{FirewallEngine, WhitelistEntry};
use tauri::{AppHandle, Manager, State};
use std::sync::Arc;

#[tauri::command]
fn add_whitelist_entry(
    engine: State<Arc<FirewallEngine>>,
    item: String,
    reason: String,
    category: String
) {
    engine.add_whitelist_entry(item, reason, category);
}

#[tauri::command]
fn get_whitelist(engine: State<Arc<FirewallEngine>>) -> Vec<WhitelistEntry> {
    engine.whitelist.read().unwrap().clone()
}

pub fn run() {
    println!("Starting Tauri Run...");
    tauri::Builder::default()
        .setup(|app| {
            println!("Tauri Setup Hook Entered");
            let engine = Arc::new(FirewallEngine::new());
            app.manage(engine.clone());
            
            // Start engine with app handle to emit events
            engine.start(app.handle().clone());

            #[cfg(debug_assertions)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            add_whitelist_entry,
            get_whitelist
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
