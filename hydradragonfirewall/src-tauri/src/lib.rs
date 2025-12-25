pub mod engine;
pub mod injector;
pub mod web_filter;

use std::sync::Arc;

use crate::engine::{FirewallEngine, WhitelistEntry};
use tauri::{AppHandle, Manager, State};

pub fn run() {
    println!("DEBUG: Initializing Tauri Builder (with mod engine)...");
    
    let engine = Arc::new(FirewallEngine::new());
    
    let result = tauri::Builder::default()
        .manage(engine)
        .setup(|app| {
            let handle = app.handle().clone();
            let engine = app.state::<Arc<FirewallEngine>>();
            engine.start(handle);
            Ok(())
        })
        .run(tauri::generate_context!());

    match result {
        Ok(_) => println!("DEBUG: Tauri finished successfully."),
        Err(e) => println!("DEBUG: Tauri error: {}", e),
    }
}
