pub mod engine;
pub mod injector;
pub mod web_filter;

use std::sync::Arc;

use crate::engine::{FirewallEngine, WhitelistEntry};
use tauri::{AppHandle, Manager, State};

pub fn run() {
    println!("DEBUG: Initializing Tauri Builder (with mod engine)...");
    
    let engine = Arc::new(FirewallEngine::new());
    
    // Explicitly use WhitelistEntry if needed to satisfy user (though it's usually just a data type)
    let _unused_entry: Option<WhitelistEntry> = None;

    let result = tauri::Builder::default()
        .manage(engine)
        .setup(|app: &mut tauri::App| {
            let handle: AppHandle = app.handle().clone();
            let engine: State<Arc<FirewallEngine>> = app.state();
            engine.start(handle);
            Ok(())
        })
        .run(tauri::generate_context!());

    match result {
        Ok(_) => println!("DEBUG: Tauri finished successfully."),
        Err(e) => println!("DEBUG: Tauri error: {}", e),
    }
}
