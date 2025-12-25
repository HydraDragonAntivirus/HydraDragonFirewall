pub mod engine;
pub mod injector;
pub mod web_filter;

// use crate::engine::{FirewallEngine, WhitelistEntry};
// use tauri::{AppHandle, Manager, State};
// use std::sync::Arc;

pub fn run() {
    println!("DEBUG: Initializing Tauri Builder (with mod engine)...");
    
    let result = tauri::Builder::default()
        .run(tauri::generate_context!());

    match result {
        Ok(_) => println!("DEBUG: Tauri finished successfully."),
        Err(e) => println!("DEBUG: Tauri error: {}", e),
    }
}
