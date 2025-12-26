// pub mod engine;
pub mod injector;
pub mod web_filter;

use std::sync::Arc;

// use crate::engine::FirewallEngine;
use tauri::{AppHandle, Manager};

#[tauri::command]
async fn add_whitelist_entry(
    item: String,
    reason: String,
    category: String,
    handle: AppHandle
) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
async fn resolve_app_decision(
    name: String,
    decision: String,
    handle: AppHandle
) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
async fn get_settings(
    handle: tauri::AppHandle
) -> Result<(), String> {
    Err("Not implemented".to_string())
}

pub fn run() {
    println!("DEBUG: hydradragonfirewall::run() entered");
    println!("--- HydraDragon Firewall Booting (Tauri 2.0) ---");

    println!("DEBUG: Initializing tauri::Builder...");
    // println!("DEBUG: Size of tauri::Builder: {} bytes", std::mem::size_of::<tauri::Builder<tauri::Wry>>());
    let builder = tauri::Builder::default();
    println!("DEBUG: tauri::Builder created.");

    builder
        .setup(|app| {
            println!("DEBUG: Entering setup closure...");
            let _handle = app.handle().clone();
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
