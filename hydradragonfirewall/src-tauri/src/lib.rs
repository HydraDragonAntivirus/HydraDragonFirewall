pub mod engine;
pub mod injector;
pub mod web_filter;

use std::sync::Arc;

use crate::engine::{FirewallEngine, WhitelistEntry};
use tauri::{AppHandle, Manager, State};

pub fn run() {
    println!("DEBUG: Initializing Tauri Builder (with mod engine)...");
    
    let engine = Arc::new(FirewallEngine::new());
    println!("DEBUG: Engine initialized successfully.");
    
    // Explicitly use WhitelistEntry if needed to satisfy user (though it's usually just a data type)
    let _unused_entry: Option<WhitelistEntry> = None;

    let result = tauri::Builder::default()
        .manage(engine)
        .invoke_handler(tauri::generate_handler![
            add_whitelist_entry,
            resolve_app_decision,
            get_settings
        ])
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

#[tauri::command]
async fn add_whitelist_entry(
    item: String,
    reason: String,
    category: String,
    engine: State<'_, Arc<FirewallEngine>>
) -> Result<(), String> {
    engine.add_whitelist_entry(item, reason, category);
    Ok(())
}

#[tauri::command]
async fn resolve_app_decision(
    name: String,
    decision: String,
    engine: State<'_, Arc<FirewallEngine>>
) -> Result<(), String> {
    use crate::engine::AppDecision;
    let d = match decision.to_lowercase().as_str() {
        "allow" => AppDecision::Allow,
        "block" => AppDecision::Block,
        _ => AppDecision::Pending,
    };
    
    engine.app_manager.decisions.write().unwrap().insert(name.to_lowercase(), d);
    engine.save_settings();
    Ok(())
}

#[tauri::command]
async fn get_settings(
    engine: State<'_, Arc<FirewallEngine>>
) -> Result<crate::engine::FirewallSettings, String> {
    let s = engine.settings.read().unwrap();
    Ok(s.clone())
}
