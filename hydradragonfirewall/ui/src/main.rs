use leptos::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    async fn listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> JsValue;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WhitelistArgs {
    item: String,
    reason: String,
    category: String,
}

#[component]
pub fn App() -> impl IntoView {
    let (logs, set_logs) = create_signal(Vec::<LogEntry>::new());
    let (blocked_count, set_blocked_count) = create_signal(0);
    let (threats_count, set_threats_count) = create_signal(0);
    let (allowed_count, set_allowed_count) = create_signal(0);
    let (total_count, set_total_count) = create_signal(0);
    
    // Modal State
    let (show_modal, set_show_modal) = create_signal(false);
    let (wl_item, set_wl_item) = create_signal(String::new());
    let (wl_category, set_wl_category) = create_signal("Trusted".to_string());
    let (wl_reason, set_wl_reason) = create_signal(String::new());

    // Setup Event Listener
    create_effect(move |_| {
        let closure = Closure::wrap(Box::new(move |event: JsValue| {
             if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                 if let Some(payload_obj) = payload.get("payload") {
                     if let Ok(entry) = serde_json::from_value::<LogEntry>(payload_obj.clone()) {
                        set_logs.update(|l: &mut Vec<LogEntry>| {
                            l.push(entry.clone());
                            if l.len() > 100 { l.remove(0); }
                        });
                        
                        set_total_count.update(|n| *n += 1);
                        match entry.level {
                            LogLevel::Warning | LogLevel::Error => {
                                if entry.message.contains("Blocking") {
                                    set_blocked_count.update(|n| *n += 1);
                                }
                                if entry.message.contains("Malicious") {
                                    set_threats_count.update(|n| *n += 1);
                                }
                            },
                            _ => set_allowed_count.update(|n| *n += 1),
                        }
                     }
                 }
             }
        }) as Box<dyn FnMut(JsValue)>);
        
        spawn_local(async move {
            let _ = listen("log", &closure).await;
            closure.forget();
        });
    });

    let submit_whitelist = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        spawn_local(async move {
            let args = WhitelistArgs {
                item: wl_item.get(),
                reason: wl_reason.get(),
                category: wl_category.get(),
            };
            let args_js = serde_wasm_bindgen::to_value(&args).unwrap();
            
            let _ = invoke("add_whitelist_entry", args_js).await;
            set_show_modal.set(false);
            set_wl_item.set(String::new());
            set_wl_reason.set(String::new());
        });
    };

    view! {
        <div class="app-container">
            <aside>
                <div class="logo-area">
                    <div class="logo-icon"></div>
                    <span class="logo-text">"HYDRADRAGON"</span>
                </div>
                <nav>
                    <a href="#" class="nav-item active">"Dashboard"</a>
                    <a href="#" class="nav-item">"Protection Rules"</a>
                    <a href="#" class="nav-item">"Network Logs"</a>
                    <a href="#" class="nav-item">"Settings"</a>
                </nav>
                <div style="margin-top: auto">
                    <button class="btn-primary" style="width: 100%" on:click=move |_| set_show_modal.set(true)>
                        "+ WHITELIST"
                    </button>
                </div>
            </aside>

            <main>
                <header style="display: flex; justify-content: space-between; align-items: center">
                    <h2 style="margin: 0; font-weight: 800; font-size: 28px">"Security Overview"</h2>
                    <span style="color: var(--accent-green); font-weight: 600; font-size: 14px">
                        "● SYSTEM SECURE"
                    </span>
                </header>

                <div class="stats-grid">
                    <div class="glass-card stat-item">
                        <h4>"Total Traffic"</h4>
                        <div class="stat-value">{move || total_count.get()}</div>
                    </div>
                    <div class="glass-card stat-item">
                        <h4>"Blocked"</h4>
                        <div class="stat-value" style="color: var(--accent-red)">{move || blocked_count.get()}</div>
                    </div>
                    <div class="glass-card stat-item" style="border-right: 4px solid var(--accent-yellow)">
                        <h4>"Threats"</h4>
                        <div class="stat-value" style="color: var(--accent-yellow)">{move || threats_count.get()}</div>
                    </div>
                    <div class="glass-card stat-item">
                        <h4>"Safe Requests"</h4>
                        <div class="stat-value" style="color: var(--accent-green)">{move || allowed_count.get()}</div>
                    </div>
                </div>

                <div class="glass-card logs-section">
                    <div class="section-header">
                        <h3 style="margin: 0; font-size: 16px; font-weight: 700">"Real-time Intelligence"</h3>
                        <span style="font-size: 12px; color: var(--text-muted)">"Scanning Network Adapters..."</span>
                    </div>
                    <div class="logs-viewport">
                        <For
                            each=move || logs.get()
                            key=|log| log.id.clone()
                            children=move |log| {
                                let level_class = match log.level {
                                    LogLevel::Info => "lvl-info",
                                    LogLevel::Success => "lvl-success",
                                    LogLevel::Warning => "lvl-warning",
                                    LogLevel::Error => "lvl-error",
                                    _ => "lvl-info",
                                };
                                view! {
                                    <div class={format!("log-row {}", level_class)}>
                                        <span class="log-time">"[" {log.timestamp % 100000} "]"</span>
                                        <span class="log-msg">{log.message}</span>
                                    </div>
                                }
                            }
                        />
                    </div>
                </div>
            </main>

            <div class={move || if show_modal.get() { "modal-overlay open" } else { "modal-overlay" }}>
                <div class="glass-modal">
                    <h2 style="margin-top: 0">"Whitelist Request"</h2>
                    <form on:submit=submit_whitelist>
                        <div class="input-group">
                            <label>"TARGET IP / DOMAIN"</label>
                            <input type="text" required placeholder="e.g. cloudflare.com"
                                   on:input=move |ev| set_wl_item.set(event_target_value(&ev))
                                   prop:value=wl_item
                            />
                        </div>
                        <div class="input-group">
                            <label>"SECURITY CATEGORY"</label>
                            <select on:change=move |ev| set_wl_category.set(event_target_value(&ev)) prop:value=wl_category>
                                <option value="Trusted">"Business / Trusted"</option>
                                <option value="Development">"Development Lab"</option>
                                <option value="Gaming">"Gaming / Latency Critical"</option>
                                <option value="Other">"General Override"</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>"JUSTIFICATION"</label>
                            <input type="text" required placeholder="Reason for bypass..."
                                   on:input=move |ev| set_wl_reason.set(event_target_value(&ev))
                                   prop:value=wl_reason
                            />
                        </div>
                        <div style="display: flex; gap: 15px; margin-top: 30px">
                            <button type="button" class="btn-primary" 
                                    style="background: #2a2d35; box-shadow: none; flex: 1"
                                    on:click=move |_| set_show_modal.set(false)>
                                "DISMISS"
                            </button>
                            <button type="submit" class="btn-primary" style="flex: 2">
                                "AUTHORIZE ACCESS"
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    }
}

pub fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}
