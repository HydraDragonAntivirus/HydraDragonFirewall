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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LogEntry {
    timestamp: u64,
    level: String,
    message: String,
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
                        match entry.level.as_str() {
                            "Warning" | "Error" => {
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
        <header>
            <h1>"HydraDragon Firewall"</h1>
            <div>
                <button class="btn" on:click=move |_| set_show_modal.set(true)>"+ Whitelist"</button>
            </div>
        </header>

        <div class="dashboard-grid">
            <div class="stat-card">
                <h3>"Total Packets"</h3>
                <div class="value" id="stat-total">{move || total_count.get()}</div>
            </div>
            <div class="stat-card">
                <h3>"Blocked"</h3>
                <div class="value" id="stat-blocked" style="color: var(--accent-red)">{move || blocked_count.get()}</div>
            </div>
            <div class="stat-card">
                <h3>"Threats"</h3>
                <div class="value" id="stat-threats" style="color: var(--warning)">{move || threats_count.get()}</div>
            </div>
            <div class="stat-card">
                <h3>"Allowed"</h3>
                <div class="value" id="stat-allowed" style="color: var(--success)">{move || allowed_count.get()}</div>
            </div>
        </div>

        <div class="logs-container">
            <div class="logs-header">
                <h2>"Live Traffic Logs"</h2>
                <span style="font-size: 12px; color: var(--text-secondary)">"Real-time Event Stream"</span>
            </div>
            <div class="logs-content">
                <For
                    each=move || logs.get()
                    key=|log| log.timestamp
                    children=move |log| {
                        let level_class = match log.level.as_str() {
                            "Info" => "log-info",
                            "Success" => "log-success",
                            "Warning" => "log-warning",
                            "Error" => "log-error",
                            _ => "log-info"
                        };
                        view! {
                            <div class={format!("log-entry {}", level_class)}>
                                <span class="log-time">"[" {log.timestamp} "]"</span>
                                <span class="log-message">{log.message}</span>
                            </div>
                        }
                    }
                />
            </div>
        </div>

        <div class={move || if show_modal.get() { "modal active" } else { "modal" }}>
            <div class="modal-content">
                <h2>"Add to Whitelist"</h2>
                <form on:submit=submit_whitelist>
                    <div class="form-group">
                        <label>"IP Address or Domain"</label>
                        <input type="text" required placeholder="e.g., 192.168.1.5"
                               on:input=move |ev| set_wl_item.set(event_target_value(&ev))
                               prop:value=wl_item
                        />
                    </div>
                    <div class="form-group">
                        <label>"Category"</label>
                        <select on:change=move |ev| set_wl_category.set(event_target_value(&ev)) prop:value=wl_category>
                            <option value="Trusted">"Trusted Device"</option>
                            <option value="Work">"Work Related"</option>
                            <option value="Gaming">"Gaming Server"</option>
                            <option value="Other">"Other"</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>"Reason"</label>
                        <input type="text" required placeholder="Description..."
                               on:input=move |ev| set_wl_reason.set(event_target_value(&ev))
                               prop:value=wl_reason
                        />
                    </div>
                    <div class="modal-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| set_show_modal.set(false)>"Cancel"</button>
                        <button type="submit" class="btn">"Add Entry"</button>
                    </div>
                </form>
            </div>
        </div>
    }
}

pub fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}
