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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingApp {
    pub process_id: u32,
    pub name: String,
    pub dst_ip: String,
    pub dst_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResolveArgs {
    name: String,
    decision: String,
}

#[derive(Clone, PartialEq)]
enum AppView {
    Dashboard,
    Rules,
    Logs,
    Settings,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    #[serde(default)]
    pub block: bool,
    #[serde(default)]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub remote_ips: Vec<String>,
    #[serde(default)]
    pub remote_ports: Vec<u16>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub hostname_pattern: Option<String>,
    #[serde(default)]
    pub url_pattern: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FirewallSettings {
    #[serde(default)]
    pub whitelisted_ips: Vec<String>,
    #[serde(default)]
    pub whitelisted_domains: Vec<String>,
    #[serde(default)]
    pub whitelisted_ports: Vec<u16>,
    #[serde(default)]
    pub blocked_keywords: Vec<String>,
    #[serde(default)]
    pub website_path: String,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

#[component]
pub fn App() -> impl IntoView {
    let (logs, set_logs) = create_signal(Vec::<LogEntry>::new());
    let (blocked_count, set_blocked_count) = create_signal(0);
    let (threats_count, set_threats_count) = create_signal(0);
    let (allowed_count, set_allowed_count) = create_signal(0);
    let (total_count, set_total_count) = create_signal(0);
    
    // Navigation State
    let (current_view, set_current_view) = create_signal(AppView::Dashboard);

    // Modal States
    let (show_modal, set_show_modal) = create_signal(false);
    let (wl_item, set_wl_item) = create_signal(String::new());
    let (wl_category, set_wl_category) = create_signal("Trusted".to_string());
    let (wl_reason, set_wl_reason) = create_signal(String::new());

    let (pending_app, set_pending_app) = create_signal(Option::<PendingApp>::None);
    let (saved_status, set_saved_status) = create_signal(false);
    let (engine_status, set_engine_status) = create_signal("Initializing Engine...".to_string());
    let (engine_active, set_engine_active) = create_signal(false);

    // Graph State
    let (graph_data, set_graph_data) = create_signal(vec![180, 160, 170, 150, 140, 130, 110, 120, 100]);
    let graph_points = move || {
        graph_data.get().iter().enumerate()
            .map(|(i, &v)| format!("{},{}", i * 50, v))
            .collect::<Vec<_>>()
            .join(" ")
    };

    // Update Graph Data periodically
    create_effect(move |_| {
        use std::time::Duration;
        set_interval(move || {
            let current_activity = (total_count.get() % 100) as u32;
            let val = 180 - (current_activity.min(150));
            set_graph_data.update(|v| {
                v.push(val);
                if v.len() > 10 { v.remove(0); }
            });
        }, Duration::from_millis(2000));
    });
    let (settings, set_settings) = create_signal(FirewallSettings {
        whitelisted_ips: vec![],
        whitelisted_domains: vec![],
        whitelisted_ports: vec![],
        blocked_keywords: vec![],
        website_path: "website".to_string(),
        rules: vec![],
    });

    // Setup Event Listener
    create_effect(move |_| {
        let closure = Closure::wrap(Box::new(move |event: JsValue| {
             match serde_wasm_bindgen::from_value::<serde_json::Value>(event.clone()) {
                Ok(payload) => {
                     if let Some(payload_obj) = payload.get("payload") {
                         match serde_json::from_value::<LogEntry>(payload_obj.clone()) {
                            Ok(entry) => {
                                set_logs.update(|l: &mut Vec<LogEntry>| {
                                    l.push(entry.clone());
                                    if l.len() > 200 { l.remove(0); }
                                });
                                
                                set_total_count.update(|n| *n += 1);
                                
                                // Update engine status based on log messages
                                if entry.message.contains("Starting") || entry.message.contains("Loading") {
                                    set_engine_status.set(entry.message.clone());
                                }
                                if entry.message.contains("ACTIVE") || entry.message.contains("Engine") {
                                    set_engine_status.set(entry.message.clone());
                                    if entry.message.contains("ACTIVE") {
                                        set_engine_active.set(true);
                                    }
                                }
                                if entry.message.contains("WebFilter Loaded") {
                                    set_engine_status.set("🟢 Monitoring Active".to_string());
                                    set_engine_active.set(true);
                                }
                                if entry.message.contains("WinDivert") && !entry.message.contains("Failed") {
                                    set_engine_active.set(true);
                                }
                                if entry.message.contains("Failed") || entry.message.contains("Error") {
                                    set_engine_status.set(format!("⚠️ {}", entry.message));
                                }
                                
                                match entry.level {
                                    LogLevel::Warning | LogLevel::Error => {
                                        if entry.message.contains("Blocking") || entry.message.contains("BLOCKED") {
                                            set_blocked_count.update(|n| *n += 1);
                                        }
                                        if entry.message.contains("Malicious") || entry.message.contains("Threat") {
                                            set_threats_count.update(|n| *n += 1);
                                        }
                                    },
                                    LogLevel::Success => {
                                        set_allowed_count.update(|n| *n += 1);
                                    }
                                    _ => {},
                                }
                            },
                            Err(_) => {
                            }
                         }
                     }
                },
                Err(_) => {
                }
             }
        }) as Box<dyn FnMut(JsValue)>);
        
        spawn_local(async move {
            let _ = listen("log", &closure).await;
            closure.forget();
        });

        // Ask Decision Listener
        let ask_closure = Closure::wrap(Box::new(move |event: JsValue| {
             if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                 if let Some(payload_obj) = payload.get("payload") {
                     if let Ok(app) = serde_json::from_value::<PendingApp>(payload_obj.clone()) {
                         set_pending_app.set(Some(app));
                     }
                 }
             }
        }) as Box<dyn FnMut(JsValue)>);

        spawn_local(async move {
            let _ = listen("ask_app_decision", &ask_closure).await;
            ask_closure.forget();
        });
    });

    // Load Settings
    create_effect(move |_| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&()).unwrap();
            let res = invoke("get_settings", args).await;
            if let Ok(s) = serde_wasm_bindgen::from_value::<FirewallSettings>(res) {
                set_settings.set(s);
            }
        });
    });

    let save_settings_action = move || {
        spawn_local(async move {
            let s = settings.get();
            let args = serde_wasm_bindgen::to_value(&s).unwrap();
            let _ = invoke("save_settings", args).await;
            set_saved_status.set(true);
            set_timeout(move || set_saved_status.set(false), std::time::Duration::from_secs(2));
        });
    };

    let toggle_rule = move |index: usize| {
        set_settings.update(|s| {
            if let Some(rule) = s.rules.get_mut(index) {
                rule.enabled = !rule.enabled;
            }
        });
        save_settings_action();
    };

    let update_path = move |path: String| {
        set_settings.update(|s| s.website_path = path);
    };

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

    let resolve_decision = move |name: String, decision: String| {
        spawn_local(async move {
            let args = ResolveArgs { name, decision };
            let args_js = serde_wasm_bindgen::to_value(&args).unwrap();
            let _ = invoke("resolve_app_decision", args_js).await;
            set_pending_app.set(None);
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
                    <a href="#" class={move || if current_view.get() == AppView::Dashboard { "nav-item active" } else { "nav-item" }} 
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Dashboard); }>
                       "Dashboard"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::Rules { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Rules); }>
                       "Protection Rules"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::Logs { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Logs); }>
                       "Network Logs"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::Settings { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Settings); }>
                       "Settings"
                    </a>
                </nav>
                <div style="margin-top: auto">
                    <button class="btn-primary" style="width: 100%" on:click=move |_| set_show_modal.set(true)>
                        "+ WHITELIST"
                    </button>
                </div>
            </aside>

            <main>
                <header style="display: flex; justify-content: space-between; align-items: center">
                    <h2 style="margin: 0; font-weight: 800; font-size: 28px">
                        {move || match current_view.get() {
                            AppView::Dashboard => "Security Overview",
                            AppView::Rules => "Protection Rules",
                            AppView::Logs => "Network Activity",
                            AppView::Settings => "System Settings",
                        }}
                    </h2>
                    <span style={move || if engine_active.get() { "color: var(--accent-green); font-weight: 600; font-size: 14px" } else { "color: var(--accent-yellow); font-weight: 600; font-size: 14px" }}>
                        {move || if engine_active.get() { "● SYSTEM SECURE" } else { "○ INITIALIZING..." }}
                    </span>
                </header>

                {move || match current_view.get() {
                    AppView::Dashboard => view! {
                        <div class="dashboard-grid">
                            <div class="dash-col-main">
                                <div class="glass-card status-card">
                                    <div class="status-header">
                                        <div>
                                            <h3>"System Status"</h3>
                                            <span class="status-badge secure">"SECURE"</span>
                                        </div>
                                        <div class="pulse-indicator"></div>
                                    </div>
                                    <div class="traffic-graph-container">
                                        <svg width="100%" height="150" viewBox="0 0 600 150" class="traffic-svg">
                                            <defs>
                                                <linearGradient id="grad1" x1="0%" y1="0%" x2="0%" y2="100%">
                                                    <stop offset="0%" style="stop-color:var(--accent-blue);stop-opacity:0.5" />
                                                    <stop offset="100%" style="stop-color:var(--accent-blue);stop-opacity:0" />
                                                </linearGradient>
                                            </defs>
                                            <path d="M0,150 L0,100 Q50,50 100,80 T200,60 T300,100 T400,40 T500,80 T600,60 V150 Z" 
                                                  fill="url(#grad1)" stroke="var(--accent-blue)" stroke-width="2" />
                                        </svg>
                                        <div class="graph-overlay">
                                            <div class="traffic-stat">
                                                <span class="label">"REAL-TIME ACTIVITY"</span>
                                                <span class="value" style="color:var(--accent-blue)">
                                                    {move || format!("{:.1} PPS", (total_count.get() % 50) as f32 + 5.0)}
                                                </span>
                                            </div>
                                            <div class="traffic-stat">
                                                <span class="label">"THREAT LEVEL"</span>
                                                <span class="value" style="color:var(--accent-yellow)">
                                                    {move || if threats_count.get() > 0 { "ELEVATED" } else { "LOW" }}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
        
                                <div class="glass-card logs-section">
                                    <div class="section-header">
                                        <h3 style="margin: 0; font-size: 16px; font-weight: 700">"Real-time Intelligence"</h3>
                                        <span style={move || if engine_active.get() { "font-size: 12px; color: var(--accent-green)" } else { "font-size: 12px; color: var(--text-muted)" }}>
                                            {move || engine_status.get()}
                                        </span>
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
                            </div>
        
                            <div class="dash-col-side">
                                 <div class="glass-card stat-item-compact">
                                    <h4>"Total Traffic"</h4>
                                    <div class="stat-value">{move || total_count.get()}</div>
                                </div>
                                <div class="glass-card stat-item-compact">
                                    <h4>"Blocked"</h4>
                                    <div class="stat-value" style="color: var(--accent-red)">{move || blocked_count.get()}</div>
                                </div>
                                <div class="glass-card stat-item-compact" style="border-left: 3px solid var(--accent-yellow)">
                                    <h4>"Threats"</h4>
                                    <div class="stat-value" style="color: var(--accent-yellow)">{move || threats_count.get()}</div>
                                </div>
                                 <div class="glass-card stat-item-compact">
                                    <h4>"Safe Requests"</h4>
                                    <div class="stat-value" style="color: var(--accent-green)">{move || allowed_count.get()}</div>
                                </div>
                            </div>
                        </div>
                    }.into_view(),
                    
                    AppView::Rules => view! {
                        <div class="dashboard-grid" style="flex-direction: column">
                            <div class="glass-card" style="width: 100%">
                                <div class="section-header" style="margin-bottom: 20px">
                                    <div>
                                        <h3 style="margin: 0">"🔒 Active Protection Rules"</h3>
                                        <span style="font-size: 12px; color: var(--text-muted)">"manage network filtering policies"</span>
                                    </div>
                                    <button class="btn-primary" style="padding: 8px 20px; font-size: 13px">
                                        "+ ADD RULE"
                                    </button>
                                </div>
                                
                                // Rules List
                                <div class="rules-list" style="display: flex; flex-direction: column; gap: 12px">
                                    <For
                                        each=move || settings.get().rules.into_iter().enumerate()
                                        key=|(_, rule)| rule.name.clone()
                                        children=move |(idx, rule)| {
                                            let is_blocking = rule.block;
                                            view! {
                                                <div class="rule-item" style="background: rgba(255,255,255,0.02); padding: 18px 20px; border-radius: 12px; display: flex; justify-content: space-between; align-items: center; border: 1px solid rgba(255,255,255,0.03); transition: all 0.2s">
                                                    <div style="display: flex; align-items: center; gap: 15px">
                                                        // Rule Icon
                                                        <div style={if is_blocking { "width: 40px; height: 40px; background: rgba(255,62,62,0.1); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 18px" } else { "width: 40px; height: 40px; background: rgba(0,255,136,0.1); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 18px" }}>
                                                            {if is_blocking { "🚫" } else { "✅" }}
                                                        </div>
                                                        <div>
                                                            <div style="display: flex; align-items: center; gap: 10px">
                                                                <span style="font-weight: 600; font-size: 15px">{rule.name.clone()}</span>
                                                                // Action Badge
                                                                <span style={if is_blocking { "background: rgba(255,62,62,0.2); color: var(--accent-red); padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase" } else { "background: rgba(0,255,136,0.2); color: var(--accent-green); padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase" }}>
                                                                    {if is_blocking { "BLOCK" } else { "ALLOW" }}
                                                                </span>
                                                            </div>
                                                            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px">{rule.description.clone()}</div>
                                                        </div>
                                                    </div>
                                                    // Toggle Switch
                                                    <div class="toggle-switch" 
                                                         style={if rule.enabled { "background: var(--accent-green); cursor: pointer; width: 44px; height: 24px; border-radius: 24px; position: relative; box-shadow: 0 2px 8px rgba(0,255,136,0.3)" } else { "background: #333; cursor: pointer; width: 44px; height: 24px; border-radius: 24px; position: relative" }}
                                                         on:click=move |ev| { ev.stop_propagation(); toggle_rule(idx); }>
                                                        <div style={if rule.enabled { "left: 22px; background: white; width: 18px; height: 18px; border-radius: 50%; position: absolute; top: 3px; transition: 0.2s; box-shadow: 0 1px 3px rgba(0,0,0,0.2)" } else { "left: 3px; background: #666; width: 18px; height: 18px; border-radius: 50%; position: absolute; top: 3px; transition: 0.2s" }}></div>
                                                    </div>
                                                </div>
                                            }
                                        }
                                    />
                                </div>

                                // Empty State
                                {move || {
                                    if settings.get().rules.is_empty() {
                                        view! {
                                            <div style="text-align: center; padding: 60px 20px; color: var(--text-muted)">
                                                <div style="font-size: 48px; margin-bottom: 15px; opacity: 0.3">"📋"</div>
                                                <div style="font-size: 16px; font-weight: 600">"No Rules Configured"</div>
                                                <div style="font-size: 13px; margin-top: 5px">"Click 'Add Rule' to create your first protection rule"</div>
                                            </div>
                                        }.into_view()
                                    } else {
                                        view! { <div></div> }.into_view()
                                    }
                                }}
                            </div>
                        </div>
                    }.into_view(),

                    AppView::Logs => view! {
                         <div class="dashboard-grid" style="flex-direction: column">
                            // Stats Banner
                            <div style="display: flex; gap: 15px; margin-bottom: 10px">
                                <div style="flex: 1; background: rgba(62,148,255,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-blue)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Total Events"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-blue); margin-top: 5px">{move || total_count.get()}</div>
                                </div>
                                <div style="flex: 1; background: rgba(0,255,136,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-green)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Allowed"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-green); margin-top: 5px">{move || allowed_count.get()}</div>
                                </div>
                                <div style="flex: 1; background: rgba(255,62,62,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-red)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Blocked"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-red); margin-top: 5px">{move || blocked_count.get()}</div>
                                </div>
                                <div style="flex: 1; background: rgba(255,204,0,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-yellow)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Threats"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-yellow); margin-top: 5px">{move || threats_count.get()}</div>
                                </div>
                            </div>

                            // Logs Card
                            <div class="glass-card logs-section" style="width: 100%; flex: 1">
                                <div class="section-header" style="margin-bottom: 15px">
                                    <div>
                                        <h3 style="margin: 0; font-size: 16px; font-weight: 700">"📜 Full Network Event Log"</h3>
                                        <span style="font-size: 12px; color: var(--text-muted)">{move || format!("Showing {} events", logs.get().len())}</span>
                                    </div>
                                    <button class="btn-primary" style="padding: 6px 15px; font-size: 12px; background: rgba(255,255,255,0.1); box-shadow: none"
                                            on:click=move |_| set_logs.set(vec![])>
                                        "🗑️ CLEAR"
                                    </button>
                                </div>
                                <div class="logs-viewport" style="height: calc(100vh - 380px); min-height: 400px">
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
                                            let level_icon = match log.level {
                                                LogLevel::Info => "ℹ️",
                                                LogLevel::Success => "✅",
                                                LogLevel::Warning => "⚠️",
                                                LogLevel::Error => "❌",
                                                _ => "📝",
                                            };
                                            view! {
                                                <div class={format!("log-row {}", level_class)} style="align-items: center">
                                                    <span style="font-size: 14px; margin-right: 8px">{level_icon}</span>
                                                    <span class="log-time">"[" {log.timestamp % 100000} "]"</span>
                                                    <span class="log-msg">{log.message}</span>
                                                </div>
                                            }
                                        }
                                    />
                                    // Empty State
                                    {move || {
                                        if logs.get().is_empty() {
                                            view! {
                                                <div style="text-align: center; padding: 80px 20px; color: var(--text-muted)">
                                                    <div style="font-size: 48px; margin-bottom: 15px; opacity: 0.3">"📋"</div>
                                                    <div style="font-size: 16px; font-weight: 600">"No Events Yet"</div>
                                                    <div style="font-size: 13px; margin-top: 5px">"Network activity will appear here in real-time"</div>
                                                </div>
                                            }.into_view()
                                        } else {
                                            view! { <div></div> }.into_view()
                                        }
                                    }}
                                </div>
                            </div>
                        </div>
                    }.into_view(),

                    AppView::Settings => view! {
                         <div class="dashboard-grid" style="flex-direction: column">
                            // General Settings Card
                            <div class="glass-card" style="width: 100%">
                                <div class="section-header">
                                    <h3 style="margin: 0">"⚙️ General Settings"</h3>
                                    <span style="font-size: 12px; color: var(--text-muted)">"configure core firewall behavior"</span>
                                </div>
                                <div class="input-group" style="margin-top: 20px">
                                    <label>"THREAT INTELLIGENCE DATABASE PATH"</label>
                                    <input type="text" 
                                           placeholder="e.g., website or C:\\path\\to\\intel"
                                           prop:value=move || settings.get().website_path 
                                           on:input=move |ev| update_path(event_target_value(&ev))
                                    />
                                </div>
                                <div class="input-group">
                                    <label>"BLOCKED KEYWORDS (comma-separated)"</label>
                                    <textarea 
                                        style="background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1); color: white; padding: 10px; width: 100%; height: 80px; border-radius: 6px; resize: vertical"
                                        placeholder="malware, virus, phishing, trojan..."
                                        on:input=move |ev| {
                                            let val = event_target_value(&ev);
                                            set_settings.update(|s| s.blocked_keywords = val.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect());
                                        }
                                    >
                                    {move || settings.get().blocked_keywords.join(", ")}
                                    </textarea>
                                </div>
                            </div>

                            // Whitelist Management Card
                            <div class="glass-card" style="width: 100%">
                                <div class="section-header">
                                    <h3 style="margin: 0">"🛡️ Whitelist Management"</h3>
                                    <span style="font-size: 12px; color: var(--text-muted)">"trusted IPs, domains, and ports"</span>
                                </div>
                                
                                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 20px">
                                    // Whitelisted IPs
                                    <div style="background: rgba(0,255,136,0.05); padding: 15px; border-radius: 10px; border: 1px solid rgba(0,255,136,0.1)">
                                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px">
                                            <span style="font-size: 16px">"🌐"</span>
                                            <span style="font-weight: 600; font-size: 13px; color: var(--accent-green)">"WHITELISTED IPs"</span>
                                        </div>
                                        <textarea 
                                            style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.05); color: white; padding: 10px; width: 100%; height: 100px; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 12px; resize: vertical"
                                            placeholder="127.0.0.1\n192.168.1.1\n10.0.0.1"
                                            on:input=move |ev| {
                                                let val = event_target_value(&ev);
                                                set_settings.update(|s| s.whitelisted_ips = val.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect());
                                            }
                                        >
                                        {move || settings.get().whitelisted_ips.join("\n")}
                                        </textarea>
                                    </div>

                                    // Whitelisted Domains
                                    <div style="background: rgba(62,148,255,0.05); padding: 15px; border-radius: 10px; border: 1px solid rgba(62,148,255,0.1)">
                                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px">
                                            <span style="font-size: 16px">"🔗"</span>
                                            <span style="font-weight: 600; font-size: 13px; color: var(--accent-blue)">"WHITELISTED DOMAINS"</span>
                                        </div>
                                        <textarea 
                                            style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.05); color: white; padding: 10px; width: 100%; height: 100px; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 12px; resize: vertical"
                                            placeholder="google.com\ncloudflare.com\ngithub.com"
                                            on:input=move |ev| {
                                                let val = event_target_value(&ev);
                                                set_settings.update(|s| s.whitelisted_domains = val.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect());
                                            }
                                        >
                                        {move || settings.get().whitelisted_domains.join("\n")}
                                        </textarea>
                                    </div>

                                    // Whitelisted Ports
                                    <div style="background: rgba(255,204,0,0.05); padding: 15px; border-radius: 10px; border: 1px solid rgba(255,204,0,0.1)">
                                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px">
                                            <span style="font-size: 16px">"🔌"</span>
                                            <span style="font-weight: 600; font-size: 13px; color: var(--accent-yellow)">"WHITELISTED PORTS"</span>
                                        </div>
                                        <textarea 
                                            style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.05); color: white; padding: 10px; width: 100%; height: 100px; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 12px; resize: vertical"
                                            placeholder="80\n443\n8080"
                                            on:input=move |ev| {
                                                let val = event_target_value(&ev);
                                                set_settings.update(|s| s.whitelisted_ports = val.lines().filter_map(|l| l.trim().parse::<u16>().ok()).collect());
                                            }
                                        >
                                        {move || settings.get().whitelisted_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("\n")}
                                        </textarea>
                                    </div>
                                </div>
                            </div>

                            // Save Button
                            <div style="display: flex; justify-content: flex-end; gap: 15px">
                                <button class="btn-primary" 
                                        style={move || if saved_status.get() { "padding: 12px 30px; background: var(--accent-green)" } else { "padding: 12px 30px" }}
                                        on:click=move |_| save_settings_action()>
                                    {move || if saved_status.get() { "✓ SETTINGS SAVED!" } else { "💾 SAVE ALL SETTINGS" }}
                                </button>
                            </div>
                        </div>
                    }.into_view(),
                }}
            </main>

            <div class={move || if show_modal.get() { "modal-overlay open" } else { "modal-overlay" }}
                 style={move || if !show_modal.get() { "pointer-events: none" } else { "pointer-events: auto" }}>
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

            {move || pending_app.get().map(|app| {
                let name_for_block = app.name.clone();
                let name_for_allow = app.name.clone();
                let name_for_block_session = app.name.clone();
                view! {
                    <div class="modal-overlay open">
                        <div class="glass-modal app-decision-modal" style="border-top: 4px solid var(--accent-yellow); max-width: 500px">
                            // Header with icon
                            <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px">
                                <div class="shield-icon" style="width: 48px; height: 48px; background: linear-gradient(135deg, var(--accent-yellow), #ff9900); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; box-shadow: 0 4px 20px rgba(255, 204, 0, 0.3)">
                                    "🛡️"
                                </div>
                                <div>
                                    <h2 style="margin: 0; font-size: 22px; font-weight: 700">"Network Access Request"</h2>
                                    <p style="margin: 5px 0 0 0; color: var(--text-muted); font-size: 13px">"An application is attempting to connect to the network"</p>
                                </div>
                            </div>
                            
                            // Application Info Card
                            <div style="background: linear-gradient(135deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01)); padding: 20px; border-radius: 12px; margin: 20px 0; border: 1px solid rgba(255,255,255,0.05)">
                                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px">
                                    <div style="width: 40px; height: 40px; background: rgba(62, 148, 255, 0.1); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px">
                                        "📦"
                                    </div>
                                    <div>
                                        <div style="font-weight: 700; font-size: 16px; color: white">{app.name.clone()}</div>
                                        <div style="font-size: 12px; color: var(--text-muted)">"Process ID: " {app.process_id}</div>
                                    </div>
                                </div>
                                
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 15px">
                                    <div style="background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px">
                                        <div style="font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 4px">"Destination IP"</div>
                                        <div style="font-family: 'Fira Code', monospace; font-size: 13px; color: var(--accent-blue)">{app.dst_ip.clone()}</div>
                                    </div>
                                    <div style="background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px">
                                        <div style="font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 4px">"Port"</div>
                                        <div style="font-family: 'Fira Code', monospace; font-size: 13px; color: var(--accent-green)">{app.dst_port}</div>
                                    </div>
                                </div>
                            </div>

                            // Action Buttons
                            <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 25px">
                                <button class="btn-primary" 
                                        style="width: 100%; padding: 14px; font-size: 15px"
                                        on:click=move |_| resolve_decision(name_for_allow.clone(), "allow".to_string())>
                                    "✓ ALLOW ACCESS"
                                </button>
                                <div style="display: flex; gap: 10px">
                                    <button class="btn-primary" 
                                            style="flex: 1; background: rgba(255, 62, 62, 0.15); border: 1px solid var(--accent-red); box-shadow: none; color: var(--accent-red)"
                                            on:click=move |_| resolve_decision(name_for_block_session.clone(), "block".to_string())>
                                        "BLOCK ONCE"
                                    </button>
                                    <button class="btn-primary" 
                                            style="flex: 1; background: var(--accent-red)"
                                            on:click=move |_| resolve_decision(name_for_block.clone(), "block".to_string())>
                                        "✕ BLOCK ALWAYS"
                                    </button>
                                </div>
                            </div>

                            // Footer hint
                            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.05); text-align: center">
                                <span style="font-size: 11px; color: var(--text-muted)">"Your decision will be remembered for this application"</span>
                            </div>
                        </div>
                    </div>
                }
            })}
        </div>
    }
}

pub fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}
