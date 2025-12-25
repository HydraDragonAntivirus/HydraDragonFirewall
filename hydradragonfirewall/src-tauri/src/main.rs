#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    println!("--- HydraDragon Firewall Starting (Stack Optimized) ---");
    hydradragonfirewall::run();
}
