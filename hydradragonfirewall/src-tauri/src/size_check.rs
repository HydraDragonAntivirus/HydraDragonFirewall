use std::mem::size_of;

mod engine_mock {
    pub struct Mock {
        pub a: [u8; 1000000],
    }
}

fn main() {
    // In actual code, I can't easily run a script that imports engine.rs because of dependencies.
    // So I will just add print statements to engine.rs itself.
    println!("Size of Statistics: {}", size_of::<crate::engine::Statistics>());
    println!("Size of DnsHandler: {}", size_of::<crate::engine::DnsHandler>());
    println!("Size of AppManager: {}", size_of::<crate::engine::AppManager>());
    println!("Size of WebFilter: {}", size_of::<crate::web_filter::WebFilter>());
    println!("Size of FirewallSettings: {}", size_of::<crate::engine::FirewallSettings>());
    println!("Size of FirewallEngine: {}", size_of::<crate::engine::FirewallEngine>());
}
