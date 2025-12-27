$env:WINDIVERT_PATH = "c:\Users\victim\Documents\GitHub\HydraDragonFirewall\everything"
$env:WINDIVERT_LIB_DIR = "c:\Users\victim\Documents\GitHub\HydraDragonFirewall\everything"
echo "--- Building HydraDragon Firewall with WINDIVERT_PATH=$env:WINDIVERT_PATH ---"
cargo build --release
