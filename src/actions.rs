use std::process::Command;

pub struct ActionExecutor;

impl ActionExecutor {
    /// Izvršava spoljnu akciju na osnovu prelaza u kvartarno stanje
    pub fn trigger_external_action(state_name: &str, threat_score: u32, webhook_url: Option<&str>) {
        // 1. Izvršavanje lokalne skripte / komande po izboru
        let script_command = match state_name {
            "Critical" | "Lockdown" => Some("echo 'QUAT_SECURITY ALERT: Visok nivo pretnje detektovan!'"),
            _ => None,
        };

        if let Some(cmd) = script_command {
            #[cfg(target_os = "windows")]
            let _ = Command::new("cmd").args(["/C", cmd]).spawn();

            #[cfg(not(target_os = "windows"))]
            let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
        }

        // 2. Slanje Webhook obaveštenja (simulacija preko standardnog HTTP klijenta ili light-weight TCP/curl poziva)
        if let Some(_url) = webhook_url {
            let _payload = format!(
                "{{\"state\": \"{}\", \"threat_score\": {}}}",
                state_name, threat_score
            );
            
            // Asinhroni ili brzi poziv curl-a da ne blokira bezbednosnu nit
            #[cfg(not(target_os = "windows"))]
            let _ = Command::new("curl")
                .args(["-X", "POST", "-H", "Content-Type: application/json", "-d", &payload, url])
                .spawn();
        }
    }
}