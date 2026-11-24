use std::process::Command;
use std::process::Stdio;

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

#[derive(Debug, Clone)]
pub struct ActionConfig {
    pub allow_shell_commands: bool,
    pub allow_webhook: bool,
}

impl Default for ActionConfig {
    fn default() -> Self {
        Self {
            allow_shell_commands: false,
            allow_webhook: false,
        }
    }
}

pub struct SafeActionExecutor {
    pub config: ActionConfig,
}

impl SafeActionExecutor {
    pub fn new(config: ActionConfig) -> Self {
        Self { config }
    }

    /// Executes a fixed, non-interpolated alert message when explicitly allowed.
    /// Avoids arbitrary shell expansion and ignores untrusted input strings.
    pub fn execute_alert(&self, state_code_bits: u8, threat_score: u32) -> Result<(), &'static str> {
        if !self.config.allow_shell_commands {
            return Err("Shell commands are disabled by ActionConfig");
        }

        let alert_msg = match state_code_bits & 0b11 {
            0b10 => format!("QUAT_SECURITY CRITICAL (score={})", threat_score),
            0b11 => format!("QUAT_SECURITY LOCKDOWN (score={})", threat_score),
            _ => return Ok(()),
        };

        #[cfg(target_os = "windows")]
        let status = Command::new("cmd")
            .args(["/C", "echo", &alert_msg])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        #[cfg(not(target_os = "windows"))]
        let status = Command::new("sh")
            .args(["-c", "printf '%s\\n' \"$1\"", "sh", &alert_msg])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(_) => Err("Alert command exited with non-zero status"),
            Err(_) => Err("Failed to spawn alert process"),
        }
    }

    pub fn send_json_webhook(
        &self,
        webhook_url: &str,
        state_code_bits: u8,
        threat_score: u32,
    ) -> Result<(), &'static str> {
        if !self.config.allow_webhook {
            return Err("Webhook dispatch is disabled by ActionConfig");
        }
        if !(webhook_url.starts_with("https://") || webhook_url.starts_with("http://")) {
            return Err("Invalid webhook URL scheme");
        }

        let payload = format!(
            "{{\"quad_state\":{},\"threat_score\":{}}}",
            state_code_bits & 0b11,
            threat_score
        );

        let status = Command::new("curl")
            .args([
                "-sS",
                "--fail",
                "--max-time",
                "3",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &payload,
                webhook_url,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(_) => Err("Webhook request failed"),
            Err(_) => Err("Failed to invoke curl"),
        }
    }
}