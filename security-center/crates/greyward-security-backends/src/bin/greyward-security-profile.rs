use greyward_security_backends::{
    PrivacyProfile, PrivacyState, apply_native_profile, read_actual_state,
};
use serde_json::json;
use std::env;

fn profile_name(profile: Option<PrivacyProfile>) -> Option<&'static str> {
    profile.map(|value| match value {
        PrivacyProfile::Standard => "STANDARD",
        PrivacyProfile::Private => "PRIVATE",
        PrivacyProfile::Travel => "TRAVEL",
    })
}

fn state_payload(state: PrivacyState, status: &'static str) -> serde_json::Value {
    json!({
        "ok": true,
        "state": status,
        "profile": profile_name(state.profile),
        "mac_policy": state.mac_policy,
        "firewall_zone": state.firewall_zone,
        "vpn_active": state.vpn_active,
    })
}

fn failed_state_payload(error: String, profile: PrivacyProfile) -> serde_json::Value {
    let mut payload = json!({
        "ok": false,
        "state": "REFUSED",
        "profile": null,
        "detail": error,
    });
    if let Ok(state) = read_actual_state() {
        payload["profile"] = profile_name(state.profile)
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null);
        payload["effective_mac_policy"] = serde_json::json!(state.mac_policy);
        payload["effective_firewall_zone"] = serde_json::json!(state.firewall_zone);
        payload["effective_state"] = serde_json::json!(state);
    }
    payload
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("--read") if args.len() == 2 => read_actual_state()
            .map(|state| state_payload(state, "OBSERVED"))
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "state": "UNAVAILABLE",
                    "profile": null,
                    "detail": error.to_string(),
                })
            }),
        Some("--set") if args.len() == 3 => match PrivacyProfile::parse(&args[2]) {
            Ok(profile) => apply_native_profile(profile)
                .map(|state| state_payload(state, "APPLIED"))
                .unwrap_or_else(|error| failed_state_payload(error.to_string(), profile)),
            Err(error) => json!({
                "ok": false,
                "state": "INVALID",
                "profile": null,
                "detail": error.to_string(),
            }),
        },
        _ => json!({
            "ok": false,
            "state": "INVALID",
            "profile": null,
            "detail": "Usage: greyward-security-profile --read|--set STANDARD|PRIVATE|TRAVEL",
        }),
    };
    println!(
        "{}",
        serde_json::to_string(&result).expect("profile response serializes")
    );
}
