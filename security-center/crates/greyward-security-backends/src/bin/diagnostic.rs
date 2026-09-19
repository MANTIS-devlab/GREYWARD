fn main() {
    let snapshot = greyward_security_backends::collect_core_snapshot();
    println!(
        "{}",
        serde_json::to_string_pretty(&snapshot).expect("snapshot serialization")
    );
}
