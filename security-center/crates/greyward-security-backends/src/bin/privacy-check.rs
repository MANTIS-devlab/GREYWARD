use chrono::Utc;
use greyward_security_backends::{
    ActivityCategory, ActivityItem, ActivitySeverity, clear_activity, collect_core_snapshot,
    load_activity, record_activity, write_safe_export,
};
use std::fs;

fn main() {
    let snapshot = collect_core_snapshot();
    record_activity(ActivityItem {
        event_id: "privacy-check".into(),
        category: ActivityCategory::Action,
        severity: ActivitySeverity::Information,
        occurred_at: Utc::now(),
        title: "Validation event".into(),
        detail: "bounded local test".into(),
        related_check_id: None,
    })
    .expect("record");
    assert_eq!(load_activity().expect("load").len(), 1);
    let path = write_safe_export(&snapshot).expect("export");
    let text = fs::read_to_string(&path).expect("read export");
    assert!(text.contains("greyward.security.export/v1"));
    assert!(!text.contains("172.29.241.10"));
    clear_activity().expect("clear");
    assert!(load_activity().expect("load after clear").is_empty());
    println!("export={} clear=ok", path.display());
}
