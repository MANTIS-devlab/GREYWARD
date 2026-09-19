use greyward_security_backends::{TrustZone, change_active_trust_zone, collect_network_facts};
fn main() {
    let before = collect_network_facts();
    let interface = before.interface.clone().expect("active interface");
    let to_trusted = change_active_trust_zone(&interface, before.trust_zone, TrustZone::Trusted)
        .expect("trusted transition");
    let after_trusted = collect_network_facts();
    assert_eq!(to_trusted, TrustZone::Trusted);
    assert_eq!(after_trusted.trust_zone, TrustZone::Trusted);
    let restored =
        change_active_trust_zone(&interface, after_trusted.trust_zone, before.trust_zone)
            .expect("rollback transition");
    let after_restore = collect_network_facts();
    assert_eq!(restored, before.trust_zone);
    assert_eq!(after_restore.trust_zone, before.trust_zone);
    println!(
        "before={:?} trusted={:?} restored={:?}",
        before.trust_zone, after_trusted.trust_zone, after_restore.trust_zone
    );
}
