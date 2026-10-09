import copy
import json
import os
import stat
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from greyward_security_context import application_security as appsec

_windows_uid = None


def setUpModule():
    # Pure wire/transport fixtures also run on the Windows authoring host.
    # Production identity always uses the actual Linux process UID.
    global _windows_uid
    if not hasattr(os, "getuid"):
        _windows_uid = patch.object(os, "getuid", return_value=1002, create=True)
        _windows_uid.start()


def tearDownModule():
    if _windows_uid is not None:
        _windows_uid.stop()


def protection():
    return {"requested_profile": "PROTECTED", "effective_profile": None, "health": "UNKNOWN",
            "coverage": dict.fromkeys(appsec.COVERAGE, False), "isolation": dict.fromkeys(appsec.ISOLATION, False),
            "reviewed_exception": False, "policy_revision": 0, "evidence_age_ms": None}


def application(index=1, uid=None):
    return {"record": {"identity": {"application_ref": "application_" + f"{index:064x}",
            "installation_ref": "installation_" + f"{index:064x}", "generation": "a" * 64,
            "provider": "RPM", "owner_uid": os.getuid() if uid is None else uid,
            "provenance": {"state": "UNKNOWN", "source_receipt": None}}, "first_seen": 1, "last_seen": 2},
            "protection": protection()}


def coverage():
    return {"schema": appsec.SCHEMA, "inventory_health": "UNKNOWN", "protection": protection()}


class ProjectionTests(unittest.TestCase):
    def validate(self, value, method="GetCoverage", **kwargs):
        return appsec.validate_projection(json.dumps(value), method, os.getuid(), **kwargs)

    def test_missing_enforcement_never_becomes_an_effective_profile(self):
        value = self.validate(coverage())
        self.assertEqual(value["protection"]["health"], "UNKNOWN")
        self.assertIsNone(value["protection"]["effective_profile"])

    def test_effective_profile_requires_complete_fresh_evidence(self):
        base = coverage()
        base["protection"].update(health="AVAILABLE", effective_profile="PROTECTED",
                                 policy_revision=1, evidence_age_ms=20)
        base["protection"]["coverage"] = dict.fromkeys(appsec.COVERAGE, True)
        self.assertEqual(self.validate(base, elapsed_ms=15)["protection"]["evidence_age_ms"], 35)
        base['protection']['coverage']['deputies_and_portals'] = False
        self.assertEqual(self.validate(base)['protection']['effective_profile'], 'PROTECTED')
        for mutation in (lambda p: p.update(evidence_age_ms=30_000),
                         lambda p: p.update(policy_revision=0),
                         lambda p: p["coverage"].update(direct_exec=False),
                         lambda p: p.update(health="UNKNOWN"),
                         lambda p: p.update(effective_profile="TRUSTED")):
            value = copy.deepcopy(base)
            mutation(value["protection"])
            with self.subTest(value=value), self.assertRaises(appsec.ApplicationReadError):
                self.validate(value, elapsed_ms=1)

    def test_isolated_and_trusted_have_their_own_additional_gates(self):
        value = coverage()
        p = value["protection"]
        p.update(health="AVAILABLE", requested_profile="ISOLATED", effective_profile="ISOLATED",
                 policy_revision=1, evidence_age_ms=0)
        p["coverage"] = dict.fromkeys(appsec.COVERAGE, True)
        p["isolation"] = dict.fromkeys(appsec.ISOLATION, True)
        self.validate(value)
        p["isolation"]["private_display"] = False
        with self.assertRaises(appsec.ApplicationReadError):
            self.validate(value)
        p.update(requested_profile="TRUSTED", effective_profile="TRUSTED")
        with self.assertRaises(appsec.ApplicationReadError):
            self.validate(value)
        p["reviewed_exception"] = True
        self.validate(value)

    def test_closed_schema_and_type_checks_reject_malformed_facts(self):
        for mutation in (lambda v: v.update(schema="other/v1"), lambda v: v.update(command="anything"),
                         lambda v: v["protection"].update(policy_revision=True),
                         lambda v: v["protection"]["coverage"].update(direct_exec=1),
                         lambda v: v["protection"].update(evidence_age_ms=-1),
                         lambda v: v["protection"].update(requested_profile=[])):
            value = coverage()
            mutation(value)
            with self.subTest(value=value), self.assertRaises(appsec.ApplicationReadError):
                self.validate(value)

    def test_duplicate_fields_nonfinite_and_oversized_json_are_rejected(self):
        for raw in ('{"schema":"x","schema":"y"}', '{"schema":NaN}', '\ud800', 'x' * (appsec.MAX_REPLY + 1)):
            with self.subTest(raw=raw[:60]), self.assertRaises(appsec.ApplicationReadError):
                appsec.validate_projection(raw, "GetCoverage", os.getuid())

    def test_application_generation_ownership_and_provenance_are_validated(self):
        base = application()
        for mutation in (lambda v: v["record"]["identity"].update(owner_uid=os.getuid() + 1),
                         lambda v: v["record"]["identity"].update(generation="A" * 64),
                         lambda v: v["record"]["identity"]["provenance"].update(state="VERIFIED"),
                         lambda v: v["record"].update(first_seen=3),
                         lambda v: v["record"]["identity"].update(installation_ref="/usr/bin/cat")):
            value = copy.deepcopy(base)
            mutation(value)
            with self.subTest(value=value), self.assertRaises(appsec.ApplicationReadError):
                self.validate({"schema": appsec.SCHEMA, "application": value}, "GetApplication",
                              reference=base["record"]["identity"]["installation_ref"])
        value = self.validate({"schema": appsec.SCHEMA, "application": base}, "GetApplication",
                              reference=base["record"]["identity"]["installation_ref"])
        self.assertIsNone(value["application"]["protection"]["effective_profile"])

    def test_null_detail_is_absence_and_different_installation_is_rejected(self):
        value = self.validate({"schema": appsec.SCHEMA, "application": None}, "GetApplication")
        self.assertIsNone(value["application"])
        with self.assertRaises(appsec.ApplicationReadError):
            self.validate({"schema": appsec.SCHEMA, "application": application()}, "GetApplication",
                          reference="installation_" + "f" * 64)

    def test_pages_preserve_revision_order_and_cursor_without_false_completeness(self):
        first, second = application(), application(2)
        ref = second["record"]["identity"]["installation_ref"]
        base = {"schema": appsec.SCHEMA, "inventory_revision": 1, "inventory_health": "UNKNOWN",
                "applications": [first, second], "next_cursor": ref}
        self.assertEqual(self.validate(base, "ListApplications", limit=2, revision=1)["inventory_health"], "UNKNOWN")
        for mutation in (lambda v: v.update(inventory_revision=2), lambda v: v.update(next_cursor=None),
                         lambda v: v.update(applications=[second, first]),
                         lambda v: v.update(applications=[first, first])):
            value = copy.deepcopy(base)
            mutation(value)
            with self.subTest(value=value), self.assertRaises(appsec.ApplicationReadError):
                self.validate(value, "ListApplications", limit=2, revision=1)
        with self.assertRaises(appsec.ApplicationReadError):
            self.validate(base, "ListApplications", limit=2, after=ref)


class AdapterTests(unittest.TestCase):
    def test_resources_are_revision_bound_and_accept_live_root_projection(self):
        resource={"resource_ref":"resource_"+"a"*64,"owner_uid":os.getuid(),
                  "category":"CREDENTIALS","label":"SSH credentials","coverage":"UNKNOWN","policy_revision":1}
        page={"schema":appsec.SCHEMA,"policy_revision":1,"inventory_health":"UNKNOWN",
              "resources":[resource],"next_cursor":resource["resource_ref"]}
        transport=Mock(read=Mock(return_value=json.dumps(page)))
        reads=appsec.ApplicationSecurityReads(transport)
        value=reads.resources(limit=1,has_revision=True,revision=1)
        self.assertEqual(value["projection"]["resources"][0]["coverage"],"UNKNOWN")
        transport.read.assert_called_once_with("ListProtectedResources","ubts",(1,True,1,""))
        live = copy.deepcopy(page)
        live['resources'][0]['coverage'] = 'PROTECTED'
        transport.read.return_value = json.dumps(live)
        self.assertEqual(reads.resources(limit=1)['projection']['resources'][0]['coverage'], 'PROTECTED')
        for field,bad in (("coverage","SUCCESS"),("owner_uid",os.getuid()+1),("policy_revision",2)):
            invalid=copy.deepcopy(page)
            invalid["resources"][0][field]=bad
            transport.read.return_value=json.dumps(invalid)
            with self.subTest(field=field):
                self.assertEqual(reads.resources(limit=1)["source_state"]["state"],"UNAVAILABLE")
        transport.read.return_value=json.dumps(page)
        self.assertEqual(reads.resources(limit=1,has_revision=True,revision=2)["source_state"]["state"],"UNAVAILABLE")
        transport.read.reset_mock()
        for call in (lambda:reads.resource("/home/user/.ssh"),lambda:reads.resources(after="resource_"+"a"*64),
                     lambda:reads.resources(has_revision=True,after="installation_"+"a"*64)):
            with self.assertRaises(appsec.ApplicationReadError): call()
        transport.read.assert_not_called()

    def test_projection_lease_is_bounded_by_remaining_enforcement_freshness(self):
        value = coverage()
        value["protection"].update(health="AVAILABLE", effective_profile="PROTECTED", policy_revision=1, evidence_age_ms=29_995)
        value["protection"]["coverage"] = dict.fromkeys(appsec.COVERAGE, True)
        transport = Mock(read=Mock(return_value=json.dumps(value)))
        with patch.object(appsec.time, "monotonic", side_effect=[10, 10]):
            result = appsec.ApplicationSecurityReads(transport).coverage()
        observed = appsec.dt.datetime.fromisoformat(result["observed_at"])
        fresh_until = appsec.dt.datetime.fromisoformat(result["fresh_until"])
        self.assertEqual((fresh_until - observed).total_seconds(), 0.005)

    def test_only_typed_operations_and_valid_identifiers_reach_transport(self):
        transport = Mock()
        transport.read.return_value = json.dumps(coverage())
        reads = appsec.ApplicationSecurityReads(transport)
        self.assertEqual(reads.coverage()["source_state"]["state"], "AVAILABLE")
        transport.read.assert_called_once_with("GetCoverage", "", ())
        transport.read.reset_mock()
        for arguments in ({"limit": 101}, {"limit": True}, {"revision": 1},
                          {"after": "installation_" + "a" * 64}, {"has_revision": 1},
                          {"has_revision": True, "after": "../secret"}):
            with self.subTest(arguments=arguments), self.assertRaises(appsec.ApplicationReadError):
                reads.applications(**arguments)
        with self.assertRaises(appsec.ApplicationReadError):
            reads.application("/usr/bin/cat")
        transport.read.assert_not_called()

    def test_absent_or_invalid_provider_is_unavailable_not_empty_protected_inventory(self):
        for outcome in (appsec.ApplicationReadError("BROKER_UNAVAILABLE"), '{}'):
            transport = Mock()
            if isinstance(outcome, Exception):
                transport.read.side_effect = outcome
            else:
                transport.read.return_value = outcome
            value = appsec.ApplicationSecurityReads(transport).applications()
            self.assertEqual(value["source_state"]["state"], "UNAVAILABLE")
            self.assertIsNone(value["projection"])

    def test_total_deadline_does_not_become_success_from_a_late_response(self):
        transport = Mock()
        transport.read.return_value = json.dumps(coverage())
        with patch.object(appsec.time, "monotonic", side_effect=[10, 17]):
            value = appsec.ApplicationSecurityReads(transport).coverage()
        self.assertEqual(value["source_state"]["reason"], "BROKER_DEADLINE")


class RootTransportTests(unittest.TestCase):
    def setUp(self):
        selector = patch("greyward_security_context.application_workflows.selected_broker", return_value=appsec.BROKER)
        selector.start(); self.addCleanup(selector.stop)
    def fixture(self, uid=0, changed=False):
        bus = Mock()
        bus.call_blocking.side_effect = [":1.3", {"UnixUserID": uid, "ProcessID": 100},
                                        json.dumps(coverage()), ":1.4" if changed else ":1.3"]
        module = SimpleNamespace(bus=SimpleNamespace(BusConnection=Mock(return_value=bus)),
                                 DBusException=RuntimeError)
        metadata = [SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
                    SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
                    SimpleNamespace(st_mode=stat.S_IFSOCK | 0o666, st_uid=0)]
        return bus, module, metadata

    def test_root_unique_destination_is_pinned_and_environment_address_is_ignored(self):
        bus, module, metadata = self.fixture()
        with patch.dict(sys.modules, {"dbus": module}), patch.object(appsec.Path, "lstat", side_effect=metadata), \
                patch.dict(os.environ, {"DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/tmp/fake"}):
            appsec.RootBrokerTransport().read("GetCoverage", "", ())
        module.bus.BusConnection.assert_called_once_with("unix:path=/run/dbus/system_bus_socket")
        self.assertEqual(bus.call_blocking.call_args_list[2].args[:4],
                         (":1.3", appsec.OBJECT, appsec.BROKER, "GetCoverage"))
        bus.close.assert_called_once()

    def test_same_user_owner_or_owner_replacement_never_establishes_authority(self):
        for uid, changed in ((1002, False), (0, True)):
            bus, module, metadata = self.fixture(uid, changed)
            with self.subTest(uid=uid, changed=changed), patch.dict(sys.modules, {"dbus": module}), \
                    patch.object(appsec.Path, "lstat", side_effect=metadata), self.assertRaises(appsec.ApplicationReadError):
                appsec.RootBrokerTransport().read("GetCoverage", "", ())
            bus.close.assert_called_once()
            if uid != 0:
                self.assertEqual(bus.call_blocking.call_count, 2)

    def test_user_owned_or_replaced_socket_and_parent_are_rejected(self):
        for index in range(3):
            bus, module, metadata = self.fixture()
            metadata[index].st_uid = 1002
            with self.subTest(index=index), patch.dict(sys.modules, {"dbus": module}), \
                    patch.object(appsec.Path, "lstat", side_effect=metadata), self.assertRaises(appsec.ApplicationReadError):
                appsec.RootBrokerTransport().read("GetCoverage", "", ())
            module.bus.BusConnection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
