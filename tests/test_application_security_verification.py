"""Regression tests for reviewed helper domains in the protected seat verifier."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / 'security-center/packaging/application-security/desktop/verify.py'
ASSEMBLER = VERIFY.with_name('ordinary-policy.py')


def load_pure_verification_rules():
    tree = ast.parse(VERIFY.read_text())
    names = {
        'REVIEWED_NON_ORDINARY_ROLE_TYPES',
        'USB_APPROVAL_CONTEXT',
        'USB_APPROVAL_EXECUTABLE',
        'role_inventory_matches',
        'reviewed_usbguard_approval',
    }
    selected = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id in names
                for target in node.targets):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            selected.append(node)
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(VERIFY), 'exec'), namespace)
    return namespace


RULES = load_pure_verification_rules()


def load_ordinary_assembler():
    tree = ast.parse(ASSEMBLER.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    namespace = {'hashlib': hashlib, 'json': json}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(ASSEMBLER), 'exec'), namespace)
    return namespace['assemble']


class OrdinaryAssemblyTests(unittest.TestCase):
    def assemble(self, domains):
        class Domain:
            def __init__(self, name):
                self.name = name

            def __str__(self):
                return self.name

            def attributes(self):
                return ['domain']

        policy = SimpleNamespace(lookup_role=lambda role: SimpleNamespace(
            types=lambda: [Domain(name) for name in domains]))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'closure'
            load_ordinary_assembler()(policy, output)
            return json.loads((output / 'ordinary.json').read_text()), (output / 'ordinary.cil').read_bytes()

    def test_fresh_install_receipt_and_generated_attribute_satisfy_live_verifier(self):
        domains = {'greyward_guard_t', 'greyward_as_display_t', 'greyward_usbguard_approval_t'}
        receipt, cil = self.assemble(domains)
        attribute = cil.decode().splitlines()[1]
        generated = attribute.removeprefix('(typeattributeset greyward_as_ordinary (').removesuffix('))').split()
        self.assertEqual(set(receipt['domains']), domains)
        self.assertEqual(set(receipt['ordinary']), {'greyward_guard_t'})
        self.assertEqual(set(generated), set(receipt['ordinary']))
        self.assertTrue(RULES['role_inventory_matches'](
            receipt['domains'], domains, receipt['ordinary'], generated))
        self.assertEqual(receipt['sha256'], hashlib.sha256(cil).hexdigest())

    def test_only_display_and_reviewed_helpers_are_excluded(self):
        helpers = RULES['REVIEWED_NON_ORDINARY_ROLE_TYPES']
        domains = {'greyward_guard_t', 'greyward_as_display_t', 'application_t'} | helpers
        receipt, _ = self.assemble(domains)
        self.assertEqual(set(receipt['ordinary']), {'greyward_guard_t', 'application_t'})
        self.assertEqual(domains - set(receipt['ordinary']), {'greyward_as_display_t'} | helpers)

    def test_old_closure_without_helper_remains_supported(self):
        receipt, _ = self.assemble({'greyward_guard_t', 'greyward_as_display_t'})
        self.assertTrue(RULES['role_inventory_matches'](
            receipt['domains'], set(receipt['domains']) | {'greyward_usbguard_approval_t'},
            receipt['ordinary'], receipt['ordinary']))

    def test_privileged_domains_still_refuse_assembly(self):
        for domain in ['unconfined_t', 'init_t', 'sshd_t', 'greyward_as_auth_t']:
            with self.subTest(domain=domain), self.assertRaisesRegex(ValueError, 'Privileged domain'):
                self.assemble({'greyward_guard_t', domain})


class ApplicationSecurityVerificationTests(unittest.TestCase):
    def setUp(self):
        self.expected_domains = {'greyward_guard_t', 'greyward_as_auth_t', 'greyward_as_display_t'}
        self.ordinary = {'greyward_guard_t', 'greyward_as_auth_t'}

    def inventory(self, actual_domains=None, actual_ordinary=None):
        return RULES['role_inventory_matches'](
            self.expected_domains,
            self.expected_domains if actual_domains is None else actual_domains,
            self.ordinary,
            self.ordinary if actual_ordinary is None else actual_ordinary,
        )

    def test_accepts_exact_saved_inventory(self):
        self.assertTrue(self.inventory())

    def test_accepts_only_reviewed_non_ordinary_usb_helper_addition(self):
        actual = self.expected_domains | {'greyward_usbguard_approval_t'}
        self.assertTrue(self.inventory(actual_domains=actual))

    def test_rejects_unknown_role_domain_addition(self):
        actual = self.expected_domains | {'unreviewed_application_t'}
        self.assertFalse(self.inventory(actual_domains=actual))

    def test_rejects_removed_saved_domain(self):
        actual = self.expected_domains - {'greyward_as_display_t'}
        self.assertFalse(self.inventory(actual_domains=actual))

    def test_rejects_ordinary_coverage_drift_and_usb_helper_admission(self):
        self.assertFalse(self.inventory(actual_ordinary=self.ordinary | {'new_ordinary_t'}))
        actual = self.ordinary | {'greyward_usbguard_approval_t'}
        self.assertFalse(self.inventory(actual_ordinary=actual))

    def test_usb_helper_requires_exact_user_context_executable_and_active_scope(self):
        check = RULES['reviewed_usbguard_approval']
        expected = (1000, 1000, RULES['USB_APPROVAL_CONTEXT'],
                    '0::/user.slice/user-1000.slice/session-2.scope',
                    'session-2.scope', RULES['USB_APPROVAL_EXECUTABLE'])
        self.assertTrue(check(*expected))
        for index, value in ((0, 1001), (2, 'unconfined_t'),
                             (3, '0::/user.slice/user-1000.slice/user@1000.service/app.slice'),
                             (5, '/tmp/greyward-usbguard-approval')):
            changed = list(expected)
            changed[index] = value
            self.assertFalse(check(*changed))


if __name__ == '__main__':
    unittest.main()
