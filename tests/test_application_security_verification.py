"""Regression tests for reviewed helper domains in the protected seat verifier."""
import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / 'security-center/packaging/application-security/desktop/verify.py'


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
