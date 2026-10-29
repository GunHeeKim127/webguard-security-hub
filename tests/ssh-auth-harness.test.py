"""Portable reporting-contract checks; these do not execute or attest Linux SSH."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('ssh_auth_harness', Path(__file__).resolve().parents[1] / 'scripts' / 'verify-linux-ssh-auth.py')
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class ReportingTests(unittest.TestCase):
    def test_failed_positive_control_never_certifies_other_cases(self):
        for case in harness.CASES:
            if case != 'allowed_key':
                self.assertEqual(harness.result_status(case, True, False), 'INCONCLUSIVE')
        self.assertEqual(harness.result_status('allowed_key', False, False), 'FAIL')

    def test_validated_control_does_not_hide_a_failed_case(self):
        self.assertEqual(harness.result_status('custom_key_location', False, True), 'FAIL')
        self.assertEqual(harness.result_status('custom_key_location', True, True), 'PASS')

    def test_configured_path_is_only_an_informational_notice(self):
        self.assertEqual(harness.path_notice()['severity'], 'info')
        self.assertIn('의도한 경로', harness.path_notice()['messageKo'])
        self.assertIn('not an error or vulnerability', harness.path_notice()['message'])

    def test_unrelated_authentication_rejection_does_not_recommend_moving_keys(self):
        for code in ('user-denied', 'locked-account', 'unregistered-key'):
            guidance = harness.reason_guidance([code])[0]
            self.assertNotIn('Check the configured key path', guidance)

    def test_path_guidance_requires_a_specific_reason(self):
        self.assertEqual(harness.reason_guidance(['unknown']), [])
        self.assertIn('resolved parent', harness.reason_guidance(['unsafe-key-directory'])[0])

    def test_missing_file_requires_failure_then_success_with_a_single_key_source(self):
        self.assertTrue(harness.missing_file_confirmed(True, True, 0, True, True))
        for arguments in ((False, True, 0, True, True), (True, False, 0, True, True),
                          (True, True, 255, False, True), (True, True, 0, False, True),
                          (True, True, 0, True, False)):
            self.assertFalse(harness.missing_file_confirmed(*arguments))

    def test_confirmed_missing_file_still_has_only_an_informational_path_notice(self):
        self.assertEqual(harness.path_notice()['severity'], 'info')
        self.assertIn('intended key-file path', harness.reason_guidance(['missing-file-paired-control'])[0])


if __name__ == '__main__':
    unittest.main()
