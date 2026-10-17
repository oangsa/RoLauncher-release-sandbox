"""No private key or live API is needed for these real OpenSSH verification tests."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import poc


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads((Path(__file__).parent / 'test-vector.json').read_text())

    def test_windows_signature_and_all_signed_faults(self):
        with patch('poc.time.time', return_value=self.vector['now']):
            results = poc.exercise(self.vector['response'], self.vector['challenge'], set())
        self.assertEqual(results['valid'], 'accepted')
        self.assertEqual(results['same-challenge-replay'], 'rejected')
        self.assertEqual(len(results), len(poc.FAULTS) + 2)

    def test_wrong_namespace_is_rejected_by_openssh(self):
        with patch('poc.NAMESPACE', 'wrong-signature-domain'):
            with self.assertRaisesRegex(ValueError, 'signature'):
                poc.verify(self.vector['response']['cases']['valid'], self.vector['challenge'], set(), self.vector['now'])

    def test_duplicate_and_oversized_json_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            poc.parse(b'{"id":1,"id":2}')
        with self.assertRaisesRegex(ValueError, 'size'):
            poc.parse(b'x' * (48 * 1024 + 1))

    def test_production_and_publication_endpoints_are_absent(self):
        for path in ('/releases', '/git/refs', '/issues/2/comments', '/rulesets/25257968',
                     'https://api.github.com/repos/oangsa/RoLauncher/rulesets/25257968'):
            self.assertFalse(poc.read_path(path))
            with self.assertRaisesRegex(ValueError, 'endpoint denied'):
                poc.gh_api(path, {'body': 'must not send'})

    def test_fixture_changes_and_missing_arrays_are_denied(self):
        fixtures = copy.deepcopy(list(poc.policy()['fixtures'].values()))
        poc.fixture_evidence(fixtures)
        fixtures[0].pop('bypass_actors')
        with self.assertRaisesRegex(ValueError, 'bypasses'):
            poc.fixture_evidence(fixtures)

    def test_boolean_run_ids_and_stale_challenges_are_denied(self):
        challenge = copy.deepcopy(self.vector['challenge'])
        challenge['run_id'] = True
        with self.assertRaisesRegex(ValueError, 'run'):
            poc.check_challenge(challenge, self.vector['now'])
        with self.assertRaisesRegex(ValueError, 'deadline'):
            poc.check_challenge(self.vector['challenge'], self.vector['now'] + 601)

    def test_gates_cannot_share_a_response(self):
        challenge = dict(self.vector['challenge'], phase='final', nonce='f' * 64)
        with self.assertRaisesRegex(ValueError, 'binding'):
            poc.verify(self.vector['response']['cases']['valid'], challenge, set(), self.vector['now'])


if __name__ == '__main__':
    unittest.main()
