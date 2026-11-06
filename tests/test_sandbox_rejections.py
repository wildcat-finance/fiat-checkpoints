"""Every released hostile fixture id refuses at its declared producer phase.

Each specimen runs through the pinned `checkpoint inspect` in its own gVisor
sandbox and must produce exactly the declared refusal class at the declared
stage. The same bytes through the full service sequence never yield evidence.
"""

import unittest

from fiat_checkpoints.validation import fixture
from fiat_checkpoints.validation.outputs import NativeEvidence
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.reject import replay
from fiat_checkpoints.validation.specimens import Corpus
from tests.validation_support import SandboxCase, request, trust


class RejectionCorpusTests(SandboxCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.corpus = Corpus.released(cls.release)

    def test_all_35_ids_refuse_at_their_declared_inspect_phase(self):
        rows = []
        for fixture_id in self.corpus.ids():
            with self.subTest(fixture=fixture_id):
                row = replay(self.sandbox, self.release, self.corpus, fixture_id, binds=self.binds)
                rows.append(row)
                self.assertEqual(("refused", row["expected_refusal"], row["expected_stage"]),
                                 (row["observed"]["outcome"], row["observed"]["protocol_code"],
                                  row["observed"]["stage"]), row["observed"])
        self.assertEqual(35, len(rows))

    def test_the_valid_archive_passes_the_same_inspect(self):
        from fiat_checkpoints.validation.outputs import InspectPassed
        archive = fixture.valid_archive(self.release)
        outcome, _ = fixture.run(self.sandbox, self.release, archive, request(), trust(), mode="inspect-case",
                                 case={"sha256": request()["outer_sha256"], "sidecar": None}, binds=self.binds)
        self.assertIsInstance(outcome, InspectPassed)

    def test_specimens_through_the_full_sequence_never_yield_evidence(self):
        # `wrong-outer-digest` and `tampered-sidecar` carry the valid bytes: their
        # hostility is an operand or a sidecar, and the service supplies neither.
        valid = fixture.valid_archive(self.release)
        operand_only = {item for item in self.corpus.ids() if self.corpus.build(item).archive == valid}
        self.assertEqual({"wrong-outer-digest", "tampered-sidecar"}, operand_only)
        for fixture_id in sorted(set(self.corpus.ids()) - operand_only):
            specimen = self.corpus.build(fixture_id)
            with self.subTest(fixture=fixture_id):
                job_request = request(attempt="service-path", outer_sha256=specimen.archive_sha256,
                                      carrier_length=len(specimen.archive))
                outcome, _ = fixture.run(self.sandbox, self.release, specimen.archive, job_request, trust(),
                                         binds=self.binds)
                self.assertNotIsInstance(outcome, NativeEvidence)
                self.assertIsInstance(outcome, ValidationRefusal)
                self.assertTrue(outcome.deterministic or outcome.code == "validation_failed", outcome)


if __name__ == "__main__":
    unittest.main()
