"""The 35 released hostile fixture ids are bound to specimens and refusal classes.

These checks start no process; the sandbox group replays every specimen
through the pinned inspect.
"""

import hashlib
import io
import unittest
import zipfile

from fiat_checkpoints.validation.refusals import stage_codes
from fiat_checkpoints.validation.specimens import BUILDERS, Corpus, write_zip
from tests.validation_support import release


class ReleasedFixtureBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = Corpus.released(release())

    def test_every_released_id_has_exactly_one_builder(self):
        declared = self.corpus.declared()
        self.assertEqual(35, len(declared))
        self.assertEqual(35, self.corpus.capabilities["hostile_fixture_count"])
        self.assertEqual(set(declared), set(BUILDERS))

    def test_each_id_keeps_its_declared_stage_and_refusal_class(self):
        names = {row["name"]: set(row["stages"]) for row in self.corpus.capabilities["refusals"]}
        self.assertEqual(24, len(names))
        for fixture_id, (refusal, stage) in self.corpus.declared().items():
            with self.subTest(fixture=fixture_id):
                self.assertIn(stage, names[refusal])
                specimen = self.corpus.build(fixture_id)
                self.assertEqual((refusal, stage), (specimen.asserted_refusal, specimen.native_stage))

    def test_classes_no_fixture_reaches_stay_visible(self):
        # All 24 classes are accounted for; the inspector does not emit all of them.
        reached = {refusal for refusal, _stage in self.corpus.declared().values()}
        unreached = {row["name"] for row in self.corpus.capabilities["refusals"]} - reached
        self.assertEqual({"boundary-occupied", "boundary-unaccepted", "bundle-oversized", "destination-occupied",
                          "identity-unavailable", "signature-format-unsupported", "worktree-dirty"}, unreached)
        allowed = stage_codes(self.corpus.capabilities)
        self.assertEqual(reached, reached & allowed["inspect"])

    def test_specimens_change_bytes_or_operands_and_rebuild_identically(self):
        valid = hashlib.sha256(self.corpus.archive).hexdigest()
        for fixture_id in self.corpus.ids():
            with self.subTest(fixture=fixture_id):
                first, second = self.corpus.build(fixture_id), self.corpus.build(fixture_id)
                self.assertEqual(first.archive, second.archive)
                if fixture_id == "wrong-outer-digest":
                    self.assertEqual(valid, first.archive_sha256)
                    self.assertNotEqual(valid, first.inspect_sha256)
                elif fixture_id == "tampered-sidecar":
                    self.assertEqual(valid, first.inspect_sha256)
                    self.assertNotIn(valid, first.sidecar)
                else:
                    self.assertNotEqual(valid, first.archive_sha256)
                    self.assertEqual(first.archive_sha256, first.inspect_sha256)
                    self.assertIsNone(first.sidecar)

    def test_independent_writer_reproduces_stored_members(self):
        members = self.corpus.members()
        entries = [{"name": name.encode(), "data": members[name]} for name in sorted(members)]
        with zipfile.ZipFile(io.BytesIO(write_zip(entries))) as container:
            self.assertEqual(members, {info.filename: container.read(info) for info in container.infolist()})
            self.assertTrue(all(info.compress_type == 0 for info in container.infolist()))

    def test_unknown_id_refuses(self):
        with self.assertRaises(KeyError):
            self.corpus.build("not-a-fixture")


if __name__ == "__main__":
    unittest.main()
