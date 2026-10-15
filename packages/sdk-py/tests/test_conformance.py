"""The Python SDK must agree with the TypeScript implementation on the shared fixtures in /conformance."""
import copy
import json
import os
import unittest

from reversi_sdk import (
    GENESIS_HASH, ManifestError, Registry, canonicalize, hash_payload, parse_jsonl, validate_manifest, verify_records,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CONF = os.path.join(ROOT, "conformance")


def load(name):
    with open(os.path.join(CONF, name), encoding="utf-8") as f:
        return f.read()


class ManifestConformance(unittest.TestCase):
    def test_cases(self):
        cases = json.loads(load("manifest-cases.json"))
        self.assertGreater(len(cases), 20)
        for i, c in enumerate(cases):
            with self.subTest(i=i, input=c["input"]):
                m, errors = validate_manifest(c["input"])
                self.assertEqual(m is not None, c["valid"], errors)
                if c["valid"]:
                    self.assertEqual(m, c["normalized"])

    def test_registry_cross_references(self):
        reg = Registry()
        reg.register({"tool": "charge", "effect": "compensable", "permission": "p", "compensation": {"tool": "refund"}})
        self.assertEqual(reg.validate(), ["`charge`: compensation tool `refund` is not registered"])
        reg.register({"tool": "refund", "effect": "idempotent", "permission": "p"})
        self.assertEqual(reg.validate(), [])
        with self.assertRaises(ManifestError):
            reg.register({"tool": "refund", "effect": "idempotent", "permission": "p"})


class HashConformance(unittest.TestCase):
    def test_vectors(self):
        vectors = json.loads(load("hash-vectors.json"))
        for v in vectors:
            with self.subTest(value=v["value"]):
                self.assertEqual(hash_payload(v["value"]), v["hash"])

    def test_canonical_rules(self):
        self.assertEqual(canonicalize({"b": 1, "a": [1.0, None, True]}), '{"a":[1,null,true],"b":1}')
        with self.assertRaises(TypeError):
            canonicalize(float("nan"))
        with self.assertRaises(TypeError):
            canonicalize(1e-7)
        with self.assertRaises(TypeError):
            canonicalize({1: 2})
        self.assertEqual(hash_payload(object()), hash_payload(object()))  # never raises


class LedgerConformance(unittest.TestCase):
    def records(self):
        return parse_jsonl(load("ledger.jsonl"))

    def test_typescript_ledger_verifies(self):
        recs = self.records()
        r = verify_records(recs)
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.records, len(recs))
        self.assertEqual(recs[0]["prev_hash"], GENESIS_HASH)
        self.assertEqual(r.head, recs[-1]["hash"])
        self.assertIn("compensated", [x["event"] for x in recs])
        self.assertIn("blocked", [x["event"] for x in recs])

    def test_edit_is_detected(self):
        recs = self.records()
        recs[1]["tool"] = "refund_everything"
        r = verify_records(recs)
        self.assertFalse(r.ok)
        self.assertEqual(r.seq, 1)

    def test_deletion_and_reorder_are_detected(self):
        recs = self.records()
        self.assertFalse(verify_records(recs[:1] + recs[2:]).ok)
        swapped = copy.deepcopy(recs)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        self.assertFalse(verify_records(swapped).ok)

    def test_truncation_is_not_detectable_without_an_anchor(self):
        # Documented limit: dropping the tail leaves a valid chain; anchor the head externally.
        recs = self.records()
        self.assertTrue(verify_records(recs[:-1]).ok)

    def test_malformed_records_do_not_crash(self):
        self.assertFalse(verify_records([None]).ok)
        self.assertFalse(verify_records([{"seq": 0}]).ok)
        self.assertFalse(verify_records([{**self.records()[0], "step": True}]).ok)

    def test_parse_names_the_line(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            parse_jsonl('{"a":1}\nnope\n')


if __name__ == "__main__":
    unittest.main()
