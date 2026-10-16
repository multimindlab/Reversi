"""Webhook signature helper, and the optional pydantic bindings (skipped when pydantic is not installed)."""
import hashlib
import hmac
import json
import os
import unittest

from reversi_sdk import ReversiClient, validate_manifest, verify_webhook_signature

CONF = os.path.join(os.path.dirname(__file__), "..", "..", "..", "conformance", "manifest-cases.json")


def sign(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


class WebhookSignature(unittest.TestCase):
    def test_valid_and_invalid(self):
        body = b'{"event":"approval.requested","id":"apr_1"}'
        good = sign(b"s3cret", body)
        self.assertTrue(verify_webhook_signature("s3cret", body, good))
        self.assertTrue(ReversiClient.verify_webhook_signature(b"s3cret", body.decode(), good))
        self.assertTrue(verify_webhook_signature("s3cret", body, good.upper().replace("SHA256=", "sha256=")))
        self.assertFalse(verify_webhook_signature("other", body, good))
        self.assertFalse(verify_webhook_signature("s3cret", body + b" ", good))
        self.assertFalse(verify_webhook_signature("s3cret", body, good[len("sha256="):]))   # missing prefix
        self.assertFalse(verify_webhook_signature("s3cret", body, "sha1=" + good[7:]))
        self.assertFalse(verify_webhook_signature("s3cret", body, good[:-2]))               # truncated
        self.assertFalse(verify_webhook_signature("s3cret", body, None))
        self.assertFalse(verify_webhook_signature("s3cret", body, ""))
        self.assertFalse(verify_webhook_signature("s3cret", body, "sha256=éé"))   # non-ascii must not raise

    def test_uses_constant_time_compare(self):
        import reversi_sdk.client as c
        calls = []
        real = c.hmac.compare_digest
        c.hmac.compare_digest = lambda a, b: calls.append(1) or real(a, b)
        try:
            verify_webhook_signature("k", b"x", sign(b"k", b"x"))
        finally:
            c.hmac.compare_digest = real
        self.assertEqual(calls, [1])


try:
    import pydantic  # noqa: F401
    HAVE_PYDANTIC = True
except ImportError:
    HAVE_PYDANTIC = False


@unittest.skipUnless(HAVE_PYDANTIC, "pydantic v2 is not installed")
class PydanticAgreesWithStdlib(unittest.TestCase):
    def test_every_conformance_case(self):
        from reversi_sdk.pydantic_models import validate_with_pydantic
        with open(CONF, encoding="utf-8") as f:
            cases = json.load(f)
        for i, case in enumerate(cases):
            with self.subTest(i=i, input=case["input"]):
                std, _ = validate_manifest(case["input"])
                pyd = validate_with_pydantic(case["input"])
                self.assertEqual(std is not None, case["valid"])
                self.assertEqual(pyd is not None, case["valid"])
                self.assertEqual(pyd, std)

    def test_models_are_typed_and_report_errors(self):
        from pydantic import ValidationError
        from reversi_sdk.pydantic_models import Compensation, ToolManifest
        m = ToolManifest(tool="charge", effect="compensable", permission="pay",
                         compensation=Compensation(tool="refund", argument_map={"id": "$result.id"}))
        self.assertEqual(m.normalized()["compensation"]["tool"], "refund")
        with self.assertRaises(ValidationError):
            ToolManifest(tool="x", effect="irreversible", permission="p", approval="never")
        with self.assertRaises(ValidationError):
            ToolManifest(tool="x", effect="read_only", permission="p", surprise=1)


if __name__ == "__main__":
    unittest.main()
