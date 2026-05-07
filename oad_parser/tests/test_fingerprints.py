import hashlib
import unittest
from unittest import mock

from oad_parser.fingerprints import md5


class FingerprintHashTests(unittest.TestCase):
    def test_md5_non_security_digest_matches_expected_value(self):
        self.assertEqual(md5(b"abc").hexdigest(), "900150983cd24fb0d6963f7d28e17f72")

    def test_md5_marks_use_as_non_security(self):
        calls = []

        def fake_md5(data=b"", *args, **kwargs):
            calls.append(kwargs.copy())
            if kwargs.get("usedforsecurity") is not False:
                raise ValueError("blocked security md5")
            return hashlib.sha256(data)

        with mock.patch("oad_parser.fingerprints.hashlib.md5", fake_md5):
            digest = md5(b"abc").hexdigest()

        self.assertEqual(digest, hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(calls, [{"usedforsecurity": False}])

    def test_md5_falls_back_when_keyword_is_unsupported(self):
        calls = []

        def fake_md5(data=b"", *args, **kwargs):
            calls.append(kwargs.copy())
            if "usedforsecurity" in kwargs:
                raise TypeError("unexpected keyword")
            return hashlib.sha1(data)

        with mock.patch("oad_parser.fingerprints.hashlib.md5", fake_md5):
            digest = md5(b"abc").hexdigest()

        self.assertEqual(digest, hashlib.sha1(b"abc").hexdigest())
        self.assertEqual(calls[0], {"usedforsecurity": False})
        self.assertEqual(calls[1], {})
