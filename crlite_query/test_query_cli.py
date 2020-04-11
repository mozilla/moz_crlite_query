import json
import socket
import tempfile
import unittest

from datetime import datetime
from pathlib import Path
from crlite_query import CRLiteDB, IntermediatesDB
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


class MockCollectionRequestHandler(BaseHTTPRequestHandler):
    def serve_collection(self, files):
        if "/collection" in self.path:
            data = []
            for entry in files:
                collection_item = {
                    "schema": 1,
                    "attachment": {
                        "hash": entry["hash"],
                        "size": entry["path"].stat().st_size,
                        "filename": entry["path"].name,
                        "location": entry["path"].name,
                        "mimetype": entry["content-type"],
                    },
                    "id": entry["hash"],
                    "last_modified": 1,
                }
                collection_item.update(entry["extra"])
                data.append(collection_item)

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"data": data}).encode("utf-8"))
            return

        for e in files:
            if self.path == "/attachments/" + e["path"].name:
                self.send_response(200)
                self.send_header("Content-Type", e["content-type"])
                self.end_headers()
                self.wfile.write(e["path"].read_bytes())
                return

        self.send_error(404, message=self.path)
        return


class MockIntermediatesDataRequestHandler(MockCollectionRequestHandler):
    def do_GET(self):
        self.serve_collection(
            [
                {
                    "path": Path(__file__).resolve().parent
                    / Path("test-intermediate.pem"),
                    "hash": "70f02be25c991671f01c41506e2963211ca7c9b89b59ffad7c412af8b5e1f40c",
                    "content-type": "application/x-pem-file",
                    "extra": {
                        "derHash": "hash",
                        "subject": "subj",
                        "subjectDN": "ZGlzdGluZ3Vpc2hlZE5hbWU=",
                        "pubKeyHash": "hash",
                        "whitelist": False,
                        "crlite_enrolled": True,
                    },
                }
            ]
        )


class MockCRLiteDataRequestHandler(MockCollectionRequestHandler):
    def do_GET(self):
        self.serve_collection(
            [
                {
                    "path": Path(__file__).resolve().parent / Path("test-1.filter"),
                    "hash": "80e8e148fbf95aed39783f1fcc2d4576074f8c487656ca2d53571da4b17e20a9",
                    "content-type": "application/octet-stream",
                    "extra": {
                        "details": {"name": "2020-04-02T06:00:00Z-full"},
                        "incremental": False,
                    },
                },
                {
                    "path": Path(__file__).resolve().parent / Path("test-1.stash"),
                    "hash": "bda63519578e451eeef9c828a003ee249c56b4cb97bdf2909e7563851d2bd985",
                    "content-type": "application/octet-stream",
                    "extra": {
                        "details": {"name": "2020-04-02T12:00:00Z-diff"},
                        "incremental": True,
                    },
                },
            ]
        )


class MockServer(object):
    def __init__(self, handler):
        # Configure mock server.
        self.server_port = MockServer.get_free_port()
        self.server = HTTPServer(("localhost", self.server_port), handler)
        self.base_uri = f"http://localhost:{self.server_port}"

    @classmethod
    def get_free_port(cls):
        s = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
        s.bind(("localhost", 0))
        address, port = s.getsockname()
        s.close()
        return port

    def __enter__(self):
        # Start running mock server in a separate thread.
        # Daemon threads automatically shut down when the main process exits.
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.setDaemon(True)
        self.server_thread.start()
        return self.base_uri

    def __exit__(self, type, value, tb):
        self.server.shutdown()
        self.server.server_close()


class TestCRLiteDB(unittest.TestCase):
    def test_load_empty_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CRLiteDB(db_path=temp_dir)

            self.assertEqual(db.filter_file, None)
            self.assertEqual(db.stash_files, [])
            self.assertEqual(db.latest_covered_date(), None)

            with MockServer(MockCRLiteDataRequestHandler) as base_uri:
                db.update(
                    collection_url=f"{base_uri}/collection/",
                    attachments_base_url=f"{base_uri}/attachments/",
                )

            self.assertNotEqual(db.filter_file, None)
            self.assertEqual(len(db.stash_files), 1)
            self.assertEqual(db.latest_covered_date(), datetime(2020, 4, 2, 12, 0))


class TestIntermediatesDB(unittest.TestCase):
    def test_load_empty_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = IntermediatesDB(db_path=temp_dir)
            self.assertTrue(db.intermediates_path.exists())
            self.assertEqual(list(db.intermediates_path.iterdir()), [])

            with MockServer(MockIntermediatesDataRequestHandler) as base_uri:
                db.update(
                    collection_url=f"{base_uri}/collection/",
                    attachments_base_url=f"{base_uri}/attachments/",
                )

            self.assertEqual(len(list(db.intermediates_path.iterdir())), 1)

            self.assertEqual(len(db), 1)
            self.assertTrue("1 Intermediate" in str(db))

            issuer = db.issuer_by_DN(b"unknownName")
            self.assertEqual(issuer, None)

            issuer = db.issuer_by_DN(b"distinguishedName")
            self.assertNotEqual(issuer, None)
            self.assertEqual(issuer["crlite_enrolled"], True)
            self.assertTrue(issuer["path"].exists())


if __name__ == "__main__":
    unittest.main()
