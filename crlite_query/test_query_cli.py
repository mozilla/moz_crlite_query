import json
import io
import socket
import tempfile
import unittest
import crlite_query

from datetime import datetime, timezone
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
                    "hash": "29bdc4ccfe77dcdc83067d33d884bca8ce9418a358a5837aa30eb81f4455e2f5",
                    "content-type": "application/octet-stream",
                    "extra": {
                        "details": {"name": "2022-01-03T18:08:48+00:00Z-full"},
                        "incremental": False,
                        "effectiveTimestamp": 1641233328000,
                        "id": "d461ffaa-337a-4e82-8608-2b8a34b9f476",
                        "coverage": [
                            {
                                "logID": "ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=",
                                "maxTimestamp": 1641229825819,
                                "minTimestamp": 1530194976600,
                            },
                            {
                                "logID": "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=",
                                "maxTimestamp": 1639518268919,
                                "minTimestamp": 1560299813384,
                            },
                            {
                                "logID": "QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvY=",
                                "maxTimestamp": 1641228904427,
                                "minTimestamp": 1530163848283,
                            },
                            {
                                "logID": "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=",
                                "maxTimestamp": 1641030593683,
                                "minTimestamp": 1630323561351,
                            },
                            {
                                "logID": "XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=",
                                "maxTimestamp": 1640994848041,
                                "minTimestamp": 1513345434092,
                            },
                        ],
                    },
                },
                {
                    "path": Path(__file__).resolve().parent / Path("test-1.stash"),
                    "hash": "fd3c4bbde807233854671be482ed8d9ede40b6d1c6af3a0a4cfe37b26560dbc3",
                    "content-type": "application/octet-stream",
                    "extra": {
                        "details": {"name": "2022-01-04T00:08:27+00:00Z-diff"},
                        "incremental": True,
                        "effectiveTimestamp": 1641254907000,
                        "parent": "d461ffaa-337a-4e82-8608-2b8a34b9f476",
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

            with MockServer(MockCRLiteDataRequestHandler) as base_uri:
                db.update(
                    collection_url=f"{base_uri}/collection/",
                    attachments_base_url=f"{base_uri}/attachments/",
                )

            self.assertNotEqual(db.filter_file, None)
            self.assertEqual(len(db.stash_files), 1)

    def test_load_explicit_filter(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CRLiteDB(db_path=temp_dir)

            self.assertEqual(db.filter_file, None)
            self.assertEqual(db.stash_files, [])
            base_path = Path(__file__).resolve().parent

            db.load_filter(
                filter_path=base_path / "test-1.filter",
                coverage_path=base_path / "test-1.coverage",
            )
            self.assertEqual(db.stash_files, [])


class TestIntermediatesDB(unittest.TestCase):
    def test_load_empty_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = IntermediatesDB(db_path=temp_dir, download_pems=True)
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


class TestHostFileParsing(unittest.TestCase):
    def test_empty_file(self):
        results = crlite_query.parse_hosts_file(io.StringIO(""))
        self.assertFalse(results)

    def test_only_comments(self):
        results = crlite_query.parse_hosts_file(
            io.StringIO(
                """
            # this is a comment
            ; and so is this

            # and that was a blank line
        """
            )
        )
        self.assertFalse(results)

    def test_one_host_and_comments(self):
        results = crlite_query.parse_hosts_file(
            io.StringIO(
                """
            # this is a comment
            ; and so is this
            example.com:999
            # and that was a blank line
        """
            )
        )
        self.assertEqual(results, ["example.com:999"])

    def test_two_hosts_and_comments(self):
        results = crlite_query.parse_hosts_file(
            io.StringIO(
                """
            example.net
            \t# this is a comment
            ; \tand so is this
            example.com:999
            # okay we should be done now
        """
            )
        )
        self.assertEqual(results, ["example.net", "example.com:999"])

    def test_one_host(self):
        results = crlite_query.parse_hosts_file(
            io.StringIO(
                """
            example.com:112
        """
            )
        )
        self.assertEqual(results, ["example.com:112"])


if __name__ == "__main__":
    unittest.main()
