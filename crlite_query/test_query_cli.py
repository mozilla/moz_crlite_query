import unittest
import tempfile

from crlite_query import CRLiteDB


class TestCRLiteDB(unittest.TestCase):
    def test_load_empty_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CRLiteDB(db_path=temp_dir)

        self.assertEqual(db.filter_file, None)
        self.assertEqual(db.stash_files, [])


if __name__ == "__main__":
    unittest.main()
