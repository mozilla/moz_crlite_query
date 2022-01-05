import base64
import collections
import hashlib
import json
import logging
import progressbar
import re
import requests
import socket
import sqlite3
import ssl
import sys

from datetime import datetime, timezone
from filtercascade import FilterCascade
from moz_crlite_lib import CertId, IssuerId, readFromAdditionsList
from pathlib import Path
from pyasn1_modules import pem
from urllib.parse import urljoin

from cryptography import x509

log = logging.getLogger("crlite_query")

assert sqlite3.sqlite_version_info >= (3, 24), "Requires SQLite 3.24 or newer"
assert sys.version_info >= (3, 7), "Requires Python 3.7 or newer"


def ensure_local(*, base_url, entry, local_path):
    url = urljoin(base_url, entry["attachment"]["location"])
    if local_path.is_file():
        h = hashlib.sha256()
        h.update(local_path.read_bytes())
        if h.hexdigest() == entry["attachment"]["hash"]:
            log.debug(f"Already downloaded {local_path}")
            return
        else:
            log.warning(
                f"While updating, {local_path.name} local sha256 digest is "
                + f"{h.hexdigest()} but remote indicates it should be "
                + f"{entry['attachment']['hash']}, re-downloading."
            )

    log.debug(f"Downloading {url} to {local_path}")
    rsp = requests.get(url, stream=True)
    rsp.raise_for_status()

    local_path.write_bytes(rsp.content)

    h = hashlib.sha256()
    h.update(local_path.read_bytes())
    if h.hexdigest() != entry["attachment"]["hash"]:
        log.warning(
            f"While updating, {local_path.name} local sha256 digest is "
            + f"{h.hexdigest()} but remote indicates it should be "
            + f"{entry['attachment']['hash']}, raising exception."
        )
        raise ValueError(f"Hash mismatch on downloaded file {local_path}")


comment_re = re.compile(r"^\s*[#;]")


def parse_hosts_file(fd):
    host_strings = []
    for l in fd:
        line = l.strip()
        if line and not comment_re.match(line):
            host_strings.append(line)
    return host_strings


def uint_to_serial_bytes(a):
    # Encode the non-negative integer |a| as a DER integer without the leading
    # tag and length prefix. The DER encoding of |a| is the shortest octet
    # string that encodes |a| in big endian two's complement form.
    assert(a >= 0)

    # Since |a| is non-negative, the shortest bit string that encodes it in
    # big-endian two's complement form has a leading 0 bit. Positive python
    # integers have a `bit_length` method that gives the index of the leading 1
    # bit. The minimal two's complement bit length is one more than this.
    #
    # NB: Python defines |int(0).bit_length() == 0|. The other cases are more
    # intuitive; for positive integers k and x with 2**k > x we have
    # |int(2**k + x).bit_length() == k+1|.
    bit_len = 1 + a.bit_length()
    byte_len = (bit_len + 7) // 8
    return a.to_bytes(byte_len, byteorder="big", signed=False)


class IntermediatesDB(object):
    def __init__(self, *, db_path, download_pems=False):
        self.db_path = Path(db_path).expanduser()
        self.conn = sqlite3.connect(str(self.db_path / Path("intermediates.sqlite")))
        self.conn.row_factory = sqlite3.Row
        self.download_pems = download_pems
        self.intermediates_path = self.db_path / "intermediates"
        if self.download_pems:
            self.intermediates_path.mkdir(exist_ok=True)

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS intermediates (
                id TEXT PRIMARY KEY, last_modified TEXT, subject TEXT,
                subjectDN BLOB, derHash BLOB, pubKeyHash BLOB,
                crlite_enrolled BOOLEAN, whitelist BOOLEAN)"""
        )

    def __len__(self):
        with self.conn as c:
            cur = c.cursor()
            cur.execute("SELECT COUNT(*) FROM intermediates;")
            return cur.fetchone()[0]

    def __str__(self):
        return f"{len(self)} Intermediates"

    def update(self, *, collection_url, attachments_base_url):
        rsp = requests.get(collection_url)

        all_remote_ids = {x["id"] for x in rsp.json()["data"]}

        with self.conn as c:
            c.executemany(
                """INSERT INTO intermediates (id, last_modified,
                                    subject, subjectDN, derHash, pubKeyHash,
                                    crlite_enrolled, whitelist)
                             VALUES(:id, :last_modified, :subject, :subjectDN,
                                    :derHash, :pubKeyHash, :crlite_enrolled,
                                    :whitelist)
                             ON CONFLICT(id)
                             DO UPDATE SET id=:id, last_modified=:last_modified,
                                    subject=:subject, subjectDN=:subjectDN,
                                    derHash=:derHash, pubKeyHash=:pubKeyHash,
                                    crlite_enrolled=:crlite_enrolled,
                                    whitelist=:whitelist;
                            """,
                rsp.json()["data"],
            )

        if self.download_pems:
            log.info(f"Intermediates Update: Syncing intermediate certificates.")
            count = 0
            for entry in progressbar.progressbar(rsp.json()["data"]):
                local_path = self.intermediates_path / entry["id"]
                ensure_local(
                    base_url=attachments_base_url, entry=entry, local_path=local_path
                )
                count += 1

            log.info(f"Intermediates Update: {count} intermediates up-to-date.")

        with self.conn as c:
            cur = c.cursor()
            all_local_ids = {
                x["id"] for x in cur.execute("SELECT id FROM intermediates;").fetchall()
            }

            ids_to_remove = all_local_ids - all_remote_ids
            if ids_to_remove:
                log.info(
                    f"A total of {len(ids_to_remove)} intermediates have been removed. "
                    + "Syncing deletions."
                )

            for id_to_remove in ids_to_remove:
                path = self.intermediates_path / id_to_remove
                log.debug(f"Removing {path.name} (on disk={path.exists()})")
                if path.exists():
                    path.unlink()
                c.execute(
                    "DELETE FROM intermediates WHERE id=:id;", {"id": id_to_remove}
                )

    def issuer_by_DN(self, distinguishedName):
        with self.conn as c:
            cur = c.cursor()
            cur.execute(
                "SELECT id, subject, pubKeyHash, crlite_enrolled FROM intermediates "
                + "WHERE subjectDN=:dn LIMIT 1;",
                {"dn": base64.urlsafe_b64encode(bytes(distinguishedName)).decode("utf-8")},
            )
            row = cur.fetchone()
            if not row:
                return None
            data = {
                "subject": row["subject"],
                "spki_hash_bytes": base64.urlsafe_b64decode(row["pubKeyHash"]),
                "crlite_enrolled": row["crlite_enrolled"] == 1,
                "issuerId": IssuerId(base64.urlsafe_b64decode(row["pubKeyHash"])),
            }
            pem_path = Path(self.intermediates_path) / Path(row["id"])
            if pem_path.is_file():
                data["path"] = pem_path

            return data


class CRLiteDB(object):
    def __init__(self, *, db_path):
        self.db_path = Path(db_path).expanduser()
        self.filter_file = None
        self.coverage_file = None
        self.stash_files = list()
        self.issuer_to_revocations = collections.defaultdict(list)
        self.filtercascade = None
        self.coverage = None

        if self.db_path.is_dir():
            self.__load()
        else:
            self.db_path.mkdir()

    def __str__(self):
        count_revocations = sum(
            map(
                lambda x: len(self.issuer_to_revocations[x]), self.issuer_to_revocations
            )
        )
        return (
            f"Current filter: {self.filter_file.stem} with {self.filtercascade.layerCount()} "
            + f"layers and {self.filtercascade.bitCount()} bit-count, {len(self.stash_files)} "
            + f"stash files with {count_revocations} stashed revocations. Age {self.age()}."
        )

    def filter_date(self):
        if not self.filter_file:
            return None
        time_str = self.filter_file.name.replace("Z-full", "")
        try:
            return datetime.fromisoformat(time_str).replace(tzinfo=timezone.utc)
        except ValueError as ve:
            log.warning(
                f"Couldn't decode filter path into timestamp, assuming it's right now: {ve}"
            )
            return datetime.now(tz=timezone.utc)

    def latest_stash_date(self):
        if not self.stash_files:
            return None
        time_str = self.stash_files[-1].name.replace("Z-diff", "")
        try:
            return datetime.fromisoformat(time_str).replace(tzinfo=timezone.utc)
        except ValueError as ve:
            log.warning(
                f"Couldn't decode stash path into timestamp, assuming it's right now: {ve}"
            )
            return datetime.now(tz=timezone.utc)

    def age(self):
        last_update = self.latest_stash_date() or self.filter_date() or datetime.datetime.min
        return datetime.now(tz=timezone.utc) - last_update

    def load_filter(self, *, filter_path, coverage_path):
        self.filter_file = filter_path
        self.coverage_file = coverage_path
        self.filtercascade = FilterCascade.from_buf(self.filter_file.read_bytes())
        self.issuer_to_revocations = collections.defaultdict(list)
        self.stash_files = list()
        self.coverage = {}
        with open(coverage_path, "r") as f:
            for ct_log in json.load(f):
                log_id = base64.b64decode(ct_log["logID"])
                self.coverage[log_id] = (ct_log["minTimestamp"], ct_log["maxTimestamp"])

    def load_stashes(self, *, stashes):
        filter_date_str = self.filter_file.stem

        self.stash_files = list(
            filter(lambda x: str(x.name) > filter_date_str, sorted(stashes))
        )
        for path in self.stash_files:
            with path.open("rb") as f:
                for entry in readFromAdditionsList(f):
                    self.issuer_to_revocations[entry["issuerId"]].extend(
                        entry["revocations"]
                    )

    def __load(self):
        filters = sorted(self.db_path.glob("*-full"))
        if not filters:
            return

        coverage = sorted(self.db_path.glob("*-coverage"))
        if not coverage:
            return

        self.load_filter(filter_path=filters.pop(), coverage_path=coverage.pop())
        self.load_stashes(stashes=self.db_path.glob("*-diff"))

    def cleanup(self):
        filters = sorted(self.db_path.glob("*-full"))
        if filters:
            filters.pop()  # Leave the most recent
        for old_filter in filters:
            log.debug(f"Cleaning up old filter {old_filter}")
            old_filter.unlink()

        old_stashes = set(self.db_path.glob("*-diff")) - set(self.stash_files)
        for old_stash in old_stashes:
            log.debug(f"Cleaning up old stash {old_stash}")
            old_stash.unlink()

    def update(self, *, collection_url, attachments_base_url):
        rsp = requests.get(collection_url)
        entries = rsp.json()["data"]
        filter_entries = list(filter(lambda x: x["incremental"] is False, entries))
        stash_entries = sorted(
            filter(lambda x: x["incremental"] is True, entries),
            key=lambda x: x["details"]["name"],
        )

        if len(filter_entries) != 1:
            log.warning(
                f"Unexpected: Found more than one full filter at Remote Settings, "
                + f"found {len(filter_entries)}: {filter_entries}"
            )

        log.info(f"CRLite Update: Syncing CRLite filters.")

        all_entries = stash_entries + [filter_entries.pop()]

        for entry in progressbar.progressbar(all_entries):
            log.debug(f"Downloading Kinto entry={entry})")
            local_path = self.db_path / entry["details"]["name"]
            ensure_local(
                base_url=attachments_base_url, local_path=local_path, entry=entry
            )
            if entry["incremental"]:
                self.stash_files.append(local_path)
            else:
                self.filter_file = local_path
                coverage_path = self.db_path / (entry["details"]["name"].rstrip("full") + "coverage")
                with open(coverage_path, "w") as f:
                    json.dump(entry["coverage"], f)

        self.__load()

    def download_to_db(self, *, base_url, entry):
        local_path = self.db_path / entry["details"]["name"]
        ensure_local(base_url=base_url, local_path=local_path, entry=entry)
        return local_path

    def validity_window_status(self, issue_time, expire_time):
        return "Too New"

    def covers(self, timestamps):
        if not timestamps:
            return False
        for log_id, timestamp in timestamps.items():
            if log_id not in self.coverage:
                continue
            minT, maxT = self.coverage[log_id]
            if minT <= timestamp and timestamp <= maxT:
                return True
        return False

    def revocation_status(self, certId):
        results = {}

        revoked_in_crlite = certId.to_bytes() in self.filtercascade
        if revoked_in_crlite:
            results["via_filter"] = self.filter_file.name

        revoked_in_stash = False
        for path in self.stash_files:
            with path.open("rb") as f:
                for entry in readFromAdditionsList(f):
                    if (
                        entry["issuerId"] == certId.issuerId
                        and certId in entry["revocations"]
                    ):
                        revoked_in_stash = True
                        results["via_stash"] = path.name
                        break

        results["revoked"] = revoked_in_crlite or revoked_in_stash
        return results


class CRLiteQueryResult(object):
    def __init__(self, *, name, issuer, cert_id, crlite_db, timestamps):
        self.name = name
        self.issuer = issuer
        self.cert_id = cert_id
        self.timestamps = timestamps
        self.via_stash = None
        self.via_filter = None

        if not issuer:
            self.state = "Unknown Issuer"
            return

        if not issuer["crlite_enrolled"]:
            self.state = "Not Enrolled"
            return

        if not crlite_db.covers(timestamps):
            self.state = "Not Covered"
            return

        rev_status = crlite_db.revocation_status(self.cert_id)

        self.state = "Revoked" if rev_status["revoked"] else "Valid"
        self.via_stash = rev_status.get("via_stash")
        self.via_filter = rev_status.get("via_filter")

    def __str__(self):
        return f"{self.name} {self.cert_id} state={self.state}"

    def is_revoked(self):
        return self.state == "Revoked"

    def result_icon(self):
        if self.state == "Revoked":
            return "⛔️"
        if self.state == "Not Enrolled":
            return "❔"
        if self.state == "Valid":
            return "👍"
        if self.state == "Too New":
            return "🐇"
        if self.state == "Expired":
            return "⏰"
        if self.state == "Unknown Issuer":
            return "⁉️"
        return ""

    def print_query_result(self, *, verbose=0):
        padded_name = self.name + " " * 5
        padding = "".ljust(len(padded_name))

        if not self.issuer:
            self.state = "Unknown Issuer"
        else:
            enrolled_icon = "✅" if self.issuer["crlite_enrolled"] else "❌"

            print(f"{padded_name} Issuer: {self.issuer['subject']}")
            print(f"{padding} Enrolled in CRLite: {enrolled_icon}")
            if verbose > 0:
                print(f"{padding} {self.cert_id}")
            if self.via_filter:
                print(f"{padding} Revoked via CRLite filter: {self.via_filter}")
            if self.via_stash:
                print(f"{padding} Revoked via Stash: {self.via_stash}")

        print(
            f"{padding} Result: {self.result_icon()} {self.state} {self.result_icon()}"
        )

    def log_query_result(self):
        if not self.issuer:
            log.warning(f"{self.name} Unknown issuer")
            return

        logdata = {
            "name": self.name,
            "issuer": self.issuer["subject"],
            "state": self.state,
            "enrolled_in_crlite": self.issuer["crlite_enrolled"],
            "cert_id": str(self.cert_id),
            "via_filter": self.via_filter,
            "via_stash": self.via_stash,
        }

        if self.state == "Revoked":
            log.warning(json.dumps(logdata))
        else:
            log.info(json.dumps(logdata))


class CRLiteQuery(object):
    def __init__(self, *, intermediates_db, crlite_db):
        self.intermediates_db = intermediates_db
        self.crlite_db = crlite_db
        self.context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS, ca_certs=None)

    def gen_from_host(self, host, port):
        try:
            with self.context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=host,
                do_handshake_on_connect=True,
            ) as conn:
                conn.connect((host, port))
                yield conn.getpeercert(binary_form=True)
        except ssl.SSLError as se:
            logging.warning(f"Failed to fetch from {host}:{port}: {se}")
        except TimeoutError:
            logging.warning(f"Failed to fetch from {host}:{port}: timed out")
        except Exception as e:
            logging.warning(f"Failed to fetch from {host}:{port}: {e}")
        return

    def gen_from_pem(self, file_obj):
        while True:
            data = pem.readPemFromFile(file_obj)
            if not data:
                return
            yield data

    def query(self, *, name, generator):
        for data in generator:
            cert = x509.load_der_x509_certificate(data)
            serial_number = cert.serial_number

            serial_bytes = uint_to_serial_bytes(int(serial_number))

            issuerDN = cert.issuer.public_bytes()
            issuer = self.intermediates_db.issuer_by_DN(issuerDN)
            if not issuer:
                yield CRLiteQueryResult(
                    name=name,
                    issuer=None,
                    cert_id=None,
                    crlite_db=self.crlite_db,
                    timestamps=None,
                )
                continue

            cert_id = CertId(issuer["issuerId"], serial_bytes)

            timestamps = {}
            try:
                scts = cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value
            except x509.ExtensionNotFound:
                pass
            else:
                for sct in scts:
                    # sct.timestamp is a python datetime.datetime with
                    # millisecond precision and the timezone set to UTC. We
                    # want milliseconds since epoch. Since timestamps are
                    # "small", the float |sct.timestamp.timestamp() * 1000|
                    # will be exactly representable and truncating with int()
                    # will give the correct result.
                    timestamps[sct.log_id] = int(sct.timestamp.timestamp() * 1000)

            yield CRLiteQueryResult(
                name=name,
                issuer=issuer,
                cert_id=cert_id,
                crlite_db=self.crlite_db,
                timestamps=timestamps,
            )
