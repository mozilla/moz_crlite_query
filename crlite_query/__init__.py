import base64
import collections
import hashlib
import logging
import requests
import progressbar
import sqlite3

from datetime import datetime
from filtercascade import FilterCascade
from moz_crlite_lib import CertId, IssuerId, readFromAdditionsList
from pathlib import Path
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1_modules import pem
from pyasn1_modules import rfc2459
from urllib.parse import urljoin

log = logging.getLogger("crlite_query")


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


class IntermediatesDB(object):
    def __init__(self, *, db_path):
        self.db_path = Path(db_path).expanduser()
        self.conn = sqlite3.connect(self.db_path / Path("intermediates.sqlite"))
        self.intermediates_path = self.db_path / "intermediates"
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

        log.info(f"Intermediates Update: Syncing intermediate certificates.")
        count = 0
        for entry in progressbar.progressbar(rsp.json()["data"]):
            local_path = self.intermediates_path / entry["id"]
            ensure_local(
                base_url=attachments_base_url, entry=entry, local_path=local_path
            )
            count += 1

        log.info(f"Intermediates Update: {count} intermediates up-to-date.")

    def issuer_by_DN(self, distinguishedName):
        with self.conn as c:
            cur = c.cursor()
            cur.execute(
                "SELECT id, subject, pubKeyHash, crlite_enrolled FROM intermediates "
                + "WHERE subjectDN=:dn LIMIT 1;",
                {"dn": base64.b64encode(bytes(distinguishedName)).decode("utf-8")},
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "path": Path(self.intermediates_path) / Path(row[0]),
                "subject": row[1],
                "spki_hash_bytes": base64.b64decode(row[2]),
                "crlite_enrolled": row[3] == 1,
                "issuerId": IssuerId(base64.b64decode(row[2])),
            }


class CRLiteDB(object):
    def __init__(self, *, db_path):
        self.db_path = Path(db_path).expanduser()
        self.filter_file = None
        self.stash_files = list()
        self.issuer_to_revocations = collections.defaultdict(list)
        self.filtercascade = None

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
            + f"stash files with {count_revocations} stashed revocations, up-to-date as of "
            + f"{self.latest_covered_date()}."
        )

    def filter_date(self):
        if not self.filter_file:
            return None
        time_str = self.filter_file.name.replace("Z-full", "")
        return datetime.fromisoformat(time_str)

    def latest_stash_date(self):
        if not self.stash_files:
            return None
        time_str = self.stash_files[-1].name.replace("Z-diff", "")
        return datetime.fromisoformat(time_str)

    def latest_covered_date(self):
        if self.stash_files:
            return self.latest_stash_date()
        return self.filter_date()

    def __load(self):
        filters = sorted(self.db_path.glob("*-full"))
        if not filters:
            return

        self.filter_file = filters.pop()
        filter_date_str = self.filter_file.stem

        self.filtercascade = FilterCascade.from_buf(self.filter_file.read_bytes())

        self.issuer_to_revocations = collections.defaultdict(list)

        stashes = sorted(self.db_path.glob("*-diff"))
        self.stash_files = list(
            filter(lambda x: str(x.name) > filter_date_str, stashes)
        )
        for path in self.stash_files:
            with path.open("rb") as f:
                for entry in readFromAdditionsList(f):
                    self.issuer_to_revocations[entry["issuerId"]].extend(
                        entry["revocations"]
                    )

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

        filter_entry = filter_entries.pop()
        self.filter_file = self.download_to_db(
            base_url=attachments_base_url, entry=filter_entry
        )
        for entry in progressbar.progressbar(stash_entries):
            path = self.download_to_db(base_url=attachments_base_url, entry=entry)
            self.stash_files.append(path)

        self.__load()

    def download_to_db(self, *, base_url, entry):
        local_path = self.db_path / entry["details"]["name"]
        ensure_local(base_url=base_url, local_path=local_path, entry=entry)
        return local_path

    def validity_window_status(self, issue_time, expire_time):
        return "Too New"

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


# Theoretically this should get us the raw serial, but it... doesn't.
# class RawSerial(univ.OctetString):
#     tagSet = tag.initTagSet(
#         tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x02)
#     )
#     subtypeSpec = constraint.ConstraintsIntersection()
#     typeId = univ.OctetString.getTypeId()


class RawTBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType(
            "version",
            rfc2459.Version("v1").subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.NamedType("serialNumber", univ.Integer()),
        namedtype.NamedType("signature", rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType("issuer", univ.Any()),
        namedtype.NamedType("validity", rfc2459.Validity()),
        namedtype.NamedType("subject", rfc2459.Name()),
        namedtype.NamedType("subjectPublicKeyInfo", rfc2459.SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType(
            "issuerUniqueID",
            rfc2459.UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
        namedtype.OptionalNamedType(
            "subjectUniqueID",
            rfc2459.UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            ),
        ),
        namedtype.OptionalNamedType(
            "extensions",
            rfc2459.Extensions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            ),
        ),
    )


class RawCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbsCertificate", RawTBSCertificate()),
        namedtype.NamedType("signatureAlgorithm", rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue", univ.BitString()),
    )


class CRLiteQuery(object):
    def __init__(self, *, intermediates_db, crlite_db):
        self.intermediates_db = intermediates_db
        self.crlite_db = crlite_db

    def pem(self, file_obj):
        while True:
            data = pem.readPemFromFile(file_obj)
            if not data:
                return
            cert, rest = der_decoder(data, asn1Spec=RawCertificate())
            assert not rest, f"unexpected leftovers in ASN.1 decoding: {rest}"

            serial_number = cert.getComponentByName(
                "tbsCertificate"
            ).getComponentByName("serialNumber")

            # Serial numbers are represented big-endian
            serial_bytes = int(serial_number).to_bytes(
                (int(serial_number).bit_length() + 7) // 8,
                byteorder="big",
                signed=False,
            )

            issuerDN = cert.getComponentByName("tbsCertificate").getComponentByName(
                "issuer"
            )
            issuer = self.intermediates_db.issuer_by_DN(issuerDN)

            issuerId = issuer["issuerId"]
            certId = CertId(issuerId, serial_bytes)

            result = {
                "issuerId": issuerId,
                "issuer_enrolled": issuer["crlite_enrolled"],
                "issuer": issuer["subject"],
                "certId": certId,
                "state": "Unknown",
            }

            validity = cert.getComponentByName("tbsCertificate").getComponentByName(
                "validity"
            )
            not_before = validity.getComponentByName("notBefore").getComponent()
            not_before = datetime.strptime(str(not_before), "%y%m%d%H%M%SZ")
            not_after = validity.getComponentByName("notAfter").getComponent()
            not_after = datetime.strptime(str(not_after), "%y%m%d%H%M%SZ")

            if issuer["crlite_enrolled"]:
                result.update(self.crlite_db.revocation_status(certId))

            if not result["issuer_enrolled"]:
                result["state"] = "Not Enrolled"
            elif result["revoked"] is True:
                result["state"] = "Revoked"
            elif self.crlite_db.latest_covered_date() < not_before:
                result["state"] = "Too New"
            elif self.crlite_db.latest_covered_date() > not_after:
                result["state"] = "Expired"
            else:
                result["state"] = "Valid"

            yield result

    def print_pem(self, file_obj):
        padded_name = file_obj.name + " " * 5
        padding = "".ljust(len(padded_name))

        for result in self.pem(file_obj):
            enrolled_icon = "✅" if result["issuer_enrolled"] else "❌"

            print(f"{padded_name} Issuer: {result['issuer']}")
            print(f"{padding} Enrolled in CRLite: {enrolled_icon}")
            print(f"{padding} {result['certId']}")
            if "via_filter" in result:
                print(f"{padding} Revoked via CRLite filter: {result['via_filter']}")
            if "via_stash" in result:
                print(f"{padding} Revoked via Stash: {result['via_stash']}")

            result_icon = ""
            if result["state"] == "Revoked":
                result_icon = "⛔️"
            elif result["state"] == "Not Enrolled":
                result_icon = "❌"
            elif result["state"] == "Valid":
                result_icon = "👍"
            elif result["state"] == "Too New":
                result_icon = "🐇"
            elif result["state"] == "Expired":
                result_icon = "⏰"

            print(f"{padding} Result: {result_icon} {result['state']} {result_icon}")
