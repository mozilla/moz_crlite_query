import argparse
import logging
import requests
import sys

from crlite_query import CRLiteDB, CRLiteQuery, IntermediatesDB
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("query_cli")


def find_attachments_base_url(urlstring):
    url = urlparse(urlstring)
    base_rsp = requests.get(f"{url.scheme}://{url.netloc}/v1/")
    return base_rsp.json()["capabilities"]["attachments"]["base_url"]


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description="Query CRLite data",
        epilog="""
      The --db option should point to a folder containing a single filter file of
      the form "YYYYMMDDnn.filter" along with a collection of files of the form
      "YYYYMMDDnn.stash" which contain updates from that original filter. By
      default, if this tool believes it is out-of-date based on the local
      database, it will attempt to update itself before performing its checks.
      To avoid that behavior, pass --no-update on the command line.
    """,
    )
    parser.add_argument(
        "files", help="PEM files to load", type=argparse.FileType("r"), nargs="+"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("~/.crlite_db"),
        help="Path to CRLite database folder",
    )
    parser.add_argument(
        "--no-update", help="Do not attempt to update the database", action="store_true"
    )
    parser.add_argument(
        "--force-update", help="Force an update to the database", action="store_true"
    )
    parser.add_argument(
        "--no-delete",
        help="Do not attempt to delete old database files",
        action="store_true",
    )
    parser.add_argument(
        "--crlite-url",
        default="https://settings.prod.mozaws.net/v1/buckets/security-state"
        + "/collections/cert-revocations/records",
        help="URL to the CRLite records at Remote Settings.",
    )
    parser.add_argument(
        "--intermediates-url",
        default="https://settings.prod.mozaws.net/v1/buckets/security-state"
        + "/collections/intermediates/records",
        help="URL to the CRLite records at Remote Settings.",
    )
    parser.add_argument(
        "--verbose", "-v", help="Be more verbose", action="count", default=0
    )

    args = parser.parse_args()

    if args.verbose > 0:
        log.setLevel("DEBUG")
        if args.verbose > 1:
            from pyasn1 import debug

            debug.setLogger(debug.Debug("all"))

    db_dir = args.db.expanduser()

    if not db_dir.is_dir():
        db_dir.expanduser().mkdir()

    last_updated_file = (db_dir / ".last_updated").expanduser()
    if last_updated_file.exists():
        updated_file_timestamp = datetime.fromtimestamp(
            last_updated_file.stat().st_mtime
        )
        grace_time = datetime.now() - timedelta(hours=6)
        if last_updated_file.is_file() and updated_file_timestamp > grace_time:
            log.info(f"Database was updated at {updated_file_timestamp}, skipping.")
            log.debug(
                f"Database was last updated {datetime.now() - updated_file_timestamp} ago."
            )
            args.no_update = True

    attachments_base_url = find_attachments_base_url(args.crlite_url)

    intermediates_db = IntermediatesDB(db_path=db_dir)
    crlite_db = CRLiteDB(db_path=args.db)

    try:
        if args.force_update or not args.no_update:
            intermediates_db.update(
                collection_url=args.intermediates_url,
                attachments_base_url=attachments_base_url,
            )
            crlite_db.update(
                collection_url=args.crlite_url,
                attachments_base_url=attachments_base_url,
            )
            last_updated_file.touch()
    except KeyboardInterrupt:
        log.warning("Interrupted.")
        sys.exit(1)

    if not args.no_delete:
        crlite_db.cleanup()

    log.info(f"Status: {intermediates_db}, {crlite_db}")

    query = CRLiteQuery(intermediates_db=intermediates_db, crlite_db=crlite_db)

    for file in args.files:
        query.print_pem(file)


if __name__ == "__main__":
    main()
