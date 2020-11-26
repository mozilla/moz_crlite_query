import argparse
import logging
import requests
import sys

from crlite_query import CRLiteDB, CRLiteQuery, IntermediatesDB, parse_hosts_file
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("query_cli")


crlite_collection_prod = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/security-state"
    + "/collections/cert-revocations/records"
)
crlite_collection_stage = (
    "https://settings.stage.mozaws.net/v1/buckets/security-state"
    + "/collections/cert-revocations/records"
)
intermediates_collection_prod = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/security-state"
    + "/collections/intermediates/records"
)


def find_attachments_base_url(urlstring):
    url = urlparse(urlstring)
    base_rsp = requests.get(f"{url.scheme}://{url.netloc}/v1/")
    return base_rsp.json()["capabilities"]["attachments"]["base_url"]


def main():
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
        "--hosts",
        help="Hosts to check, in the form host[:port] where "
        + "port is assumed 443 if not provided. Can be specified multiple times.",
        action="append",
        nargs="+",
        default=[],
        metavar="host[:port]",
    )
    parser.add_argument(
        "--hosts-file",
        help="File of hosts to check, in the form of 'host[:port]' each line, "
        + "where port is assumed 443 if not provided. Can be specified multiple "
        + " times.",
        action="append",
        default=[],
        type=Path,
    )
    parser.add_argument(
        "files", help="PEM files to load", type=argparse.FileType("r"), nargs="*"
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
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--force-update", help="Force an update to the database", action="store_true"
    )
    group.add_argument(
        "--use-filter",
        help="Use this specific filter file, ignoring the database",
        type=Path,
    )
    parser.add_argument(
        "--check-freshness",
        help="Set exit code 0 if the database is more than this many hours old",
        type=int,
    )
    parser.add_argument(
        "--check-not-revoked",
        help="Set exit code 0 if none of the supplied certificates are revoked",
        action="store_true",
    )
    parser.add_argument(
        "--no-delete",
        help="Do not attempt to delete old database files",
        action="store_true",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--crlite-url",
        default=crlite_collection_prod,
        help="URL to the CRLite records at Remote Settings.",
    )
    group.add_argument(
        "--crlite-staging",
        action="store_true",
        help="Use the staging URL for CRLite",
    )
    parser.add_argument(
        "--intermediates-url",
        default=intermediates_collection_prod,
        help="URL to the CRLite records at Remote Settings.",
    )
    parser.add_argument(
        "--download-intermediates",
        action="store_true",
        help="Download all intermediate PEM files to the database",
    )
    parser.add_argument(
        "--verbose", "-v", help="Be more verbose", action="count", default=0
    )
    parser.add_argument(
        "--structured",
        help="Emit log entries intended for structured loggers",
        action="store_true",
    )

    args = parser.parse_args()

    if args.crlite_staging:
        args.crlite_url = crlite_collection_stage

    if args.verbose > 1:
        logging.basicConfig(level=logging.DEBUG)
        if args.verbose > 2:
            from pyasn1 import debug

            debug.setLogger(debug.Debug("all"))
    else:
        logging.basicConfig(level=logging.INFO)

    db_dir = args.db.expanduser()

    if not db_dir.is_dir():
        db_dir.expanduser().mkdir()

    last_updated_file = (db_dir / ".last_updated").expanduser()
    if last_updated_file.exists() and not args.force_update:
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

    intermediates_db = IntermediatesDB(
        db_path=db_dir, download_pems=args.download_intermediates
    )
    crlite_db = CRLiteDB(db_path=args.db)

    try:
        if args.force_update or not args.no_update:
            if args.download_intermediates:
                log.info(
                    "Downloading all intermediate certificates. Look in "
                    + f"{intermediates_db.intermediates_path}"
                )

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

    if args.use_filter:
        crlite_db.load_filter(path=args.use_filter)

    if not args.no_delete:
        crlite_db.cleanup()

    log.info(f"Status: {intermediates_db}, {crlite_db}")

    if args.check_freshness:
        freshness_limit = timedelta(hours=args.check_freshness)
        if crlite_db.age() > freshness_limit:
            log.error(
                f"Database age is {crlite_db.age()}, which is larger than {freshness_limit}, "
                + "aborting!"
            )
            sys.exit(1)

    query = CRLiteQuery(intermediates_db=intermediates_db, crlite_db=crlite_db)

    if not args.files and not args.hosts and not args.hosts_file:
        log.info("No PEM files or hosts specified to load. Run with --help for usage.")

    to_test = list()

    for file in args.files:
        to_test.append((file.name, query.gen_from_pem(file)))

    host_strings = []
    for host_list in args.hosts:
        host_strings.extend(host_list)

    for path in args.hosts_file:
        with path.open("r") as fd:
            host_strings.extend(parse_hosts_file(fd))

    for host_str in host_strings:
        parts = host_str.split(":")
        hostname = parts[0]
        port = 443
        if len(parts) > 1:
            port = int(parts[1])
        to_test.append((f"{hostname}:{port}", query.gen_from_host(hostname, port)))

    failures = list()

    for (name, generator) in to_test:
        for result in query.query(name=name, generator=generator):
            if args.structured:
                result.log_query_result()
            else:
                result.print_query_result(verbose=args.verbose)

            if args.check_not_revoked and result.is_revoked():
                failures.append(result)

    if failures:
        log.error(f"{len(failures)} failures logged:")
        for result in failures:
            log.error(result)
        sys.exit(1)


if __name__ == "__main__":
    main()
