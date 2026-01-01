"""Command-line interface for the static traffic analyzer."""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .evaluator import MatchMode, evaluate_policy
from .models import Decision
from .parsers.db import parse_database
from .parsers.excel import parse_excel
from .parsers.fortigate import parse_fortigate_config
from .utils import ParseError, parse_ipv4_network, parse_ports_file


def _load_csv_networks(path: Path, header_name: str) -> list[dict[str, str]]:
    """Load CSV records with at least the given header."""
    records: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if header_name not in reader.fieldnames:
            raise ParseError(f"CSV file missing required header: {header_name}")
        for row in reader:
            records.append({key: (value or "").strip() for key, value in row.items()})
    return records


def _select_rule_source(config: str | None, excel: str | None, db_conn: str | None):
    """Ensure exactly one rules source is selected."""
    provided = [value for value in (config, excel, db_conn) if value]
    if len(provided) != 1:
        raise ParseError("Specify exactly one of --config, --excel, or --db-conn")


def _iter_ports(ports_path: Path):
    """Yield port specs from the ports file."""
    with ports_path.open(encoding="utf-8") as handle:
        for spec in parse_ports_file(handle.readlines()):
            yield spec


def _write_output(
    output_path: Path,
    rows: Iterable[dict[str, str | int | None]],
) -> None:
    """Write output rows to CSV file."""
    fieldnames = [
        "src_network_segment",
        "dst_network_segment",
        "dst_gn",
        "dst_site",
        "dst_location",
        "service_label",
        "protocol",
        "port",
        "decision",
        "matched_policy_id",
        "matched_policy_name",
        "matched_policy_action",
        "reason",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Static Traffic Analyzer")
    parser.add_argument("--config", help="FortiGate CLI config file")
    parser.add_argument("--excel", help="Excel rules workbook")
    parser.add_argument("--db-conn", help="MariaDB DSN")
    parser.add_argument("--src-csv", required=True, help="Source CIDR list CSV")
    parser.add_argument("--dst-csv", required=True, help="Destination CIDR list CSV")
    parser.add_argument("--ports", required=True, help="Ports list file")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--ignore-schedule", action="store_true", help="Ignore policy schedules")
    parser.add_argument(
        "--match-mode",
        choices=["segment", "sample-ip", "expand"],
        default="segment",
        help="Address match mode",
    )
    parser.add_argument("--max-hosts", type=int, default=256, help="Max hosts for expand mode")

    args = parser.parse_args()

    try:
        _select_rule_source(args.config, args.excel, args.db_conn)

        if args.config:
            with Path(args.config).open(encoding="utf-8") as handle:
                data = parse_fortigate_config(handle.readlines())
        elif args.excel:
            data = parse_excel(args.excel)
        else:
            data = parse_database(args.db_conn)

        src_records = _load_csv_networks(Path(args.src_csv), "Network Segment")
        dst_records = _load_csv_networks(Path(args.dst_csv), "Network Segment")
        ports = list(_iter_ports(Path(args.ports)))

        output_rows: list[dict[str, str | int | None]] = []
        match_mode = MatchMode(mode=args.match_mode, max_hosts=args.max_hosts)

        for src_record in src_records:
            src_network = parse_ipv4_network(src_record["Network Segment"])
            for dst_record in dst_records:
                dst_network = parse_ipv4_network(dst_record["Network Segment"])
                for port_spec in ports:
                    match = evaluate_policy(
                        policies=data.policies,
                        address_book=data.address_book,
                        service_book=data.service_book,
                        src_network=src_network,
                        dst_network=dst_network,
                        protocol=port_spec.protocol,
                        port=port_spec.port,
                        match_mode=match_mode,
                        ignore_schedule=args.ignore_schedule,
                    )
                    output_rows.append(
                        {
                            "src_network_segment": str(src_network),
                            "dst_network_segment": str(dst_network),
                            "dst_gn": dst_record.get("GN") or "",
                            "dst_site": dst_record.get("Site") or "",
                            "dst_location": dst_record.get("Location") or "",
                            "service_label": port_spec.label,
                            "protocol": port_spec.protocol.value,
                            "port": port_spec.port,
                            "decision": match.decision.value,
                            "matched_policy_id": match.matched_policy_id or "",
                            "matched_policy_name": match.matched_policy_name or "",
                            "matched_policy_action": match.matched_policy_action or "",
                            "reason": match.reason,
                        }
                    )

        _write_output(Path(args.out), output_rows)
    except ParseError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
