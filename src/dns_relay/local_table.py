"""Load and query the assignment's dnsrelay.txt local record table."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path


@dataclass(frozen=True)
class LocalTable:
    records: dict[str, str]

    @classmethod
    def load(cls, path: str | Path) -> "LocalTable":
        table_path = Path(path)
        records: dict[str, str] = {}
        for line_number, raw_line in enumerate(
            table_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                raise ValueError(f"{table_path}:{line_number}: expected 'IPv4 domain'")
            address, domain = parts
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError(
                    f"{table_path}:{line_number}: invalid IP address {address!r}"
                ) from exc
            if parsed_address.version != 4:
                raise ValueError(f"{table_path}:{line_number}: only IPv4 is supported")
            normalized = normalize_domain(domain)
            if not normalized:
                raise ValueError(f"{table_path}:{line_number}: empty domain name")
            records[normalized] = str(parsed_address)
        return cls(records)

    def lookup(self, domain: str) -> str | None:
        return self.records.get(normalize_domain(domain))


def normalize_domain(domain: str) -> str:
    return domain.rstrip(".").lower()
