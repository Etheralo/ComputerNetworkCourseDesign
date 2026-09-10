"""Load and query the assignment's dnsrelay.txt local record table."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path


@dataclass(frozen=True)
class LocalTable:
    # 域名 -> IPv4 字符串；0.0.0.0 在 relay 中解释为屏蔽标记。
    # frozen 禁止属性重新赋值，并不会让内部 dict 自动变为不可修改对象。
    records: dict[str, str]

    @classmethod
    def load(cls, path: str | Path) -> "LocalTable":
        # 启动时一次性读取 UTF-8 文件，非逐请求读取，也不提供热更新。
        table_path = Path(path)
        records: dict[str, str] = {}
        for line_number, raw_line in enumerate(
            table_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            # 去掉整行/行尾注释和空白；空行直接跳过。
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                raise ValueError(f"{table_path}:{line_number}: expected 'IPv4 domain'")
            address, domain = parts
            # 由标准库验证地址格式，错误附带配置路径和行号，便于定位。
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
            # 同一规范化域名重复出现时，后面的配置覆盖前面的配置。
            records[normalized] = str(parsed_address)
        return cls(records)

    def lookup(self, domain: str) -> str | None:
        # 查表时也做相同规范化；None 表示未命中，不等于屏蔽。
        return self.records.get(normalize_domain(domain))


def normalize_domain(domain: str) -> str:
    # DNS 名称匹配忽略大小写和末尾根域点，例如 LOCAL.Test. -> local.test。
    return domain.rstrip(".").lower()
