"""Default service catalog for common well-known services."""
from __future__ import annotations

from .models import Protocol, ServiceEntry, ServiceObject


DEFAULT_SERVICES: dict[str, ServiceObject] = {
    "DNS": ServiceObject("DNS", (ServiceEntry(protocol=Protocol.UDP, start_port=53, end_port=53),)),
    "HTTP": ServiceObject("HTTP", (ServiceEntry(protocol=Protocol.TCP, start_port=80, end_port=80),)),
    "HTTPS": ServiceObject("HTTPS", (ServiceEntry(protocol=Protocol.TCP, start_port=443, end_port=443),)),
    "SSH": ServiceObject("SSH", (ServiceEntry(protocol=Protocol.TCP, start_port=22, end_port=22),)),
    "SMTP": ServiceObject("SMTP", (ServiceEntry(protocol=Protocol.TCP, start_port=25, end_port=25),)),
}
