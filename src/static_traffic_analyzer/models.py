"""Core data structures for the static traffic analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable, Optional


class AddressType(str, Enum):
    """Supported address object types."""

    IPMASK = "ipmask"
    IPRANGE = "iprange"
    FQDN = "fqdn"


@dataclass(frozen=True)
class AddressObject:
    """Represents a single address object."""

    name: str
    address_type: AddressType
    subnet: Optional[IPv4Network] = None
    start_ip: Optional[IPv4Address] = None
    end_ip: Optional[IPv4Address] = None

    def contains_ip(self, ip: IPv4Address) -> bool:
        """Return True if the IP address is contained by this object."""
        if self.address_type == AddressType.IPMASK and self.subnet is not None:
            return ip in self.subnet
        if self.address_type == AddressType.IPRANGE and self.start_ip and self.end_ip:
            return self.start_ip <= ip <= self.end_ip
        return False

    def contains_network(self, network: IPv4Network) -> bool:
        """Return True if the network is fully contained by this object."""
        if self.address_type == AddressType.IPMASK and self.subnet is not None:
            return network.subnet_of(self.subnet)
        if self.address_type == AddressType.IPRANGE and self.start_ip and self.end_ip:
            return self.start_ip <= network.network_address and self.end_ip >= network.broadcast_address
        return False


@dataclass(frozen=True)
class AddressGroup:
    """Represents a named group of address objects."""

    name: str
    members: tuple[str, ...]


class Protocol(str, Enum):
    """Supported L4 protocols."""

    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True)
class ServiceEntry:
    """Represents a single service entry (protocol + port range)."""

    protocol: Optional[Protocol]
    start_port: Optional[int]
    end_port: Optional[int]

    def matches(self, protocol: Protocol, port: int) -> bool:
        """Return True if this service entry matches the protocol and port."""
        if self.protocol is None:
            return True
        if self.protocol != protocol:
            return False
        if self.start_port is None or self.end_port is None:
            return False
        return self.start_port <= port <= self.end_port


@dataclass(frozen=True)
class ServiceObject:
    """Represents a named service definition."""

    name: str
    entries: tuple[ServiceEntry, ...]


@dataclass(frozen=True)
class ServiceGroup:
    """Represents a named group of services."""

    name: str
    members: tuple[str, ...]


@dataclass(frozen=True)
class PolicyRule:
    """Represents a firewall policy rule."""

    policy_id: str
    name: str
    priority: int
    source: tuple[str, ...]
    destination: tuple[str, ...]
    services: tuple[str, ...]
    action: str
    enabled: bool
    schedule: Optional[str] = None
    comment: Optional[str] = None


class MatchOutcome(str, Enum):
    """Possible evaluation outcomes for a match step."""

    MATCH = "match"
    NO_MATCH = "no_match"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    """Final decision result."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class MatchDetail:
    """Detailed information about how a policy matched."""

    decision: Decision
    matched_policy_id: Optional[str]
    matched_policy_name: Optional[str]
    matched_policy_action: Optional[str]
    reason: str


@dataclass
class AddressBook:
    """Holds address objects and groups with resolution helpers."""

    objects: dict[str, AddressObject] = field(default_factory=dict)
    groups: dict[str, AddressGroup] = field(default_factory=dict)

    def resolve_group_members(self, name: str, _visited: Optional[set[str]] = None) -> Iterable[AddressObject]:
        """Resolve all address objects inside a group, recursively."""
        if name in self.objects:
            return [self.objects[name]]
        if name not in self.groups:
            return []
        visited = _visited or set()
        if name in visited:
            return []
        visited.add(name)
        resolved: list[AddressObject] = []
        for member in self.groups[name].members:
            resolved.extend(self.resolve_group_members(member, visited))
        return resolved


@dataclass
class ServiceBook:
    """Holds service objects and groups with resolution helpers."""

    services: dict[str, ServiceObject] = field(default_factory=dict)
    groups: dict[str, ServiceGroup] = field(default_factory=dict)

    def resolve_group_members(self, name: str, _visited: Optional[set[str]] = None) -> Iterable[ServiceObject]:
        """Resolve all service objects inside a group, recursively."""
        if name in self.services:
            return [self.services[name]]
        if name not in self.groups:
            return []
        visited = _visited or set()
        if name in visited:
            return []
        visited.add(name)
        resolved: list[ServiceObject] = []
        for member in self.groups[name].members:
            resolved.extend(self.resolve_group_members(member, visited))
        return resolved
