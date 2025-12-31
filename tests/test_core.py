"""Unit tests for static traffic analyzer core logic."""
from __future__ import annotations

from ipaddress import ip_network

import pytest

from static_traffic_analyzer.evaluator import MatchMode, evaluate_policy
from static_traffic_analyzer.models import (
    AddressBook,
    AddressGroup,
    AddressObject,
    AddressType,
    Decision,
    PolicyRule,
    Protocol,
    ServiceBook,
    ServiceGroup,
    ServiceObject,
    ServiceEntry,
)
from static_traffic_analyzer.utils import ParseError, parse_ports_file


def test_parse_ports_file_valid():
    specs = parse_ports_file(["ssh,22/tcp", "dns,53/udp"])
    assert specs[0].label == "ssh"
    assert specs[0].port == 22
    assert specs[0].protocol == Protocol.TCP


def test_parse_ports_file_invalid():
    with pytest.raises(ParseError):
        parse_ports_file(["bad-line"])


def test_cidr_containment():
    address = AddressObject(name="net", address_type=AddressType.IPMASK, subnet=ip_network("10.0.0.0/16"))
    book = AddressBook(objects={"net": address})
    service_book = ServiceBook(services={"ALL": ServiceObject("ALL", (ServiceEntry(None, None, None),))})
    rule = PolicyRule(
        policy_id="1",
        name="1",
        priority=1,
        source=("net",),
        destination=("net",),
        services=("ALL",),
        action="accept",
        enabled=True,
        schedule="always",
    )
    result = evaluate_policy(
        policies=[rule],
        address_book=book,
        service_book=service_book,
        src_network=ip_network("10.0.1.0/24"),
        dst_network=ip_network("10.0.2.0/24"),
        protocol=Protocol.TCP,
        port=22,
        match_mode=MatchMode(mode="segment", max_hosts=256),
        ignore_schedule=False,
    )
    assert result.decision == Decision.ALLOW


def test_service_group_parsing():
    service = ServiceObject("tcp_3000-3001", (ServiceEntry(Protocol.TCP, 3000, 3001),))
    service_book = ServiceBook(
        services={"tcp_3000-3001": service},
        groups={"group": ServiceGroup("group", ("tcp_3000-3001",))},
    )
    rule = PolicyRule(
        policy_id="1",
        name="1",
        priority=1,
        source=("all",),
        destination=("all",),
        services=("group",),
        action="accept",
        enabled=True,
        schedule="always",
    )
    address_book = AddressBook(
        objects={"all": AddressObject("all", AddressType.IPMASK, subnet=ip_network("0.0.0.0/0"))}
    )
    result = evaluate_policy(
        policies=[rule],
        address_book=address_book,
        service_book=service_book,
        src_network=ip_network("10.1.0.0/24"),
        dst_network=ip_network("10.2.0.0/24"),
        protocol=Protocol.TCP,
        port=3001,
        match_mode=MatchMode(mode="segment", max_hosts=256),
        ignore_schedule=False,
    )
    assert result.decision == Decision.ALLOW


def test_address_group_nested():
    address_book = AddressBook(
        objects={
            "net1": AddressObject("net1", AddressType.IPMASK, subnet=ip_network("10.0.0.0/24")),
            "net2": AddressObject("net2", AddressType.IPMASK, subnet=ip_network("10.0.1.0/24")),
        },
        groups={
            "group1": AddressGroup("group1", ("net1",)),
            "group2": AddressGroup("group2", ("group1", "net2")),
        },
    )
    service_book = ServiceBook(services={"ALL": ServiceObject("ALL", (ServiceEntry(None, None, None),))})
    rule = PolicyRule(
        policy_id="1",
        name="1",
        priority=1,
        source=("group2",),
        destination=("group2",),
        services=("ALL",),
        action="accept",
        enabled=True,
        schedule="always",
    )
    result = evaluate_policy(
        policies=[rule],
        address_book=address_book,
        service_book=service_book,
        src_network=ip_network("10.0.1.0/24"),
        dst_network=ip_network("10.0.1.0/24"),
        protocol=Protocol.UDP,
        port=53,
        match_mode=MatchMode(mode="segment", max_hosts=256),
        ignore_schedule=False,
    )
    assert result.decision == Decision.ALLOW


def test_policy_order_first_match():
    address_book = AddressBook(objects={"all": AddressObject("all", AddressType.IPMASK, subnet=ip_network("0.0.0.0/0"))})
    service_book = ServiceBook(services={"ALL": ServiceObject("ALL", (ServiceEntry(None, None, None),))})
    policies = [
        PolicyRule(
            policy_id="1",
            name="1",
            priority=1,
            source=("all",),
            destination=("all",),
            services=("ALL",),
            action="deny",
            enabled=True,
            schedule="always",
        ),
        PolicyRule(
            policy_id="2",
            name="2",
            priority=2,
            source=("all",),
            destination=("all",),
            services=("ALL",),
            action="accept",
            enabled=True,
            schedule="always",
        ),
    ]
    result = evaluate_policy(
        policies=policies,
        address_book=address_book,
        service_book=service_book,
        src_network=ip_network("10.0.0.0/24"),
        dst_network=ip_network("10.0.1.0/24"),
        protocol=Protocol.TCP,
        port=443,
        match_mode=MatchMode(mode="segment", max_hosts=256),
        ignore_schedule=False,
    )
    assert result.decision == Decision.DENY


def test_implicit_deny():
    address_book = AddressBook(objects={"net": AddressObject("net", AddressType.IPMASK, subnet=ip_network("10.0.0.0/24"))})
    service_book = ServiceBook(services={"HTTP": ServiceObject("HTTP", (ServiceEntry(Protocol.TCP, 80, 80),))})
    rule = PolicyRule(
        policy_id="1",
        name="1",
        priority=1,
        source=("net",),
        destination=("net",),
        services=("HTTP",),
        action="accept",
        enabled=True,
        schedule="always",
    )
    result = evaluate_policy(
        policies=[rule],
        address_book=address_book,
        service_book=service_book,
        src_network=ip_network("10.0.1.0/24"),
        dst_network=ip_network("10.0.2.0/24"),
        protocol=Protocol.TCP,
        port=80,
        match_mode=MatchMode(mode="segment", max_hosts=256),
        ignore_schedule=False,
    )
    assert result.decision == Decision.DENY
