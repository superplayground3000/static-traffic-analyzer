# Overview

fortigate rule parser is a tool that can read a fortigate configuration file, a target ip list, a src ip list and a port list, then output a csv list that shows each src ip, dst ip and port will be allowed to pass the fortigate or not.

# Key Points

Implementation must follow below descriptions

## Detail Requirements

- src ip list is a csv with fields "Network Segment", ip is represented with cidr
- dst ip list is a csv with fields "Network Segment,GN,Site,Location", "Network Segment" is represented with cidr
- port list does not have header field, each line caontains a port info like "ssh,22/tcp"
- "config firewall policy" defines the routes will be denied or passed, and the sequence of the rule matters, it works like a if-else structure
- Default deny if no rule in "config firewall policy" matches

## General Implementation Requirements
- Use Golang
- Follow SOLID design principle
- Core functions must have unit tests
