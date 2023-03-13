# Security Project
Reykjavik University Security course (Spring 2023). 

# Content

## Profiling attacking IPs: "Who is attacking?"
- passive checks:
    - known blocked IP? (https://github.com/firehol/blocklist-ipsets)
    - known TOR exit node? (https://www.dan.me.uk/tornodes)
    - known VPN/Proxy server? (https://iphub.info/api)
    - Reverse DNS lookup?
    - geolocation (https://ip-api.com/)
- active checks:
    - which ports are open?
        - default scan 


## Analyzing honeypot data: "What does the attacker do?"
- connection attempts geo-map
- used passwords
- executed commands (tty)
- investigate downloaded files

## Using honeypot data to secure network: "How to prevent attacks?"
- use logs to configure firewall


# Components
This repo contains the final project of the course.
It consists of the following components:

## Honeypot
Cowrie honeypot that monitors live attacks and produces logs.

## Application server
A simple flask server which stores information about all incoming connections.

## RTTD
A python script which parses the honeypot logs and configures the firewall of the operating system accordingly.
