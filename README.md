# Security Project
Reykjavik University Security course (Spring 2023). 

# Content

## Profiling attacking IPs: "Who is attacking?"
- passive checks:
    - blocklists? (https://github.com/firehol/blocklist-ipsets)
    - known TOR exit node? (https://www.dan.me.uk/tornodes) -> Umm... You can only fetch the data every 30 minutes - sorry.  It's pointless any faster as I only update every 30 minutes anyway.
If you keep trying to download this list too often, you may get blocked from accessing it completely.
(this is due to some people trying to download this list every minute!)
    - known VPN/Proxy server? (https://iphub.info/api)
    - Reverse DNS lookup?
    - geolocation (https://ip-api.com/)
- active checks:
    - which ports are open?
        - default scan 


## Analyzing honeypot data: "What does the attacker do?"
- hoeypot at 22:
  - used passwords
  - executed commands (tty)
  - investigate downloaded files
- webserver at 80:
  - called paths
  - credentials?
  - form/json data
- tcp server at 443:
  - what data is sent to the tcp socket?

## Using honeypot data to secure network: "How to prevent attacks?"
- use hoeypot logs to configure firewall
  - protect ports 80 and 443
  - as fast as possible
  - delete rules if IP is not active anymore
  - whitelist our IPs


# Components
This repo contains the final project of the course.
It consists of the following components:

## Honeypot
Cowrie honeypot that monitors live attacks and produces logs.

## Application server
A simple flask server which stores information about all incoming connections.

## RTTD
A python script which parses the honeypot logs and configures the firewall of the operating system accordingly.

The script consists of three main parts, run based on certain conditions, which can be seen below.
- At a honeypot log file modification: Firewall Rule Additions (`on_modified(self, event)`)
- Every 5 minutes: IP cache updates (`update_cached_rules()`)
- Every 10 minutes: Firewall Rule Deletions (`cleanup()`)

