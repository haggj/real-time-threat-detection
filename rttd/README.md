# Real-Time Threat Detection

A python script which parses the honeypot logs and configures the firewall of the operating system accordingly.

## UFW commands

#### Create rule for certain IP on certain PORT
`sudo ufw deny from <IP> to any port <PORT>`

#### Delete rule by ID
`sudo ufw --force delete <ID>`

#### Delete all rules on certain PORT
`sudo ufw --force delete $(sudo ufw status numbered |(grep '<PORT>'|awk -F"[][]" '{print $2}'))`

#### Delete all rules of a certain IP
`sudo ufw --force delete $(sudo ufw status numbered |(grep '<IP>'|awk -F"[][]" '{print $2}'))`

#### List all IPs which are denied on certain PORT
`sudo ufw status numbered |(grep '3306'|grep 'DENY' | awk '{print $6}')`