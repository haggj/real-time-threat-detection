# Honeypot

The honeypot we are using is [cowrie](https://github.com/cowrie/cowrie).

To start it via docker you can use the following command:
`docker run -p 2223:2222/tcp -v ./log:/cowrie/cowrie-git/var/log/cowrie -d cowrie/cowrie`