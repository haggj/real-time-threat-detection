# Honeypot

The used honeypot we are using is `cowrie`.
It can be found [here](https://github.com/cowrie/cowrie)

To start it via docker you can use the following command:
`docker run -p 2223:2222/tcp -v ~/Uni/Security/project/cowrie/log:/cowrie/cowrie-git/var/log/cowrie -d cowrie/cowrie`