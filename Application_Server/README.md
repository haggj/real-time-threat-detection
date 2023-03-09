# Application server

## Run in WSGI Server
```bash
be root user (sudo su)
source wsgiServerEnv/bin/activate
pip3 install gunicorn flask gevent
gunicorn -k gevent --bind 0.0.0.0:80 wsgi:app --daemon
http://164.90.232.157:80
```

## Run local
```bash
pip3 install flask
sudo python3 application_server.py
# OR
sudo -E python3 application_server.py
```