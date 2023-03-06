# Application server

## Run in WSGI Server
```bash
be root user (sudo su)
source wsgiServerEnv/bin/activate
gunicorn --bind 0.0.0.0:80 wsgi:app
```

## Run local
```bash
pip3 install flask
sudo python3 application_server.py
# OR
sudo -E python3 application_server.py
```