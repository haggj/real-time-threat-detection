import json

from flask import Flask, render_template, request
import os
from datetime import datetime

app = Flask(__name__)

@app.route('/1234')
def statistics():
    unique_ips = {}
    all_requests = []
    all_count = 0
    with open("client_ips.txt", "r") as f:
        for line in f:
            data = line.strip().split('\t')
            ip = data[0]
            all_requests.append(data)
            if ip in unique_ips:
                unique_ips[ip] += 1
            else:
                unique_ips[ip] = 1
            all_count += 1

    unique_count = len(unique_ips)
    unique_ips = sorted(unique_ips.items())

    return render_template('index.html', unique_ips=unique_ips, unique_count=unique_count, all_requests=all_requests,
                           all_count=all_count)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    auth_header = request.headers.get("Authorization")
    if auth_header:
        auth_header = '"' + request.headers.get("Authorization") + '"'
    body_data = request.get_json()
    form_data = json.dumps(request.form)
    path = '/' + path
    with open("client_ips.txt", "a") as f:
        f.write(f"{client_ip}\t{timestamp}\t{path}\t{auth_header}\t{body_data}\t{form_data}\n")
    return render_template('hello_world.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)

