from flask import Flask, render_template, request
import os
from datetime import datetime

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("client_ips.txt", "a") as f:
        f.write(f"{client_ip}\t{timestamp}\n")
    
    unique_ips = set()
    all_ips = {}
    all_count = 0
    with open("client_ips.txt", "r") as f:
        for line in f:
            ip = line.strip().split('\t')[0]
            unique_ips.add(ip)
            if ip in all_ips:
                all_ips[ip] += 1
            else:
                all_ips[ip] = 1
            all_count += 1
    
    unique_count = len(unique_ips)
    all_ips = sorted(all_ips.items())
    
    return render_template('index.html', unique_ips=unique_ips, unique_count=unique_count, all_ips=all_ips, all_count=all_count)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)

