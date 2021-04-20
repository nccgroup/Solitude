import datetime
import decimal
import ipaddress
import json 
import os
import subprocess
import time
from os import path
from threading import Lock

from flask import Flask, render_template
from flask import Response, request
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from sqlalchemy import text
from functools import wraps

from solitudeCode.database import Database
from solitudeCode.models.connections import Connections
from solitudeCode.models.violations import Violations

from solitudeCode.rules import createYaraRules


app = Flask(__name__)
socketio = SocketIO(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:{}@{}:3306/solitude'.format(os.getenv('DB_PASSWORD'), os.getenv('DB_HOSTNAME'))

db = SQLAlchemy(app)

connection = Database.engine
thread = None
thread_lock = Lock()


def background_thread():
    lastID = 0
    connection_session = db.create_scoped_session()
    while True:
        # while loop so we are always querying the DB
        statement = select([Violations]).order_by(text('id DESC')).limit(1)
        result = connection_session.execute(statement)
        # return the first row of the latest query
        a = result.first()
        if a == None:
            firstQuery = 0
        else:
            firstQuery = a[0]
        if lastID < firstQuery:
            for c, v in connection_session.query(Connections, Violations).filter(
                    Connections.id == Violations.connection_ID).filter(Violations.id > lastID):
                socketio.emit('ViolationResponse', json.dumps({"host": c.host, "violation": v.violation_message,
                                                               "phorcys object": "<a href=javascript:getphorcysobject(" + str(
                                                                   v.id) + ")" + ">Click to view Decoded Object</a>",
                                                               "time": str(c.time), "Violation ID": v.id}))
            lastID = firstQuery



        connection_session.remove()
        socketio.sleep(1)


def alchemyencoder(obj):
    """JSON encoder function for SQLAlchemy special classes."""
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    elif isinstance(obj, decimal.Decimal):
        return float(obj)
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')


def is_valid_ipv4_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def timePulseforDHPEM():
    # Minute of when the file was created
    creation_time = time.gmtime((os.path.getmtime('/mnt/vpnconfig/dh.pem')))[4]

    # Minute of the current time
    current_time = time.gmtime((time.time()))[4]
    # We need to see if two minutes have passed. If they haven't then don't delete the file
    if current_time <= creation_time + 1:
        return True
    else:
        return False





def antiDNSRebind(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_valid_ipv4_address(request.headers.get('host').split(':')[0]) and request.headers.get('host').split(':')[0] != 'localhost':
            return render_template('404.html')
        return f(*args, **kwargs)

    return decorated_function

@app.route('/')
@antiDNSRebind
def hello():
    return render_template('index.html', async_mode=socketio.async_mode)


@app.route('/api/v1/connections')
@antiDNSRebind
def API_connections():
    # limit = request.args.get('limit', default=10, type=int)
    # orderBy = request.args.get('orderBy', default="id DESC", type=str)
    result = connection.execute(db.select([Connections]))
    return Response(json.dumps([dict(r) for r in result], default=alchemyencoder, indent=2),
                    mimetype='application/json')


@app.route('/api/v1/violations')
@antiDNSRebind
def API_violations():
    # limit = request.args.get('limit', default=200, type=int)
    # orderBy = request.args.get('orderBy', default="id DESC", type=str)
    result = connection.execute(db.select([Violations]))
    return Response(json.dumps([dict(r) for r in result], default=alchemyencoder, indent=2),
                    mimetype='application/json')


@app.route('/api/v1/combined')
@antiDNSRebind
def API_combined_tables():
    # limit = request.args.get('limit', default=10, type=int)
    # orderBy = request.args.get('orderBy', default="id DESC", type=str)
    result = connection.execute(
        "SELECT * FROM connections, violations WHERE connections.id = violations.connection_ID")
    return Response(json.dumps([dict(r) for r in result], default=alchemyencoder, indent=2),
                    mimetype='application/json')


@app.route('/api/v1/getphorchysobject')
@antiDNSRebind
def getphorcysobject():
    connection_session = db.create_scoped_session()
    if request.args.get('id'):
        violation_id = request.args.get('id')

        response = connection_session.query(Violations).filter(Violations.id == violation_id)
        for v in response:
            return v.phorcies_object


@app.route('/api/v1/myrule_settings', methods=['GET', 'POST'])
@antiDNSRebind
def API_retrieve_myrule_settings():
    if os.getenv('ENVIRONMENT') == "local":
        path = "configs/myrules.json"

    if os.getenv('ENVIRONMENT') == "container-prod" or os.getenv('ENVIRONMENT') == "container-dev":
        path = "/mnt/configs/myrules.json"

    if request.method == "GET":
        with open(path) as f:
            return Response(f.read(), mimetype="application/json")
    elif request.method == "POST":
        rules = request.json.get("rules")
        f = open(path, "w")
        f.write(rules)
        f.close()
        createYaraRules()

        return 'True'

@app.route('/api/v1/vpnconfigpoll', methods=["POST"])
@antiDNSRebind
def vpnconfigpoll():
    if path.exists('/mnt/static/clientTCP.ovpn') and path.exists('/mnt/static/clientUDP.ovpn'):
        return 'True'
    else:
        ip = request.json.get('ip')
        if ip == 'none':
            return 'False'

        if is_valid_ipv4_address(ip):
            subprocess.Popen(['/usr/local/sbin/run', '--config', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(4)
            # Check to see if we are running in a prod container
            if os.getenv('PYTHON_PATH') == 'python3':
                # subprocess.Popen(['cp', '/mnt/vpnconfig/clientTCP.ovpn', '/home/solitude/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                # subprocess.Popen(['cp', '/mnt/vpnconfig/clientUDP.ovpn', '/home/solitude/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.Popen(['cp', '/mnt/vpnconfig/clientTCP.ovpn', '/mnt/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.Popen(['cp', '/mnt/vpnconfig/clientUDP.ovpn', '/mnt/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.Popen(['ln', '-s', '/mnt/static/clientTCP.ovpn', '/home/solitude/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.Popen(['ln', '-s', '/mnt/static/clientUDP.ovpn', '/home/solitude/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return 'False'
            else:
                subprocess.Popen(['cp', '/mnt/vpnconfig/clientTCP.ovpn', '/mnt/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.Popen(['cp', '/mnt/vpnconfig/clientUDP.ovpn', '/mnt/static/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return 'False'

        else:
            return 'False'


@app.route('/api/v1/deletevpnconfig',  methods=["POST"])
@antiDNSRebind
def deletevpnconfig():
    if request.json.get('delete') == 'True':
        # For prod container not in the mnt
        if path.exists('/home/solitude/static/clientTCP.ovpn') and path.exists('/home/solitude/static/clientUDP.ovpn'):
            subprocess.Popen(['rm', '/home/solitude/static/clientTCP.ovpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.Popen(['rm', '/home/solitude/static/clientUDP.ovpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        subprocess.Popen(['rm', '/mnt/vpnconfig/clientTCP.ovpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(['rm', '/mnt/static/clientTCP.ovpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(['rm', '/mnt/vpnconfig/clientUDP.ovpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(['rm', '/mnt/static/clientUDP.ovpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return 'deleted'

@app.route('/api/v1/startvpn', methods=["POST"])
@antiDNSRebind
def startvpn():
    if request.json.get('vpn') == 'tcp':
        if path.exists('/dev/net/tun') != True:
            subprocess.Popen(['/usr/local/sbin/run', '--proxy'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.Popen(['/usr/local/sbin/run', '--init'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        proc = subprocess.Popen(['openvpn', '/mnt/vpnconfig/tcp443.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        if proc.poll() == None:
            return 'True'
        elif proc.poll() == 0:
            subprocess.Popen(['openvpn', '/mnt/vpnconfig/tcp443.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return 'True'
    elif request.json.get('vpn') == 'udp':
        if path.exists('/dev/net/tun') != True:
            subprocess.Popen(['/usr/local/sbin/run', '--proxy'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.Popen(['/usr/local/sbin/run', '--init'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        proc = subprocess.Popen(['openvpn', '/mnt/vpnconfig/udp1194.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        if proc.poll() == None:
            return 'True'
        elif proc.poll() == 0:
            subprocess.Popen(['openvpn', '/mnt/vpnconfig/udp1194.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return 'True'


@app.route('/api/v1/stopvpn', methods=["POST"])
@antiDNSRebind
def stopvpn():
    if request.json.get('stop') == 'vpn':
        subprocess.Popen(['/usr/local/sbin/run', '--stopvpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return 'True'


@app.route('/api/v1/startproxy', methods=["POST"])
@antiDNSRebind
def startproxy():
    if request.json.get('start') == 'True':
        subprocess.Popen(['/usr/local/sbin/run', '--proxy'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #subprocess.Popen(['/usr/local/sbin/run', '--init'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return 'True'


@app.route('/checkIfClientConfigGenerated')
@antiDNSRebind
def checkIfClientConfigGenerated():
    if path.exists('/mnt/static/clientTCP.ovpn') and path.exists('/mnt/static/clientUDP.ovpn'):
        return 'True'
    else:
        return 'False'


@app.route('/initserverconfig')
@antiDNSRebind
def initserverconfig():

    if os.getenv('DB_HOSTNAME') == '127.0.0.1':
        return 'local'

    if path.exists('/mnt/vpnconfig/udp1194.conf') and path.exists('/mnt/vpnconfig/tcp443.conf'):
       # Start Proxy and pre VPN config
       if path.exists('/dev/net/tun') != True:
           subprocess.Popen(['/usr/local/sbin/run', '--proxy'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
           subprocess.Popen(['/usr/local/sbin/run', '--init'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
           return 'True'


       return 'True'

    if os.getenv('DB_HOSTNAME') == 'database':
        if path.exists('/mnt/vpnconfig/dh.pem') != True:
            subprocess.Popen(['/usr/local/sbin/run', '--proxy'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.Popen(['/usr/local/sbin/run', '--init'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.Popen(['/usr/local/sbin/run', '--tcp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return 'False'

        if os.path.getsize('/mnt/vpnconfig/dh.pem') == 0:
            if timePulseforDHPEM() == False:
                subprocess.Popen(['rm', '/mnt/vpnconfig/dh.pem'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                return 'False'
            else:
                return 'False'

        else:
            return 'True'


@socketio.on('connect')
@antiDNSRebind
def on_connect():
    pass
    connection_session = db.create_scoped_session()

    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(target=background_thread)
        else:
            for c, v in connection_session.query(Connections, Violations).filter(
                    Connections.id == Violations.connection_ID):
                socketio.emit('ViolationResponse', json.dumps({"host": c.host, "violation": v.violation_message,
                                                               "phorcys object": "<a href=javascript:getphorcysobject(" + str(
                                                                   v.id) + ")" + ">Click to view Decoded Object</a>",
                                                               "time": str(c.time), "Violation ID": v.id}),
                              to=request.sid)


if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0")
