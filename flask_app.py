from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from syn_scan import *
import time


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'

socketio = SocketIO()
socketio.init_app(app, cors_allowed_origins='*')

name_space = '/dcenter'


def scan_on_web(ip: str, port: int, timeout=1.0, retries=1, show_closed=False):
    res = scan(ip, port, timeout, retries)
    broadcasted_data = {'data': f"{ip}:{port} {res}"}
    if res == 'open':
        socketio.emit('scan_response', broadcasted_data,
                      broadcast=False, namespace=name_space)
    elif show_closed:
        socketio.emit('scan_response', broadcasted_data,
                      broadcast=False, namespace=name_space)
    pass


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/push')
def push_once():
    event_name = 'dcenter'
    broadcasted_data = {'data': "test message!"}
    socketio.emit(event_name, broadcasted_data,
                  broadcast=False, namespace=name_space)
    return 'done!'


@socketio.on('connect', namespace=name_space)
def connected_msg():
    print('client connected.')


@socketio.on('disconnect', namespace=name_space)
def disconnect_msg():
    print('client disconnected.')


@socketio.on('scan_event', namespace=name_space)
def mtest_message(message):
    print(message)
    ips = parse_ip_range(message['ipList'])
    ports = parse_port_range(message['portList'])
    tasks = tqdm(itertools.product(ips, ports), total=len(ips)*len(ports))
    for ip, port in tasks:
        res = scan(ip, port, float(message['timeout']), int(message['retry']))
        broadcasted_data = {'data': f"{ip}:{port} {res}"}
        if res == 'open':
            emit('scan_response', broadcasted_data)
        elif message['showClosedPorts']:
            emit('scan_response', broadcasted_data)
    emit('scan_response',
         {'data': "Scan finished."})


if __name__ == '__main__':

    socketio.run(app, host='0.0.0.0', port=5000)
