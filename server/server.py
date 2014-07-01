# Copyright (c) 2014, Patrick Uiterwijk <puiterwijk@gmail.com>
# All rights reserved.
#
# This file is part of webSilvia.
#
# webSilvia is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# webSilvia is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with webSilvia.  If not, see <http://www.gnu.org/licenses/>.

# Please configure the path to the silvia verifier and issuer bin dir and the IRMA configuration dir
VERIFIER_PATH = '/usr/bin/silvia_verifier'
ISSUER_PATH = '/usr/bin/silvia_issuer'
CONFIG_ROOT = '/usr/share/irma_configuration'
ENABLE_TEST_REQUEST = False
SECRET_KEY = 'setme'
SHARED_SECRET = 'setme'


# No changes need hereunder
from gevent import monkey
monkey.patch_all()

try:
    import subprocess32 as subprocess
except ImportError:
    import subprocess

from time import time
from itsdangerous import TimedSerializer
from uuid import uuid4 as uuid
from flask import Flask, render_template, session, request, jsonify
from flask.ext.socketio import SocketIO, emit, join_room


import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)


app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = SECRET_KEY
socketio = SocketIO(app)

connections = {}
seen_nonces = set()


signer = TimedSerializer(SHARED_SECRET)


if ENABLE_TEST_REQUEST:
    @app.route('/')
    def index():
        # This is used to create a testing request
        credentials = {}
        credentials['rootNone'] = {'issuer-spec-path': 'Surfnet/Issues/root/description.xml',
                                   'verifier-spec-path': 'Surfnet/Verifies/rootNone/description.xml',
                                   'publickey-path': 'Surfnet/ipk.xml'}


        new_req = {'token': uuid().hex,
                   'nonce': time(),
                   'return_url': '/test/',
                   'credentials': credentials}
        new_req = signer.dumps(new_req)

        return render_template('index.html',
                               request=new_req)

    @app.route('/test/', methods=['POST'])
    def view_test():
        result = request.form['result']
        result = signer.loads(result)

        return jsonify(result)


@app.route('/authenticate/', methods=['POST'])
def view_authenticate():
    json_request = request.form['request']
    json_request = signer.loads(json_request)

    # Check nonce
    if json_request['nonce'] in seen_nonces:
        return 'USED NONCE'
    seen_nonces.add(json_request['nonce'])

    session['connid'] = uuid().hex
    connection = {}
    connection['token'] = json_request['token']
    connection['to_verify'] = json_request['credentials']
    connection['to_issue'] = json_request.get('issue')
    connection['current_credential'] = None
    connection['verify_results'] = {}
    connection['issue_results'] = {}
    connections[session['connid']] = connection

    return render_template('authenticate.html',
                           connid=session['connid'],
                           returnurl=json_request['return_url'])


@socketio.on('join', namespace='/irma')
def room_join(message):
    join_room(message['room'])
    emit('joined', {'data': 'Room joined'}, room=message['room'])


def get_max_version(clientVersions):
    if 'proxy-1' in clientVersions:
        return 'proxy-1'
    else:
        return None


# These functions are used by the proxy
@socketio.on('login', namespace='/irma')
def login(message):
    clientVersions = message['supportedVersions']
    version_to_use = get_max_version(clientVersions)
    if version_to_use is None:
        emit('finished', {'status': 'error', 'code': 'invalid-version'})
        return

    connid = message['connID']
    session['connid'] = message['connID']
    session['version'] = version_to_use
    emit('proxied', {'data': 'Proxy connected'}, room=connid)
    emit('loggedin', {'version': session['version']})


def kill_process():
    if 'process' in session:
        session['process'].poll()
        if session['process'].returncode is None:
            session['process'].kill()
        session['process'].poll()
        del session['process']


@socketio.on('card_connected', namespace='/irma')
def card_connected(message):
    # Get the next credential
    current_operation = ''
    if len(connections[session['connid']]['to_verify']) > 0:
        current_operation = 'verify'
    elif len(connections[session['connid']]['to_issue']) > 0:
        current_operation = 'issue'
        credentials = connections[session['connid']]['to_issue']
        # ISSUE
    else:
        # Huh?
        raise Exception('Invalid state: no-ver and no-iss')

    credentials = connections[session['connid']]['to_%s' % current_operation]
    credential_name = credentials.keys()[0]
    credential = credentials[credential_name]
    connections[session['connid']]['current_credential'] = credential
    connections[session['connid']]['current_credential']['name'] = credential_name
    connections[session['connid']]['current_credential']['operation'] = current_operation
    del connections[session['connid']]['to_%s' % current_operation][credential_name]

    cmd = None
    if current_operation == 'verify':
        emit('retrieving', credential_name, room=session['connid'])
        cmd = [VERIFIER_PATH,
               '-S',
               '-I',
               '%s/%s' % (CONFIG_ROOT, credential['issuer-spec-path']),
               '-V',
               '%s/%s' % (CONFIG_ROOT, credential['verifier-spec-path']),
               '-k',
               '%s/%s' % (CONFIG_ROOT, credential['publickey-path'])]
    elif current_operation == 'issue':
        # TODO: START ISSUER
        emit('issueing', credential_name, room=session['connid'])
        pass

    session['process'] = subprocess.Popen(cmd,
                                          stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)

    session['process'].poll()
    if session['process'].returncode is not None:
        emit('weird-error', {'stdout': session['process'].stdout.read(),
                             'stderr': session['process'].stderr.read()})
        kill_process()
        return

    return handle_next_command()


@socketio.on('card_response', namespace='/irma')
def card_response(message):
    session['process'].stdin.write('response %s\n' % message['data'])

    return handle_next_command()


@socketio.on('pin_ok', namespace='/irma')
def card_pin_ok(message):
    session['process'].stdin.write('PIN-result OK\n')

    return handle_next_command()


@socketio.on('pin', namespace='/irma')
def card_pin(message):
    session['process'].stdin.write('PIN %s\n' % message['pin'])

    return handle_next_command()


def handle_next_command():
    result = session['process'].stdout.readline().replace('\n', '')
    if result == '' or ' ' not in result:
        emit('card_error', {'code': result})
        kill_process()
        return

    control, options = result.split(' ', 1)

    if control == 'request':
        emit('card_request', {'data': options})
    elif control == 'control' and options == 'send-pin':
        emit('card_authenticate', {})
        return
    elif control == 'result':
        results = session['process'].stdout.read().split('\n')
        results = [rslt.split(' ') for rslt in results[:-1]]
        status = result.split(' ')[1]
        expiry = 0
        attributes = {}

        for result in results:
            if result[0] == 'result' and result[1] == 'expiry':
                expiry = result[2]
            elif result[0] == 'attribute':
                attributes[result[1]] = result[2]

        credential = connections[session['connid']]['current_credential']
        if credential['operation'] == 'verify':
            # TODO: Check expected credential result values against retrieved values

            connections[session['connid']]['verify_results'][credential['name']] = {'status': status,
                                                                                    'expiry': expiry,
                                                                                    'attributes': attributes}
        elif credential['operation'] == 'issue':
            # TODO: check for issuance result
            connections[session['connid']]['issue_results'][credential['name']] = {'status': status}
            pass


        kill_process()

        if (len(connections[session['connid']]['to_verify']) > 0 or
                len(connections[session['connid']]['to_issue']) > 0):
            # Tell the client again they can start the protocol, so it reconnects to the card
            emit('loggedin', {'version': session['version']})
            return
        else:
            # No more credentials. Return
            response = {'credentials': connections[session['connid']]['verify_results'],
                        'issued': connections[session['connid']]['issue_results'],
                        'token': connections[session['connid']]['token']}

            response = signer.dumps(response)

            emit('finished', response, room=session['connid'])
            # This is to the proxy, so it doesn't need to be in the room
            emit('finished', {'status': 'OK'})
    elif control == 'error':
        emit('card_error', {'code': options})
        kill_process()
    else:
        # Something went wrong!!!!
        emit('weird_response', {'control': control,
                                'options': options,
                                'stderr': session['process'].stderr.read()})
        kill_process()


@socketio.on('connect', namespace='/irma')
def irma_connect():
    emit('connected', {'data': 'Connected'})
    print 'Client connected'


@socketio.on('disconnect', namespace='/irma')
def irma_disconnect():
    print('Client disconnected')
    kill_process()


if __name__ == '__main__':
    socketio.run(app)
