# Copyright (c) 2014, Patrick Uiterwijk <puiterwijk@gmail.com>
# All rights reserved.
#
# This file is part of pySilvia.
#
# pySilvia is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pySilvia is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pySilvia.  If not, see <http://www.gnu.org/licenses/>.

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
    connection['credentials'] = json_request['credentials']
    connection['current_credential'] = None
    connection['credentials_results'] = {}
    connections[session['connid']] = connection

    return render_template('authenticate.html',
                           connid=session['connid'],
                           returnurl=json_request['return_url'])


@socketio.on('join', namespace='/irma')
def room_join(message):
    join_room(message['room'])
    emit('joined', {'data': 'Room joined'}, room=message['room'])


# These functions are used by the proxy
@socketio.on('login', namespace='/irma')
def login(message):
    connid = message['connID']
    session['connid'] = message['connID']
    emit('proxied', {'data': 'Proxy connected'}, room=connid)
    emit('loggedin', {})


def kill_verifier():
    if 'verifier' in session:
        session['verifier'].poll()
        if session['verifier'].returncode is None:
            session['verifier'].kill()
        session['verifier'].poll()
        del session['verifier']


@socketio.on('card_connected', namespace='/irma')
def card_connected(message):
    # Get the next credential
    credentials = connections[session['connid']]['credentials']
    credential = credentials.keys()[0]
    connections[session['connid']]['current_credential'] = credential
    credential_name = credential
    credential = credentials[credential]

    emit('retrieving', credential_name, room=session['connid'])

    cmd = [VERIFIER_PATH,
           '-S',
           '-I',
           '%s/%s' % (CONFIG_ROOT, credential['issuer-spec-path']),
           '-V',
           '%s/%s' % (CONFIG_ROOT, credential['verifier-spec-path']),
           '-k',
           '%s/%s' % (CONFIG_ROOT, credential['publickey-path'])]

    session['verifier'] = subprocess.Popen(cmd,
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)

    session['verifier'].poll()
    if session['verifier'].returncode is not None:
        emit('weird-error', {'stdout': session['verifier'].stdout.read(),
                             'stderr': session['verifier'].stderr.read()})
        kill_verifier()
        return

    command = session['verifier'].stdout.readline().replace('\n', '')

    if command == '':
        emit('no-response', {'stderr': session['verifier'].stderr.read()})
        kill_verifier()
        return

    control, options = command.split(' ', 1)

    if control == 'request':
        emit('card_request', {'data': options})
        return
    elif control == 'error':
        emit('card_error', {'code': options})
        kill_verifier()
        return
    else:
        # Something went wrong
        emit('weird_response', {'control': control,
                                'options': options,
                                'stderr': session['verifier'].stderr.read()})
        kill_verifier()
        return


@socketio.on('card_response', namespace='/irma')
def card_response(message):
    session['verifier'].stdin.write('%s\n' % message['data'])

    result = session['verifier'].stdout.readline().replace('\n', '')
    if result == '' or ' ' not in result:
        emit('card_error', {'code': result})
        kill_verifier()
        return

    control, options = result.split(' ', 1)

    if control == 'request':
        emit('card_request', {'data': options})
    elif control == 'result':
        results = session['verifier'].stdout.read().split('\n')
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
        connections[session['connid']]['credentials_results'][credential] = {'status': status,
                                                                             'expiry': expiry,
                                                                             'attributes': attributes}

        del connections[session['connid']]['credentials'][credential]
        kill_verifier()

        if len(connections[session['connid']]['credentials']) > 0:
            # Tell the client again they can start the protocol, so it reconnects to the card
            emit('loggedin', {})
            return
        else:
            # No more credentials. Return
            response = {'credentials': connections[session['connid']]['credentials_results'],
                        'token': connections[session['connid']]['token']}

            response = signer.dumps(response)

            emit('finished', response, room=session['connid'])
            # This is to the proxy, so it doesn't need to be in the room
            emit('finished', {})
    elif control == 'error':
        emit('card_error', {'code': options})
        kill_verifier()
    else:
        # Something went wrong!!!!
        emit('weird_response', {'control': control,
                                'options': options,
                                'stderr': session['verifier'].stderr.read()})
        kill_verifier()


@socketio.on('connect', namespace='/irma')
def irma_connect():
    emit('connected', {'data': 'Connected'})
    print 'Client connected'


@socketio.on('disconnect', namespace='/irma')
def irma_disconnect():
    print('Client disconnected')
    kill_verifier()


if __name__ == '__main__':
    socketio.run(app)
