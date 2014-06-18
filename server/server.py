from gevent import monkey
monkey.patch_all()

import subprocess32 as subprocess

from flask import Flask, render_template, session, jsonify, abort, request
from flask.ext.socketio import SocketIO, emit


import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)



app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/transaction/create/', methods=['POST'])
def transaction_create():
    if not request.json or 'authorization' not in request.json:
        abort(400)

    return jsonify({'test': 'test123'})


def kill_verifier():
    if 'verifier' in session:
        session['verifier'].poll()
        if session['verifier'].returncode is None:
            session['verifier'].kill()
        session['verifier'].poll()
        del session['verifier']


@socketio.on('card_connected', namespace='/irma')
def card_connected(message):
    cmd = ['/home/puiterwijk/Documents/Development/Upstream/silvia/src/bin/verifier/silvia_verifier',
           '-S',
           '-I',
           '/home/puiterwijk/Documents/Development/Fedora/IRMA/irma_configuration/Fedora/Issues/fasRoot/description.xml',
           '-V',
           '/home/puiterwijk/Documents/Development/Fedora/IRMA/irma_configuration/Fedora/Verifies/fedora/description.xml',
           '-k',
           '/home/puiterwijk/Documents/Development/Fedora/IRMA/irma_configuration/Fedora/ipk.xml']

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
        results = [result] + session['verifier'].stdout.read().split('\n')
        # TODO: Mark this session as DONE

        print 'Results: %s' % results

        emit('finished', {})
        kill_verifier()
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
