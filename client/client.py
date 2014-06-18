from socketIO_client import SocketIO, BaseNamespace
import sys

import subprocess32 as subprocess

import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)


class IrmaNamespace(BaseNamespace):
    def initialize(self):
        print 'irma init'

    def on_connected(self, *args):
        print 'Connected to server', args
        print 'Initializing proxy'
        self.proxy = subprocess.Popen('/home/puiterwijk/Documents/Development/Upstream/silvia/src/bin/proxy/silvia_proxy',
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.proxy.poll()
        if self.proxy.returncode is not None:
            print 'proxy error!'
            print 'stdout: %s' % self.proxy.stdout.read()
            print 'stderr: %s' % self.proxy.stderr.read()
            sys.exit(1)

        status = self.proxy.stdout.readline().replace('\n', '')
        if status == '' or not status.startswith('control wait-for-card'):
            print 'Error! Not waiting for card?'
            print 'Status: %s' % status
            sys.exit(1)

        print 'Proxy read. Waiting for: %s' % status.split(' ')[2]
        status = self.proxy.stdout.readline().replace('\n', '')
        if status == 'control connected':
            print 'Card connected! Notifying server and starting protocol.'
            irma_namespace.emit('card_connected', {})
            socketIO.wait(seconds=1)
        else:
            print 'Error, unknown response: %s' % status
            sys.exit(1)

    def perform_request(self, request):
        self.proxy.stdin.write('request %s\n' % request)
        return self.proxy.stdout.readline().replace('\n', '')


    def on_card_connect_response(self, *args):
        print 'on_card_connect_response', args

    def on_card_request(self, *args):
        print 'Card request recieved!'
        request = args[0]['data']
        response = self.perform_request(request)
        if response.startswith('response'):
            irma_namespace.emit('card_response', {'data': response})
            socketIO.wait(seconds=1)

    def on_finished(self, *args):
        print 'Process finished!'
        irma_namespace.disconnect()


with SocketIO('localhost', 5000) as socketIO:
    irma_namespace = socketIO.define(IrmaNamespace, '/irma')

    socketIO.wait(seconds=1)
