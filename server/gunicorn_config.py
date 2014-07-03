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

# You can not increase this from one for now, as we use global variables
workers = 1

worker_class = 'socketio.sgunicorn.GeventSocketIOWorker'
bind = '0.0.0.0:5000'
pidfile = '/opt/webSilvia/server/gunicorn.pid'
debug = True
loglevel = 'debug'
errorlog = '/opt/webSilvia/server/gunicorn.log'
daemon = True
# keyfile = '/opt/webSilvia/silvia.fedoauth.org.key'
# certfile = '/opt/webSilvia/silvia.fedoauth.org.pem'
