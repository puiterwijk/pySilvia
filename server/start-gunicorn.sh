#!/bin/bash
WEBSILVIA_SERVER_CONFIG=server.cfg gunicorn -c gunicorn_config.py server:app
