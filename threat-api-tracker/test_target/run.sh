#!/usr/bin/env bash
set -e
export FLASK_APP=app.server
export FLASK_ENV=production
flask run --host=0.0.0.0 --port=8080
