#!/usr/bin/env bash
cd "$(dirname "$0")"
export APP_PORT=${APP_PORT:-5000}
echo "Starting Etsy Listing Manager on port $APP_PORT ..."
pipenv run python app.py
