#!/bin/bash
cd ~/docker_factorio_server
git fetch
git pull
cd 0.17
docker build --no-cache -t factorio_local .

cd ~/plexdocker
dc stop factorio
dc up -d factorio
