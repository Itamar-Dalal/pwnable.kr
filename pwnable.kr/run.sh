#!/bin/sh
set -eu

image="towelroot"
container="towelroot"

docker build -t "$image" .
docker rm -f "$container" >/dev/null 2>&1 || true
docker run -d \
  --name "$container" \
  --restart always \
  --privileged \
  --pids-limit 100 \
  --memory 256m \
  --cpus 1.0 \
  -p 127.0.0.1:10052:10052 \
  "$image"

printf 'running: socat STDIO,raw,echo=0,opost,onlcr TCP:127.0.0.1:10052\n'
