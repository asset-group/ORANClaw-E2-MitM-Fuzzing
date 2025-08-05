#!/usr/bin/env bash

docker compose exec -it oai-ue-rfsimu-$1 iperf3 -c $2 -t0
