#!/bin/bash

sudo DPRC=dprc.2 ./bin/arm64/sia-lx2160/prototype -c 0xffff --master-lcore 0 -n 1 --log-level=8 --log-level=".*,6" --log-level="prototype,8" "$@"
