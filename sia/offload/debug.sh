#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Run the app with gdb
sudo DPRC=dprc.2 gdb -ex=r --args ${DIR}/bin/arm64/sia-lx2160/prototype -c 0xffff --master-lcore 0 -n 1
