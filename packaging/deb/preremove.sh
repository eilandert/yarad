#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl stop yarad >/dev/null 2>&1 || true
    systemctl disable yarad >/dev/null 2>&1 || true
fi
