#!/bin/sh
set -e

# Create the yarad service account (sysusers if available, else useradd).
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/yarad.conf >/dev/null 2>&1 || true
elif ! getent passwd yarad >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/yarad --no-create-home \
            --shell /usr/sbin/nologin --comment "yarad scanning daemon" yarad || true
fi

# Own the state dir.
if getent passwd yarad >/dev/null 2>&1; then
    mkdir -p /var/lib/yarad/rules /var/cache/yarad
    chown -R yarad:yarad /var/lib/yarad /var/cache/yarad
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "yarad installed. Fetch rules:  sudo -u yarad yarad fetch-rules -cache-dir /var/cache/yarad"
echo "Set a token in /etc/yarad/yarad.env, then:  systemctl enable --now yarad"
