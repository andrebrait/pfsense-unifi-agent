#!/bin/sh
# pfSense boot hook: /etc/rc.start_packages invokes /usr/local/etc/rc.d/*.sh.
exec /usr/sbin/service pfsense_unifi_agent "${1:-start}"
