#! /usr/bin/env sh

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

if [ "$ROLE" = "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    sleep 3
    cd /downloads || exit
    client -i eth0 -w $REQUESTS
elif [ "$ROLE" = "server" ]; then
    server -i eth0 -d /www -p 443 -t 0 -c /tls/dummy.crt -k /tls/dummy.key
fi
