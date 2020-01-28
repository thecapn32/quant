#! /usr/bin/env bash

# Set up the routing needed for the simulation
/setup.sh

if [ -n "$TESTCASE" ]; then
    case "$TESTCASE" in
    "versionnegotiation"|"handshake"|"transfer"|"retry"|"resumption")
        ;;
    "http3")
        # if [ "$ROLE" == "client" ]; then
        #     CLIENT_ARGS=-3
        # else
            exit 127
        # fi
        ;;
    *)
        exit 127
        ;;
    esac
fi

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

rm -f /logs/$ROLE.log
if [ "$ROLE" == "client" ]; then
    CLIENT_ARGS="-i eth0 -w -q /logs/$ROLE.qlog $CLIENT_ARGS"

    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    cd /downloads || exit

    case "$TESTCASE" in
    "versionnegotiation")
        CLIENT_ARGS="-e 12345678 $CLIENT_ARGS"
        ;;
    "resumption")
        REQS=($REQUESTS)
        REQUESTS=${REQS[0]}
        client $CLIENT_ARGS $REQUESTS >> /logs/$ROLE.log 2>&1
        REQUESTS=${REQS[@]:1}
        ;;
    *)
        ;;
    esac

    client $CLIENT_ARGS $REQUESTS >> /logs/$ROLE.log 2>&1

elif [ "$ROLE" == "server" ]; then
    case "$TESTCASE" in
    "retry")
        SERVER_ARGS="-r $SERVER_ARGS"
        ;;
    *)
        ;;
    esac

    server $SERVER_ARGS -i eth0 -d /www -p 443 -p 4434 -t 0 \
        -c /tls/dummy.crt -k /tls/dummy.key \
        -q /logs/$ROLE.qlog >> /logs/$ROLE.log 2>&1
fi
