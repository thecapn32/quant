#! /usr/bin/env bash
set -e

echo "Starting quant $ROLE..."
echo "Params: $CLIENT_PARAMS"
echo "Testcase: $TESTCASE"

if [ "$ROLE" == "client" ]; then
        cd /downloads
        /bin/client -i eth0 -w $REQUESTS
else
        /bin/server -i eth0 -d /www -p 443 -t 0 \
                -c /tls/dummy.crt -k /tls/dummy.key
fi
