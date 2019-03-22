#! /usr/bin/env bash

# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2016-2019, NetApp, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


declare -A servers=(
    # [tag]=name:flags:port:retry-port:h3-port:URL
    # [apple]=172.30.197.241::4433:4434:4433:/index.html
    [ats]=quic.ogre.com::4433:4434:4433:/en/latest/_static/jquery.js
    [f5]=208.85.208.226::4433:4433:4433:/file50k
    [lsquic]=http3-test.litespeedtech.com:-3:4433:4434:4433:/
    # [minq]=minq.dev.mozaws.net::4433:4434:4433:/index.html
    # [mozquic]=mozquic.ducksong.com::4433:4434:4433:/index.html
    [mvfst]=fb.mvfst.net::4433:4434:4433:/index.html
    [ngtcp2]=nghttp2.org::4433:4434:4433:/documentation/
    [ngx_quic]=cloudflare-quic.com:-3:443:443:443:/index.html
    # [pandora]=pandora.cm.in.tum.de::4433:4434:4433:/index.html
    [picoquic]=test.privateoctopus.com::4433:4434:4433:/40000
    [quant]=quant.eggert.org::4433:4434:4433:/40000
    # [quic-go]=172.30.197.239::4433:4433:4433:/10000
    [quiche]=quic.tech::4433:4433:8443:/random
    # [quicker]=quicker.edm.uhasselt.be::4433:4434:4433:/index.html
    [quicly]=kazuhooku.com::4433:4433:8443:/40000.txt
    [quinn]=ralith.com::4433:4434:4433:/100K
    [winquic]=quic.westus.cloudapp.azure.com::4433:4434:443:/draft-ietf-quic-http-11.txt
)

results=(live fail vneg hshk data clse rsmt zrtt rtry migr bind kyph http spin aecn)
declare -A ${results[@]}


iface=$(route get default | grep interface: | cut -f2 -d: | tr -d "[:space:]")

# use colordiff, if installed
if command -v colordiff > /dev/null; then
    colordiff=$(command -v colordiff)
else
    colordiff=$(command -v cat)
fi


pid=$$
script=$(basename -s .sh "$0")
rm -f /tmp/"$script"*

function test_server {
    # run quant client and produce a pure ASCII log for post-processing
    local opts="-i $iface -t4 -v5"
    local log_base="/tmp/$script.$1.$pid"

    IFS=':' read -ra info <<< "${servers[$1]}"
    # 0=name, 1=flags, 2=port, 3=retry-port, 4=h3-port, 5=URL

    # initial 1rtt run followed by consecutive rsmt/0rtt run
    local cache="/tmp/$script.$1.$pid.cache"
    bin/client $opts -s "$cache" ${info[1]} \
        "https://${info[0]}:${info[2]}${info[5]}" \
        > "$log_base.1rtt.log" 2>&1 ; \
    bin/client $opts -s "$cache" ${info[1]} \
        "https://${info[0]}:${info[2]}${info[5]}" \
        > "$log_base.0rtt.log" 2>&1 ; \
    rm -f "$cache" &

    # rtry run
    bin/client $opts ${info[1]} -s /dev/null \
        "https://${info[0]}:${info[3]}${info[5]}" > "$log_base.rtry.log" 2>&1 &

    # key update run
    bin/client $opts ${info[1]} -s /dev/null -u \
        "https://${info[0]}:${info[2]}${info[5]}" > "$log_base.kyph.log" 2>&1 &

    # h3 run
    bin/client $opts ${info[1]} -s /dev/null -3 \
        "https://${info[0]}:${info[4]}${info[5]}" > "$log_base.h3.log" 2>&1 &

    # NAT rebinding run
    bin/client $opts ${info[1]} -s /dev/null -n \
        "https://${info[0]}:${info[2]}${info[5]}" > "$log_base.nat.log" 2>&1 &

    wait
    printf "%s " "$s"
}


function check_fail {
    local log="$2"
    if ! grep -q -E 'assertion failed|AddressSanitizer|runtime error' "$log"; then
        return 0
    fi

    fail[$1]="X"
    echo "Test with $1 crashed (log $log):"
    tail -n 10 "$log"
    echo
    return 1
}


function analyze {
    local sed_pattern='s,\x1B\[[0-9;]*[a-zA-Z],,g'

    # analyze 1rtt
    local log="/tmp/$script.$1.$pid.1rtt.log"
    check_fail "$1" "$log"

    gsed "$sed_pattern" "$log" | grep -E -q 'RX.*len=' && live[$1]="*"

    perl -n -e 'BEGIN{$v=-1};
                /0xbabababa, retrying with/ and $v=1;
                /no vers in common/ and $v=0;
                END{exit $v};' "$log"
    local ret=$?
    if [ $ret == 1 ]; then
        vneg[$1]=V
    elif [ $ret == 0 ]; then
        vneg[$1]=v
    fi

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/TX.*Short kyph/ and $x=1;
            /RX.*len=.*Short/ && $x && exit 1;'
    [ $? == 1 ] && hshk[$1]=H

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/read (.*) bytes.*on clnt conn/ and ($1 > 0 ? $x=1 : next);
            $x && /CLOSE.*err=0x0000/ && exit 1;'
    [ $? == 1 ] && data[$1]=D

    gsed "$sed_pattern" "$log" | \
        perl -n -e 'BEGIN{$x=-1};
            /TX.*len=/ and $x=1;
            /RX.*len=/ and $x=0;
            /CLOSE.*err=0x0000/ && ($x==1 ? $xc=1 : $rc=1);
            END{exit $xc+$rc};'
    local ret=$?
    if [ $ret == 2 ]; then
        clse[$1]=C
    elif [ $ret == 1 ]; then
        clse[$1]=C #c
    fi

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/dec_new_cid_frame.*NEW_CONNECTION_ID|preferred_address.*cid=1:/ and $n=1;
            /migration to dcid/ && $n && exit 1;'
    [ $? == 1 ] && migr[$1]=M

    # analyze spin
    gsed "$sed_pattern" "$log" | \
        perl -n -e '/TX.*spin=1/ and $n=1;
            $n && /RX.*spin=1/ && exit 1;'
    [ $? == 1 ] && spin[$1]=P

    # analyze ECN
    gsed "$sed_pattern" "$log" | \
        perl -n -e '/ECN verification failed/ and $n=-1;
            $n==0 && /dec_ack_frame.*ECN ect0=/ && exit 1;'
    [ $? == 1 ] && aecn[$1]=E
    [ ${fail[$1]} ] || rm -f "$log"

    # analyze rsmt and 0rtt
    local log="/tmp/$script.$1.$pid.0rtt.log"
    check_fail "$1" "$log"

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/new 0-RTT clnt conn/ and $x=1;
            $x && /CLOSE.*err=0x0000/ && exit 1;'
    [ $? == 1 ] && rsmt[$1]=R

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/connected after 0-RTT/ and $x=1;
            $x && /CLOSE.*err=0x0000/ && exit 1;'
    [ $? == 1 ] && zrtt[$1]=Z
    [ ${fail[$1]} ] || rm -f "$log"

    # analyze rtry
    local log="/tmp/$script.$1.$pid.rtry.log"
    check_fail "$1" "$log"

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/RX.*len=.*Retry/ and $x=1;
           $x && /CLOSE.*err=0x0000/ && exit 1;'
    [ $? == 1 ] && rtry[$1]=S
    [ ${fail[$1]} ] || rm -f "$log"

    # analyze key update
    local log="/tmp/$script.$1.$pid.kyph.log"
    check_fail "$1" "$log"

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/TX.*Short kyph=1/ and $x=1;
           $x && /RX.*Short kyph=1/ && exit 1;'
    [ $? == 1 ] && kyph[$1]=U
    [ ${fail[$1]} ] || rm -f "$log"

    # analyze h3
    local log="/tmp/$script.$1.$pid.h3.log"
    check_fail "$1" "$log"

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/read (.*) bytes.*on clnt conn/ and ($1 > 0 ? $x=1 : next);
            /no h3 payload/ and $x=0;
            $x && /CLOSE.*err=0x0000/ && exit 1;'
    [ $? == 1 ] && http[$1]=3
    [ ${fail[$1]} ] || rm -f "$log"

    # analyze NAT rebind
    local log="/tmp/$script.$1.$pid.nat.log"
    check_fail "$1" "$log"

    gsed "$sed_pattern" "$log" | \
        perl -n -e '/NAT rebinding/ and $x=1;
            /dec_path.*PATH_CHALLENGE/ and $x==1 and $x=2;
            /enc_path.*PATH_RESPONSE/ and $x==2 and $x=3;
            /read (.*) bytes.*on clnt conn/ and $x==3 and ($1 > 0 ? $x=4 : next);
            $x==4 && /CLOSE.*err=0x0000/ && exit 1;'
    [ $? == 1 ] && bind[$1]=B
    [ ${fail[$1]} ] || rm -f "$log"
}

printf "Testing servers: "
for s in "${!servers[@]}"; do
    test_server "$s" &
done
wait
printf "\\n\\n"

tmp=$(mktemp)
printf "%8s\\t" "" >> "$tmp"
for r in "${results[@]}"; do
    printf "%s\\t" "$r" >> "$tmp"
done
printf "\\n" >> "$tmp"

mapfile -d '' sorted < <(printf '%s\0' "${!servers[@]}" | sort -z)
for s in "${sorted[@]}"; do
    printf "%-8s\\t" "$s" >> "$tmp"
    analyze "$s"
    for r in "${results[@]}"; do
        v=$r[$s]
        printf "%s\\t" "${!v}" >> "$tmp"
    done
    printf "\\n" >> "$tmp"
done

expand -t 5 "$tmp" | sponge "$tmp"
# cat "$tmp"
wdiff -n "$(dirname $0)/$script.result" "$tmp" | $colordiff
rm -f "$tmp"
