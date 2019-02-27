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
        [ats]=quic.ogre.com::4433:4434:4433:/en/latest/
        [f5]=208.85.208.226::4433:4433:4433:/file15k
        [lsquic]=http3-test.litespeedtech.com:-3:4433:4434:4433:/
        # [minq]=minq.dev.mozaws.net::4433:4434:4433:/index.html
        # [mozquic]=mozquic.ducksong.com::4433:4434:4433:/index.html
        [mvfst]=fb.mvfst.net::4433:4434:4433:/index.html
        [ngtcp2]=nghttp2.org::4433:4434:4433:/blog/
        [ngx_quic]=cloudflare-quic.com::443:4434:4433:/index.html
        # [pandora]=pandora.cm.in.tum.de::4433:4434:4433:/index.html
        [picoquic]=test.privateoctopus.com::4433:4434:4433:/20000
        [quant]=quant.eggert.org::4433:4434:4433:/20000
        # [quic-go]=172.30.197.239::4433:4433:4433:/10000
        [quiche]=quic.tech::4433:4433:4433:/random
        # [quicker]=quicker.edm.uhasselt.be::4433:4434:4433:/index.html
        [quicly]=kazuhooku.com::4433:4433:8443:/20000.txt
        [quinn]=ralith.com::4433:4434:4433:/100K
        [winquic]=msquic.westus.cloudapp.azure.com::4433:4434:4433:/draft-ietf-quic-http-11.txt
)

results=(live fail vneg hshk data clse rsmt zrtt rtry migr kyph http)
declare -A ${results[@]}


iface=$(route get default | grep interface: | cut -f2 -d: | tr -d "[:space:]")

# prefer gsed on Mac (install with homebrew, gnu-sed formula)
if command -v gsed > /dev/null; then
        sed=$(command -v gsed)
else
        sed=$(command -v sed)
fi

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
        local cache="/tmp/$script.$1.$pid.cache"
        local opts="-i $iface -t6 -v5 -s $cache"
        local sed_pattern='s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g'
        local log_base="/tmp/$script.$1.$pid"

        IFS=':' read -ra info <<< "${servers[$1]}"
        # 0=name, 1=flags, 2=port, 3=retry-port, 4=h3-port, 5=URL

        # initial 1rtt run
        bin/client $opts ${info[1]} \
                "https://${info[0]}:${info[2]}${info[5]}" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.1rtt.log"

        # consecutive rsmt/0rtt run
        bin/client $opts ${info[1]} \
                "https://${info[0]}:${info[2]}${info[5]}" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.0rtt.log"
        rm -f "$cache"

        # rtry run
        bin/client $opts ${info[1]} \
                "https://${info[0]}:${info[3]}${info[5]}" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.rtry.log"
        rm -f "$cache"

        # key update run
        bin/client $opts ${info[1]} -u \
                "https://${info[0]}:${info[2]}${info[5]}" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.kyph.log"
        rm -f "$cache"

        # h3 run
        bin/client $opts ${info[1]} -3 \
                "https://${info[0]}:${info[4]}${info[5]}" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.h3.log"
        rm -f "$cache"

        printf "%s " "$s"
}


function check_fail {
        local log="$2"
        perl -n -e '/assertion failed|AddressSanitizer|runtime error/ && exit 1;' "$log"
        if [ $? == 1 ]; then
                fail[$1]="X"
                echo "Test with $1 crashed (log $log):"
                tail -n 10 "$log"
                echo
                return 1
        fi
        return 0

}


function analyze {
        # analyze 1rtt
        local log="/tmp/$script.$1.$pid.1rtt.log"
        check_fail "$1" "$log"

        perl -n -e '/RX.*len=/ && exit 1;' "$log"
        [ $? == 1 ] && live[$1]="*"

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

        perl -n -e '/TX.*Short kyph/ and $x=1;
                    /RX.*len=.*Short/ && $x && exit 1;' "$log"
        [ $? == 1 ] && hshk[$1]=H

        perl -n -e '/read (.*) bytes.*on clnt conn/ and ($1 > 0 ? $t=1 : next);
                    $t && /CLOSE.*err=0x0000/ && exit 1;' "$log"
        [ $? == 1 ] && data[$1]=D

        perl -n -e 'BEGIN{$t=-1};
                    /TX.*len=/ and $t=1;
                    /RX.*len=/ and $t=0;
                    /CLOSE.*err=0x0000/ && ($t==1 ? $tc=1 : $rc=1);
                    END{exit $tc+$rc};' "$log"
        local ret=$?
        if [ $ret == 2 ]; then
                clse[$1]=C
        elif [ $ret == 1 ]; then
                clse[$1]=C #c
        fi

        perl -n -e '/dec_new_cid_frame.*NEW_CONNECTION_ID/ and $n=1;
                    /migration to dcid/ && $n && exit 1;' "$log"
        [ $? == 1 ] && migr[$1]=M
        # [ ${fail[$1]} ] || rm -f "$log"

        # analyze rsmt and 0rtt
        local log="/tmp/$script.$1.$pid.0rtt.log"
        check_fail "$1" "$log"

        perl -n -e '/new 0-RTT clnt conn/ and $x=1;
                    $x && /CLOSE.*err=0x0000/ && exit 1;' "$log"
        [ $? == 1 ] && rsmt[$1]=R

        perl -n -e '/connected after 0-RTT/ and $x=1;
                    $x && /CLOSE.*err=0x0000/ && exit 1;' "$log"
        [ $? == 1 ] && zrtt[$1]=Z
        [ ${fail[$1]} ] || rm -f "$log"

        # analyze rtry
        local log="/tmp/$script.$1.$pid.rtry.log"
        check_fail "$1" "$log"

        perl -n -e '/RX.*len=.*Retry/ and $x=1;
                   $x && /CLOSE.*err=0x0000/ && exit 1;' "$log"
        [ $? == 1 ] && rtry[$1]=S
        [ ${fail[$1]} ] || rm -f "$log"

        # analyze key update
        local log="/tmp/$script.$1.$pid.kyph.log"
        check_fail "$1" "$log"

        perl -n -e '/TX.*Short kyph=1/ and $x=1;
                   $x && /RX.*Short kyph=1/ && exit 1;' "$log"
        [ $? == 1 ] && kyph[$1]=U
        [ ${fail[$1]} ] || rm -f "$log"

        # analyze h3
        local log="/tmp/$script.$1.$pid.h3.log"
        check_fail "$1" "$log"

        perl -n -e '/read (.*) bytes.*on clnt conn/ and ($1 > 0 ? $t=1 : next);
                    /no h3 payload/ and $t=0;
                    $t && /CLOSE.*err=0x0000/ && exit 1;' "$log"
        [ $? == 1 ] && http[$1]=3
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
