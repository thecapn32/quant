#! /usr/bin/env bash

# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2016-2018, NetApp, Inc.
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
        [ats]=quic.ogre.com
        [f5]=208.85.208.226
        [minq]=minq.dev.mozaws.net
        [mozquic]=mozquic.ducksong.com
        [mvfst]=fb.mvfst.net
        [ngtcp2]=nghttp2.org
        [ngx_quic]=quic.tech
        [pandora]=pandora.cm.in.tum.de
        [picoquic]=test.privateoctopus.com
        [quant]=quant.eggert.org
        [quicker]=quicker.edm.uhasselt.be
        [quicly]=kazuhooku.com
        [winquic]=msquic.westus.cloudapp.azure.com
)

results=(live fail vneg hshk data close zrtt hrr)
declare -A ${results[@]}


iface=$(route get default | grep interface: | cut -f2 -d: | tr -d "[:space:]")

# prefer gsed on Mac (install with homebrew, gnu-sed formula)
if which gsed > /dev/null; then
        sed=$(which gsed)
else
        sed=$(which sed)
fi

# use colordiff, if installed
if which colordiff > /dev/null; then
        colordiff=$(which colordiff)
else
        colordiff=$(which cat)
fi


pid=$$
script=$(basename -s .sh $0)


function test_server {
        # run quant client and produce a pure ASCII log for post-processing
        local cache="/tmp/$script.$1.$pid.cache"
        local opts="-i $iface -t3 -v4 -s $cache"
        local sed_pattern='s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g'
        local log_base="/tmp/$script.$1.$pid"

        # initial 1rtt run
        bin/client $opts "https://${servers[$1]}:4433/index.html" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.1rtt.log"

        # consecutive 0rtt run
        bin/client $opts "https://${servers[$1]}:4433/index.html" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.0rtt.log"
        rm -f "$cache"

        # hrr run
        bin/client $opts "https://${servers[$1]}:4434/index.html" 2>&1 | \
                $sed -r "$sed_pattern" > "$log_base.hrr.log"
        rm -f "$cache"

        printf "%s " "$s"
}


function analyze {
        # analyze 1rtt
        local log="/tmp/$script.$1.$pid.1rtt.log"

        perl -n -e '/assertion failed/ && exit 1;' "$log"
        if [ $? == 1 ]; then
                fail[$1]="X"
                tail -n 20 "$log"
                return
        fi

        perl -n -e '/RX len=/ && exit 1;' "$log"
        [ $? == 1 ] && live[$1]="*"

        perl -n -e '/0xbabababa, retrying with/ && exit 1;' "$log"
        [ $? == 1 ] && vneg[$1]=V

        perl -n -e '/TX len=.*Short/ and $x=1;
                    /RX len=.*Short/ && $x && exit 1;' "$log"
        [ $? == 1 ] && hshk[$1]=H

        perl -n -e '/read (.*) bytes on clnt conn/ &&
                            ($1 > 0 ? exit 1 : next);' "$log"
        [ $? == 1 ] && data[$1]=D

        perl -n -e 'BEGIN{$t=-1};
                    /TX len=/ and $t=1;
                    /RX len=/ and $t=0;
                    /CLOSE err=0x0000/ && ($t==1 ? $tc=1 : $rc=1);
                    END{exit $tc+$rc};' "$log"
        local ret=$?
        if [ $ret == 2 ]; then
                close[$1]=C
        elif [ $ret == 1 ]; then
                close[$1]=c
        fi
        rm -f "$log"

        # analyze 0rtt
        local log="/tmp/$script.$1.$pid.0rtt.log"

        if [ $? == 1 ]; then
                fail[$1]="X"
                tail -n 20 "$log"
                return
        fi

        perl -n -e '/connected after 0-RTT/ and $x=1;
                    $x && /CLOSE err=0x0000/ && exit 1;' "$log"
        [ $? == 1 ] && zrtt[$1]=Z
        rm -f "$log"

        # analyze hrr
        local log="/tmp/$script.$1.$pid.hrr.log"

        if [ $? == 1 ]; then
                fail[$1]="X"
                tail -n 20 "$log"
                return
        fi

        perl -n -e '/RX len=.*Retry/ and $x=1;
                   $x && /CLOSE err=0x0000/ && exit 1;' "$log"
        [ $? == 1 ] && hrr[$1]=S
        rm -f "$log"
}

printf "Testing servers: "
for s in "${!servers[@]}"; do
        test_server "$s" &
done
wait
printf "\\n\\n"

tmp=$(mktemp)
printf "%10s\\t" "" >> "$tmp"
for r in "${results[@]}"; do
        printf "%s\\t" "$r" >> "$tmp"
done
printf "\\n" >> "$tmp"

mapfile -d '' sorted < <(printf '%s\0' "${!servers[@]}" | sort -z)
for s in "${sorted[@]}"; do
        printf "%-10s\\t" "$s" >> "$tmp"
        analyze "$s"
        for r in "${results[@]}"; do
                v="$r[$s]"
                printf "%s\\t" "${!v}" >> "$tmp"
        done
        printf "\\n" >> "$tmp"
done

# cat "$tmp"
wdiff -n "$(dirname $0)/$script.result" "$tmp" | $colordiff
rm -f "$tmp"
