#! /usr/bin/env bash


opts=('' NO_64BIT NO_SERVER MINIMAL_CIPHERS NO_MIGRATION NO_ERR_REASONS
      NO_SRT_MATCHING NO_OOO_0RTT NO_OOO_DATA NO_QINFO)

always="-DNDEBUG -DRELEASE_BUILD"

i=0
for flag in "${opts[@]}"; do
        b=$((!i))
        ((i++))
        data="$i-${flag:-NONE}".func
        flags="${flag:+-D$flag} $flags"
        if [ ! -s "$data" ]; then
                echo -n "${flag:-NONE}"
                out=$(env COMPILE_LTO=y \
                        BUILD_FLAGS="$always -DHAVE_64BIT=$b $flags" \
                        po argon build 2>/dev/null | grep particle-argon.elf)
                bin=$(echo $out | cut -d' ' -f6)
                echo "$out"
                arm-none-eabi-nm -C -l -S --size-sort "$bin" | \
                        gsed -e 's| |\t|' -e 's| |\t|' -e 's| |\t|' | \
                                cut -f2- > "$data"
        fi
done
