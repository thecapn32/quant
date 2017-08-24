#! /usr/bin/env bash

export PATH="$PATH:~/bin"

mkdir -p ~/quant/Debug
cd ~/quant/Debug || exit
git pull
cmake -GNinja ..
ninja

name=/var/www/html/index.html
path=$(dirname "$name")
filename=$(basename "$name")
extension="${filename##*.}"
filename="${filename%.*}"
if [[ -e $path/$filename.$extension ]] ; then
    i=1
    while [[ -e $path/$filename-$i.$extension ]] ; do
        let i++
    done
    filename=$filename-$i
fi
mv "$name" "$path/$filename.$extension"
mail -s "$path/$filename.$extension" lars@netapp.com -A "$path/$filename.$extension"

bin/server -i eth0 2>&1 | aha > "$name"
