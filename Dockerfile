FROM ntap/warpcore:latest
RUN apk add --no-cache cmake ninja gcc g++ git musl-dev linux-headers \
        mercurial openssl openssl-dev http-parser-dev libev-dev libbsd-dev
RUN git config --global user.email "docker@example.com"
ADD . /src
WORKDIR /src/Debug
RUN cmake -GNinja -DNO_SANITIZERS=True -DNO_FUZZER_CORPUS_COLLECTION=True \
        -DCMAKE_INSTALL_PREFIX=/dst ..
RUN ninja install
ADD https://github.com/gabrielecirulli/2048/archive/master.zip /
RUN unzip /master.zip -d /
WORKDIR /tls
RUN openssl req -batch -new -newkey rsa:2048 -sha256 -days 9365 -nodes -x509 \
        -keyout quant.key -out quant.crt -subj "/"

FROM alpine:latest
COPY --from=0 /dst /
COPY --from=0 /2048-master /www
COPY --from=0 /tls /tls
RUN apk add --no-cache libcrypto1.0 http-parser libev libbsd ethtool
EXPOSE 4433/UDP
CMD ["/bin/server", "-i", "eth0", "-d", "/www", \
        "-c", "/tls/quant.crt", "-k", "/tls/quant.key"]
