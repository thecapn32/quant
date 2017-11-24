FROM ntap/warpcore:dev
RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/main" \
        >> /etc/apk/repositories
RUN apk add --no-cache cmake@edge ninja gcc g++ git musl-dev linux-headers \
        libbsd-dev mercurial openssl \
        openssl-dev http-parser-dev libev-dev
RUN git config --global user.email "docker@example.com"
ADD . /src
WORKDIR /src/Debug
RUN cmake -GNinja -DNO_SANITIZERS=True -DCMAKE_INSTALL_PREFIX=/dst ..
RUN ninja install
ADD https://github.com/gabrielecirulli/2048/archive/master.zip /www
WORKDIR /tls
RUN openssl req -batch -new -newkey rsa:2048 -sha256 -days 9365 -nodes -x509 \
        -keyout quant.key -out quant.crt

FROM alpine:3.6
COPY --from=0 /dst /
COPY --from=0 /www /www
COPY --from=0 /tls /tls
RUN find /tls
RUN apk add --no-cache openssl http-parser libev
EXPOSE 4433/UDP
CMD ["server", "-i", "eth0", "-d", "/www", "-c", "/tls/quant.crt", \
        "-k", "/tls/quant.key"]
