FROM ntap/warpcore:dev
RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/main" \
        >> /etc/apk/repositories
RUN apk add --no-cache cmake@edge ninja gcc g++ git musl-dev linux-headers \
        libbsd-dev mercurial \
        openssl-dev http-parser-dev libev-dev
RUN git config --global user.email "docker@example.com"
ADD . /src
WORKDIR /src/Debug
RUN cmake -GNinja -DNO_SANITIZERS=True -DCMAKE_INSTALL_PREFIX=/dst ..
RUN ninja install

FROM alpine:3.6
COPY --from=0 /dst /
RUN apk add --no-cache openssl http-parser libev
EXPOSE 4433/UDP
CMD ["server", "-i", "eth0"]
