FROM alpine:latest
RUN apk add --no-cache cmake ninja gcc g++ git musl-dev linux-headers \
        bsd-compat-headers openssl openssl-dev http-parser-dev
RUN git config --global user.email "docker@example.com"
ADD . /src
WORKDIR /src/Debug
RUN cmake -GNinja -DNO_FUZZER_CORPUS_COLLECTION=True -DDOCKER=True \
        -DCMAKE_INSTALL_PREFIX=/dst ..
RUN ninja install

FROM alpine:latest
COPY --from=0 /dst /
COPY --from=0 /src/Debug/test/dummy.* /tls/
RUN apk add --no-cache openssl http-parser ethtool
EXPOSE 4433/UDP
EXPOSE 4434/UDP
CMD ["/bin/server", "-i", "eth0", "-d", "/tmp", \
        "-c", "/tls/dummy.crt", "-k", "/tls/dummy.key"]
