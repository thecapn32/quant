#include <Particle.h>
#include <netdb.h>

extern const void * const stack_start = __builtin_frame_address(0);

#include "quant/quant.h"

SYSTEM_MODE(MANUAL);
// SYSTEM_THREAD(ENABLED);

static SerialDebugOutput serial;
static const int led = D7;


// don't use entropy from cloud
void random_seed_from_cloud(unsigned int seed) {}


struct addrinfo * resolve(const char * const name, const char * const port)
{
    struct addrinfo hints;
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo * peer;
    ensure(getaddrinfo(name, port, &hints, &peer) == 0, "");
    return peer;
}


void warpcore_transaction()
{
    struct w_engine * const w = w_init("wl3", 0, 50);
    struct w_sock * const s = w_bind(w, 0, 0, 0);
    struct addrinfo * const peer = resolve("quant.eggert.org", "4433");
    struct w_iov_sq o = w_iov_sq_initializer(o);

    w_alloc_cnt(w, AF_INET, &o, 1, 0, 0);
    w_connect(s, peer->ai_addr);
    freeaddrinfo(peer);

    struct w_iov * const v = sq_first(&o);
    const float voltage = analogRead(BATT) * 0.0011224;
    v->len =
        sprintf((char *)v->buf, "Hello from Particle! Voltage is %f.", voltage);

    w_tx(s, &o);
    while (w_tx_pending(&o))
        w_nic_tx(w);
    warn(DBG, "pkt tx: %s", v->buf);

    struct w_iov_sq i = w_iov_sq_initializer(i);
    if (w_nic_rx(w, 1 * MS_PER_S)) {
        w_rx(s, &i);
        warn(DBG, "pkt rx");
    }

    w_free(&o);
    w_free(&i);
    w_cleanup(w);
}


void quic_transaction()
{
    static const struct q_conf qc = {0, 0, 0, 0, 0, 0, 20, false};
    struct w_engine * const w = q_init("wl3", &qc);

    static const char peername[] = "10.100.25.62";
    struct addrinfo * peer = 0;
    do {
        peer = resolve(peername, "4433");
        if (peer == 0) {
            warn(WRN, "unable to resolve %s, retrying", peername);
            delay(1000);
        }
    } while (peer == 0);

    static const char req[] = "GET /5000\r\n";
    struct w_iov_sq o = w_iov_sq_initializer(o);
    q_alloc(w, &o, AF_INET, sizeof(req) - 1);
    struct w_iov * const v = sq_first(&o);
    memcpy(v->buf, req, sizeof(req) - 1);

    struct q_stream * s;
    static const struct q_conn_conf qcc = {0, 0, 0, 0,
                                           0, 0, 0, 0xff000000 + DRAFT_VERSION};
    struct q_conn * const c = q_connect(w, peer->ai_addr, peername, &o, &s,
                                        true, "hq-" DRAFT_VERSION_STRING, &qcc);
    freeaddrinfo(peer);

    if (c) {
        struct w_iov_sq i = w_iov_sq_initializer(i);
        q_read_stream(s, &i, true);
        warn(NTE, "retrieved %" PRIu32 " bytes", w_iov_sq_len(&i));
    } else
        warn(WRN, "could not retrieve %s", req);

    q_cleanup(w);
}


void button_action()
{
    Serial.begin(9600);
    delay(1000);

    WiFi.on();
    WiFi.connect(WIFI_CONNECT_SKIP_LISTEN);
    waitUntil(WiFi.ready);
    digitalWrite(led, HIGH);

    // warpcore_transaction();
    quic_transaction();

    WiFi.off();
    digitalWrite(led, LOW);
}


void setup()
{
    // let's gather some entropy and seed the RNG
    const int temp = analogRead(A0);
    const int volt = analogRead(BATT);
    randomSeed(((temp << 12) | volt));

    pinMode(led, OUTPUT);
    button_action();
}


void loop()
{
    System.sleep(BTN, FALLING);
    if (System.sleepResult().reason() == WAKEUP_REASON_PIN)
        button_action();
}
