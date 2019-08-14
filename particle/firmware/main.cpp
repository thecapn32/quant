// #ifndef NDEBUG
// #define DEBUG_BUILD
// #endif

#include <Particle.h>
#include <netdb.h>

#include "quant/quant.h"
// #include "warpcore/warpcore.h"

SYSTEM_MODE(MANUAL);
// SYSTEM_THREAD(ENABLED);

static SerialDebugOutput serial;
static const int led = D7;


// don't use entropy from cloud
void random_seed_from_cloud(unsigned int seed) {}


struct addrinfo * resolve(const char * const name, const char * const port)
{
    struct addrinfo hints;
    hints.ai_family = PF_INET;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo * peer;
    ensure(getaddrinfo(name, port, &hints, &peer) == 0, "");
    return peer;
}


void warpcore_transaction()
{
    struct w_engine * const w = w_init("wl3", 0, 50);
    struct w_sock * const s = w_bind(w, 0, 0);
    struct addrinfo * const peer = resolve("quant.eggert.org", "4433");
    struct w_iov_sq o = w_iov_sq_initializer(o);

    w_alloc_cnt(w, &o, 1, 0, 0);
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
    if (w_nic_rx(w, 1 * MSECS_PER_SEC)) {
        w_rx(s, &i);
        warn(DBG, "pkt rx");
    }

    w_free(&o);
    w_free(&i);
    w_cleanup(w);
}


void quic_transaction()
{
    const struct q_conf qc = {0, 0, 0, 0, 0, 0, 10, false};
    struct w_engine * const w = q_init("wl3", &qc);
    const char peername[] = "172.19.235.111";
    struct addrinfo * const peer = resolve(peername, "4433");
    struct q_conn * const c = q_connect(w, peer->ai_addr, peername, 0, 0, true,
                                        "hq-" DRAFT_VERSION_STRING, 0);
    ensure(c, "could not open connection");
    freeaddrinfo(peer);
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
