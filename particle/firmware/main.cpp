#include <Particle.h>
#include <netdb.h>

#include "warpcore/warpcore.h"


static const int led = D7;
static const float volt_div = 0.0011224;

static SerialDebugOutput log;
static int led_mode = HIGH;

static struct w_engine * w;
static struct w_sock * s;
static struct w_iov_sq o = w_iov_sq_initializer(o);


// static void cleanup()
// {
//     w_cleanup(w);
// }


void setup()
{
    pinMode(led, OUTPUT);
    w = w_init("wl3", 0, 10);
    s = w_bind(w, 0, 0);

    static struct addrinfo hints;
    hints.ai_family = PF_INET;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo * peer;
    ensure(getaddrinfo("quant.eggert.org", "4433", &hints, &peer) == 0,
           "getaddrinfo peer");

    w_alloc_cnt(w, &o, 1, 0, 0);
    w_connect(s, peer->ai_addr);
    freeaddrinfo(peer);
}


void loop()
{
    struct w_iov * const v = sq_first(&o);
    const float voltage = analogRead(BATT) * volt_div;

    runtime_info_t info = {0};
    info.size = sizeof(info);
    HAL_Core_Runtime_Info(&info, 0);
    v->len = sprintf((char *)v->buf,
                     "Hello from Particle! OS %s, %.2fV, %" PRIu32 "/%" PRIu32
                     "KB RAM",
                     System.version().c_str(), voltage, info.freeheap / 0x400,
                     info.total_init_heap / 0x400);

    digitalWrite(led, led_mode);
    led_mode = led_mode == HIGH ? LOW : HIGH;

    w_tx(s, &o);
    while (w_tx_pending(&o))
        w_nic_tx(w);
    warn(DBG, "TX: %s", v->buf);

    struct w_iov_sq i = w_iov_sq_initializer(i);
    if (w_nic_rx(w, 0)) {
        w_rx(s, &i);
        warn(DBG, "RX");
    }

    delay(5000);
}
