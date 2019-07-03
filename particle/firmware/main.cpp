#ifndef NDEBUG
#define DEBUG_BUILD
#endif

#include <Particle.h>
#include <netdb.h>

#include "quant/quant.h"
#include "warpcore/warpcore.h"


static const int led = D7;
static const float volt_div = 0.0011224;

// static SerialDebugOutput log;
static int led_mode = HIGH;

static struct w_engine * w;
static struct q_conn * c;
static struct w_iov_sq req = w_iov_sq_initializer(req);


// static void cleanup()
// {
//     q_cleanup(w);
// }


void setup()
{
    pinMode(led, OUTPUT);

    const struct q_conf qc = {0, 0, 0, 0, 20, false};
    w = q_init("wl3", &qc);

    static struct addrinfo hints;
    hints.ai_family = PF_INET;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo * peer;
    const char peername[] = "quant.eggert.org";
    ensure(getaddrinfo(peername, "4433", &hints, &peer) == 0,
           "getaddrinfo peer");

    w_alloc_cnt(w, &req, 1, 0, 0);

    c = q_connect(w, peer->ai_addr, peername, 0, 0, true, 0);
    ensure(c, "could not open connection");

    freeaddrinfo(peer);
}


void loop()
{
    struct w_iov * const v = sq_first(&req);
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

    struct q_stream * const s = q_rsv_stream(c, true);
    q_write(s, &req, true);
    warn(DBG, "TX: %s", v->buf);

    delay(5000);
}
