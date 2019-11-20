#! /usr/bin/env Rscript

library("tidyverse")
library("formattable")
library("RColorBrewer")


theme_lars = function(base_size = 9,
                      base_family = "Times",
                      base_line_size = base_size,
                      base_rect_size = base_size) {
    theme_void(base_size = base_size,
               base_family = base_family,
               base_line_size = base_line_size) %+replace%
    theme(complete = TRUE,
          line=element_line(color="black",
                            size=1/2.835,
                            linetype="solid",
                            lineend="round"),
          plot.title=element_text(size=base_size),
          legend.text=element_text(size=base_size),
          axis.title=element_text(size=base_size),
          axis.title.y=element_text(angle=90,
                                    margin=margin(0, base_size/2, 0, 0, "pt")),
          axis.title.x=element_text(margin=margin(base_size/2, 0, 0, 0, "pt")),
          axis.text=element_text(size=base_size),
          axis.ticks.length=unit(1, "mm"),
          panel.grid.major.x=element_blank(),
          panel.grid.minor=element_blank(),
          panel.grid.major.y=element_line(color="gray",
                                          size=1/2.835,
                                          linetype="solid",
                                          lineend="round"),
          legend.margin=margin(0, 0, 0, base_size/2, "pt"),
          legend.key.size=unit(base_line_size, "pt")
          )
}

update_geom_defaults("text", list(family=theme_lars()$text$family,
                                  size=theme_lars()$text$size/2.835))


# order matters!
file_cat = list("app"           = "/firmware/main.cpp",
                "os"            = "/.po-util/src/",
                "cifra"         = "/deps/cifra/",
                "micro-ecc"     = "/deps/micro-ecc/",
                "picotls"       = "/deps/picotls/",
                "timeout"       = "/deps/timeout/",
                "warpcore"      = "/deps/warpcore/",
                "quant"         = "/quant/")


func_cat = list("libc"          = c("std::",
                                    "__",
                                    "vtable",
                                    "operator",
                                    "calloc",
                                    "gettimeofday",
                                    "memcmp",
                                    "memcpy",
                                    "memmove",
                                    "memset",
                                    "srand",
                                    "strcmp",
                                    "strdup",
                                    "strlen",
                                    "strncpy"),

                "os"            = c("::",
                                    "SLEEP_NETWORK_OFF",
                                    "pinAvailable",
                                    "impure"),

                "micro-ecc"     = c("uECC_",
                                    "sha256_final",
                                    "vli_modInv_update"),

                "picotls"       = c("aesgcm_decrypt",
                                    "default_emit_certificate",
                                    "derive_exporter_secret",
                                    "derive_resumption_secret",
                                    "emit_server_name_extension",
                                    "extension_bitmap_",
                                    "handle_unknown_extension",
                                    "on_client_hello",
                                    "ptls_is_server",
                                    "ptls_server_name_is_ipaddr",
                                    "push_change_cipher_spec",
                                    "push_signature_algorithms",
                                    "select_key_share",
                                    "send_certificate_and_certificate_verify",
                                    "send_finished",
                                    "serial1_rx_buffer",
                                    "serial1_tx_buffer",
                                    "update_traffic_key"),

                "timeout"       = c("timeouts_sched",
                                    "timeouts_timeout"),

                "warpcore"      = c("w_set_sockopt",
                                    "w_alloc_iov",
                                    "to_sockaddr",
                                    "w_addr_hash"),

                "quant"         = c("ack_alarm",
                                    "add_scid",
                                    "cancel_api_call",
                                    "congestion_event",
                                    "conns_by_id_del",
                                    "conns_by_id_ins",
                                    "dec_tp",
                                    "do_stream_id_fc",
                                    "enc1",
                                    "enc2",
                                    "enc4",
                                    "enter_closed",
                                    "enter_closing",
                                    "epoch_in",
                                    "flip_label",
                                    "frame_ok",
                                    "free_tls",
                                    "hex2str",
                                    "is_srt",
                                    "key_exchanges",
                                    "log_labels",
                                    "mark_fin",
                                    "need_ctrl_update",
                                    "pn_for_epoch",
                                    "q_conn_af",
                                    "remove_from_in_flight",
                                    "salt",
                                    "set_ld_timer",
                                    "strm_epoch",
                                    "varint_size"))


cat_by_file = function(file) {
        if (is.na(file)) return(NA)
        m = str_match(file, unlist(file_cat))
        i = which.min(is.na(m))
        if (is.na(m[i])) return(NA) else return(names(file_cat)[i])
}


cat_by_func = function(func) {
        for (c in names(func_cat)) {
                m = str_match(func, unlist(func_cat[c]))
                i = which.min(is.na(m))
                if (!is.na(m[i])) return(c)
        }
        return("misc")
}


read_data = function(fname) {
        d = read_tsv(fname,
             col_names=c("size", "type", "func", "file"),
             col_types="-cccc")

        fields = str_split(fname, "[-.]")[[1]]
        d = d %>% mutate(buildnr=strtoi(fields[1], base=10), build=fields[2])
        d = d %>% mutate(size=strtoi(size, base=16))
        d = d %>% mutate(file_mod=sapply(file, cat_by_file))
        d = d %>% mutate(func_mod=sapply(func, cat_by_func))
        d = d %>% mutate(module=case_when(!is.na(file_mod) ~ file_mod, TRUE ~ func_mod))
        select(d, -c(file, file_mod, func_mod))
}


ylabeller = function(b) {
    dlab = d %>% distinct(build, buildnr)
    return(dlab$build)
}


ybreaks = function(b) {
    dlab = d %>% distinct(build, buildnr)
    return(dlab$buildnr)
}


shortb = function(byte) {
  ifelse(byte >= 10^9, paste(comma(format="d", byte/10^9), "G"),
         ifelse(byte >= 10^6, paste(comma(format="d", byte/10^6), "M"),
                ifelse(byte >= 10^3, paste(comma(format="d", byte/10^3), "K"),
                       comma(format="d", byte))))
}


d = bind_rows(lapply(commandArgs(trailingOnly=TRUE), read_data))

components = list("quic" = c("quant", "warpcore", "timeout"),
                  "tls"  = c("picotls", "cifra", "micro-ecc"),
                  "glue" = c("libc", "os", "misc")
                 )

order = c("app", unlist(components, use.names=FALSE))

dsum = d %>% group_by(buildnr, module) %>% summarise(sum=sum(size))
dsum$module = ordered(dsum$module, order)

dsum = dsum %>% mutate(component=case_when(module %in% components$quic ~ "quic",
                                           module %in% components$tls ~ "tls",
                                           module == "app" ~ "app",
                                           TRUE ~ "glue"))
print(dsum)

pal=c(rev(brewer.pal(name="Purples", n=4))[c(1)],
      rev(brewer.pal(name="Reds", n=4))[c(1, 2, 3)],
      rev(brewer.pal(name="Greens", n=4))[c(1, 2, 3)],
      rev(brewer.pal(name="Blues", n=4))[c(1, 2, 3)])

ggsave("argon.pdf", device=cairo_pdf, units="in", width=7, height=3.5,
       plot=ggplot() +
       geom_col(data=dsum, aes(y=sum, x=buildnr, fill=module)) +
       # geom_text(data=dsum, aes(y=sum, x=buildnr, label=sum)) +
       scale_x_continuous(labels=ylabeller, breaks=ybreaks,
                          name="Build options", expand=c(0, 0)) +
       scale_y_continuous(labels=shortb, name="Size", expand=c(0, 0)) +
       scale_fill_manual(values = pal) +
       theme_lars() +
       theme(axis.text.x=element_text(angle=-30, hjust=0)))


