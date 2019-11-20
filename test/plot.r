#! /usr/bin/env Rscript

library("tidyverse")
library("cowplot")

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
        return("unknown")
}


read_data = function(fname) {
        d = read_tsv(fname,
             col_names=c("size", "type", "func", "file"),
             col_types="-cccc")

        d = d %>% mutate(build=fname)
        d = d %>% mutate(size=strtoi(size, base=16))
        d = d %>% mutate(file_mod=sapply(file, cat_by_file))
        d = d %>% mutate(func_mod=sapply(func, cat_by_func))
        d = d %>% mutate(module=case_when(!is.na(file_mod) ~ file_mod, TRUE ~ func_mod))
        select(d, -c(file, file_mod, func_mod))
}


d = bind_rows(lapply(commandArgs(trailingOnly=TRUE), read_data))

# options(width = 10000)
# print(d)

dsum = d %>% group_by(build, module) %>% summarise(sum=sum(size))
# print(dsum,n=100)

ggsave2("argon.pdf", device="pdf", units="in", width=7, height=3.5,
       plot=ggplot() +
        geom_col(aes(y=sum, x=build, fill=module), data=dsum) +
        theme_cowplot(font_size=9, font_family="Times") +
        theme(axis.text.x=element_text(angle=-60)) +
        background_grid(major="y", minor="none"))




