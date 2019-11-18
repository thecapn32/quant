#! /usr/bin/env bash


function analyze_sizes() {
        rm -f "$2".ann
        while read -r line; do
                case "$line" in

                */firmware/main.cpp*|*qcc*|*qc*|*digitalWrite*|*peername*)
                        comp=app
                        ;;
                *std::*|*__*|*vtable*|*operator*|\
                *calloc*|\
                *gettimeofday*|\
                *memcmp*|\
                *memcpy*|\
                *memmove*|\
                *memset*|\
                *srand*|\
                *strcmp*|\
                *strdup*|\
                *strlen*|\
                *strncpy*)
                        comp=libc
                        ;;

                *::*|*/.po-util/src/*|*SLEEP_NETWORK_OFF*|*pinAvailable*|*impure*)
                        comp=OS
                        ;;

                */deps/warpcore/*|*w_set_sockopt*|*w_alloc_iov*|*to_sockaddr*|*w_addr_hash*)
                        comp=warpcore
                        ;;

                */deps/timeout*|*timeouts_sched*|*timeouts_timeout*)
                        comp=timeout
                        ;;

                */deps/micro-ecc*|*uECC_*|*sha256_final*|*vli_modInv_update*)
                        comp=micro-ecc
                        ;;

                */deps/cifra*)
                        comp=cifra
                        ;;

                */deps/picotls/*|\
                *aesgcm_decrypt*|\
                *default_emit_certificate*|\
                *derive_exporter_secret*|\
                *derive_resumption_secret*|\
                *emit_server_name_extension*|\
                *extension_bitmap_*|\
                *handle_unknown_extension*|\
                *on_client_hello*|\
                *ptls_is_server*|\
                *ptls_server_name_is_ipaddr*|\
                *push_change_cipher_spec*|\
                *push_signature_algorithms*|\
                *select_key_share*|\
                *send_certificate_and_certificate_verify*|\
                *send_finished*|\
                *serial1_rx_buffer*|\
                *serial1_tx_buffer*|\
                *update_traffic_key*)
                        comp=picotls
                        ;;

                */quant/*|\
                *ack_alarm*|\
                *add_scid*|\
                *cancel_api_call*|\
                *congestion_event*|\
                *conns_by_id_del*|\
                *conns_by_id_ins*|\
                *dec_tp*|\
                *do_stream_id_fc*|\
                *enc1*|\
                *enc2*|\
                *enc4*|\
                *enter_closed*|\
                *enter_closing*|\
                *epoch_in*|\
                *flip_label*|\
                *frame_ok*|\
                *free_tls*|\
                *hex2str*|\
                *is_srt*|\
                *key_exchanges*|\
                *log_labels*|\
                *mark_fin*|\
                *need_ctrl_update*|\
                *pn_for_epoch*|\
                *q_conn_af*|\
                *remove_from_in_flight*|\
                *salt*|\
                *set_ld_timer*|\
                *strm_epoch*|\
                *varint_size*)
                        comp=quant
                        ;;

                *)
                        comp=XXX
                        ;;
                esac
                echo "$comp $line" >> "$2".ann
        done < "$2"
}


opts=('' NO_ERR_REASONS NO_OOO_0RTT NO_OOO_DATA
      NO_MIGRATION NO_SRT_MATCHING NO_QINFO NO_SERVER)

always=-DNDEBUG


for flag in "${opts[@]}"; do
        data="${flag:-NONE}".func
        if [ ! -s "$data" ]; then
                echo -n "${flag:-NONE}"
                out=$(env build_flags="$always ${flag:+-D$flag}" \
                        po argon build 2>/dev/null | grep particle-argon.elf)
                all="$all -D$flag"
                bin=$(echo $out | cut -d' ' -f6)
                echo "$out"
                arm-none-eabi-nm -C --line-numbers --print-size --size-sort \
                        "$bin" > "$data"
        fi
        analyze_sizes "$bin" "$data"
done

echo -n ALL
env build_flags="$always $all" po argon build 2>/dev/null | grep particle-argon.elf
