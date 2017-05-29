event new_packet(c: connection, p:pkt_hdr){
    print c$orig$l2_addr;
    piped_exec("python block_port.py", c$orig$l2_addr);
}
