type URL_IDX: record {url: string;};
type IP_IDX: record {ip: addr;};

global url_blacklist: table[string] of IP_IDX = table();
global ip_blacklist: table[addr] of URL_IDX = table();

event bro_init(){
    # Read in blocked urls from text file.
    Input::add_table([$source="block_list.data", $name="urls",
                    $idx=URL_IDX, $val=IP_IDX, $destination=url_blacklist]);
    Input::remove("urls");
    
    Input::add_table([$source="block_list.data", $name="ips",
                    $idx=IP_IDX, $val=URL_IDX, $destination=ip_blacklist]);
    Input::remove("ips");
}

function send_ip(ip: addr){
    # Send ip address to python script which configures faucet to block it.
    piped_exec("python block_ip.py", addr_to_uri(ip));
    print "Added Address:", ip;
}

event dns_request(c:connection, msg:dns_msg, query:string, qtype:count, qclass:count){
    # Check dns requests for blocked urls.
    if (query in url_blacklist){
        print c$id$orig_h, "DNS Lookup: "+query;
        send_ip(url_blacklist[query]$ip);
    }
}

event new_connection(c: connection){
    # Check connections for blocked ips.
    if (c$id$resp_h in ip_blacklist){
        print c$id$orig_h, "New Connection: "+ip_blacklist[c$id$resp_h]$url, c$id$resp_h;
        send_ip(c$id$resp_h);
    }
}
