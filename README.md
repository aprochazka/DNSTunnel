# ISA 2022 DNS Tunneling  

## Autor: Adam Prochazka

## Login: xproch0f

## Server

    make receiver

    dns_receiver {BASE_HOST} {DST_DIRPATH}

    $ dns_receiver example.com ./data

## Client

    make client

    dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]

    $ dns_sender -u 127.0.0.1 example.com data.txt ./data.txt

    $ echo "abc" | dns_sender -u 127.0.0.1 example.com data.txt

    -u to force the remote DNS server   
        if not specified, the program uses the default DNS server set in the system
