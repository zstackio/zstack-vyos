#!/bin/bash
# ZStack QGA Tools -- Get nic info for Linux bash

info_str=$(ip addr)

#Example Result :
#00:00:00:00:00:00 lo: 127.0.0.1 8
#02:42:31:f1:54:c7 docker0: 172.17.0.1 16
#fa:94:3b:9a:66:00 br_eth0: 10.0.180.192 8
#ca:c8:ff:06:10:04 br_conn_all_ns: 169.254.64.1 18
ipv4_results=$(echo "$info_str" | \
               awk '/^[0-9]: / { dev=$2 } \
                    /(link\/ether|link\/loopback)/{ mac=$2 } \
                    /inet / { \
                        split($2, ip_parts, "/"); \
                        ipv4=ip_parts[1]; \
                        mask=(ip_parts[2]!="")?ip_parts[2]:"32"; \
                        print mac, dev, ipv4, mask \
                    }')
#Example Result :
#00:00:00:00:00:00 lo: ::1 128
#fa:02:ea:bd:77:01 ens12: 1000::18 64
ipv6_results=$(echo "$info_str" | \
               awk '/^[0-9]: / { dev=$2 } \
                    /(link\/ether|link\/loopback)/{ mac=$2 } \
                    /inet6 / { \
                        split($2, ip_parts, "/"); \
                        ipv6=ip_parts[1]; \
                        prefix=(ip_parts[2]!="")?ip_parts[2]:"128"; \
                        if (ipv6 !~ /^(fe80|fc|fd)/) print mac, dev, ipv6, prefix \
                    }')
declare -A network_mac_ip_dict

# Process IPv4 addresses
while read -r line; do
    key=$(echo $line | cut -d' ' -f1)
    addr=$(echo $line | cut -d' ' -f3)
    mask=$(echo $line | cut -d' ' -f4)

    if [[ -z ${network_mac_ip_dict[$key]} ]]; then
        network_mac_ip_dict[$key]="[\"$addr/$mask\""
    else
        network_mac_ip_dict[$key]="${network_mac_ip_dict[$key]}, \"$addr/$mask\""
    fi
done <<< "$ipv4_results"

# Process IPv6 addresses
while read -r line; do
    key=$(echo $line | cut -d' ' -f1)
    addr=$(echo $line | cut -d' ' -f3)
    mask=$(echo $line | cut -d' ' -f4)

    if [[ -z ${network_mac_ip_dict[$key]} ]]; then
        network_mac_ip_dict[$key]="[\"$addr/$mask\""
    else
        network_mac_ip_dict[$key]="${network_mac_ip_dict[$key]}, \"$addr/$mask\""
    fi
done <<< "$ipv6_results"

# Close the arrays in the dictionary
for key in "${!network_mac_ip_dict[@]}"; do
    network_mac_ip_dict[$key]="${network_mac_ip_dict[$key]}]"
done

# Construct JSON output
output="{"
for key in "${!network_mac_ip_dict[@]}"; do
    output+="\"$key\": ${network_mac_ip_dict[$key]},"
done
output="${output%?}}"
echo "$output"

#Example $output
#{
#    "fa:92:08:38:fd:01": [
#        "192.168.123.188/24",
#        "1000::119/64"
#    ],
#    "fa:f8:df:e4:bd:00": [
#        "192.168.100.134/24",
#        "1000:5a18:8725:0:7171:c0d8:ed33:1db1/64"
#    ]
#}