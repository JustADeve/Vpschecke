#!/bin/zsh

# List of known malicious software/processes and inappropriate content
malicious_software_list=(
    xmrig tor minerd cpuminer ethminer nsfminer
    zmap masscan sqlmap nmap hping hydra john
    medusa aircrack-ng ettercap kismet wireshark
    tcpdump strace ltrace netcat nc socat ncat
    ngrep dsniff tcpflow darkstat iftop iptraf
    ntop bmon vnstat htop onion darkweb boobies
)

# Function to check for high CPU usage
check_high_cpu_usage() {
    local threshold=80
    local cpu_usage
    cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5} {if (NR==1){pu=u;pt=t} else print 100*(u-pu)/(t-pt)}' <(grep 'cpu ' /proc/stat) <(sleep 1;grep 'cpu ' /proc/stat))
    if (( ${cpu_usage%.*} > threshold )); then
        echo "High CPU usage detected: ${cpu_usage}%"
        return 0
    fi
    return 1
}

# Function to check for high memory usage
check_high_memory_usage() {
    local threshold=80
    local mem_usage
    mem_usage=$(free | awk '/Mem/ {printf("%.0f"), $3/$2*100}')
    if (( mem_usage > threshold )); then
        echo "High memory usage detected: ${mem_usage}%"
        return 0
    fi
    return 1
}

# Function to check for high disk usage
check_high_disk_usage() {
    local threshold=80
    local disk_usage
    disk_usage=$(df / | awk 'END{print $5}' | tr -d '%')
    if (( disk_usage > threshold )); then
        echo "High disk usage detected: ${disk_usage}%"
        return 0
    fi
    return 1
}

# Function to check for specific malicious software
check_malicious_software() {
    local found_software=()
    for software in $malicious_software_list; do
        if command -v $software >/dev/null 2>&1; then
            found_software+=$software
        fi
    done
    if (( ${#found_software[@]} > 0 )); then
        echo "Malicious software detected: ${found_software[@]}"
        return 0
    fi
    return 1
}

# Function to check for unusual process activity
check_unusual_process_activity() {
    local cpu_threshold=50
    local memory_threshold=50
    local unusual_processes=()
    ps -eo pid,comm,%cpu,%mem --sort=-%cpu | while read pid comm cpu mem; do
        if (( ${cpu%.*} > cpu_threshold || ${mem%.*} > memory_threshold )); then
            unusual_processes+=("$pid $comm CPU: $cpu% MEM: $mem%")
        fi
    done
    if (( ${#unusual_processes[@]} > 0 )); then
        echo "Unusual process activity detected:"
        for process in $unusual_processes; do
            echo $process
        done
        return 0
    fi
    return 1
}

# Function to check for unusual network activity
check_unusual_network_activity() {
    local suspicious_ports=(8333 7777 4444 9050 9150)
    local suspicious_connections=()
    netstat -tulnp | grep -E ':(8333|7777|4444|9050|9150)' | while read line; do
        suspicious_connections+=$line
    done
    if (( ${#suspicious_connections[@]} > 0 )); then
        echo "Unusual network activity detected:"
        for connection in $suspicious_connections; do
            echo $connection
        done
        return 0
    fi
    return 1
}

# Function to check for suspicious DNS queries
check_suspicious_dns_queries() {
    local dns_log_file="/var/log/dnsmasq.log"
    local suspicious_queries=()
    local suspicious_domains=("onion" "darkweb" "boobies" "porn" "xxx" "adult")

    if [[ -f $dns_log_file ]]; then
        while read -r line; do
            for domain in $suspicious_domains; do
                if [[ $line == *"$domain"* ]]; then
                    suspicious_queries+=$line
                fi
            done
        done < $dns_log_file
    fi
    if (( ${#suspicious_queries[@]} > 0 )); then
        echo "Suspicious DNS queries detected:"
        for query in $suspicious_queries; do
            echo $query
        done
        return 0
    fi
    return 1
}

# Main function to run all checks and log results
main() {
    echo "System Monitoring Script"
    local log=()
    check_high_cpu_usage && log+=(high_cpu_usage)
    check_high_memory_usage && log+=(high_memory_usage)
    check_high_disk_usage && log+=(high_disk_usage)
    check_malicious_software && log+=(malicious_software)
    check_unusual_process_activity && log+=(unusual_processes)
    check_unusual_network_activity && log+=(suspicious_connections)
    check_suspicious_dns_queries && log+=(suspicious_dns_queries)

    # Print and save the log as JSON
    local json_log=$(printf '%s\n' "${log[@]}" | jq -R . | jq -s .)
    echo $json_log | jq .
    echo $json_log > system_monitor_log.json
}

main
