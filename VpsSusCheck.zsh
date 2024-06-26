#!/bin/zsh

# Function to ensure necessary packages are installed
ensure_packages() {
    local required_packages=("awk" "net-tools" "procps-ng" "busybox-extras")
    local missing_packages=()

    for pkg in "${required_packages[@]}"; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            missing_packages+=("$pkg")
        fi
    done

    if (( ${#missing_packages[@]} > 0 )); then
        echo "Installing necessary packages: ${missing_packages[*]}"
        apk update
        apk add --no-cache ${missing_packages[@]}
    fi
}

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

# Function to check for specific malicious software
check_malicious_software() {
    local found_software=()
    local malicious_software_list=(
        xmrig tor minerd cpuminer ethminer nsfminer
        zmap masscan sqlmap nmap hping hydra john
        medusa aircrack-ng ettercap kismet wireshark
        tcpdump strace ltrace netcat nc socat ncat
        ngrep dsniff tcpflow darkstat iftop iptraf
        ntop bmon vnstat htop onion darkweb boobies
    )

    for software in "${malicious_software_list[@]}"; do
        if command -v "$software" >/dev/null 2>&1; then
            found_software+=("$software")
        fi
    done

    if (( ${#found_software[@]} > 0 )); then
        echo "Malicious software detected: ${found_software[*]}"
        return 0
    fi
    return 1
}

# Function to check for unusual process activity
check_unusual_process_activity() {
    local cpu_threshold=50
    local memory_threshold=50
    local unusual_processes=()
    ps aux | awk -v cpu_thresh="$cpu_threshold" -v mem_thresh="$memory_threshold" '
        NR > 0 && $3 > cpu_thresh || $4 > mem_thresh {
            print "PID: "$2", Name: "$11", CPU: "$3"% MEM: "$4"%"
        }'
    return 0
}

# Function to check for unusual network activity
check_unusual_network_activity() {
    local suspicious_ports=(8333 7777 4444 9050 9150)
    local suspicious_connections=()
    netstat -tuln | awk -v ports="${suspicious_ports[*]}" '
        BEGIN {
            split(ports, arr, " ");
        }
        NR > 2 && ($4 ~ /:[0-9]+$/ && substr($4, index($4, ":")+1) ~ arr) {
            print "PID: "$7", Local Address: "$4", Remote Address: "$5
        }'
    return 0
}

# Function to check for suspicious DNS queries
check_suspicious_dns_queries() {
    local dns_log_file="/var/log/dnsmasq.log"
    local suspicious_queries=()
    local suspicious_domains=("onion" "darkweb" "boobies" "porn" "xxx" "adult")

    if [[ -f $dns_log_file ]]; then
        while IFS= read -r line; do
            for domain in "${suspicious_domains[@]}"; do
                if [[ $line == *"$domain"* ]]; then
                    suspicious_queries+=("$line")
                fi
            done
        done < "$dns_log_file"
    fi

    if (( ${#suspicious_queries[@]} > 0 )); then
        echo "Suspicious DNS queries detected:"
        printf '%s\n' "${suspicious_queries[@]}"
        return 0
    fi
    return 1
}

# Main function to run all checks and log results
main() {
    echo "System Monitoring Script"

    ensure_packages

    local log=()
    check_high_cpu_usage && log+=(high_cpu_usage)
    check_high_memory_usage && log+=(high_memory_usage)
    check_malicious_software && log+=(malicious_software)
    check_unusual_process_activity && log+=(unusual_processes)
    check_unusual_network_activity && log+=(suspicious_connections)
    check_suspicious_dns_queries && log+=(suspicious_dns_queries)

    # Print log
    if (( ${#log[@]} == 0 )); then
        echo "No issues detected."
    else
        echo "Issues detected:"
        printf '%s\n' "${log[@]}"
    fi
}

main
