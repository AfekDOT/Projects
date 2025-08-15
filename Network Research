#!/bin/bash
RED="\033[1;31m"
GREEN="\033[1;32m"
DARK_YELLOW="\033[0;33m"
NC="\033[0m"


#Student name: Afek Tzabari
#Student code: s16
#unit code: TMagen773634
#Lecturer's name: Doron Zohar, Natalie 




echo -e "${DARK_YELLOW}[!] Checking if sshpass is installed${NC}"
sleep 0.5

# Function to check and install sshpass
function sshpass_check {
    if command -v sshpass > /dev/null 2>&1; then
        echo -e "${GREEN}[+] sshpass is already installed!${NC}"
        sleep 0.5
    else
        echo -e "${RED}[-] sshpass is not installed!${NC}"
        sleep 0.5
        echo -e "${GREEN}[+] Installing sshpass:${NC}"
        sleep 0.5
        sudo apt-get install sshpass -y > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] sshpass installed successfully!${NC}"
        else
            echo -e "${RED}[-] Failed to install sshpass. Exiting.${NC}"
            exit 1
        fi
    fi
}

sshpass_check

echo -e "${DARK_YELLOW}[!] Checking if geoiplookup is installed${NC}"
sleep 0.5

# Function to check and install geoiplookup
function geoiplookup_check {
    if command -v geoiplookup > /dev/null 2>&1; then
        echo -e "${GREEN}[+] geoiplookup is already installed!${NC}"
        sleep 0.5
    else
        echo -e "${RED}[-] geoiplookup is not installed!${NC}"
        sleep 0.5
        echo -e "${GREEN}[+] Installing geoip-bin:${NC}"
        sleep 0.5
        sudo apt-get install geoip-bin -y > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] geoiplookup installed successfully!${NC}"
        else
            echo -e "${RED}[-] Failed to install geoiplookup. Exiting.${NC}"
            exit 1
        fi
    fi
}

geoiplookup_check

echo -e "${DARK_YELLOW}[!] Checking if nipe is installed${NC}"
sleep 0.5

# Function to check and install nipe
function nipe_check {
    nipe_path=$(sudo find "$HOME" -type d -name nipe | head -1 2>/dev/null)
    if [ -z "$nipe_path" ]; then
        echo -e "${RED}[-] nipe is not installed!${NC}"    
        sleep 0.5
        echo -e "${GREEN}[+] Installing nipe:${NC}"
        sleep 0.5
        git clone https://github.com/GouveaHeitor/nipe "$HOME/Desktop/nipe" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] nipe installed successfully!${NC}"
        else
            echo -e "${RED}[-] Failed to install nipe. Exiting.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}[+] nipe is already installed!${NC}"
    fi   
}   

nipe_check

# Function to start nipe and check anonymity
function nipe_start {
	echo -e "${DARK_YELLOW}[!] Starting nipe service and checking anonymity${NC}"
    sleep 0.5
    cd "$HOME/Desktop/nipe"
    sleep 0.5
    sudo cpanm --notest --force Switch JSON Config::Simple > /dev/null 2>&1
    sudo cpanm --notest --force --installdeps . > /dev/null 2>&1
    sleep 0.5
    sudo perl nipe.pl install > /dev/null 2>&1 
    sleep 0.5
    sudo perl nipe.pl start 
    sleep 0.5
    sudo perl nipe.pl restart
    sleep 0.5
    nipe_status=$(sudo perl nipe.pl status | grep -i true | awk '{print $(NF)}')
    
    if [ "$nipe_status" == "true" ]; then
        echo -e "${GREEN}[+] You are anonymous${NC}"
    else
        echo -e "${RED}[-] You are not anonymous${NC}"
        exit 1
    fi
}

nipe_start

# Check spoofed country
spoofip=$(sudo perl "$HOME/Desktop/nipe/nipe.pl" status | grep -i 'Ip' | awk '{print $(NF)}')
spoofcountry=$(geoiplookup "$spoofip" | awk '{print $4, $5}')
echo -e "${GREEN}[+] Spoofed country is: $spoofcountry ${NC}"
echo ""

# Remote Host details
read -p "[~] Enter the IP of the remote host: " RM_IP
read -p "[~] Enter the username of the remote host: " RMUSER
read -sp "[~] Enter the password of the remote host: " PASS
echo ""

# Get external IP, uptime, and country of the remote host
external_ip=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" 'curl -s https://ifconfig.me/')
echo -e "${GREEN}[+] The external IP of the remote host is: $external_ip${NC}"

uptime=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" 'uptime')
echo -e "${GREEN}[+] The remote host uptime is: $uptime ${NC}"

rmcountry=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" "geoiplookup $external_ip" | awk -F': ' '{print $2}')
echo -e "${GREEN}[+] The country of the remote host is: $rmcountry${NC}"
echo ""

# Create directory on remote host to save all scans
echo -e "${DARK_YELLOW}[!] Creating a directory to save scans${NC}"
sleep 1
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" 'mkdir -p ~/Desktop/Scan'
echo -e "${GREEN}[+] Directory was created successfully${NC}"
sleep 1

# Target IP for analysis
read -p "[!] Enter the target IP for analysis: " ANALYZE_IP

# Whois scan
echo -e "${GREEN}[+] Starting whois scan...${NC}"
sleep 1
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" "whois $ANALYZE_IP >> ~/Desktop/Scan/Whois.txt"
echo -e "${GREEN}[+] Whois scan successfully saved to Whois.txt${NC}"

# Nmap scan
sleep 1
echo -e "${GREEN}[+] Starting the nmap scan...${NC}"
sleep 1
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" "nmap $ANALYZE_IP -oA > /dev/null 2>&1 ~/Desktop/Scan/scan_results.txt"
echo -e "${GREEN}[+] Scan was saved successfully to scan_results.txt${NC}"

# Transfer Scan directory to local host
echo -e "${DARK_YELLOW}[!] Transferring the Scan directory from the remote host to the local host...${NC}"
sleep 1
sshpass -p "$PASS" scp -r -o StrictHostKeyChecking=no "$RMUSER@$RM_IP:$HOME/Desktop/Scan" "$HOME/Desktop"
sleep 1
echo -e "${GREEN}[+] Scan directory transferred successfully to the local host.${NC}"
echo ""

# Remove Scan directory from remote host
echo -e "${DARK_YELLOW}[!] Removing the Scan directory from the remote host...${NC}"
sleep 1
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" 'rm -rf ~/Desktop/Scan'
sleep 1
echo -e "${GREEN}[+] Scan directory removed successfully from the remote host.${NC}"
echo ""

# Clear /var/log/auth.log on remote host
echo -e "${DARK_YELLOW}[!] Clearing /var/log/auth.log on the remote host...${NC}"
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$RMUSER@$RM_IP" "echo $PASS | sudo -S sh -c '> /var/log/auth.log'"
echo -e "${GREEN}[+] /var/log/auth.log cleared successfully.${NC}"
echo "[:)] Removed traces. BYE BYE!!"
exit 0
