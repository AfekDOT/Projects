#!/bin/bash

RED="\033[1;31m"
GREEN="\033[1;32m"
DARK_YELLOW="\033[0;33m"
NC="\033[0m"


#Student name : Afek Tzabari
#Student code : s16
#Unit : TMagen773634
#Lecturer : Natalie Erez

# installing toilet
sudo apt-get install toilet -y  > /dev/null 2>&1
toilet -f big  "Vulner"
toilet -f small -F metal -w 200 --filter border "By: Afek Tzabari"

echo "Description:
• Scan the network for ports and services.
• Map vulnerabilities.
• Look for login weak passwords."


echo ""

echo "---------------------------------------------------------------"

echo ""

USER=$(whoami)


function AGAIN()
{
    NET
}

#function that validate if the ip is correct. Used chatgpt for this function
function VALID_NET() 
{
    # Allow both IP and IP/CIDR input
    if [[ ! $network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; 
    then
        sleep 1
        echo -e "${RED}[-] Invalid network. ${NC}"
        sleep 1
        echo -e "${DARK_YELLOW}[?] Would you like to retry ? (Enter \"y\" or \"n\")${NC}"
        read answer
        
        if [ "$answer" == "y" ] || [ "$answer" == "Y" ]; then 
            AGAIN
        elif [ "$answer" == "n" ] || [ "$answer" == "N" ]; then
            echo "[~] Exiting..."
            exit 1
        fi
    fi
}

#letting the user choose if they want to change the entered network
function CHANGE_NET()
 {   
    echo -e "${DARK_YELLOW}[?] Do you want to change the selected network ? (Enter 1 to change or enter to continue)${NC}"
    read choise
    sleep 1
    
        if [ "$choise" == "1" ];
        then 
            sleep 0.5
            NET
        elif [ "$choise" = "" ];
        then    
            echo "[!] Continuing with the selected network..."
            VALID_NET
            sleep 0.5
        fi
 }

#letting the user enter a network to scan 
function NET() 
{
read -p "[~] Enter the network you would like to scan: " network
sleep 1

    if [ "$network" == "" ];
    then    
        echo -e "${RED}[-] Invalid input. Try again ${NC}"
        sleep 0.5
        AGAIN
    else
        echo -e "${GREEN}[+] The network you choose is: $network ${NC}"
        CHANGE_NET
        sleep 1
    fi
}
NET
VALID_NET

function  DIR_AGAIN()
{
    OUTPUT_DIR
}

#lettin the user to enter a name for a dir to save the results
function OUTPUT_DIR() {
    while true; do
        read -p "[~] Enter the name of the directory you would like to save the results to: " output_dir
        dir_path=$(find /home -type d -name "$output_dir" 2>/dev/null)

        if [ -z "$dir_path" ]; then 
            echo -e "${GREEN}[+] Creating \"$output_dir\" on the Desktop... ${NC}"
            sleep 0.5
            mkdir -p "/home/$USER/Desktop/$output_dir"
            sleep 0.5
            echo -e "${GREEN}[+] Directory was created successfully! ${NC}"
            break
        else
            echo -e "${RED}[-] Directory name is already in use ${NC}"
            sleep 0.5
            echo -e "${DARK_YELLOW}[?] Do you want to change the name ? (Enter \"y\" or \"n\")${NC}"
            read answer2
            if [[ "$answer2" =~ ^[Nn]$ ]]; then
                echo "[~] Exiting..."
                exit 1
            fi
        fi
    done
}
OUTPUT_DIR

#After taking all the information that the user gave now scannin the network with nmap and looking for open ports and
#then tryin to brute force with hydra 
#Got help from CHATGPT for some parts
function BASIC_SCAN() {
    echo -e "${GREEN}[+] Scanning $network for open TCP/UDP ports and service versions...${NC}"
    nmap -sS -sV -Pn -oN "/home/$USER/Desktop/$output_dir/nmap_basic_$network.txt" $network

    echo -e "${GREEN}[+] Checking for login services (SSH, FTP, TELNET, RDP)...${NC}"
    open_ports=$(grep -E "open" "/home/$USER/Desktop/$output_dir/nmap_basic_$network.txt" | grep -E "ssh|ftp|telnet|ms-wbt-server" | awk '{print $1}' | cut -d'/' -f1)

    if [ -z "$open_ports" ]; then
        echo -e "${RED}[-] No login services found on $network.${NC}"
        return
    fi

    echo -e "${GREEN}[+] Found login ports: $open_ports${NC}"

    read -p "[?] Do you want to provide a custom user list? (y/n): " use_custom_users
    if [[ "$use_custom_users" =~ ^[Yy]$ ]]; then
        read -p "[~] Enter path to your usernames file: " user_file
    else
        user_file="/home/$USER/Desktop/$output_dir/common_users.txt"
        echo -e "admin\nroot\nuser\ntest\nguest\nkali\nmsfadmin" > "$user_file"
    fi

    read -p "[?] Do you want to provide a custom password list? (y/n): " use_custom_pass
    if [[ "$use_custom_pass" =~ ^[Yy]$ ]]; then
        read -p "[~] Enter path to your passwords file: " pass_file
    else
        pass_file="/home/$USER/Desktop/$output_dir/common_passwords.txt"
        echo -e "admin\n123456\npassword\ntoor\nroot\nkali\n1234\n12345\nguest\nletmein\nmsfadmin" > "$pass_file"
    fi

    for port in $open_ports; do
        service=$(grep "^$port/" "/home/$USER/Desktop/$output_dir/nmap_basic_$network.txt" | awk '{print $3}')

        case $service in
            ssh)
                echo -e "${GREEN}[+] Launching Hydra on SSH port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" ssh://$network -o "/home/$USER/Desktop/$output_dir/hydra_ssh_${network}_${port}.txt"
                ;;
            ftp)
                echo -e "${GREEN}[+] Launching Hydra on FTP port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" ftp://$network -o "/home/$USER/Desktop/$output_dir/hydra_ftp_${network}_${port}.txt"
                ;;
            telnet)
                echo -e "${GREEN}[+] Launching Hydra on TELNET port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" telnet://$network -o "/home/$USER/Desktop/$output_dir/hydra_telnet_${network}_${port}.txt"
                ;;
            ms-wbt-server)
                echo -e "${GREEN}[+] Launching Hydra on RDP port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" rdp://$network  -o "/home/$USER/Desktop/$output_dir/hydra_rdp_${network}_${port}.txt"
                ;;
            *)
                echo -e "${DARK_YELLOW}[~] Skipping unsupported service: $service on port $port${NC}"
                ;;
        esac
    done
}


function FULL_SCAN() {
    echo -e "${GREEN}[+] Running FULL scan on $network...${NC}"

    # Step 1: Basic port scan with service detection
    echo -e "${GREEN}[+] Running initial Nmap service scan...${NC}"
    nmap -sS -sV -Pn -oN "/home/$USER/Desktop/$output_dir/nmap_FULL_$network.txt" $network

    open_ports=$(grep -E "open" "/home/$USER/Desktop/$output_dir/nmap_FULL_$network.txt" | grep -E "ssh|ftp|telnet|ms-wbt-server" | awk '{print $1}' | cut -d'/' -f1)

    if [ -z "$open_ports" ]; then
        echo -e "${RED}[-] No login services found on $network.${NC}"
        return
    fi

    echo -e "${GREEN}[+] Found login ports: $open_ports${NC}"

    # Run NSE scripts based on services found
    for port in $open_ports; do
        service=$(grep "^$port/" "/home/$USER/Desktop/$output_dir/nmap_FULL_$network.txt" | awk '{print $3}')
        echo -e "${GREEN}[+] Running NSE scripts for $service on port $port...${NC}"

        case $service in
            ssh)
                
                nmap -sV -p $port --script "ssh-auth-methods.nse" -Pn -oN "/home/$USER/Desktop/$output_dir/nmap_ssh_$port.txt" $network
                ;;
            ftp)
                
                nmap -sV -p $port --script "ftp-anon.nse" -Pn -oN "/home/$USER/Desktop/$output_dir/nmap_ftp_$port.txt" $network
                ;;
            telnet)
                
                nmap -sV -p $port --script "telnet-encryption.nse" -Pn -oN "/home/$USER/Desktop/$output_dir/nmap_telnet_$port.txt" $network
                ;;
            ms-wbt-server)
                
                nmap -sV -p $port --script "rdp-enum-encryption.nse" -Pn -oN "/home/$USER/Desktop/$output_dir/nmap_rdp_$port.txt" $network
                ;;
        esac
    done

    # Step 2: Weak password brute-force (same as basic)
    read -p "[?] Do you want to provide a custom user list? (y/n): " use_custom_users
    if [[ "$use_custom_users" =~ ^[Yy]$ ]]; then
        read -p "[~] Enter path to your usernames file: " user_file
    else
        user_file="/home/$USER/Desktop/$output_dir/common_users.txt"
        echo -e "admin\nroot\nuser\ntest\nguest\nkali" > "$user_file"
    fi

    read -p "[?] Do you want to provide a custom password list? (y/n): " use_custom_pass
    if [[ "$use_custom_pass" =~ ^[Yy]$ ]]; then
        read -p "[~] Enter path to your passwords file: " pass_file
    else
        pass_file="/home/$USER/Desktop/$output_dir/common_passwords.txt"
        echo -e "admin\n123456\npassword\ntoor\nroot\nkali\n1234\n12345\nguest\nletmein" > "$pass_file"
    fi

    for port in $open_ports; do
        service=$(grep "^$port/" "/home/$USER/Desktop/$output_dir/nmap_FULL_$network.txt" | awk '{print $3}')

        case $service in
            ssh)
                echo -e "${GREEN}[+] Launching Hydra on SSH port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" ssh://$network -o "/home/$USER/Desktop/$output_dir/hydra_ssh_${network}_${port}.txt"
                ;;
            ftp)
                echo -e "${GREEN}[+] Launching Hydra on FTP port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" ftp://$network -o "/home/$USER/Desktop/$output_dir/hydra_ftp_${network}_${port}.txt"
                ;;
            telnet)
                echo -e "${GREEN}[+] Launching Hydra on TELNET port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" telnet://$network -o "/home/$USER/Desktop/$output_dir/hydra_telnet_${network}_${port}.txt"
                ;;
            ms-wbt-server)
                echo -e "${GREEN}[+] Launching Hydra on RDP port $port...${NC}"
                hydra -L "$user_file" -P "$pass_file" -s "$port" rdp://$network  -o "/home/$USER/Desktop/$output_dir/hydra_rdp_${network}_${port}.txt"
                ;;
            *)
                echo -e "${DARK_YELLOW}[~] Skipping unsupported service: $service on port $port${NC}"
                ;;
        esac
    done

    echo -e "${GREEN}[✓] FULL scan complete. Results saved in: /home/$USER/Desktop/$output_dir${NC}"
}


function CHOOSE_SCAN_AGAIN()
{
    CHOOSE_SCAN
}


function CHOOSE_SCAN()
{
    echo "[~] Choose the type of scan you want to do:
1) Basic scan
2) Full scan (Includes NSE scripts)"

    read answer3 

    if [ "$answer3" == "1" ]; then
        BASIC_SCAN
    elif [ "$answer3" == "2" ]; then
        FULL_SCAN
    else 
        echo -e "${RED}[-] Invalid input.${NC}"
        sleep 1
        echo -e "${DARK_YELLOW}[?] Would you like to try again? (y/n)${NC}"
        read answer4

        if [[ "$answer4" =~ ^[Yy]$ ]]; then 
            CHOOSE_SCAN
        elif [[ "$answer4" =~ ^[Nn]$ ]]; then    
            exit 1
        fi
    fi
}
CHOOSE_SCAN
