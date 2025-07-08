#!/bin/bash
RED="\033[1;31m"
GREEN="\033[1;32m"
DARK_YELLOW="\033[0;33m"
NC="\033[0m"

#Student name : Afek Tzabari
#Student code : s16
#Unit : TMagen773634
#Lecturer : Natalie Erez / Doron Zohar

# installing toilet
sudo apt-get install toilet -y  > /dev/null 2>&1
toilet -f big -F gay -w 200   "Analyzer"
toilet -f small -F metal -w 200 --filter border "By: Afek Tzabari"

echo ""
sleep 2
#Checking if the user is root if not exit using function

function check_root() {
USER=$(whoami)
sleep 1

if [ "$USER" == "root" ]; then

	echo -e "${GREEN}[+] You are root ${NC}"
else
	echo -e "${RED}[-] You are not root exiting...${NC}"
	sleep 1
	exit 1
fi

}


echo "[!] Checking if user is root... "
sleep 1
check_root
echo ""

#Installing the needed tools if missing
echo "[!] Checking if needed tools are installed and if not going to install"
echo ""
sleep 1
function tools() 
{
	TOOLS="binwalk bulk_extractor foremost strings"
	
	for VAR in $TOOLS 
	do
		ch_tool=$(command -v $VAR)
		if [ "$ch_tool" == "" ] 
		then 
			echo -e "${RED}[-] The tool $VAR is not installed. ${NC}"
			sleep 2
			echo -e "${DARK_YELLOW}[!] Installing $VAR... ${NC}"
			sudo apt-get install $VAR -y > /dev/null 2>&1
			sleep 2
			echo -e "${GREEN}[+] The tool $VAR is installed. ${NC}"
			
		else
			echo -e "${GREEN}[+] The tool $VAR is already installed. ${NC}"
			sleep 2
			
		fi
	done
			
	
}

tools

echo ""
function vol_check() #cheking if volatility is installed and if not install it
{
	echo "[!] Checking if volatility is installed..."
	vol_path=$(find "$HOME" -type d -name volatility_2.6_lin64_standalone 2>/dev/null | head -1)
	sleep 0.5
	if [ -z "$vol_path" ]
	then 
		echo -e "${RED}[-] The tool volatility is not installed${NC}"
		sleep 0.5
		echo "[!] installing volatility..."
		sleep 0.5
		cd $HOME/Desktop && wget https://github.com/volatilityfoundation/volatility/releases/download/2.6.1/volatility_2.6_lin64_standalone.zip > /dev/null 2>&1
		sleep 0.5
		unzip volatility_2.6_lin64_standalone.zip > /dev/null 2>&1
		sleep 2
		rm volatility_2.6_lin64_standalone.zip 
		echo -e "${GREEN}[+] The tool volatility was installed successful.${NC}"
		sleep 0.5
	else 
		sleep 0.5
		echo -e "${GREEN}[+] The tool volatility is already installed.${NC}"
	fi
}
vol_check
path_vol=$(find $HOME -type d -name volatility_2.6_lin64_standalone | head -1 2>/dev/null)


#letting the user to enter a file type and checking if the file exist
read -p "[~] Enter the filename you want to analyze: " F_ANALYZE
sleep 1
function file_check() {
    filepath=$(sudo find / -type f -name "$F_ANALYZE" 2>/dev/null)
    
    if [ -z "$filepath" ]; then
        echo -e "${RED}[-] The file does not exist. Check if the filename is correct.${NC}"
        exit 1
    else
        echo -e "${GREEN}[+] File exists at: $filepath${NC}"
    fi
}

file_check

echo "" 
# Function to analyze the file using binwalk
function analyze_binwalk() {
    echo -e "${DARK_YELLOW}[!] Running binwalk on $F_ANALYZE...${NC}"
    binwalk "$F_ANALYZE" > binwalk_scan > /dev/null 2>&1
}

# Function to analyze the file using bulk_extractor
function analyze_bulk_extractor() {
    echo -e "${DARK_YELLOW}[!] Running bulk_extractor on $F_ANALYZE...${NC}"
    if ! bulk_extractor -o bulk_output "$F_ANALYZE" > /dev/null 2>&1; then
        echo -e "${RED}[-] bulk_extractor failed to run.${NC}"
        return 1
    fi
    
    echo -e "${DARK_YELLOW}[!] Trying to find if there is a network traffic file.${NC}" 
    pcap=$(find ./bulk_output -type f -name *.pcap)
    if [ -z "$pcap" ]; then
        echo -e "${RED}[-] No network traffic file was found.${NC}"
    else
        size=$(du -h "$pcap" | awk '{print $1}')
        echo -e "${GREEN}[+] Network traffic file found at $pcap and the size is $size ${NC}"
    fi
    sleep 3
}

# Function to analyze the file using foremost
function analyze_foremost() {
    echo -e "${DARK_YELLOW}[!] Running foremost on $F_ANALYZE...${NC}"
    foremost -o foremost_output "$F_ANALYZE"  > /dev/null 2>&1
}

# Function to analyze the file using strings
function analyze_strings() {
    echo -e "${DARK_YELLOW}[!] Running strings on $F_ANALYZE...${NC}"
    strings "$F_ANALYZE" | less > strings_output > /dev/null 2>&1
}

# Function to analyze the file using volatility
function analyze_volatility() {
    if [ -z "$path_vol" ]; then
        echo -e "${RED}[-] Volatility is not installed or not found.${NC}"
        exit 1
    fi

    echo -e "${DARK_YELLOW}[!] Running volatility on $F_ANALYZE...${NC}"
    
    # 2.2 Find the memory profile and save it into a variable
    profile=$("$path_vol/volatility_2.6_lin64_standalone" -f "$F_ANALYZE" imageinfo 2>/dev/null | \
              grep -oP 'Suggested Profile\(s\) : \K[^,]+' | head -n 1) #used this command from chatGPT to grab the profile

    if [ -z "$profile" ]; then
        echo -e "${RED}[-] Failed to determine the memory profile. Check the memory dump file.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Using memory profile: $profile${NC}"
    sleep 1
    
    #2.3 - 2.5 i used the internet to find the commands.
    # 2.3 Display the running processes
    echo -e "${DARK_YELLOW}[!] Displaying running processes...${NC}"
    "$path_vol/volatility_2.6_lin64_standalone" -f "$F_ANALYZE" --profile="$profile" pslist
    sleep 1

    # 2.4 Display network connections
    echo -e "${DARK_YELLOW}[!] Displaying network connections...${NC}"
    "$path_vol/volatility_2.6_lin64_standalone" -f "$F_ANALYZE" --profile="$profile" netscan
    sleep 1

    # 2.5 Attempt to extract registry information
    echo -e "${DARK_YELLOW}[!] Extracting registry information...${NC}"
    
    # First, find the registry hives
    "$path_vol/volatility_2.6_lin64_standalone" -f "$F_ANALYZE" --profile="$profile" hivelist
    
    # Extract specific registry keys (example: SYSTEM and SOFTWARE hives)
    echo -e "${DARK_YELLOW}[!] Attempting to extract SYSTEM hive information...${NC}"
    "$path_vol/volatility_2.6_lin64_standalone" -f "$F_ANALYZE" --profile="$profile" printkey -K 'ControlSet001\Services' > /dev/null 2>&1

    echo -e "${DARK_YELLOW}[!] Attempting to extract SOFTWARE hive information...${NC}"
    "$path_vol/volatility_2.6_lin64_standalone" -f "$F_ANALYZE" --profile="$profile" printkey -K 'Microsoft\Windows\CurrentVersion\Run' > /dev/null 2>&1
    
    echo -e "${GREEN}[+] Volatility analysis complete.${NC}"
}

#Using a function to put the case inside to let the user choose what carver to use
function carving ()
{
echo "[!] Enter what tool would you like to use on the file: 

 [1] Binwalk
 [2] Bulk_extractor
 [3] foremost
 [4] strings
 [5] Volatility
 [6] Use all
 [9] Exit  "
 read choise
 case "$choise" in 
	1)
		echo -e "${GREEN}[+] Using binwalk...${NC}"
		sleep 1
		analyze_binwalk
		;;
	2)
		echo -e "${GREEN}[+] Using bulk extractor...${NC}"
		sleep 1
		analyze_bulk_extractor
		;;
	3)
		echo -e "${GREEN}[+] Using foremost...${NC}"
		sleep 1
		analyze_foremost
		;;
	4)
		echo -e "${GREEN}[+] Using strings...${NC}"
		sleep 1
		analyze_strings
		;;
	5)
		echo -e "${GREEN}[+] Using volatility...${NC}"
		sleep 1
		analyze_volatility
		;;
	6)
		echo -e "${GREEN}[+] Using every carver..."
		sleep 1
		analyze_binwalk
		sleep 1
		analyze_bulk_extractor
		sleep 1
		analyze_foremost
		sleep 1
		analyze_strings
		sleep 1
		analyze_volatility
		;;
	9)
		echo -e "${DARK_YELLOW}[!] Exiting..."
		exit 2
		;;
		
	*)
		echo -e "${RED} Invalid optiong try again."
		carving
	esac
		
}
	
carving

start_time=$(date)

# After all analysis is done
end_time=$(date)
num_files_found=$(find . -type f | wc -l)

echo -e "${GREEN}[+] Analysis started at: $start_time${NC}"
echo -e "${GREEN}[+] Analysis ended at: $end_time${NC}"
echo -e "${GREEN}[+] Number of files found: $num_files_found${NC}"

report_file="analysis_report.txt"

echo "Analysis Report" > "$report_file"
echo "----------------" >> "$report_file"
echo "Start Time: $start_time" >> "$report_file"
echo "End Time: $end_time" >> "$report_file"
echo "Number of Files Found: $num_files_found" >> "$report_file"
echo "Extracted Files:" >> "$report_file"
find . -type f >> "$report_file"

echo -e "${GREEN}[+] Report saved to $report_file${NC}"

zip_name="forensics_analysis.zip"
zip -r "$zip_name" ./foremost_output ./bulk_output "$report_file" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Files and report zipped to $zip_name${NC}"
else
    echo -e "${RED}[-] Failed to create zip file.${NC}"
fi
