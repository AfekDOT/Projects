📜 Overview

This Bash script, developed by Afek Tzabari, is designed to automate the process of:

    Ensuring anonymity via the Tor network using Nipe

    Connecting to a remote host using SSH

    Running Whois and Nmap scans on a target IP

    Collecting and transferring scan results securely

    Cleaning logs to reduce traceability

It's a valuable utility for cybersecurity learning, basic reconnaissance, and practicing ethical hacking procedures in controlled environments.
⚙️ Features

    ✅ Checks & installs dependencies: sshpass, geoiplookup, and nipe

    🌐 Starts Nipe and verifies anonymous routing

    🌍 Displays spoofed country and remote host geo/IP info

    🧠 Runs whois and nmap on a target IP from the remote host

    💾 Transfers scan results from remote to local machine

    🧹 Cleans up logs and temporary directories

🧩 Requirements

    Bash (Linux-based system)

    sshpass

    geoip-bin

    git

    cpanminus

    Nipe dependencies (Switch, JSON, Config::Simple)

    Internet connection

🚀 How to Use

    Run the script:

    chmod +x script.sh
    ./script.sh

    Follow the prompts:

        Enter remote host IP, username, and password.

        Enter the target IP you want to analyze.

    View the results:

        Whois.txt and scan_results.txt will be available on your local desktop inside a folder named Scan.

    ⚠️ Note: Use this script responsibly and only on machines and networks you have explicit permission to access.

📁 Output

    Scan/Whois.txt: Whois data of target IP

    Scan/scan_results.txt: Nmap scan results

👨‍💻 Author

Afek Tzabari
Cybersecurity Student – TMagen773634
Lecturers: Doron Zohar, Natalie