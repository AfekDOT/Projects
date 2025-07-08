🧪 Memory & File Forensics Analyzer Script
📜 Overview

This Bash script, created by Afek Tzabari, automates the forensic analysis of memory dumps and files using several open-source tools. It checks for required tools, installs missing ones, performs multiple analysis techniques, and generates a final zipped report with the findings.
🧩 Features

    ✅ Root user check

    🧰 Verifies and installs essential forensic tools:

        binwalk, bulk_extractor, foremost, strings

        Installs Volatility 2.6 automatically if missing

    📁 Validates file existence before analyzing

    🛠️ Offers multiple analysis options:

        Binwalk: Embedded file scan

        Bulk Extractor: Disk image carving + PCAP detection

        Foremost: File recovery

        Strings: Extract printable strings

        Volatility:

            Auto profile detection

            Process list

            Network connections

            Registry key extraction

    🧾 Generates a timestamped report

    📦 Zips extracted output and report for easy storage

⚙️ Requirements

    Linux OS

    Bash

    Internet connection

    Tools (installed automatically if missing):

        binwalk, bulk_extractor, foremost, strings, toilet, unzip, zip

    Python dependencies bundled in Volatility 2.6

🚀 Usage

    Make the script executable:

chmod +x analyzer.sh

Run the script as root:

    sudo ./analyzer.sh

    Follow prompts:

        Enter the filename to analyze (must exist on the system)

        Choose which tool(s) to use (1–6)

        View the results and report

    Outputs:

        Analysis outputs in folders: bulk_output, foremost_output

        Summary: analysis_report.txt

        All zipped together in forensics_analysis.zip

📁 Output Example

├── bulk_output/
├── foremost_output/
├── analysis_report.txt
└── forensics_analysis.zip

👨‍💻 Author

Afek Tzabari
Cybersecurity Student – TMagen773634
Lecturer: Natalie Erez / Doron Zohar
