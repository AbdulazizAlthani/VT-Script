import os
import requests
import csv
from datetime import datetime
from tqdm import tqdm

API_KEY_FILE = "Enter_API_Key.txt"

VT_URL = "https://www.virustotal.com/api/v3/"
CSV_FILE = "Malicious_IPs_Domains_Hashes.csv"

def get_api_key():
    try:
        with open(API_KEY_FILE, "r") as f:
            api_key = f.read().strip()
        return api_key
    except FileNotFoundError:
        print(f"Error: {API_KEY_FILE} not found. Please create the file and add your VirusTotal API key.")
        return None
    except Exception as e:
        print(f"Error reading API key: {e}")
        return None

def scan_targets(targets_file):
    api_key = get_api_key()
    if not api_key:
        return

    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
    }

    with open(CSV_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Target", "Type", "Malicious"])

        with open(targets_file) as f:
            target_list = f.read().splitlines()

        start_time = datetime.now()
        print("Script started at:", start_time.strftime("%Y-%m-%d %H:%M:%S"))

        progress_bar = tqdm(target_list, desc="Scanning", unit="target")

        target_results = []

        for target in progress_bar:
            target_type = get_target_type(target)
            url = f"{VT_URL}{get_target_url(target_type, target)}"

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                try:
                    malicious = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
                    target_results.append([target, target_type, malicious])
                except KeyError:
                    print("Error occurred while processing target:", target)
                    target_results.append([target, target_type, "Error"])
            else:
                print("Error occurred while processing target:", target)
                target_results.append([target, target_type, "Error"])

        progress_bar.close()

        sorted_results = sorted(target_results, key=lambda x: int(x[2]), reverse=True)
        writer.writerows(sorted_results)

        end_time = datetime.now()
        print("Script finished at:", end_time.strftime("%Y-%m-%d %H:%M:%S"))
        elapsed_time = end_time - start_time
        print("Elapsed time:", elapsed_time)

        print(f"The scan has been completed. Results are saved in: {os.path.abspath(CSV_FILE)}")

def get_target_type(target):
    return "IP" if target.count(".") >= 1 and all(part.isdigit() for part in target.split(".")) else "Domain" if target.count(".") >= 1 else "Hash"

def get_target_url(target_type, target):
    return f"ip_addresses/{target}" if target_type == "IP" else f"domains/{target}" if target_type == "Domain" else f"files/{target}"

def print_banner():
    banner = r"""

 __      __  _______      _____                 _           _   
 \ \    / / |__   __|    / ____|               (_)         | |  
  \ \  / /     | |      | (___     ___   _ __   _   _ __   | |_ 
   \ \/ /      | |       \___ \   / __| | '__| | | | '_ \  | __|
    \  /       | |       ____) | | (__  | |    | | | |_) | | |_ 
     \/        |_|      |_____/   \___| |_|    |_| | .__/   \__|
                                                   | |          
                                                   |_|          
                                                   
     Author: Abdulaziz S. Althani
     Version: 1.0
     Linkedin: https://www.linkedin.com/in/abdulaziz-al-thani
                                                                                                                
"""

    print("\033[91m")  # Set text color to red
    print(banner)
    print("\033[0m")  # Reset text color

def print_instructions():
    instructions = """
Instructions:
--------------
1. Install the required libraries:

pip install -r requirements.txt

2. Create an account on VirusTotal.
3. Generate an API key from your account settings.
4. Copy the API key.
5. Paste the API key in 'Enter_API_Key.txt'
6. Create any file as (txt) format <targets_file> such as "targets.txt", then enter inside it any IP, hashes, and domain to scan them.
7. Run the script using the following command:
  python script.py -f <targets_file>
  
### Please feel free to contact me on my Linkedin private messages: https://www.linkedin.com/in/abdulaziz-al-thani


Note:
-----
- The scan results will be saved in a CSV file named 'Malicious_IPs_Domains_Hashes.csv' in the current directory.
"""
    print(instructions)

if __name__ == "__main__":
    print_banner()

    import argparse

    parser = argparse.ArgumentParser(description="Scan IP addresses, domains, and file hashes using VirusTotal API.")
    parser.add_argument("-f", "--file", dest="targets_file", help="Path to the file containing the targets")
    args = parser.parse_args()

    if args.targets_file:
        scan_targets(args.targets_file)
    else:
        print("KINDLY, FOLLOW THE INSTRUCTIONS BELOW TO RUN THE SCRIPT CORRECTLY!")

    print_instructions()
