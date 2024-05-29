# VT Script
### Reach me at:

- Linkedin: (https://www.linkedin.com/in/abdulaziz-al-thani)

### Description
* The script has the following key features:

    - Target Scanning: The script can scan IP addresses, domains, and file hashes for potential malicious activities. It supports reading targets from a file specified by the user.
    - VirusTotal API Integration: The script uses the VirusTotal API to fetch information about the provided targets. It requires an API key, which should be stored in a .env file.
    - CSV Output: The script generates a CSV file named Malicious_IPs_Domains_Hashes.csv in the current directory, which contains the scanned targets, their types, and their maliciousness scores.
    - Progress Tracking: The script uses a progress bar to display the scanning progress for each target.
    - Error Handling: The script attempts to handle errors that may occur during the scanning process and provides appropriate error messages.
    - Detailed Instructions: The script includes a banner and detailed instructions on how to use the tool and set up the required environment.

* The script is designed to be user-friendly and can be easily integrated into various security workflows or used as a standalone tool for investigating potential security threats.

### Requirements:
1. **Python**: The script is written in Python, so you will need to have Python installed on your system. The script was developed using Python 3.9, but it should work with other versions of Python 3 as well.
2. **Required Python Packages**:
   - `requests`: Used for making HTTP requests to the VirusTotal API.
   - `csv`: Used for writing the scan results to a CSV file.
   - `dotenv`: Used for loading the VirusTotal API key from a `.env` file.
   - `argparse`: Used for parsing command-line arguments.
   - `datetime`: Used for recording the start and end times of the script.
   - `tqdm`: Used for displaying a progress bar during the scanning process.
   
You can install the required packages using the following command:
```
pip install requests csv dotenv argparse datetime tqdm

```
3. **VirusTotal API Key**: The script requires a valid VirusTotal API key to access the VirusTotal API. You need to create an account on the VirusTotal website and generate an API key. Once you have the API key, store it in a "nter_API_Key.txt" file in the same directory as the script as is it.
4. **Targets File**: The script expects a file containing the targets (IP addresses, domains, or file hashes) that you want to scan. Each target should be on a new line in the file.
5. **Operating System**: The script should work on any operating system that can run Python, such as Windows, macOS, or Linux.

Make sure you have all the requirements in place before running the Virustotal_checker script. If you encounter any issues, refer to the instructions provided in the script's banner or the `print_instructions()` function.
### Usage:
1. Install the required libraries:
```
pip install -r requirements.txt

```
2. Create an account on VirusTotal.
3. Generate an API key from your account settings.
4. Copy the API key
5. Paste the API key in 'Enter_API_Key.txt'
![Enter_API_Key.txt.png](Enter_API_Key.txt.png)
7. Create any file as (txt) format <targets_file>, then enter any IP, hashes, and domain to scan them.
![target.txt.png](target.txt.png)
9. Run the script using the following command:
  python script.py
![Script.txt.png](Script.txt.png)
 python script.py -f <targets_file>
![running.png](running.png)
![finish.png](finish.png)
![Malicious_IPs_Domain.csv.png](Malicious_IPs_Domain.csv.png)
### Please feel free to contact me on my Linkedin private messages: https://www.linkedin.com/in/abdulaziz-al-thani
