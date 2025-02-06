# BitThief
> [!CAUTION]
> **USE OF THIS CODE IS AT YOUR OWN RISK.**  
> The repository owner (greenstorm5417) is not responsible for any actions taken using this code. This tool is provided for educational and research purposes only. By using this code, you acknowledge that you are solely responsible for any consequences that may arise. Always ensure you have permission to use such tools in your environment.


## Overview

**BitThief** is a comprehensive tool written in Go that extracts, aggregates, and exfiltrates various types of local data from a Windows machine. Its top-level features include:

- **Data Extraction:**  
  - **Browser Data:** Extracts browsing history, logins, cookies, bookmarks, autofill data, and credit card information from various browsers.
  - **WiFi Passwords:** Retrieves saved WiFi profiles and their associated passwords.
  - **System Information:** Gathers details about the operating system, CPU, GPU, RAM, and a unique hardware identifier (HWID).

- **Data Packaging:**  
  - Combines the extracted data into a folder (named `Vault`) and then compresses the folder into a ZIP archive.
  
- **Data Exfiltration:**  
  - Uploads the ZIP file to a specified Discord webhook.
  - Sends additional embeds containing system and browser information to Discord.

- **Anti-Debugging Features:**  
  - Checks for debugging environments by inspecting running processes, network information (IP/MAC addresses), and system details.
  - If a debugging environment is detected, the program exits immediately.

- **Token Extraction:**  
  - Extracts and uploads Discord tokens from various locations on the system, with further details provided via Discord embeds.
  
- **Cleanup:**  
  - After exfiltration, the tool cleans up temporary files and even creates a cleanup batch file to remove itself from the system.



## VirusTotal Report

According to recent tests, the compiled binary scores **0/70** on VirusTotal. You can review the detailed report [here](https://www.virustotal.com/gui/file/edc360283400689e08a5745896ad696ca8aedf4ac667f33a3c6c12035ff2bbb5).



## How to Compile

This project is built using Go version **1.23.4**. To compile the code, run the following command in the repository's root directory:

```bash
go build -ldflags "-w " .
```

This command builds a binary (approximately 12.7 MB) without debug information.





## Usage

After compilation, running the resulting binary will automatically:
- Hide the console window.
- Perform anti-debug checks and exit if a debugging environment is detected.
- Extract various data from the system (browser data, WiFi passwords, system info).
- Package the data into a folder named `Vault`, compress it into a ZIP file, and send the ZIP file (along with detailed embeds) to a predefined Discord webhook.
- Attempt to extract Discord tokens and send the token information to Discord.
- Clean up all temporary files after the operation.

**Note:**  
This tool should only be used on systems where you have explicit permission to extract and exfiltrate data. Misuse of this tool may result in severe legal consequences.





## Contributing

Contributions are welcome! If you’d like to help improve BitThief, please follow these guidelines:

1. **Fork the Repository:**  
   Create your own fork of the repository on GitHub.

2. **Clone Your Fork:**  
   ```bash
   git clone https://github.com/yourusername/BitThief.git
   cd BitThief
   ```

3. **Create a Branch:**  
   Create a branch for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Implement Your Changes:**  
   Make your changes in a clear, concise, and modular manner. Ensure that your code adheres to the existing style guidelines.

5. **Test Your Changes:**  
   Thoroughly test your modifications on a safe and controlled environment.

6. **Submit a Pull Request:**  
   Once your changes are ready, submit a pull request describing your improvements and the rationale behind them.

7. **Discussion and Review:**  
   Engage in discussion on your pull request if further changes or clarifications are requested by the maintainers.

Your contributions, whether they’re bug fixes, improvements, or new features, are greatly appreciated. Please ensure that all changes respect the disclaimer and ethical guidelines stated in this README.


## Repository Information

- **Repository URL:** [https://github.com/greenstorm5417/BitThief.git](https://github.com/greenstorm5417/BitThief.git)
- **License:** See the LICENSE file for more details.
- **Go Version:** 1.23.4


---
> [!CAUTION]
> **Important Legal Notice**
> This repository is provided solely for educational and research purposes. Use of the BitThief tool in any unauthorized manner (e.g., on systems without explicit permission) is illegal and unethical. The repository owner disclaims any liability for damages or legal repercussions that may result from misuse of this software. Always respect privacy, data protection laws, and ethical guidelines in your jurisdiction.




