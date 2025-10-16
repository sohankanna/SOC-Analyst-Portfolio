# 	SOC164 - Suspicious Mshta Behavior


## Executive Summary

On March 5, 2022, the Security Operations Center (SOC) received an alert for suspicious `mshta.exe` behavior on the host **Roberto** (172.16.17.38). The investigation confirmed a successful, multi-stage "living-off-the-land" attack. The user executed a malicious HTML Application (`Ps1.hta`), which in turn used `mshta.exe` to launch a heavily obfuscated PowerShell command. This command deobfuscated itself in memory, then downloaded and executed a secondary payload from a remote C2 server (`193.142.58.23`). The `EDR Action: Allowed` and endpoint logs confirming the entire process chain and subsequent C2 connection indicate a full host compromise. This is a **True Positive** critical incident.

## Incident Details

The initial alert was triggered by the malicious use of the `mshta.exe` binary:

<img width="1327" height="648" alt="image" src="https://github.com/user-attachments/assets/48400f1b-8306-4efb-9ac6-0c7588d0fd23" />

| | |
| :--- | :--- |
| **Date of Incident**| March 5, 2022 |
| **Source Host**| Roberto (172.16.17.38) |
| **Initial Vector**| `Ps1.hta` |
| **Initial Vector Hash (MD5)**| 6685c433705f558c5535789234db0e5a |
| **Attacker C2 IP**| 193.142.58.23 |
| **Attack Type**| LOLBin / Fileless Malware / Downloader |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/114))* |

## Investigation and Analysis

### 1. Alert Context: `mshta.exe` as a LOLBin

The rule `SOC164 - Suspicious Mshta Behavior` is designed to detect the malicious use of a legitimate Windows binary.
*   **Legitimate Use:** `mshta.exe` (Microsoft HTML Application Host) is a utility for running HTML Applications (`.hta` files), which are essentially standalone web pages that can run with the permissions of a local application.
*   **Malicious Use (T1218.005):** Attackers abuse `mshta.exe` to execute remote scripts (VBScript/JScript) without ever writing them to disk. This "fileless" technique is stealthy and can bypass security controls that focus on scanning files on the hard drive. An `.hta` file can easily contain code that launches PowerShell, as seen in this incident.

### 2. Deconstructing the Attack Chain via Endpoint Logs

The EDR's command-line history provides a perfect, step-by-step narrative of the attack.

**Stage 1: The Initial Dropper (`Ps1.hta`)**
The attack began when the user `Roberto` executed the file `Ps1.hta` from their desktop. The endpoint logs confirm this initial action.
*   **Command:** `C:/Windows/System32/mshta.exe C:/Users/roberto/Desktop/Ps1.hta`
*   **Threat Intelligence:** The hash of `Ps1.hta` is flagged as malicious by **29 vendors on VirusTotal**, confirming it is the initial malicious file.
    <img width="1634" height="855" alt="image" src="https://github.com/user-attachments/assets/85ad2726-540d-4e72-94df-0a3b11480c01" />

**Stage 2: The Obfuscated PowerShell Downloader**
The `.hta` file contained code that launched a second, highly obfuscated PowerShell command.

<img width="1002" height="353" alt="image" src="https://github.com/user-attachments/assets/3e01e7d0-c6bc-4cc5-b6e2-e58fab9c1acc" />

**Deconstructing the PowerShell Command:**
This one-line command is a masterpiece of obfuscation designed to download and execute a payload in memory.
1.  **Hex-to-ASCII Function:** It defines a function `H1` that converts hexadecimal strings back into readable text. This is used to hide all the key commands.
2.  **String Obfuscation:** It uses string formatting (`-f`) to build the string `'net.WebClient'` to avoid detection.
3.  **Command Reconstruction:** It decodes several hex strings (`'446f776E'`, `'6C6f'`, etc.) and concatenates them to build the command string **`"Downloadstring"`** in memory.
4.  **Payload Download:** It uses the `net.WebClient` object and the dynamically built `Downloadstring` command to download the contents of `http://193.142.58.23/Server.txt` into a variable.
5.  **In-Memory Execution:** Finally, it uses `iEX` (an alias for `Invoke-Expression`) to execute the downloaded content directly from memory, without ever saving it to disk. This is a classic "fileless" attack technique.

### 3. Confirmation of Success

The compromise is confirmed by multiple pieces of evidence.
*   **Execution Allowed:** The `EDR Action: Allowed` in the alert confirms the initial `.hta` file was not blocked.
*   **Endpoint Logs:** The EDR logs show the full chain of execution: `explorer.exe` -> `mshta.exe` -> `powershell.exe`.
    <img width="1209" height="315" alt="image" src="https://github.com/user-attachments/assets/b968d51f-a504-47de-b637-e3d7cc80d9eb" />
*   **Network Logs (The "Smoking Gun"):** Network logs confirm a successful outbound connection from the host to the attacker's C2 IP address, **`193.142.58.23`**. This proves the PowerShell script successfully ran and downloaded its secondary payload.
    <img width="1420" height="102" alt="image" src="https://github.com/user-attachments/assets/a425943a-8871-4799-90db-6219880314d6" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, VirusTotal
*   **Skills Demonstrated:** LOLBin Analysis (mshta), PowerShell Deobfuscation, Fileless Malware Triage, Attack Chain Reconstruction, Log Correlation.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a successful execution of a fileless downloader.
*   **What Is The Attack Type?** **LOLBin / Fileless Malware.**
*   **Was the Attack Successful?** **Yes.** The script was executed, and the C2 server was contacted.
*   **Do You Need Tier 2 Escalation?** **Yes.** A confirmed fileless malware execution and C2 connection is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC164 was a **true positive** for a successful and sophisticated fileless malware attack. An attacker tricked the user into running a malicious HTA file, which then used PowerShell and `mshta.exe` to download and execute a payload directly in memory. The host **Roberto** is fully compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **Roberto** (172.16.17.38) from the network to sever any active C2 connection and prevent lateral movement.
2.  **CREDENTIALS - Disable and Reset:** Immediately disable the `Roberto` user account and reset their password.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full forensic investigation.
4.  **INVESTIGATION:** The IR team must perform a full memory analysis of the host to try and recover the in-memory payload from `Server.txt`. They must also hunt for any persistence mechanisms that may have been established.
5.  **RECOVERY:** The compromised host cannot be trusted and must be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:**
    *   **IP:** Block the C2 IP `193.142.58.23` at the network firewall.
    *   **Hash:** Add the hash of `Ps1.hta` (`6685c433705f558c5535789234db0e5a`) to the EDR blocklist.
7.  **Initial Access Vector:** The investigation must also determine how `Ps1.hta` was delivered to the user's desktop (e.g., phishing email, web download).





