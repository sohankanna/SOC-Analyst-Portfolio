# SOC112 - Traffic to Blacklisted IP (Event ID:43)

## Executive Summary

On January 31, 2021, the Security Operations Center (SOC) received a critical alert for traffic to a blacklisted IP address originating from the host **Jack** (172.16.17.21). The investigation confirmed that a PowerShell script was used to download a malicious executable, `OBBBOP.exe`, from the known-malicious IP **193.239.147.32**. The `User-Agent` string explicitly identifies the client as `PowerShell/6.0.0`, indicating a non-interactive, scripted download rather than user browsing. The `Device Action: Allowed` confirms the malware was successfully downloaded to the host. The system is considered compromised. This is a **True Positive** critical incident.

## Incident Details

The initial alert was triggered by an outbound connection to an IP address on a threat intelligence blocklist:

<img width="1443" height="497" alt="image" src="https://github.com/user-attachments/assets/f5daeabf-7e64-4aa2-88ee-1b55151d8e41" />

| | |
| :--- | :--- |
| **Date of Incident**| January 31, 2021 |
| **Source Host**| Jack (172.16.17.21) |
| **Username**| jack2021 |
| **Malicious IP**| 193.239.147.32 |
| **Malicious File**| `OBBBOP.exe` |
| **User Agent**| PowerShell/6.0.0 |
| **Attack Type**| Malware Download / Living-off-the-Land |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/43))* |

## Investigation and Analysis

### 1. Alert Context and Threat Intelligence

The alert `SOC112 - Traffic to Blacklisted IP` is a high-confidence indicator of compromise. It signifies that a device on the internal network is communicating with a server known to be associated with malicious activity.
*   **IP Reputation (VirusTotal):** A check on the destination IP `193.239.147.32` confirmed its malicious reputation, with **10 security vendors** flagging it.
    <img width="1670" height="744" alt="image" src="https://github.com/user-attachments/assets/59cc27b9-dfea-467f-97ca-95590c98be39" />
*   **URL Reputation (VirusTotal):** The full URL, `http://193.239.147.32/OBBBOP.exe`, was also flagged by **8 vendors**, with tags clearly indicating malware.
    <img width="1652" height="723" alt="image" src="https://github.com/user-attachments/assets/cdfd8369-4653-4580-8f26-8f6bc75a14d4" />

### 2. The "Smoking Gun": PowerShell as the User-Agent

The most critical piece of evidence in this alert is the `User-Agent`.
*   **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.15063; en-US) PowerShell/6.0.0`
*   **Analysis:** A legitimate user browsing the web will have a User-Agent identifying their browser (e.g., Chrome, Firefox, Edge). The presence of `PowerShell/6.0.0` is definitive proof that this download was initiated by a script, not by a user clicking in a browser. This is a classic "Living-off-the-Land" (LOLBin) technique, where an attacker uses legitimate, built-in system tools like PowerShell to perform malicious actions (in this case, downloading a secondary payload).

### 3. Confirmation of Successful Download

Multiple log sources confirm that the malware was successfully downloaded to the host.
*   **Network Logs:** Log management confirms the GET request for `OBBBOP.exe` and shows the `Device Action` was `Allowed`, meaning the download was not blocked by perimeter security.
    <img width="906" height="298" alt="image" src="https://github.com/user-attachments/assets/5f871e08-1352-47a5-9397-bb016bb6b125" />
*   **Endpoint Logs:** EDR logs corroborate the network connection from the host to the malicious IP address, providing a complete picture of the event.
    <img width="971" height="173" alt="image" src="https://github.com/user-attachments/assets/da6832db-ae69-4e49-b20d-acc0547d4b3a" />

Although there is no immediate evidence of the `OBBBOP.exe` process running, this does not mean the host is safe. The malicious file is now present on the system, waiting for a trigger or having already executed and terminated. The compromise has already occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Network Logs, VirusTotal
*   **Skills Demonstrated:** Log Correlation, LOLBin Technique Recognition (PowerShell), C2 Traffic Identification, Malware Triage.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a scripted download of an executable from a blacklisted IP.
*   **What Is The Attack Type?** **Malware Download.**
*   **Was the Attack Successful?** **Yes.** The malicious executable was successfully downloaded to the endpoint.
*   **Do You Need Tier 2 Escalation?** **Yes.** A confirmed malware download to a host is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC112 was a **true positive** for a successful malware download. An attacker, likely having already gained some form of access to the host, used a PowerShell script to download a second-stage payload. The host **Jack** is compromised, and the `OBBBOP.exe` file must be considered an active threat.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **Jack** (172.16.17.21) from the network to prevent the malware from being executed (if it hasn't already) and to stop any potential C2 communication.
2.  **CREDENTIALS - Disable and Reset:** Immediately disable the `jack2021` user account and reset their password.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full forensic investigation.
4.  **INVESTIGATION:** The primary goals for the IR team are:
    *   To find and analyze the initial PowerShell script that performed the download. This is key to understanding the initial access vector.
    *   To locate and analyze the `OBBBOP.exe` file to determine its capabilities and search for its hash on other systems.
    *   To hunt for any persistence mechanisms the attacker may have established.
5.  **RECOVERY:** The compromised host must be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:** Block the malicious IP `193.239.147.32` at the network firewall. Once the hash of `OBBBOP.exe` is confirmed, add it to the EDR blocklist.

