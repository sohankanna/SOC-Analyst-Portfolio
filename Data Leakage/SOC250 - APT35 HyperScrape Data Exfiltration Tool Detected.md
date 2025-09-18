# SOC250 - APT35 HyperScrape Data Exfiltration Tool Detected

## Executive Summary

On December 27, 2023, the Security Operations Center (SOC) detected the execution of **HyperScrape**, a known data exfiltration tool used by the Iranian state-sponsored threat actor **APT35 (Charming Kitten)**, on the host **Arthur** (172.16.17.72). The investigation confirmed that after gaining initial access to the machine via a successful RDP login, the attacker executed the tool (disguised as `EmailDownloader.exe`) to connect to a C2 server and systematically exfiltrate emails directly from the user's Outlook Web App (OWA) session. The attack was successful, resulting in a confirmed data breach of the user's mailbox. This is a **True Positive** for a critical incident involving a sophisticated threat actor.

## Incident Details

The initial alert was triggered by the detection of a malicious file hash associated with APT35's tooling:

<img width="1481" height="653" alt="image" src="https://github.com/user-attachments/assets/ddda8f17-6276-41c1-b110-63da9d48ad10" />

| | |
| :--- | :--- |
| **Date of Incident**| December 27, 2023 |
| **Attacker IPs**| 173.209.51.54 (Initial Access via RDP)<br>136.243.108.14 (Malware C2) |
| **Destination Host**| Arthur (172.16.17.72) |
| **Compromised Account**| `Arthur` / `arthur@letsdefend.io` |
| **Threat Actor**| APT35 (Charming Kitten, Phosphorus) |
| **Malware**| HyperScrape (`EmailDownloader.exe`) |
| **File Hash (SHA256)**| `cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa` |
| **Case Link**| *[(Case link)](https://app.letsdefend.io/case-management/casedetail/sohankanna/212)* |

## Investigation and Analysis

### 1. Threat Actor Profile: APT35 (Charming Kitten) and HyperScrape

**APT35**, also known as **Charming Kitten** or **Phosphorus**, is an Iranian state-sponsored threat group known for its persistent cyber-espionage campaigns. Their primary objectives typically involve intelligence gathering in support of Iranian government interests.
*   **Targets:** They frequently target academics, journalists, human rights activists, and governmental organizations in the US, Israel, and the Middle East.
*   **Tactics:** Their primary tactics include spear-phishing to harvest credentials, social engineering, and deploying custom malware.
*   **HyperScrape Tool:** As noted in the alert, HyperScrape is a custom tool specifically designed by APT35 for one purpose: to steal the contents of a user's mailbox (Gmail, Yahoo, Outlook) with high efficiency. It works by authenticating to the mail server, often using stolen cookies or credentials, and then systematically scrapes and downloads emails, attachments, and contacts. It is designed to be stealthy by mimicking legitimate browser activity. The filename `EmailDownloader.exe` is a literal and unsophisticated name for this highly targeted tool.

### 2. Reconstructing the Attack Chain: From Initial Access to Exfiltration

The investigation revealed a clear, multi-stage attack chain:

**Stage 1: Initial Access (RDP Compromise)**
Just before the HyperScrape tool was run, a Windows Security Event Log shows a successful remote login to the victim machine.
<img width="784" height="270" alt="image" src="https://github.com/user-attachments/assets/1708d764-1c0f-472e-8022-cd0036e04d87" />



*   **Event ID:** 4624 (Successful Logon)
*   **Username:** `Arthur`
*   **Logon Type:** 10 (RemoteInteractive / RDP)
*   **Source IP:** `173.209.51.54`

This log is strong evidence that the attacker first gained access to the machine by compromising the `Arthur` user account, likely through a prior phishing campaign or brute-force attack.

**Stage 2: Malware Execution and C2 Communication**
Once on the system, the attacker executed the HyperScrape tool.
*   **Endpoint Log:** The EDR log shows `EmailDownloader.exe` was run from the user's Downloads folder. Its parent process, `Explorer.EXE`, indicates it was likely executed manually by the attacker during their RDP session.
    <img width="1294" height="370" alt="image" src="https://github.com/user-attachments/assets/e8217b50-8a15-4722-b363-017019619241" />
*   **Firewall Log:** Network logs confirm the malware initiated an outbound connection from the victim host to the C2 server `136.243.108.14`. This connection was used to receive commands and exfiltrate the stolen data.
    <img width="813" height="409" alt="image" src="https://github.com/user-attachments/assets/15538f17-5bfb-4fec-843d-7c1095b15f64" />

**Stage 3: Confirmation of Data Exfiltration**
The most critical piece of evidence comes from the mailbox audit log, which provides definitive proof of data theft.

<img width="800" height="808" alt="image" src="https://github.com/user-attachments/assets/7c9d5476-65fc-4d74-bb46-f88decfa5b33" />

*   **Operation:** `Download`
*   **OperationResult:** `Succeeded`
*   **FolderPathName:** `\Mails\Inbox`
*   **ClientInfoString:** `Client:OWA;Action:ViaProxy`

This log shows that the tool successfully accessed the `Arthur` mailbox via an OWA session and began downloading the contents of the inbox. The subject "Notification of Multiple Mail Download" is likely an automated alert generated by the mail system in response to the tool's mass-download activity.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Firewall Logs, Mailbox Audit Logs, VirusTotal
*   **Skills Demonstrated:** APT Analysis, Attack Chain Reconstruction, Log Correlation, Threat Intelligence.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is C2 traffic from a known APT tool.
*   **What Is The Attack Type?** **Data Exfiltration** (post-compromise).
*   **Was the Attack Successful?** **Yes.** Emails were successfully exfiltrated from the user's mailbox.
*   **Containment:** **Yes.** The host and user account must be contained immediately.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC250 was a **true positive** for a successful cyber-espionage attack by the APT35 threat actor. The attacker gained initial access via RDP, deployed the HyperScrape tool, and successfully exfiltrated email data. The user account and host are fully compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host and Disable Account:**
    *   Immediately isolate the host **Arthur** (172.16.17.72) from the network.
    *   Immediately disable the `Arthur` user account in Active Directory and force a password reset. Invalidate all active login sessions.
2.  **ESCALATE:** Escalate immediately to the Tier 2/Incident Response team for a full forensic investigation into an APT compromise.
3.  **INVESTIGATION:** The scope of the investigation must assume the attacker has been present since the initial RDP login. The IR team must hunt for persistence, lateral movement, and credential dumping. All activity by the `Arthur` account since the time of compromise must be considered malicious.
4.  **REMEDIATE - Secure RDP:** The root cause of the incident appears to be an exposed RDP service. RDP access from the internet must be disabled immediately and placed behind a secure VPN with Multi-Factor Authentication (MFA).
5.  **BLOCK INDICATORS:** Block all identified IOCs at the perimeter:
    *   **IPs:** `173.209.51.54` and `136.243.108.14`.
    *   **Hash:** `cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa`.
