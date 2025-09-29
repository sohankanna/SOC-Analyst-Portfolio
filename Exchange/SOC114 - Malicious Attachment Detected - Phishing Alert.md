# 	SOC114 - Malicious Attachment Detected - Phishing Alert

## Executive Summary

On January 31, 2021, the Security Operations Center (SOC) detected a malicious attachment delivered to the user `richard@letsdefend.io`. The investigation confirmed that the email was part of a targeted phishing campaign delivering a weaponized document. Dynamic analysis revealed the document successfully exploited **CVE-2017-11882**, a well-known Remote Code Execution (RCE) vulnerability in the Microsoft Office Equation Editor. Endpoint security logs confirmed that the user opened the attachment, triggering the exploit and spawning the vulnerable `EQNEDT32.EXE` process. The `Device Action: Allowed` status confirms the email was delivered and the subsequent RCE was not blocked. This is a **True Positive** for a critical host compromise.

## Incident Details

The initial alert was triggered by the detection of a malicious attachment in an email:

<img width="1513" height="566" alt="image" src="https://github.com/user-attachments/assets/7e2ef46d-964a-43bf-8fb9-7ba3ae8c90b4" />

| | |
| :--- | :--- |
| **Date of Incident**| January 31, 2021 |
| **Attacker SMTP IP**| 49.234.43.39 |
| **Sender Address**| accounting@cmail.carleton.ca (Likely Spoofed) |
| **Recipient Address**| richard@letsdefend.io |
| **Vulnerability**| CVE-2017-11882 (Equation Editor RCE) |
| **Attack Type**| Phishing with Exploit Document |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/45))* |

## Investigation and Analysis

### 1. Vulnerability Profile: Microsoft Equation Editor RCE (CVE-2017-11882)

**CVE-2017-11882** is a critical memory corruption vulnerability in an old, outdated component of Microsoft Office called the Equation Editor (`EQNEDT32.EXE`).

*   **How it Works:** The vulnerability is a stack buffer overflow. By crafting a special equation object within a document (like RTF, DOC, or DOCX), an attacker can cause the `EQNEDT32.EXE` process to crash in a predictable way, allowing them to execute arbitrary code on the victim's machine.
*   **Significance:** This exploit is particularly popular with attackers because it is reliable, affects many versions of Office, and does not require the user to enable macros. The exploit triggers automatically when the document is opened.
*   **Key Indicator:** The primary indicator of this exploit is the parent process (e.g., `WINWORD.EXE` or `OUTLOOK.EXE`) spawning the child process `EQNEDT32.EXE`.

### 2. Phishing Email and Malware Analysis

The attack began with a standard phishing email themed as an "Invoice" to create a sense of business legitimacy. The `Device Action: Allowed` confirms it was delivered to the user's inbox.

<img width="1520" height="642" alt="image" src="https://github.com/user-attachments/assets/2a424330-a4d9-4400-94c1-f1cbb21556b3" />

A deep analysis of the attachment confirmed its malicious nature:
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **35 security vendors**.
    <img width="1785" height="866" alt="image" src="https://github.com/user-attachments/assets/271d78e9-a330-43cc-bb59-c9373d0f56e9" />
*   **Dynamic Analysis (Hybrid Analysis):** The sandbox run provided definitive proof of the exploit, scoring it **100/100**. The analysis explicitly states, "**Possible Equation Editor exploit detected**" and notes that the document spawned `EQNEDT32.EXE` in a context matching CVE-2017-11882. The analysis also showed the payload attempting to download a secondary executable (`network.exe`) from a C2 server (`andaluciabeach.net`).
    <img width="1710" height="754" alt="image" src="https://github.com/user-attachments/assets/f46d983a-13f6-4e33-ae3e-20634995c2c9" />

### 3. Confirmation of Successful Exploitation

The investigation confirmed that the user opened the file and the exploit was successful.
*   **Endpoint Logs (Initial Access):** EDR logs show the user's browser process (`chrome.exe`) downloading the 2nd payload from the C2 server.
    <img width="1215" height="139" alt="image" src="https://github.com/user-attachments/assets/2bbf1c71-879c-41eb-ace5-1e54134e9c8d" />
*   **Endpoint Logs (Exploit Execution):** Crucially, the logs also show the `EQNEDT32.EXE` process running on the victim's machine. This is the "smoking gun," confirming that the vulnerability was successfully triggered.
    <img width="1108" height="65" alt="image" src="https://github.com/user-attachments/assets/695a561c-3780-4f2f-81c9-025919c9af1c" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway, VirusTotal, Hybrid Analysis
*   **Skills Demonstrated:** Phishing Analysis, Exploit Triage (CVE-2017-11882), Dynamic Malware Analysis, Log Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment is a weaponized document exploiting CVE-2017-11882.
*   **Was the Attack Successful?** **Yes.** The user opened the document, and the exploit process (`EQNEDT32.EXE`) was executed.
*   **Do You Need Tier 2 Escalation?** **Yes.** A successful RCE on an endpoint is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC114 was a **true positive** for a successful phishing attack resulting in Remote Code Execution. An attacker successfully exploited the known vulnerability CVE-2017-11882 to compromise the user `Richard's` workstation. The host is compromised and was attempting to download a secondary payload.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the user's machine from the network to prevent the download of the secondary payload and to stop any potential C2 communication or lateral movement.
2.  **CREDENTIALS - Disable and Reset:** Immediately disable the `Richard` user account in Active Directory. The password must be reset after the investigation.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for full forensic analysis.
4.  **INVESTIGATION:** The IR team must determine if the secondary payload (`network.exe`) was successfully downloaded and what its function is. They must also hunt for persistence mechanisms and other signs of compromise.
5.  **PATCHING:** Ensure all Microsoft Office installations across the organization are fully patched to mitigate CVE-2017-11882.
6.  **BLOCK INDICATORS:**
    *   **IP/Domains:** Block the C2 domain (`andaluciabeach.net`) and the sender's IP (`49.234.43.39`) at the perimeter.
    *   **Hash:** Add the attachment hash to the EDR blocklist.
7.  **REMEDIATE - Purge Email:** Use the email security gateway to search for and purge this malicious email from any other mailboxes it may have been delivered to.
























