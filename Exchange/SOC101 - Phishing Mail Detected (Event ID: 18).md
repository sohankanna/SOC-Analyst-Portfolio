# 	SOC101 - Phishing Mail Detected (Event ID: 18)
## Executive Summary

On September 22, 2020, the Security Operations Center (SOC) received an alert for a phishing email delivered to the user `katharine@letsdefend.io`. The investigation confirmed a successful phishing attack where the email, themed as an urgent bank account notification, was **Allowed** by the email security gateway. The email contained a malicious attachment, identified by threat intelligence as an **ELF executable**, a file type designed to run on **Linux** systems, not Windows. Endpoint security logs provide definitive proof that the user executed this `creditcard` file. The delivery of a Linux binary to a corporate user and its subsequent execution is a highly anomalous and critical event, suggesting a targeted or unusual attack. The host is compromised.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1465" height="547" alt="image" src="https://github.com/user-attachments/assets/a863d0fa-10ff-4aa6-8001-edcce45ebf92" />

| | |
| :--- | :--- |
| **Date of Incident**| September 22, 2020 |
| **Attacker SMTP IP**| 172.82.128.241 |
| **Sender Address**| david@cashbank.com |
| **Recipient Address**| katharine@letsdefend.io |
| **Attachment Hash (MD5)**| 7299c49dd85069e47d6514ab5e10c264 |
| **Attachment Type**| ELF (Linux Executable) |
| **Attack Type**| Phishing with Malware |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/18))* |

## Investigation and analysis

### 1. Phishing Email analysis

The attack began with a phishing email using a strong social engineering tactic: a subject line designed to create fear and urgency ("URGENT! Your bank account may have fallen into the hands of fraudsters!"). The `Device Action: Allowed` confirms this email successfully bypassed initial security filters and was delivered to the user's inbox, giving them the opportunity to interact with the malicious payload.

<img width="1486" height="626" alt="image" src="https://github.com/user-attachments/assets/80dbcee3-3c82-4809-b018-d7cc2415ec2f" />

### 2. Malware analysis (ELF Executable)

The most unusual aspect of this attack is the malware itself.
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **42 out of 70 security vendors**, confirming its malicious nature.
*   **File Type Identification:** Critically, VirusTotal identifies the file type as **ELF 64-bit LSB pie executable**. ELF is the standard executable format for Linux and other Unix-like operating systems. It is not natively executable on Windows. This suggests one of two scenarios:
    1.  The attacker made a mistake and sent a Linux tool to a Windows user.
    2.  The victim machine has a subsystem like the Windows Subsystem for Linux (WSL) installed, making it a targeted and more sophisticated attack.

    <img width="1650" height="870" alt="image" src="https://github.com/user-attachments/assets/d20653c0-01d9-42d9-9bb9-9555426ca472" />

### 3. Confirmation of Successful Execution

Despite the unusual file type, endpoint security logs provide the "smoking gun" that the user successfully ran the file.
*   **Endpoint Logs:** The EDR logs show the process `creditcard` running on the host `KatharinePRD`. The `Device Action: Allowed` for this process execution confirms that the endpoint security controls did not block it. This proves that the user received the email, opened the attachment, and was able to execute it (likely via WSL).

    <img width="1500" height="654" alt="image" src="https://github.com/user-attachments/assets/24342b33-5b67-452b-b66c-257d098d8fb5" />

The absence of immediate follow-on C2 traffic or command-line activity is concerning, not reassuring. It could mean the malware is dormant, waiting for instructions, or that its communication is being stealthily proxied.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway, VirusTotal
*   **Skills Demonstrated:** Phishing Analysis, Malware Triage (ELF executables), Log Correlation, Recognition of Anomalous Activity.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment is a confirmed Linux executable.
*   **Was the Attack Successful?** **Yes.** The email was delivered, and the user executed the payload.
*   **Do You Need Tier 2 Escalation?** **Yes.** A successful and highly unusual malware execution on an endpoint is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a successful and highly unusual phishing attack. An attacker successfully delivered a Linux executable to a user, who then ran it. The host `KatharinePRD` is compromised. The use of a Linux binary makes this a high-priority incident that requires immediate investigation to understand the attacker's capabilities and intent.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **KatharinePRD** from the network to prevent any potential C2 communication or lateral movement.
2.  **CREDENTIALS - Disable and Reset:** Immediately disable the `Katharine` user account in Active Directory and reset their password.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full forensic investigation.
4.  **INVESTIGATION:** The primary goal for the IR team is to understand how a Linux executable was run and what its purpose is. The investigation must:
    *   Confirm if the host has the Windows Subsystem for Linux (WSL) installed.
    *   Perform a full forensic analysis of the `creditcard` binary to determine its function (e.g., is it a backdoor, a data stealer, a crypto miner?).
    *   Analyze all network traffic from the host since the time of infection for any signs of covert C2 communication.
5.  **RECOVERY:** The compromised host must be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:** Block the sender's IP (`172.82.128.241`), domain (`cashbank.com`), and the attachment hash (`7299c49dd85069e47d6514ab5e10c264`) at the perimeter.






























