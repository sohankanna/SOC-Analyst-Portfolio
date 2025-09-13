# 	SOC168 - Whoami Command Detected in Request Body

## Executive Summary

On February 28, 2022, the Security Operations Center (SOC) received a critical alert for a command injection attack against **WebServer1004** (172.16.17.16). The attack originated from the IP address **61.177.172.87**, a known malicious actor. The investigation confirmed that the attacker successfully executed a series of commands by injecting them into the POST body of a request. The server responded with an **HTTP 200 OK** status and a non-zero response size, indicating that the command output, including the contents of the sensitive `/etc/passwd` and `/etc/shadow` files, was exfiltrated to the attacker. This is a **True Positive** for a successful system compromise that requires immediate escalation and full incident response activation.

Case 

## Incident Details

The initial alert was triggered by the detection of the `whoami` command in a request body:

<img width="1471" height="601" alt="image" src="https://github.com/user-attachments/assets/2c2af0be-e464-4ba7-9162-732dcc95a982" />

| | |
| :--- | :--- |
| **Date of Incident** | February 28, 2022 |
| **Source IP Address** | 61.177.172.87 |
| **Destination Host** | WebServer1004 (172.16.17.16) |
| **Attack Type** | Command Injection |
| **Malicious Payload** | POST Parameter: `?c=[command]` (e.g., `?c=whoami`) |
| **Case Link** | [View Full Case on LetsDefend.io](https://app.letsdefend.io/case-management/casedetail/sohankanna/118) |
## Investigation and Analysis

### 1. Log Analysis and Attack Progression

A review of the logs for the source IP `61.177.172.87` revealed a sequence of POST requests to `https://172.16.17.16/video/`, each containing an injected command.

<img width="1556" height="618" alt="image" src="https://github.com/user-attachments/assets/519ff8fa-a418-4306-b7d3-9690ffaf871c" />

The attack followed a logical progression from reconnaissance to data exfiltration:

1.  **Initial Reconnaissance (`whoami`):** The attacker first checked the current user context.
    <img width="641" height="360" alt="image" src="https://github.com/user-attachments/assets/b67ce543-d1f6-4965-bbd9-1595f4fe3ac7" />

2.  **.System Enumeration (`ls`):** The attacker then gathered information about the files in the system 
    <img width="646" height="361" alt="image" src="https://github.com/user-attachments/assets/df05122e-1318-4c08-90cb-cfd394065cba" />

3.  **System Enumeration (`uname`):** The attacker then gathered information about the operating system and kernel.
    <img width="651" height="359" alt="image" src="https://github.com/user-attachments/assets/225ceed0-627a-4a3e-a0ea-f77b547e914d" />

4.  **Password Hash Exfiltration (`cat /etc/shadow`):** In a critical escalation, the attacker successfully exfiltrated the file containing hashed user passwords.<br>
    <img width="646" height="365" alt="image" src="https://github.com/user-attachments/assets/13f5b191-0ce5-4bf9-99cf-1919687681e6" />
    <img width="644" height="353" alt="image" src="https://github.com/user-attachments/assets/a426f0c8-8bb2-4910-8699-a9f5eeafa7ca" />

### 2. Confirmation of Success

The attack was unequivocally successful. The evidence is clear in the server's responses:
*   **HTTP Response Status: 200 OK:** This code confirms the server successfully processed the request, including the malicious command.
*   **HTTP Response Size (e.g., 1501):** A non-zero response size indicates that data was sent back. In this context, it was the output of the executed commands, meaning the contents of `/etc/passwd` and `/etc/shadow` were sent directly to the attacker.
*   **Device Action: Allowed:** The security controls in place did not block the malicious request.

### 3. Threat Intelligence

An analysis of the source IP `61.177.172.87` on AbuseIPDB shows it is a well-known malicious actor with nearly 80,000 reports, confirming the hostile intent.

<img width="1517" height="808" alt="image" src="https://github.com/user-attachments/assets/fb991de8-6933-4667-b9a7-855d7f6c2647" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Log Management, AbuseIPDB
*   **Skills Demonstrated:** Web Attack Analysis (Command Injection), Log Correlation, HTTP Protocol Analysis, Threat Intelligence.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It contained active command injection payloads.
*   **What Is The Attack Type?** **Command Injection.**
*   **What Is the Direction of Traffic?** **Internet → Company Network.**
*   **Was the Attack Successful?** **Yes.** The server processed the commands and returned the output.
*   **Do You Need Tier 2 Escalation?** **Yes.** This is a confirmed system compromise and requires immediate escalation.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC168 was a **true positive** for a critical and successful command injection attack. The attacker exploited a vulnerability on **WebServer1004** to execute commands, enumerate the system, and exfiltrate highly sensitive files containing user account and password hash information. The server must be considered fully compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect **WebServer1004** from the network to prevent any further attacker activity, such as lateral movement or establishing persistence.
2.  **ESCALATE - Activate Full Incident Response Protocol:** This is a critical incident that must be escalated to the Tier 2/Incident Response (IR) team immediately for forensic investigation.
3.  **CREDENTIAL RESET - Mandate Password Changes:** Since the `/etc/shadow` file was exfiltrated, all user account passwords on the compromised server—and potentially any reused passwords elsewhere in the organization—must be considered compromised and must be reset immediately.
4.  **INVESTIGATION:** The IR team must conduct a full forensic analysis to determine the initial vulnerability, check for persistence mechanisms, and search for evidence of lateral movement.
5.  **ERADICATION & RECOVERY:** The compromised server must be rebuilt from a known-good, trusted image. Do not simply patch the running system.
6.  **VULNERABILITY REMEDIATION:** The web application vulnerability that allowed the command injection must be identified and patched before the application is brought back online.
7.  **BLOCK INDICATORS:** Block the attacker IP `61.177.172.87` at the network perimeter.

