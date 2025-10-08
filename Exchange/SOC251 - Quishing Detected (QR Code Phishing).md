# 	SOC251 - Quishing Detected (QR Code Phishing)

## Executive Summary

On January 1, 2024, the Security Operations Center (SOC) received an alert for a "Quishing" (QR Code Phishing) attack targeting the user `Claire@letsdefend.io`. The investigation confirmed that a malicious email, impersonating a mandatory MFA security update, was **Allowed** by the email security gateway and successfully delivered. The email used a QR code instead of a traditional hyperlink to deliver its malicious payload, a technique designed to bypass URL scanning filters. Analysis of the QR code revealed a link to a malicious IPFS-hosted page, confirmed by multiple threat intelligence platforms. Although there is no direct evidence of the user scanning the code, the successful delivery of a sophisticated phishing email to an end user constitutes a significant security risk. This is a **True Positive** for a delivered threat that requires immediate remediation.

## Incident Details

The initial alert was triggered by a rule detecting the characteristics of a QR code phishing email:

<img width="1456" height="508" alt="image" src="https://github.com/user-attachments/assets/d46c6dee-7f42-4886-a0c8-8932b2656114" />

| | |
| :--- | :--- |
| **Date of Incident**| January 1, 2024 |
| **Attacker SMTP IP**| 158.69.201.47 |
| **Sender Address**| security@microsecmfa.com |
| **Recipient Address**| Claire@letsdefend.io |
| **Malicious URL (Decoded)**| `https://ipfs[.]io/ipfs/Qmbr8wmr41C35c3K2GfiP2F8YGzLhYpKpb4K66KU6mLmL4#` |
| **Attack Type**| Quishing (QR Code Phishing) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/214))* |

## Investigation and Analysis

### 1. Alert Context: Quishing (QR Code Phishing)

"Quishing" is a phishing technique where the attacker embeds the malicious link within a QR code (an image) instead of using text-based hyperlinks. This method is specifically designed to evade email security gateways, as many traditional scanners are built to parse and analyze text-based URLs but are not as effective at scanning images to decode and analyze QR codes. When a user scans the code with their mobile device, their phone's browser opens the malicious link, often bypassing corporate network protections.

### 2. Phishing Email Analysis

The attack used a highly effective social engineering lure:
*   **The Lure:** The subject line "New Year's Mandatory Security Update: Implementing Multi-Factor Authentication (MFA)" creates a strong sense of urgency and legitimacy, pressuring the user to act quickly.
*   **Impersonation:** The sender's domain, `microsecmfa.com`, is designed to look official and related to security.
*   **The Payload:** The QR code is the sole payload, instructing the user to scan it to complete the "mandatory" action.

<img width="1388" height="642" alt="image" src="https://github.com/user-attachments/assets/549de82a-4ba7-4ca1-91a4-9aa913bc06a9" />

### 3. Threat Intelligence Analysis

The investigation confirmed that all components of the attack were malicious.
*   **Decoded URL:** Using an online scanner, the QR code was decoded to the URL `https://ipfs[.]io/...`. IPFS is a legitimate decentralized file-hosting service, but it is frequently abused by attackers to host phishing pages. VirusTotal confirmed the URL's malicious nature with **8 vendor detections**.
    <img width="1787" height="714" alt="image" src="https://github.com/user-attachments/assets/acbf04be-c8b5-4038-b941-6528bb4f3fce" />
*   **URL's Host IP:** The IP address for the IPFS gateway, `209.94.90.1`, has a poor reputation, with nearly **500 reports on AbuseIPDB** and **6 detections on VirusTotal**.
    <img width="1626" height="749" alt="image" src="https://github.com/user-attachments/assets/766b2dc8-f20f-4550-9465-c73670078c0e" />
    <img width="1803" height="682" alt="image" src="https://github.com/user-attachments/assets/34ca857b-40af-49b3-ab4a-36d880a6e526" />
*   **Sender's SMTP IP:** The originating IP of the email, `158.69.201.47`, was also confirmed as malicious by **7 vendors on VirusTotal**.
    <img width="1756" height="814" alt="image" src="https://github.com/user-attachments/assets/f44206d9-56e6-4841-903c-7d609d86b0dd" />

### 4. Final Assessment

The **`Device Action: Allowed`** status confirms this malicious email successfully bypassed security filters and was delivered to the user's inbox. This represents a significant failure in the email security posture and created a high-risk situation. Although endpoint logs do not show that the user browsed to the malicious site from their corporate device, it's impossible to know if they scanned the code with a personal mobile phone. Therefore, the user's credentials must be considered potentially compromised as a precaution.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, QR Code Scanner, VirusTotal, AbuseIPDB
*   **Skills Demonstrated:** Quishing Analysis, Threat Intelligence Correlation, Social Engineering Triage.

## Playbook Solution: Incident Classification

*   **Analyze URL/Email:** **Malicious.** The email is a confirmed Quishing attack.
*   **Was the Attack Successful?** **Partially.** The email was successfully delivered, creating a high-risk event, but there is no confirmation of user interaction leading to compromise.
*   **Do You Need Tier 2 Escalation?** **No, but requires immediate remediation.** While a full-blown IR investigation may not be needed without evidence of a click, the user's account must be secured.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC251 was a **true positive** for a Quishing attack. A malicious email designed to bypass URL filters was successfully delivered to a user. Although there is no evidence of a compromise, the risk is high enough to warrant immediate preventative action.

**Recommendations:**

1.  **REMEDIATE - Purge Email:** The highest priority is to use the email security gateway to immediately and permanently delete the malicious email from the user's (`Claire@letsdefend.io`) inbox.
2.  **CONTAINMENT - Proactive Credential Reset:** As a precautionary measure, the user's password should be immediately reset, and all active sessions should be invalidated. The user should be contacted and asked if they scanned the QR code.
3.  **HUNT:** Proactively search email logs to determine if this same email or sender has targeted any other users in the organization and purge those emails as well.
4.  **BLOCK INDICATORS:** Block the following indicators at the perimeter:
    *   **IPs:** `158.69.201.47` and `209.94.90.1`.
    *   **Domains:** `microsecmfa.com` and `ipfs.io` (if business use is not required).
5.  **USER AWARENESS:** This incident should be used to create a security awareness bulletin specifically warning employees about the dangers of Quishing and advising them not to scan QR codes from untrusted emails.
6.  **TECHNOLOGY REVIEW:** Escalate this incident to the email security team to review why their filters failed to detect the QR code and improve their image scanning capabilities.






