# 	SOC101 - Phishing Mail Detected (Event ID:8)


## Executive Summary

On August 29, 2020, the Security Operations Center (SOC) received an alert for a phishing email delivered to the user `mark@letsdefend.io`. The investigation confirmed a successful delivery of a malicious email that impersonated a **UPS** notification. The email contained a document with a highly obfuscated and malicious VBA macro, confirmed by a high detection rate on VirusTotal. Analysis of the macro's code reveals its intent to disable security warnings, download a secondary executable payload, and execute it. The email was **Allowed** by the security gateway and delivered to the user's inbox. However, a review of endpoint logs showed **no evidence** that the user opened the malicious attachment. This is a **True Positive** for a delivered threat, but the attack was ultimately **unsuccessful** due to the user's non-interaction.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1489" height="541" alt="image" src="https://github.com/user-attachments/assets/6aec6fbb-ea2d-433b-8692-479f43440598" />

| | |
| :--- | :--- |
| **Date of Incident**| August 29, 2020 |
| **Attacker SMTP IP**| 63.35.133.186 |
| **Sender Address**| info@nexoiberica.com (Likely a compromised account) |
| **Recipient Address**| mark@letsdefend.io |
| **Attachment Hash (MD5)**| 21b3a9b03027779dc3070481a468b211 |
| **Attack Type**| Phishing with Malicious VBA Macro |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/8))* |



## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a phishing email using a common "UPS Express" subject line and theme to create a sense of urgency related to a package delivery. The `Device Action: Allowed` confirms this email successfully bypassed initial security filters and was delivered to the user's inbox, creating a significant risk.

<img width="1508" height="575" alt="image" src="https://github.com/user-attachments/assets/d7fe1d1c-07cd-4125-8345-e6597de6f909" />

### 2. Malware Analysis (Obfuscated VBA Macro)

A deep analysis of the attached document confirmed its highly malicious nature.
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **49 out of 70 security vendors**, providing definitive confirmation of the threat.
    <img width="1784" height="859" alt="image" src="https://github.com/user-attachments/assets/e63773e3-baec-4309-9289-abee757befe7" />
*   **Behavioral Analysis (VirusTotal Code Insights):** The analysis of the embedded VBA macro code revealed numerous malicious indicators:
    *   **Heavy Obfuscation:** The code uses randomized variable and function names and Base64 encoding to hide its true commands.
    *   **Security Disablement:** It attempts to disable macro security warnings and screen updating to hide its execution from the user.
    *   **Payload Delivery:** The code contains functions designed to download an executable (`.exe`) file from a remote server, write it to the local disk, and then execute it.
    *   **Auto-Execution:** The use of an `Auto_Open()` or `Document_Open()` subroutine means the malicious code is designed to run automatically as soon as the user opens the document and enables macros.

### 3. Confirmation of Non-Interaction

Despite the successful delivery of the email, the most critical part of the investigation was to determine if the user interacted with the payload.
*   **Endpoint Log Analysis:** A thorough review of the endpoint security logs for the host associated with `mark@letsdefend.io` was conducted for the time of and following the email delivery.
*   **Result:** The investigation found **no evidence** that the malicious document was opened or that any of the behaviors described in the macro analysis (e.g., spawning of new processes, suspicious network connections) occurred. This indicates that the user correctly identified the email as suspicious and did not open the attachment.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway, VirusTotal
*   **Skills Demonstrated:** Phishing Analysis, Malware Triage (VBA Macros), Log Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment contains a sophisticated, obfuscated macro downloader.
*   **Was the Attack Successful?** **No.** Although the email was delivered, the user did not open the malicious attachment, so no compromise occurred.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was delivered but not activated, and can be remediated by the Tier 1 analyst.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email was delivered).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive**. A malicious email containing a dangerous macro-based downloader was successfully delivered to a user's inbox. However, the attack ultimately **failed** because the user did not fall for the phish and did not open the attachment. This is a "near-miss" scenario.

**Recommendations:**

1.  **REMEDIATE - Purge Email:** The highest priority is to use the email security gateway to immediately and permanently delete the malicious email from the user's (`mark@letsdefend.io`) inbox to prevent any future accidental interaction.
2.  **Acknowledge User Action:** Recognize the user's good security practice in not opening the unsolicited attachment. This is a positive security outcome.
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`63.35.133.186`), domain (`nexoiberica.com`), and the attachment hash (`21b3a9b03027779dc3070481a468b211`) are on all relevant blocklists.
4.  **HUNT:** Proactively search email logs to determine if this same attachment or sender has targeted any other users in the organization and purge those emails as well.
