# SOC101 - Phishing Mail Detected (Event ID: 	41)

## Executive Summary

On January 2, 2021, the Security Operations Center (SOC) received an alert for a phishing email sent to the user `mark@letsdefend.io`. The investigation identified the email as a malicious lure themed as a "Credit Card Statement," which contained a malicious executable attachment. Threat intelligence analysis confirmed the attachment was a WinRAR self-extracting (SFX) archive, a common malware delivery technique, with a very high detection rate. The email security gateway successfully identified this threat, and the **Device Action** was **Blocked**. The alert is a **True Positive** for a real threat, but the attack was **unsuccessful** as the email never reached the user.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1475" height="542" alt="image" src="https://github.com/user-attachments/assets/fe18a201-5181-4345-afdc-2390a66bd6b7" />

| | |
| :--- | :--- |
| **Date of Incident**| January 2, 2021 |
| **Attacker SMTP IP**| 104.140.188.46 |
| **Sender Address**| david@cashbank.com |
| **Recipient Address**| mark@letsdefend.io |
| **Attachment Hash (MD5)**| 9ed9ad87a1564fbb5e1b652b3e7148c8 |
| **Attack Type**| Phishing with Malicious SFX Archive |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/41))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a phishing email using a common financial lure, "Credit Card Statement," to create a sense of urgency and importance, compelling the user to open the attachment. The sender's domain, `cashbank.com`, is generic and likely chosen to appear legitimate at a quick glance.

<img width="1466" height="591" alt="image" src="https://github.com/user-attachments/assets/23956722-2f6d-4845-a23f-ea20206cd969" />

### 2. Malware Analysis (Self-Extracting Archive)

A deep analysis of the attachment confirmed its highly malicious nature.
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **49 out of 71 security vendors**, providing a definitive confirmation of the threat.
    <img width="1675" height="867" alt="image" src="https://github.com/user-attachments/assets/c0e37070-3602-4a72-afd2-3c291ac99171" />
*   **File Type Analysis:** The file was identified as a **WinRAR Self-Extracting (SFX) archive**. This is a technique where an attacker packages their malicious payload (e.g., a trojan, keylogger) inside a compressed archive that is wrapped in an executable. When the user double-clicks the file, it automatically extracts and runs the hidden malware, often without any further user interaction. This is a popular method for bypassing simple email filters that might block more common script or document types.

### 3. Confirmation of Successful Prevention

The most critical finding of this investigation is that the attack was stopped before it could cause harm. The **`Device Action: Blocked`** status in the SIEM alert is the key piece of evidence. This confirms that the corporate email security gateway correctly identified the email or its attachment as malicious and prevented it from being delivered to the user `mark@letsdefend.io`. Because the user never received the email, they could not have opened the malicious archive, and no compromise occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, VirusTotal
*   **Skills Demonstrated:** Phishing Analysis, Malware Triage (SFX Archives), Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment is a confirmed SFX archive used to deliver malware.
*   **Was the Attack Successful?** **No.** The email was blocked by the security gateway.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a phishing attempt delivering a malicious self-extracting archive. The investigation confirms the malicious intent of the email and its attachment but, most importantly, confirms that the attack was successfully **blocked** by the email security gateway. No systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the email security gateway.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`104.140.188.46`), sender domain (`cashbank.com`), and the attachment hash (`9ed9ad87a1564fbb5e1b652b3e7148c8`) are on all relevant blocklists.
