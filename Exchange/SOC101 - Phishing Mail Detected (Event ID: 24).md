# SOC101 - Phishing Mail Detected (Event ID: 24)

## Executive Summary

On October 25, 2020, the Security Operations Center (SOC) received an alert for a phishing email sent to the user `james@letsdefend.io`. The investigation confirmed the email was a malicious lure using a "Covid-19 News!" theme and contained a document with a highly obfuscated VBA macro. Threat intelligence analysis confirmed the attachment was malicious with a very high detection rate. The email security gateway successfully identified the threat, and the **Device Action** was **Blocked**. The alert is a **True Positive** for a real threat, but the attack was **unsuccessful** as the malicious email was prevented from reaching the user's inbox.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1452" height="523" alt="image" src="https://github.com/user-attachments/assets/1fb77d7a-7823-4d26-bb27-1c60042d87d4" />

| | |
| :--- | :--- |
| **Date of Incident**| October 25, 2020 |
| **Attacker SMTP IP**| 173.194.68.27 |
| **Sender Address**| darcy.downey@gmail.com |
| **Recipient Address**| james@letsdefend.io |
| **Attachment Hash (MD5)**| 1ceda3ccc4e450088204e23409904fa8 |
| **Attack Type**| Phishing with Malicious VBA Macro |
| **Case Link**| *([Case link ](https://app.letsdefend.io/case-management/casedetail/sohankanna/24))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a phishing email using a timely and high-interest theme (COVID-19) to create a sense of urgency and entice the user into opening the malicious attachment. This is a common social engineering tactic designed to bypass a user's normal caution.

### 2. Malware Analysis (Obfuscated VBA Macro)

A deep analysis of the attachment confirmed its malicious nature.
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **49 out of 72 security vendors**, providing a definitive confirmation of the threat.
    <img width="1811" height="874" alt="image" src="https://github.com/user-attachments/assets/50062a0f-b461-4242-9e44-708d9e43168c" />
*   **Behavioral Analysis Summary:** The document contains a highly obfuscated VBA (Visual Basic for Applications) macro designed to execute when the file is opened. The code uses multiple layers of obfuscation to hide its true purpose, including complex string manipulation, non-sensical variable names, and splitting/joining data to reconstruct malicious commands at runtime. The ultimate goal of such a macro is typically to download and execute a secondary payload (like a trojan or ransomware) from a C2 server, or to create a shell object to run commands directly on the host. The use of `CreateObject` is a classic indicator of malicious intent within a VBA macro.

### 3. Confirmation of Successful Prevention

The most critical finding of this investigation is that the attack was stopped before it could cause harm. The **`Device Action: Blocked`** status in the SIEM alert is the key piece of evidence. This confirms that the corporate email security gateway correctly identified the email or its attachment as malicious and prevented it from being delivered to the user `james@letsdefend.io`. Because the user never received the email, they could not have opened the attachment, and no compromise occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, VirusTotal
*   **Skills Demonstrated:** Phishing Analysis, Malware Triage, Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment contains an obfuscated VBA macro.
*   **Was the Attack Successful?** **No.** The email was blocked by the security gateway.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a phishing attempt delivering a malicious document. The investigation confirms the malicious intent of the email and its attachment but, most importantly, confirms that the attack was successfully **blocked** by the email security gateway. No systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the email security gateway.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`173.194.68.27`), sender address (`darcy.downey@gmail.com`), and the attachment hash (`1ceda3ccc4e450088204e23409904fa8`) are on all relevant blocklists.

