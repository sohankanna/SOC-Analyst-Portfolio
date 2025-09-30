# SOC101 - Phishing Mail Detected (Event ID: 29)

## Executive Summary

On October 29, 2020, the Security Operations Center (SOC) received an alert for a phishing email sent to the user `sofia@letsdefend.io`. The investigation confirmed the email was a malicious lure themed as an "Invoice" and contained a highly malicious attachment. Threat intelligence from VirusTotal and Hybrid Analysis confirmed the attachment was a potent malware with a near-unanimous detection rate. The email security gateway successfully identified the threat, and the **Device Action** was **Blocked**. The alert is a **True Positive** for a real threat, but the attack was **unsuccessful** as the malicious email was prevented from reaching the user's inbox.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1468" height="552" alt="image" src="https://github.com/user-attachments/assets/b09f8b94-95db-48c5-9b89-b61d395de285" />

| | |
| :--- | :--- |
| **Date of Incident**| October 29, 2020 |
| **Attacker SMTP IP**| 191.233.193.73 |
| **Sender Address**| icianb@hotmail.com |
| **Recipient Address**| sofia@letsdefend.io |
| **Attachment Hash (MD5)**| 4abd5dd8377e5810116f3665bd8d92f0 |
| **Attack Type**| Phishing with Malware Attachment |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/29))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a phishing email using a common "Invoice" subject line to entice a user in a corporate environment to open the attachment. The sender address, a generic `hotmail.com` account, is a common indicator of a non-legitimate business email.

<img width="1507" height="560" alt="image" src="https://github.com/user-attachments/assets/54af40c7-9348-4463-a94d-95a4cb1eb0ba" />

### 2. Malware Analysis

A deep analysis of the attachment confirmed its highly malicious nature.
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **49 out of 72 security vendors**, providing a very strong initial indicator of compromise.
    <img width="1676" height="882" alt="image" src="https://github.com/user-attachments/assets/833a7d1a-28e2-485d-9bae-21963fee24d3" />
*   **Dynamic Analysis (Hybrid Analysis):** A sandbox run provided further definitive proof, assigning the malware a threat score of **100/100**. This confirms the file is unequivocally malicious.
    <img width="1789" height="809" alt="image" src="https://github.com/user-attachments/assets/54363cdf-5175-4e54-872e-1fbcfed7d014" />

### 3. Confirmation of Successful Prevention

The most critical finding of this investigation is that the attack was prevented. The **`Device Action: Blocked`** status in the SIEM alert is the definitive piece of evidence. This confirms that the corporate email security gateway correctly identified the email or its attachment as malicious and stopped it from ever being delivered to the user's inbox. Because the user never had the opportunity to open the attachment, no compromise occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, VirusTotal, Hybrid Analysis
*   **Skills Demonstrated:** Phishing Analysis, Malware Triage, Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment is confirmed malware.
*   **Was the Attack Successful?** **No.** The email was blocked by the security gateway.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a phishing attempt delivering a malicious payload. The investigation confirms the malicious intent of the email and its attachment but, most importantly, confirms that the attack was successfully **blocked** by the email security gateway. No systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the email security gateway.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`191.233.193.73`), sender address (`icianb@hotmail.com`), and the attachment hash (`4abd5dd8377e5810116f3665bd8d92f0`) are on all relevant blocklists.
