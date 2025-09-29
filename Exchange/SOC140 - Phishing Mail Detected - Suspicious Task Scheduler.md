# 	SOC140 - Phishing Mail Detected - Suspicious Task Scheduler
## Executive Summary

On March 21, 2021, the Security Operations Center (SOC) received an alert for a phishing email sent to the user `mark@letsdefend.io`. The investigation confirmed the email was a malicious lure, using the COVID-19 vaccine as a theme, and contained a malicious attachment. Static and dynamic analysis of the attachment identified it as a potent information stealer designed to exfiltrate browser data and other sensitive information. The email security gateway successfully identified the threat, and the **Device Action** was **Blocked**. The alert is a **True Positive** for a real threat, but the attack was **unsuccessful** as the email was prevented from reaching the user's inbox.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email with a suspicious attachment:

<img width="1514" height="587" alt="image" src="https://github.com/user-attachments/assets/c108846f-a96c-4143-bbef-f8e822a497b4" />

| | |
| :--- | :--- |
| **Date of Incident**| March 21, 2021 |
| **Attacker SMTP IP**| 189.162.189.159 |
| **Sender Address**| aaronluo@cmail.carleton.ca (Likely Spoofed) |
| **Recipient Address**| mark@letsdefend.io |
| **Attachment Hash**| `72c812cf21909a48eb9cceb9e04b865d` |
| **Attack Type**| Phishing with Malware (Information Stealer) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/82))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The investigation began by retrieving the email from the security gateway. The email used a timely and compelling theme (COVID-19 Vaccine) to entice the user into opening the attachment. The sender address appears to be from a legitimate Canadian university (`carleton.ca`), suggesting the attacker either compromised that account or was spoofing the address.

<img width="1540" height="656" alt="image" src="https://github.com/user-attachments/assets/b4e1e91b-d696-49ec-93d1-e22678464e63" />

### 2. Malware Analysis

A detailed analysis of the attachment confirmed its malicious nature and capabilities.
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **26 security vendors**, providing a strong initial indicator of compromise.
    <img width="1846" height="826" alt="image" src="https://github.com/user-attachments/assets/f8ae50e6-69f2-4b96-b683-db3800e0867f" />
*   **Dynamic Analysis (Hybrid Analysis):** A sandbox run provided deep behavioral insights, assigning the malware a threat score of **100/100**. The key malicious behaviors identified were:
    *   **Spyware/Information Retrieval (T1005):** The malware was observed actively attempting to access sensitive files related to the Microsoft Edge browser, including `Local State`, `Secure Preferences`, and `Preferences`. This is a classic technique used by information stealers to harvest saved passwords, cookies, and browsing history.
    *   **Data Exfiltration (T1041):** It initiated a POST request to `login.live.com`, likely attempting to exfiltrate the stolen data under the guise of legitimate Microsoft traffic.
    *   **Evasion/Destruction:** The malware also interacted with the primary disk partition and dropped suspicious text files, indicating potential for further disruptive or evasive actions.

    <img width="1900" height="734" alt="image" src="https://github.com/user-attachments/assets/8b3df25e-e3c2-4af4-87eb-1700b0288fed" />

### 3. Confirmation of Successful Prevention

The most critical finding of this investigation is that the attack was prevented. The **`Device Action: Blocked`** status in the SIEM alert is the definitive piece of evidence. This confirms that the email security gateway correctly identified the email or its attachment as malicious and stopped it from ever being delivered to the user's inbox. Because the user never had the opportunity to open the attachment, no compromise occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, VirusTotal, Hybrid Analysis
*   **Skills Demonstrated:** Phishing Analysis, Dynamic Malware Analysis, Threat Intelligence Correlation, Triage.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment is a confirmed information stealer.
*   **Was the Attack Successful?** **No.** The email was blocked by the security gateway.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email).

## Conclusion and Recommendations

The alert for SOC140 was a **true positive** for a phishing attempt delivering a potent information-stealing malware. The investigation confirms the malicious intent of the email and its payload but, most importantly, confirms that the attack was successfully **blocked** by the email security gateway. No systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the email security gateway.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`189.162.189.159`), domain (`cmail.carleton.ca` - if confirmed malicious and not just spoofed), and the attachment hash are on all relevant blocklists.
4.  **Threat Intelligence Sharing:** If the sender's account at `carleton.ca` is suspected to be compromised, it is good practice to share this intelligence with the university's security team.
