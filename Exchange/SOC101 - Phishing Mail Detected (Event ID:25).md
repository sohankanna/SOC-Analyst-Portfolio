# SOC101 - Phishing Mail Detected (Event ID:25)

## Executive Summary

On October 29, 2020, the Security Operations Center (SOC) received an alert for a phishing email sent to the user `mark@letsdefend.io`. The investigation identified the email as a malicious lure impersonating a UPS package notification. The email contained a PDF attachment that was confirmed to be a sophisticated weaponized document. Threat intelligence analysis revealed the PDF contained embedded `/Launch` actions, a mechanism designed to execute external programs and achieve Remote Code Execution (RCE). The email security gateway successfully identified this threat, and the **Device Action** was **Blocked**. The alert is a **True Positive** for a real threat, but the attack was **unsuccessful** as the email never reached the user.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1474" height="467" alt="image" src="https://github.com/user-attachments/assets/b6591648-9736-4eda-a93b-370519677c0c" />

| | |
| :--- | :--- |
| **Date of Incident**| October 29, 2020 |
| **Attacker SMTP IP**| 157.230.109.166 |
| **Sender Address**| aaronluo@cmail.carleton.ca (Likely Spoofed) |
| **Recipient Address**| mark@letsdefend.io |
| **Attachment Hash (MD5)**| 72c812cf21909a48eb9cceb9e04b865d |
| **Attack Type**| Phishing with Malicious PDF |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/25))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a phishing email using a common "UPS Your Packages Status Has Changed" subject line to create a sense of urgency. The email body instructs the user to open the attachment to view a secure message, a classic social engineering tactic. The sender address appears to be from a legitimate Canadian university, suggesting the account was either compromised or the address was spoofed.

<img width="1496" height="592" alt="image" src="https://github.com/user-attachments/assets/76f6bcfe-bf9b-4088-ae92-dd630ef812e0" />

### 2. Malware Analysis (Weaponized PDF with /Launch Action)

A deep analysis of the PDF attachment confirmed its malicious nature.
*   **Threat Intelligence (VirusTotal):** The file hash was flagged as malicious by **23 security vendors**, providing a strong confirmation of the threat.
*   **Behavioral Analysis (VirusTotal Code Insights):** The analysis revealed the PDF's primary malicious component: the presence of multiple `/Launch` actions within its structure.
    *   **What is a `/Launch` Action?** This is a feature within the PDF specification that allows a document to execute an external application or run a command on the host operating system. When a user opens the PDF, their reader application may prompt them to allow this action. If the user clicks "Allow," the embedded command is executed, leading to a full system compromise.
    *   **The Lure:** The document's visual layer was a deliberately blurry "Purchase Order" image. This is a social engineering trick designed to frustrate the user and make them more likely to click "Allow" on any security prompts in an attempt to view the document clearly.
    *   **Conclusion:** The presence of the `/Launch` action moves the file from merely suspicious to definitively malicious, as its sole purpose in this context is to achieve RCE.

### 3. Confirmation of Successful Prevention

The most critical finding of this investigation is that the attack was stopped before it could cause harm. The **`Device Action: Blocked`** status in the SIEM alert is the key piece of evidence. This confirms that the corporate email security gateway correctly identified the email or its attachment as malicious and prevented it from being delivered to the user `mark@letsdefend.io`. Because the user never received the email, they could not have opened the PDF, and no compromise occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, VirusTotal
*   **Skills Demonstrated:** Phishing Analysis, Malware Triage (Malicious PDF), Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The PDF contains `/Launch` actions for RCE.
*   **Was the Attack Successful?** **No.** The email was blocked by the security gateway.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a phishing attempt delivering a weaponized PDF. The investigation confirms the malicious nature of the email and its attachment but, most importantly, confirms that the attack was successfully **blocked** by the email security gateway. No systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the email security gateway.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`157.230.109.166`), the sender domain (`cmail.carleton.ca` if confirmed malicious), and the attachment hash (`72c812cf21909a48eb9cceb9e04b865d`) are on all relevant blocklists.
