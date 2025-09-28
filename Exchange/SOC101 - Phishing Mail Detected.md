# SOC101 - Phishing Mail Detected

## Executive Summary

On February 14, 2021, the Security Operations Center (SOC) received a low-severity alert for a phishing email sent to the user `mark@letsdefend.io`. The investigation identified the email as a common **sextortion** or **blackmail scam**, a type of phishing that uses psychological manipulation rather than technical exploits. The email, originating from a known malicious IP address, contained no malicious attachments or links but threatened to release fabricated compromising information. The email security gateway successfully identified the threat and the **Device Action** was **Blocked**. The alert is a **True Positive** for a real threat, but the attack was **unsuccessful** as the email never reached the user's inbox.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1506" height="511" alt="image" src="https://github.com/user-attachments/assets/4d4c32f0-4483-4943-986a-82161cae293e" />

| | |
| :--- | :--- |
| **Date of Incident**| February 14, 2021 |
| **Attacker SMTP IP**| 27.128.173.81 |
| **Sender Address**| hahaha@ihackedyourcomputer.com |
| **Recipient Address**| mark@letsdefend.io |
| **Attack Type**| Sextortion / Blackmail Scam |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/59))* |

## Investigation and Analysis

### 1. Alert Context: Sextortion Scams

The email's subject, "I hacked your computer," and its content are characteristic of a sextortion scam. This is a type of phishing that relies on intimidation and fear. The attacker claims to have embarrassing or compromising material (e.g., webcam footage) and demands payment, usually in cryptocurrency, to prevent its public release. In almost all cases, these claims are false, and the emails are sent in massive, non-targeted campaigns. The goal is to frighten a small percentage of recipients into paying.

### 2. Email Analysis

An analysis of the email content confirms its nature as a blackmail attempt.

<img width="1552" height="539" alt="image" src="https://github.com/user-attachments/assets/afb112c9-9e4c-4049-a387-90a9f973e8e7" />

The email contains no malicious attachments or URLs. Its only "payload" is the threatening text itself. The sender's address, `hahaha@ihackedyourcomputer.com`, is deliberately taunting and not attempting to impersonate a legitimate service, which is also typical of this scam type.

### 3. Threat Intelligence

An analysis of the source SMTP IP address `27.128.173.81` on AbuseIPDB confirms it is a known bad actor.

<img width="1492" height="734" alt="image" src="https://github.com/user-attachments/assets/feff2ac5-1cca-433f-9663-193801a3f86d" />

The IP address, located in China, has over **15,000 reports**, reinforcing the conclusion that this is not a targeted attack but part of a large-scale spam operation.

### 4. Confirmation of Successful Prevention

The most critical finding in this investigation is the **`Device Action: Blocked`** status in the SIEM alert. This indicates that the corporate email security gateway successfully identified the email as malicious (either through sender reputation, content analysis, or other rules) and prevented it from being delivered to the user's (`mark@letsdefend.io`) inbox. Because the user never received the email, there was zero risk of compromise or psychological distress.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, AbuseIPDB
*   **Skills Demonstrated:** Phishing Analysis, Threat Intelligence Correlation, Triage.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a blackmail email from a known-bad IP.
*   **What Is The Attack Type?** **Sextortion / Phishing.**
*   **Was the Attack Successful?** **No.** The email was blocked by the security gateway.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a sextortion phishing attempt. The investigation confirms the malicious nature of the email but, most importantly, confirms that it was successfully **blocked** by the email security gateway. No compromise occurred, and no user interaction was possible.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the email security gateway.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **Verify Block Rules:** As a best practice, ensure the sender's IP (`27.128.173.81`) and domain (`ihackedyourcomputer.com`) are permanently on the blocklist.
4.  **User Awareness:** This event can serve as a good, anonymous example in general security awareness communications to educate employees about sextortion scams and to reinforce the policy of never paying ransoms and always reporting such emails.
