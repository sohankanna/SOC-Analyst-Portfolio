# SOC143 - Password Stealer Detected

## Executive Summary

On April 26, 2021, the Security Operations Center (SOC) received an alert for a password stealer delivered via email to the user `ellie@letsdefend.io`. The investigation confirmed that a malicious HTML attachment was **Allowed** by the email security gateway. Analysis of the HTML file revealed a sophisticated, locally-rendered phishing page designed to impersonate a Microsoft/LetsDefend login portal. The page was pre-filled with the recipient's email address and was crafted to send any entered password to a malicious third-party server. Although the email was delivered, a review of endpoint and network logs showed **no evidence** that the user opened the attachment or that any data was sent to the attacker's server. This is a **True Positive** for a delivered threat, but the attack was ultimately **unsuccessful**.

## Incident Details

The initial alert was triggered by signatures associated with a password-stealing attachment:

<img width="1452" height="540" alt="image" src="https://github.com/user-attachments/assets/357e7819-f10c-4ef1-aa5b-42dde6621ffc" />

| | |
| :--- | :--- |
| **Date of Incident**| April 26, 2021 |
| **Attacker SMTP IP**| 180.76.101.229 |
| **Sender Address**| bill@microsoft.com (Spoofed) |
| **Recipient Address**| ellie@letsdefend.io |
| **Attachment Hash (MD5)**| bd05664f01205fa90774f42468a8743a |
| **Exfiltration URL**| `https://tecyardit.com/wp-content/card/2/post.php` |
| **Attack Type**| Phishing / Credential Harvesting |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/90))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a deceptive email sent from a spoofed `bill@microsoft.com` address. The email had a blank subject and body, a tactic designed to arouse curiosity and encourage the user to open the attachment to see its contents. The `Device Action: Allowed` confirms this email successfully bypassed initial security filters.

<img width="1473" height="527" alt="image" src="https://github.com/user-attachments/assets/cd3ea40e-2c6b-492c-98e9-d5dac6e74371" />

### 2. Malware Analysis (HTML Credential Stealer)

A deep analysis of the HTML attachment confirmed its purpose as a credential harvester.
*   **Threat Intelligence:** The file hash was flagged as malicious by **21 vendors on VirusTotal** and received a **100/100 threat score on Hybrid Analysis**, confirming its malicious nature.
    <img width="1782" height="862" alt="image" src="https://github.com/user-attachments/assets/c66a045c-c6ca-4578-8835-2ee7521d26ea" />
    <img width="1864" height="828" alt="image" src="https://github.com/user-attachments/assets/cc704a36-36f3-4a89-a41f-ce866093525a" />
*   **Static Code Analysis:** The HTML code creates a fake login form that opens locally in the user's browser.
    *   **Impersonation:** It uses a Microsoft logo and the title "Letsdefend.io" to appear legitimate.
    *   **Targeting:** The "Email ID" field is pre-filled with the recipient's email, `ellie@letsdefend.io`, making the phish more convincing.
    *   **The Trap:** The crucial element is the `<form>` tag's `action` attribute. It is set to `https://tecyardit.com/wp-content/card/2/post.php`. This means when the user types their password and clicks "Sign In," the form will send the `userid` and `pass` values directly to the attacker's server, not to a legitimate service. The URL itself, being a `.php` file in a WordPress content directory, is highly suspicious.

### 3. Confirmation of Non-Interaction

Despite the successful delivery of the email, the investigation found no evidence that the user fell for the attack.
*   **Log Analysis:** A thorough review of all available logs (Endpoint, Firewall, Proxy) for the host associated with `ellie@letsdefend.io` was conducted.
*   **Result:** The investigation found **no outbound network connections** from the user's host to the malicious exfiltration domain (`tecyardit.com`) or its IP address. This indicates that the user correctly identified the email as suspicious and did not open the HTML attachment.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway, VirusTotal, Hybrid Analysis, Static Code Analysis
*   **Skills Demonstrated:** Phishing Analysis, HTML/Web Form Analysis, Credential Harvesting Triage, Log Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Malicious.** The attachment is an HTML credential stealer.
*   **Was the Attack Successful?** **No.** Although the email was delivered, the user did not open the attachment, and no data was exfiltrated.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was delivered but not activated and can be remediated by the Tier 1 analyst.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email was delivered).

## Conclusion and Recommendations

The alert for SOC143 was a **true positive**. A malicious email containing an HTML attachment designed to steal credentials was successfully delivered to a user's inbox. However, the attack ultimately **failed** because the user did not open the attachment. This is a "near-miss" scenario that highlights both a gap in email filtering and a success in user awareness.

**Recommendations:**

1.  **REMEDIATE - Purge Email:** The highest priority is to use the email security gateway to immediately and permanently delete the malicious email from the user's (`ellie@letsdefend.io`) inbox.
2.  **Acknowledge User Action:** Recognize the user's good security practice in not opening the unsolicited attachment.
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`180.76.101.229`), the exfiltration domain (`tecyardit.com`), and the attachment hash (`bd05664f01205fa90774f42468a8743a`) are on all relevant blocklists.
4.  **HUNT:** Proactively search email logs to determine if this same attachment or sender has targeted any other users in the organization and purge those emails as well.














