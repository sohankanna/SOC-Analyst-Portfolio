# SOC101 - Phishing Mail Detected (Event ID : 34)

## Executive Summary

On December 5, 2020, the Security Operations Center (SOC) received an alert for a phishing email delivered to the user `emily@letsdefend.io`. The investigation confirmed a successful phishing attack where an email, impersonating the brand **Netflix**, was **Allowed** by the email security gateway. The email contained a malicious shortened URL (`bit.ly`) designed to lure the user to a credential harvesting page or malware distribution site. Endpoint security logs provide definitive proof that the user clicked the malicious link. Although the link is now defunct, the initial click represents a successful compromise. This is a **True Positive** for a successful phishing attack, and the user's account and host must be considered potentially compromised.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1472" height="517" alt="image" src="https://github.com/user-attachments/assets/3ffd732b-2b96-4fe1-a6c4-bad31eeaa2e6" />

| | |
| :--- | :--- |
| **Date of Incident**| December 5, 2020 |
| **Attacker SMTP IP**| 112.85.42.180 |
| **Sender Address**| admin@netflix-payments.com |
| **Recipient Address**| emily@letsdefend.io |
| **Malicious URL**| `http://bit.ly/3ecXem52` |
| **Attack Type**| Phishing / Brand Impersonation |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/34))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a phishing email designed to impersonate the popular streaming service, Netflix.
*   **The Lure:** The subject line, "Netflix Deals!", is a common social engineering tactic designed to entice users with a promotional offer.
*   **Suspicious Sender:** The sender's domain, `netflix-payments.com`, is a classic example of typosquatting or brand impersonation. Legitimate communications from Netflix would only come from the official `@netflix.com` domain. This is a clear indicator of a phishing attempt.
*   **Malicious Link:** The email contained a shortened `bit.ly` link, a technique attackers use to obscure the true, malicious destination URL from both users and basic email filters.

<img width="1490" height="516" alt="image" src="https://github.com/user-attachments/assets/0fecf58b-28de-4a2e-9107-4714331e9cd3" />

### 2. Confirmation of User Interaction

The most critical finding of the investigation is that the user fell for the phish and interacted with the malicious link.
*   **Endpoint Logs:** EDR logs provide the "smoking gun" evidence. They show the user's web browser process (`chrome.exe`) initiating a connection to the malicious `bit.ly` URL. This confirms that the user `Emily` clicked the link in the phishing email.

    <img width="994" height="76" alt="image" src="https://github.com/user-attachments/assets/2f0d1919-51d9-4f24-aa25-a356191c9c66" />
*   **Link Status:** While the `bit.ly` link is now inactive, it must be assumed that it was live at the time of the incident. Phishing infrastructures are often taken down quickly after a campaign, but the initial click still represents a successful compromise. The attacker's goal (credential theft or malware download) was likely achieved in that moment.

### 3. Final Assessment

The `Device Action: Allowed` status confirms the email bypassed security filters. The endpoint logs confirm the user clicked the link. Therefore, despite the current status of the link, the attack must be treated as successful.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway
*   **Skills Demonstrated:** Phishing Analysis, Brand Impersonation Recognition, Log Correlation.

## Playbook Solution: Incident Classification

*   **Analyze URL/Email:** **Malicious.** The email used brand impersonation and a suspicious link.
*   **Was the Attack Successful?** **Yes.** The user received the email and clicked the malicious link.
*   **Do You Need Tier 2 Escalation?** **Yes.** A confirmed user click on a malicious link requires escalation to investigate the potential impact.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a successful phishing attack. An attacker successfully delivered a brand-impersonating email, and the user clicked the malicious link. We must assume the worst-case scenario: that the user entered their corporate credentials on a phishing page or that malware was downloaded in the background. The user's account and host are considered compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host and Reset Credentials:**
    *   Immediately isolate the user's host machine to prevent any potential malware from communicating or spreading.
    *   Immediately reset the user's (`Emily's`) corporate password and invalidate all active login sessions.
2.  **ESCALATE:** Escalate this incident to the Tier 2/Incident Response (IR) team for a full investigation.
3.  **INVESTIGATION:** The IR team must:
    *   Analyze the host for any suspicious files downloaded or processes executed around the time of the click.
    *   Review the user's account authentication logs for any anomalous logins from unusual IPs or locations since the time of the incident.
4.  **REMEDIATE - Purge and Block:**
    *   Use the email security gateway to search for and purge this email from any other mailboxes it may have been delivered to.
    *   Block the sender's IP (`112.85.42.180`), domain (`netflix-payments.com`), and the `bit.ly` URL.
5.  **USER AWARENESS:** The user `Emily` should be enrolled in remedial phishing awareness training.
