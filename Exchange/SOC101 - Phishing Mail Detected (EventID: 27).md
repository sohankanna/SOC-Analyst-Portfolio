# SOC101 - Phishing Mail Detected (EventID: 27)

## Executive Summary

On October 29, 2020, the Security Operations Center (SOC) received an alert for a phishing email sent to the user `susie@letsdefend.io`. The investigation identified the email as a malicious lure, impersonating a UPS notification to trick the user into clicking a link. Threat intelligence analysis of the URL confirmed it was a known distribution point for the **Emotet** trojan, a dangerous and prolific malware. The email security gateway successfully identified the threat, and the **Device Action** was **Blocked**. The alert is a **True Positive** for a real threat, but the attack was **unsuccessful** as the malicious email was prevented from reaching the user's inbox.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1499" height="472" alt="image" src="https://github.com/user-attachments/assets/bf2dc50c-3671-4ef7-a137-18a7e11423ee" />

| | |
| :--- | :--- |
| **Date of Incident**| October 29, 2020 |
| **Attacker SMTP IP**| 146.56.209.252 |
| **Sender Address**| ndt@zol.co.zw (Likely a compromised account) |
| **Recipient Address**| susie@letsdefend.io |
| **Malicious URL**| `https://hredoybangladesh.com/content/docs/wvoiha4vd1aqty/` |
| **Associated Threat**| Emotet |
| **Attack Type**| Phishing with Malicious Link |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/27))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a phishing email designed to impersonate a common brand, UPS, with the subject "UPS Your Packages Status Has Changed." The body of the email contained a link, instructing the user to click it to read a secure message. This is a standard social engineering tactic to create a sense of legitimacy and urgency.

<img width="1512" height="518" alt="image" src="https://github.com/user-attachments/assets/609a7bc8-c7fc-4193-9049-1aaa32d3c14c" />

### 2. Threat Intelligence Analysis

An analysis of the malicious URL provided definitive confirmation of the threat.
*   **VirusTotal:** The URL `https://hredoybangladesh.com/...` was flagged as malicious by **11 security vendors**, confirming it was not a legitimate site.
    <img width="1758" height="825" alt="image" src="https://github.com/user-attachments/assets/bf7f737e-f95d-41c8-9b89-7db584c3b6bc" />
*   **URLhaus:** This platform provided critical context, tagging the URL with **"emotet," "epoch2,"** and **"heodo."** Emotet is a notorious trojan that primarily spreads through phishing. It acts as a downloader for other malware, often leading to secondary infections like TrickBot, Qakbot, and ultimately, ransomware. This confirms the email was not just a credential harvester but a malware delivery mechanism.
    <img width="1322" height="212" alt="image" src="https://github.com/user-attachments/assets/9f6f109e-ee76-4b76-8871-a0ed2c6a52bd" />

### 3. Confirmation of Successful Prevention

The most important finding of this investigation is that the attack was stopped before it could cause harm. The **`Device Action: Blocked`** status in the SIEM alert is the key piece of evidence. This confirms that the corporate email security gateway correctly identified the email as a threat and prevented it from being delivered to the user `susie@letsdefend.io`. Since the user never received the email, they could not have clicked the link, and no compromise occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, VirusTotal, URLhaus
*   **Skills Demonstrated:** Phishing Analysis, Threat Intelligence Correlation, Malware Triage.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Malicious.** The URL is a known distribution point for the Emotet malware.
*   **Was the Attack Successful?** **No.** The email was blocked by the security gateway.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive** for a phishing attempt delivering the Emotet trojan. The investigation confirms the malicious nature of the email and its payload but, most importantly, confirms that it was successfully **blocked** by the email security gateway. No systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the email security gateway. This is a good outcome demonstrating the effectiveness of the security stack.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`146.56.209.252`), domain (`zol.co.zw`), and the malicious URL (`hredoybangladesh.com`) are permanently on all relevant blocklists (firewall, web proxy, email gateway).
