# SOC326 - Impersonating Domain MX Record Change Detected


## Executive Summary

On September 17, 2024, the Security Operations Center (SOC) received a proactive threat intelligence alert regarding a change to the MX record for an impersonating domain, **`letsdefwnd[.]io`**. This domain was being monitored for brand protection and typosquatting. The CTI report indicated that the domain was now configured to send and receive email, a common precursor to a phishing campaign. The investigation confirmed that an active phishing campaign was underway, as an email from this malicious domain was successfully delivered to a user, **Mateo**. Endpoint security logs confirm the user opened the malicious link contained in the email. This is a **True Positive** for a successful phishing attack, and the user's account and host must be considered potentially compromised.

## Incident Details

The initial alert was a CTI report, not a detection on the wire:

<img width="1513" height="535" alt="image" src="https://github.com/user-attachments/assets/4be45d68-0ac9-4feb-b5cd-7716cf6de435" />

| | |
| :--- | :--- |
| **Date of Incident**| September 17, 2024 |
| **Monitored Domain**| LETSDEFEND |
| **Impersonating Domain**| `letsdefwnd[.]io` |
| **Recipient User**| Mateo |
| **Attack Type**| Phishing / Credential Harvesting |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/304))* |

## Investigation and Analysis

### 1. The Proactive CTI Alert

The incident began with an alert from a Digital Risk Protection service. This type of service monitors the internet for newly registered domains that are confusingly similar to a company's actual domain (`letsdefend.io` vs. `letsdefwnd[.]io`).

*   **The Trigger:** The alert was specifically triggered because the attacker added an **MX (Mail Exchange) record** (`mail.mailerhost[.]net`) to their malicious domain.
*   **Significance:** An MX record tells the internet's email system where to deliver mail for a domain. Adding one is a definitive step an attacker takes when they are preparing to use the domain to send phishing emails and potentially receive replies. This alert served as a critical early warning.

<img width="1492" height="638" alt="image" src="https://github.com/user-attachments/assets/122f076e-4789-4bf6-980b-02db911052d2" />

### 2. Hunting for Impact: From CTI to Internal Logs

Armed with the malicious domain `letsdefwnd[.]io`, a hunt was initiated in the internal logs to see if any emails from this domain had been received.
*   **Email Security Gateway:** The search revealed a successful delivery of a phishing email from this domain to the user `Mateo`.
    <img width="1455" height="655" alt="image" src="https://github.com/user-attachments/assets/a896189e-79ae-4754-b23a-7bb578c88607" />
*   **Threat Intelligence on URL:** While VirusTotal showed a low detection rate for the domain, this is common for new, targeted phishing sites. The typosquatting nature and the context of the CTI alert are enough to confirm its malicious intent.
    <img width="1797" height="769" alt="image" src="https://github.com/user-attachments/assets/af7da1c7-67a3-413d-b4e8-5bb1481db221" />

### 3. Confirmation of User Interaction

The final step was to determine if the user interacted with the phishing email.
*   **Endpoint Security Logs:** EDR logs provided the "smoking gun" evidence. They show that the user's web browser process (`chrome.exe`) made a network connection to the malicious domain `letsdefwnd.io`. This confirms that the user `Mateo` clicked the link in the phishing email.
    <img width="1155" height="414" alt="image" src="https://github.com/user-attachments/assets/3e494ec8-6a54-43db-8844-ae10c849a25d" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway, EDR, VirusTotal, Digital Risk Protection Platform
*   **Skills Demonstrated:** CTI Analysis, Proactive Threat Hunting, Phishing Analysis, Log Correlation.

## Playbook Solution: Incident Classification

*   **Was the email delivered?** **Yes.** Confirmed in email security logs.
*   **Did the user open the URL?** **Yes.** Confirmed by EDR logs showing the browser connection.
*   **Analyze URL:** **Malicious.** Confirmed by CTI and its use in a phishing campaign.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC326 was a **true positive** for a successful phishing attack. The proactive CTI alert provided an early warning that was successfully used to identify a real-world compromise. A user clicked on a link in a phishing email from a known impersonating domain. It must be assumed that the user entered their credentials on the phishing site.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host and Reset Credentials:**
    *   Immediately isolate the user's host machine to prevent any potential malware deployment from the phishing site.
    *   Immediately reset the user's (`Mateo's`) corporate password and invalidate all active login sessions.
2.  **ESCALATE:** Escalate this incident to the Tier 2/Incident Response (IR) team to investigate for any further compromise.
3.  **INVESTIGATION:** The IR team should analyze the phishing site to determine its objective (e.g., credential harvesting, malware delivery). They should also review the user's account activity since the time of the click for any anomalous logins or actions.
4.  **REMEDIATE - Purge and Block:**
    *   Use the email security gateway to search for and purge this email from any other mailboxes it may have been delivered to.
    *   Block the domain `letsdefwnd[.]io` and all associated IPs and the MX record domain `mail.mailerhost[.]net` on the web proxy and firewall.
5.  **USER AWARENESS:** The user `Mateo` should be enrolled in remedial phishing awareness training.
6.  **DOMAIN TAKEDOWN:** Initiate the takedown process for the malicious domain `letsdefwnd[.]io` through the Digital Risk Protection service or the domain registrar.
