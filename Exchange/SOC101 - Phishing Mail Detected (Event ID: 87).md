# SOC101 - Phishing Mail Detected (Event ID: 87)

## Executive Summary

On April 4, 2021, the Security Operations Center (SOC) received an alert for a phishing email delivered to the user `mark@letsdefend.io`. The investigation confirmed a malicious email, designed to lure the user into clicking a suspicious link, was **Allowed** by the email security gateway and delivered to the user's inbox. Threat intelligence on the URL `http[:]//nuangaybantiep.xyz/` indicated it was malicious, although it appears to have been taken down since the incident. A review of network and endpoint logs showed **no evidence** that the user ever clicked the link. This is a **True Positive** for a delivered threat, but the attack was ultimately **unsuccessful** due to the user's non-interaction.

## Incident Details

The initial alert was triggered by a rule detecting a phishing email:

<img width="1475" height="484" alt="image" src="https://github.com/user-attachments/assets/4ae73367-3711-4f6b-8e36-82235c2b0d0c" />

| | |
| :--- | :--- |
| **Date of Incident**| April 4, 2021 |
| **Attacker SMTP IP**| 146.56.195.192 |
| **Sender Address**| lethuyan852@gmail.com |
| **Recipient Address**| mark@letsdefend.io |
| **Malicious URL**| `http[:]//nuangaybantiep.xyz/` |
| **Attack Type**| Phishing with Malicious Link |
| **Case Link**| *([Case link ](https://app.letsdefend.io/case-management/casedetail/sohankanna/87))* |

## Investigation and Analysis

### 1. Phishing Email Analysis

The attack began with a simple phishing email using a generic, clickbait subject line ("Its a Must have for your Phone") to arouse curiosity. The body of the email contained only a malicious link. The sender address is a standard `@gmail.com` account, which is a strong indicator that this is not a legitimate corporate communication.

<img width="1537" height="556" alt="image" src="https://github.com/user-attachments/assets/e3e2540d-69fa-493d-aaf7-4dddc12882e0" />

### 2. Threat Intelligence Analysis

An analysis of the indicators confirmed the malicious nature of the campaign.
*   **Malicious URL (`http[:]//nuangaybantiep.xyz/`):** A check on VirusTotal revealed that the URL was flagged as malicious by 2 security vendors. While a low count, any detection is a significant indicator. Further investigation showed that the domain is no longer active and does not resolve to an IP address, suggesting it was part of a temporary campaign that has since been taken down.
    <img width="1723" height="786" alt="image" src="https://github.com/user-attachments/assets/f6375d5c-3aef-46aa-ac9b-e190ddb383e2" />
    <img width="1442" height="702" alt="image" src="https://github.com/user-attachments/assets/f7ab8ec2-8f25-46cc-bf47-9b53f7056888" />

### 3. Confirmation of Non-Interaction

The most critical part of the investigation was determining if the user interacted with the malicious link, especially since the email was successfully delivered.
*   **Log Analysis:** A thorough review of the endpoint and network logs for the host associated with `mark@letsdefend.io` was conducted for the time of and following the email delivery.
*   **Result:** The investigation found **no evidence** of any outbound network traffic from the user's machine to the malicious domain `nuangaybantiep.xyz`. This indicates that the user correctly identified the email as suspicious and did not click the link.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway, VirusTotal
*   **Skills Demonstrated:** Phishing Analysis, Log Correlation, Threat Intelligence Triage.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Malicious.** The URL was flagged by threat intelligence.
*   **Was the Attack Successful?** **No.** Although the email was delivered, the user did not click the link, so no compromise occurred.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was delivered but not activated and can be remediated by the Tier 1 analyst.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious email was delivered).

## Conclusion and Recommendations

The alert for SOC101 was a **true positive**. A malicious phishing email was successfully delivered to a user's inbox. However, the attack ultimately **failed** because the user demonstrated good security awareness and did not click the malicious link. This is a "near-miss" scenario that highlights both a gap in email filtering and a success in user training.

**Recommendations:**

1.  **REMEDIATE - Purge Email:** The highest priority is to use the email security gateway to immediately and permanently delete the malicious email from the user's (`mark@letsdefend.io`) inbox to prevent any future accidental clicks.
2.  **Acknowledge User Action:** Recognize the user's good security practice in not clicking the suspicious link.
3.  **BLOCK INDICATORS:** As a proactive measure, ensure the sender's IP (`146.56.195.192`), sender address (`lethuyan852@gmail.com`), and the malicious domain (`nuangaybantiep.xyz`) are on all relevant blocklists.
4.  **HUNT:** Proactively search email logs to determine if this same email or sender has targeted any other users in the organization and purge those emails as well.
