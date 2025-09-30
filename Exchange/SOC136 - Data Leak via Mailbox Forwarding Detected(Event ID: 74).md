# 	SOC136 - Data Leak via Mailbox Forwarding Detected(Event ID: 74).md
## Executive Summary

On March 7, 2021, the Security Operations Center (SOC) received a high-severity alert for a data leak attempt originating from an internal user account, `katharine@letsdefend.io`. The investigation confirmed that a malicious mailbox forwarding rule had been set on the user's account to automatically exfiltrate data to an external, suspicious email address, `katharine.isabell@yandex.ru`. An email containing what appears to be a list of usernames and passwords for critical accounts (e.g., `root`, `admin`) was captured. The email security gateway's Data Loss Prevention (DLP) policy successfully identified and **Blocked** this outbound forwarded email. This alert is a **True Positive** for a critical post-compromise activity. While the specific data exfiltration attempt was blocked, the existence of the forwarding rule itself is definitive proof that the `katharine@letsdefend.io` account is compromised.

## Incident Details

The initial alert was triggered by a rule detecting the forwarding of sensitive information to an external address:

<img width="1465" height="468" alt="image" src="https://github.com/user-attachments/assets/f4369524-71fc-43cf-9297-d67538599f43" />

| | |
| :--- | :--- |
| **Date of Incident**| March 7, 2021 |
| **Source Account**| katharine@letsdefend.io |
| **Attacker Destination**| katharine.isabell@yandex.ru |
| **Data Exfiltrated**| User Credentials (Attempted) |
| **Attack Type**| Data Exfiltration via Mailbox Forwarding (Post-Compromise) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/74))* |

## Investigation and Analysis

### 1. Alert Context: Mailbox Forwarding as a TTP

The rule `SOC136 - Data Leak via Mailbox Forwarding Detected` is designed to detect a stealthy and highly effective data exfiltration technique (MITRE ATT&CK T1114.003 - Email Forwarding Rule). After an attacker gains access to a user's mailbox (typically through phishing or password spraying), they create a forwarding rule. This allows them to silently receive a copy of all incoming (and sometimes outgoing) emails, giving them access to sensitive conversations, attachments, and credentials without having to log in again.

### 2. Email Content Analysis: The "Crown Jewels"

The content of the blocked email is the most critical piece of evidence.

<img width="1493" height="641" alt="image" src="https://github.com/user-attachments/assets/2a044ad0-1b63-416f-b208-cd2906146459" />
The body contains a list of what are clearly usernames and passwords for privileged accounts:
`root:Q@6PY4jF john:4\@sMpH/ bill:Pxt5\p6V admin:Y[H6mBu_`

This indicates that the attacker, having already compromised one part of the environment, was attempting to send a list of other compromised credentials back to their external email account. The exfiltration of these credentials would enable widespread lateral movement and access to critical systems.

### 3. Confirmation of Successful Prevention

The investigation confirmed that this specific data exfiltration attempt was stopped. The **`Device Action: Blocked`** status in the SIEM alert is the definitive proof. This means the email security gateway or Exchange server, likely using a DLP policy that inspects for patterns resembling passwords, intercepted the outbound forwarded email and prevented its delivery to the attacker's `yandex.ru` address.

### 4. Root Cause: A Pre-Existing Compromise

It is critical to understand that this alert is not the *start* of the incident. The creation of a mailbox forwarding rule is a *post-compromise* action. This alert is a symptom of a larger problem: **the `katharine@letsdefend.io` user account is already compromised**. The attacker had sufficient access to her mailbox to create the forwarding rule in the first place.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway / Exchange Logs
*   **Skills Demonstrated:** Data Exfiltration Analysis, TTP Recognition (Mailbox Forwarding), DLP Policy Triage, Root Cause Analysis.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is an attempt to exfiltrate credentials.
*   **What Is The Attack Type?** **Data Exfiltration.**
*   **Was the Attack Successful?** **No.** The email containing the credentials was blocked. However, the underlying account compromise was successful.
*   **Do You Need Tier 2 Escalation?** **Yes.** A compromised user account with evidence of an attacker attempting to exfiltrate further credentials is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC136 was a **true positive**. An attacker, having previously compromised the `katharine@letsdefend.io` account, attempted to exfiltrate a list of privileged credentials by creating a malicious email forwarding rule. The attempt to send this specific email was successfully **blocked** by a DLP control. However, the user's account remains compromised and poses an active threat to the organization.

**Recommendations:**

1.  **CONTAINMENT - Disable Account and Terminate Sessions:** Immediately disable the `katharine@letsdefend.io` user account in Active Directory. Concurrently, terminate all active sessions (O365, VPN, etc.) for this user to evict the attacker.
2.  **ERADICATION - Remove Forwarding Rule:** Access the user's mailbox settings (via an Exchange administrator) and immediately remove the malicious forwarding rule that sends email to `katharine.isabell@yandex.ru`.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full investigation into the initial account compromise.
4.  **INVESTIGATION:** The primary goal for the IR team is to determine the root cause. They must:
    *   Analyze authentication logs for `katharine@letsdefend.io` to find the initial unauthorized login (e.g., from an unusual IP, time, or location). This will likely point to a prior phishing or password spray attack.
    *   Determine the origin of the exfiltrated credentials. Were they from Katharine's machine, a server she accessed, or from the email itself?
5.  **CREDENTIAL ROTATION:** All passwords in the exfiltrated list (`root`, `john`, `bill`, `admin`) must be considered compromised and reset immediately across all systems.
6.  **REVIEW DLP/FORWARDING RULES:** Review email security policies to determine if all external mailbox forwarding can be disabled by default, requiring administrative approval for exceptions.
