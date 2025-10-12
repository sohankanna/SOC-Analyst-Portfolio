# 	SOC275 - Application Token Steal Attempt Detected (Event ID:250)

## Executive Summary

On April 19, 2024, the Security Operations Center (SOC) received an alert for an application token theft attempt targeting the user `gloriana@letsdefend.io`. The investigation confirmed a successful, multi-stage phishing attack. The user was lured by an email to click a malicious link, initiating a fake password reset process. Web server and endpoint logs show the user first visiting the attacker's site, which then led to a successful POST request that included a static token (`123letsdefendisthebest123`). This sequence is indicative of a successful session token or credential capture. Endpoint logs confirm a connection from the user's browser to an IP address associated with the malicious infrastructure. This is a **True Positive** for a successful phishing attack resulting in a compromised user session.

## Incident Details

The initial alert was triggered by a request pattern indicative of token theft:

<img width="1470" height="504" alt="image" src="https://github.com/user-attachments/assets/2b4df1bd-adf7-4e24-90ca-aa6d377efdc6" />

| | |
| :--- | :--- |
| **Date of Incident**| April 19, 2024 |
| **Attacker Infrastructure IPs**| 23.82.12.29, 20.42.73.27 |
| **Malicious Domain**| `homespottersf.com` |
| **Affected User**| gloriana@letsdefend.io |
| **Affected Host**| Gloriana (172.16.17.172) |
| **Attack Type**| Phishing / Credential & Token Theft |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/250))* |

## Investigation and Analysis

### 1. Phishing Email and The Lure

The attack began with a phishing email sent to the user `gloriana@letsdefend.io`. The email contained a malicious link designed to initiate a fake password reset workflow, a common tactic to steal credentials or session tokens.

<img width="1405" height="651" alt="image" src="https://github.com/user-attachments/assets/9b13b140-8a1e-4796-85fc-3856acc9ac29" />

### 2. Deconstructing the Attack via Log Analysis

The web server access logs show a clear, two-step process that confirms the user interacted with the phishing site and submitted information.

*   **Stage 1: The Initial Click (User Arrives at Phishing Page)**
    <img width="1045" height="495" alt="image" src="https://github.com/user-attachments/assets/05ab8057-5db6-456c-a1a8-55323b380b35" />
    *   **Request:** `GET /reset-password?email=gloriana@letsdefend.io`
    *   **Status Code:** `302 Redirect`
    *   **Explanation:** This log confirms the user clicked the link in the email. The browser made a GET request to the attacker's server, helpfully pre-filling the user's email address. The server responded with a `302 Redirect`, which likely sent the user to a fake password entry form.

*   **Stage 2: The Credential/Token Submission (The "Sting")**
    <img width="749" height="393" alt="image" src="https://github.com/user-attachments/assets/5566a3ad-1cdc-4843-841a-6e0f92515be4" />
    *   **Request:** `POST /reset-password?token=123letsdefendisthebest123`
    *   **Status Code:** `200 OK`
    *   **Explanation:** This is the "smoking gun." After being presented with the fake form, the user submitted information. The browser sent a POST request back to the attacker's server. The `token=123...` could be a static value, or it could represent a real session token that the user was tricked into submitting. The **`200 OK`** response confirms the attacker's server successfully received this data.

### 3. Confirmation of User Interaction

Endpoint security logs provide the final piece of corroborating evidence.
*   **Endpoint Logs:** EDR logs show a network connection from the user's browser process (`chrome.exe`) to one of the IP addresses (`20.42.73.27`) associated with the attacker's infrastructure. This confirms the activity seen in the web logs originated from the user's machine.
    <img width="1073" height="220" alt="image" src="https://github.com/user-attachments/assets/a33ad80c-d138-4e25-b010-a51da052f41a" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway, Web Server Logs
*   **Skills Demonstrated:** Phishing Analysis, Log Correlation, Attack Chain Reconstruction, Token Theft Triage.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a multi-stage phishing attack designed to steal credentials or session tokens.
*   **What Is The Attack Type?** **Application Token Steal / Credential Theft.**
*   **Was the Attack Successful?** **Yes.** The user clicked the link and submitted data to the attacker's server.
*   **Do You Need Tier 2 Escalation?** **Yes.** A confirmed credential or token compromise is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC275 was a **true positive** for a successful phishing attack. The user `Gloriana` was tricked into interacting with a malicious website, which resulted in the submission of a password or session token to an attacker-controlled server. The user's account and session must be considered fully compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host and Invalidate Session:**
    *   Immediately isolate the user's host machine **Gloriana** (172.16.17.172) from the network to prevent any further interaction.
    *   Immediately reset the user's (`gloriana@letsdefend.io`) password.
    *   **Crucially, invalidate all active login sessions** for the user to ensure any stolen session tokens are rendered useless.
2.  **ESCALATE:** Escalate this incident to the Tier 2/Incident Response (IR) team for a full investigation.
3.  **INVESTIGATION:** The IR team must review all of Gloriana's account activity (logins, file access, emails sent) since the time of the incident to hunt for any signs of malicious behavior by the attacker.
4.  **REMEDIATE - Purge and Block:**
    *   Use the email security gateway to search for and purge the initial phishing email from any other mailboxes it may have been delivered to.
    *   Block the malicious domain (`homespottersf.com`) and associated IPs (`23.82.12.29`, `20.42.73.27`) at the network perimeter.
5.  **USER AWARENESS:** The user `Gloriana` should be enrolled in remedial phishing awareness training.


































