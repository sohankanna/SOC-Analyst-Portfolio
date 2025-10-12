# 	SOC102 - Proxy - Suspicious URL Detected (Event ID: 22)


## Executive Summary

On October 25, 2020, the Security Operations Center (SOC) received an alert for a suspicious URL accessed from the host **Sofia** (172.16.17.56). The investigation confirmed that the user `Sofia2020` connected to the domain `stylefix.co`, which threat intelligence platforms identify as malicious. Dynamic sandbox analysis from Hybrid Analysis returned a definitive **100/100 malicious score**, indicating the site actively performs malicious actions. The **`Device Action: Allowed`** confirms that the corporate web proxy did not block the connection, and the user's browser successfully loaded the malicious page. The host must be considered potentially compromised. This is a **True Positive** incident that requires immediate containment and escalation.

## Incident Details

The initial alert was triggered by a URL request matching a suspicious pattern or reputation:

<img width="1448" height="517" alt="image" src="https://github.com/user-attachments/assets/2f01d0af-82c6-4c7e-a6ab-e36ecf8b1290" />

| | |
| :--- | :--- |
| **Date of Incident**| October 25, 2020 |
| **Source Host**| Sofia (172.16.17.56) |
| **Username**| Sofia2020 |
| **Malicious Domain**| stylefix.co (35.189.10.17) |
| **Malicious URL**| `http://stylefix.co/guillotine-cross/CTRNOQ/` |
| **Attack Type**| Malicious Website / Malware Dropper |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/22))* |

## Investigation and Analysis

### 1. Alert Triage and Log Analysis

The investigation began by confirming the activity in the network logs. The logs verified that the user's browser made a GET request to the suspicious URL and, critically, that the **`Device Action`** was **`Allowed`**. This means the security controls at the perimeter failed to block the connection, allowing the user's machine to communicate directly with the malicious server and render the page content.

<img width="921" height="431" alt="image" src="https://github.com/user-attachments/assets/d1ac3f5b-1283-4bec-9095-744b3d09219d" />

### 2. Threat Intelligence Analysis

While initial static checks were not overwhelming, dynamic analysis provided definitive proof of malicious intent.
*   **Static Analysis (VirusTotal):** A check of the URL on VirusTotal showed it was flagged as malicious by **4 security vendors**. While not a high number, any detection is a significant red flag.
    <img width="1788" height="666" alt="image" src="https://github.com/user-attachments/assets/36febda4-e139-4cf6-8a67-4bd99b195b3f" />
*   **Dynamic Analysis (Hybrid Analysis):** This provided the "smoking gun." The sandbox environment, which actively browses to the URL to observe its behavior, assigned it a **100/100 malicious threat score**. This high score indicates that the website is not just suspicious but actively performs malicious actions, such as attempting to exploit the browser, download malware, or redirect to a phishing page.
    <img width="1627" height="615" alt="image" src="https://github.com/user-attachments/assets/849bb4c1-45b3-4cc6-819a-eacf82cf6d76" />

### 3. Final Assessment

The combination of the `Allowed` device action and the 100/100 malicious score from a dynamic sandbox is conclusive. The user's machine connected to a malicious site, and it must be assumed that a compromise event (e.g., malware download, browser exploit) occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy Logs, VirusTotal, Hybrid Analysis
*   **Skills Demonstrated:** Triage, Threat Intelligence Correlation, Differentiating Static vs. Dynamic Analysis, Log Analysis.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Malicious.** Confirmed by dynamic analysis and multiple TI vendors.
*   **Was the Attack Successful?** **Yes.** The connection was allowed, and the user's browser loaded the malicious content.
*   **Do You Need Tier 2 Escalation?** **Yes.** A user's machine connecting to a confirmed malicious site constitutes a potential compromise and requires deeper investigation.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC102 was a **true positive**. A user successfully connected to a website confirmed to be malicious. The host **Sofia** must be considered compromised. Immediate action is required to contain the threat and investigate the impact.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **Sofia** (172.16.17.56) from the network to prevent any potential malware from establishing a C2 connection, spreading laterally, or exfiltrating data.
2.  **CREDENTIALS - Disable and Reset:** Immediately disable the `Sofia2020` user account and reset their password.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full forensic investigation.
4.  **INVESTIGATION:** The IR team must perform a full analysis of the host to identify any dropped files, new processes, or persistence mechanisms. All network traffic from the host since the time of the incident should be scrutinized.
5.  **RECOVERY:** The compromised host should be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:** Block the malicious domain (`stylefix.co`) and its IP (`35.189.10.17`) at the network firewall and web proxy to protect other users.
7.  **USER AWARENESS:** The user `Sofia` should be interviewed to determine how they came to visit the malicious site (e.g., phishing email, malvertising) and should be enrolled in remedial security awareness training.
















