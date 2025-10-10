# SOC108 - Malicious Remote Access Software Detected (Event ID:54)

## Executive Summary

On February 7, 2021, the Security Operations Center (SOC) received an alert for malicious remote access software detected from the device **MarksPhone** (10.15.15.12). The investigation confirmed the user `Mark` was accessing the official website for **TeamViewer**, a legitimate and widely used remote access application. Threat intelligence analysis of the domain `teamviewer.com` confirms it is benign. The activity is consistent with a user downloading or accessing a legitimate commercial tool. The alert is therefore classified as a **False Positive**, where the SIEM rule correctly identified a dual-use tool but lacked the context to determine the non-malicious intent.

## Incident Details

The initial alert was triggered by a user accessing the website for a legitimate remote access tool:

<img width="1464" height="563" alt="image" src="https://github.com/user-attachments/assets/3327cc60-02b2-4e97-96f1-9f5f3f07d387" />

| | |
| :--- | :--- |
| **Date of Incident**| February 7, 2021 |
| **Source Host**| MarksPhone (10.15.15.12) |
| **Username**| Mark |
| **Destination Host**| teamviewer.com (13.95.16.245) |
| **Tool**| TeamViewer |
| **Suspected Tactic**| Remote Access Software (MITRE ATT&CK T1219) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/54))* |

## Investigation and Analysis

### 1. Alert Context: Remote Access Software as a "Dual-Use" Tool

The rule `SOC108 - Malicious Remote Access Software Detected` is designed to flag the presence of tools like TeamViewer, AnyDesk, etc. While these are legitimate commercial products used for remote support and administration, they are also frequently abused by threat actors to establish persistent access to compromised hosts. This makes them "dual-use" tools, and their presence or download in a corporate environment often warrants an investigation to confirm the intent.

### 2. Threat Intelligence and Log Analysis

The investigation focused on verifying the legitimacy of the destination and the context of the connection.
*   **Domain Analysis (VirusTotal):** A check of the requested hostname, `teamviewer.com`, on VirusTotal shows **zero detections** and confirms it is the official website for the TeamViewer software. This is the strongest indicator of legitimate activity.
    <img width="1809" height="813" alt="image" src="https://github.com/user-attachments/assets/ff6b3aa3-0bc3-43a6-bb4f-5b0235e20611" />
*   **Log Confirmation:** A review of the network logs confirms the connection from `MarksPhone` to `teamviewer.com`. The `Device Action: Allowed` is expected, as there is likely no policy in place to block this well-known site.
    <img width="1005" height="384" alt="image" src="https://github.com/user-attachments/assets/f91864e1-d33f-4a13-bd93-144a827bcf8b" />
*   **Contextual Clues:** The source hostname is `MarksPhone`, and the User-Agent is a "Chrome - Mobile Agent," indicating the user was browsing from a mobile device. This is consistent with a user accessing the TeamViewer website for personal or legitimate business use. The destination IP `13.95.16.245` resolving to Microsoft is not unusual, as many large services use major cloud providers like Azure for their web infrastructure.

### 3. Final Assessment

All evidence indicates this was a benign event. A legitimate user accessed the official website for a legitimate application. The SIEM rule, while working as designed to flag a dual-use tool, generated a false positive because it lacked the context to differentiate between malicious and legitimate use.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy Logs, VirusTotal
*   **Skills Demonstrated:** False Positive Analysis, Dual-Use Tool Triage, Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Non-malicious.** The URL is the official TeamViewer website.
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC108 was a **false positive**. The investigation confirmed that a user accessed the legitimate website for TeamViewer. No malicious activity occurred.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive, with notes detailing the findings.
2.  **Policy Verification:** The key follow-up action is to verify corporate policy.
    *   **Is TeamViewer an approved application?** If yes, the detection rule should be tuned to be less sensitive to traffic to `www.teamviewer.com` to reduce future false positives.
    *   **Is TeamViewer an unapproved application?** If no, this event is a **policy violation**, not a malicious attack. The information should be passed to the appropriate IT or management team to address the use of unauthorized software with the user `Mark`.
