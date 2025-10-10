# 	SOC108 - Malicious Remote Access Software Detected (Event ID :38)


## Executive Summary

On January 1, 2021, the Security Operations Center (SOC) received an alert for "Malicious Remote Access Software Detected" on the host **DanielPRD** (172.16.17.33). The alert was triggered by the execution of `AnyDesk.exe`. An investigation was launched to determine if this was a "dual-use" tool being leveraged by an attacker for unauthorized remote access. A thorough analysis of the file hash on multiple threat intelligence platforms (VirusTotal, Hybrid-Analysis) showed **zero malware detections** and confirmed the file is the legitimate, signed AnyDesk application. While dynamic analysis noted some "suspicious" behaviors, these are consistent with the normal operation of a remote access tool. The alert is therefore classified as a **False Positive**, where a legitimate tool's inherent capabilities were misidentified as malicious.

## Incident Details

The initial alert was triggered by the execution of a legitimate remote access tool:

<img width="1474" height="528" alt="image" src="https://github.com/user-attachments/assets/6f122f63-a94b-496a-abcc-6ebbdfc82d89" />

| | |
| :--- | :--- |
| **Date of Incident**| January 1, 2021 |
| **Source Host**| DanielPRD (172.16.17.33) |
| **File Name**| AnyDesk.exe |
| **File Hash (MD5)**| ff6bbddc34cbd33e2501872b97c4bacd |
| **Suspected Tactic**| Remote Access Software (MITRE ATT&CK T1219) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/38))* |

## Investigation and Analysis

### 1. Alert Context: Remote Access Software as a "Dual-Use" Tool

The rule `SOC108 - Malicious Remote Access Software Detected` is designed to detect the presence of tools like AnyDesk, TeamViewer, etc. While these are legitimate commercial products, they are also frequently abused by threat actors (both external attackers and malicious insiders) to establish persistent, interactive access to a compromised host. This makes them "dual-use" tools, and their presence in an environment where they are not officially sanctioned is a security risk that must be investigated.

### 2. File and Threat Intelligence Analysis

The investigation focused on verifying the legitimacy of the `AnyDesk.exe` file.
*   **VirusTotal:** The file hash `ff6bbddc34cbd33e2501872b97c4bacd` showed **zero detections** from all security vendors and was identified as the legitimate AnyDesk executable.
    <img width="1709" height="830" alt="image" src="https://github.com/user-attachments/assets/ec7d4e43-ca3e-412a-a1fe-9558ef945779" />
*   **Hybrid Analysis:** This platform also returned no malicious verdict and confirmed the file was signed by the legitimate publisher, "AnyDesk Software GmbH."
    <img width="1860" height="844" alt="image" src="https://github.com/user-attachments/assets/fedae1fd-15a6-4705-8071-1be2f847006f" />
*   **Any.Run:** The dynamic analysis noted some "suspicious" activities, such as creating mutexes ("ANYDESK mutex") and downloading/deleting files. However, these are normal operational behaviors for a remote access tool establishing a session and updating itself.
    <img width="1803" height="853" alt="image" src="https://github.com/user-attachments/assets/c357e034-4279-4d72-b2ef-932b64ff9a50" />

### 3. Final Assessment

The evidence confirms that the file is the legitimate AnyDesk software. The `Device Action: Allowed` is expected if the software is not explicitly blocklisted. The alert is a **false positive** in the sense that the file is not *malware*. However, it could still be a **True Positive** for a *policy violation* if AnyDesk is not an approved application for remote access in the corporate environment. Without evidence of malicious control, the immediate threat is low.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, VirusTotal, Hybrid-Analysis, Any.Run
*   **Skills Demonstrated:** False Positive Analysis, Dual-Use Tool Triage, Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Analyze Malware:** **Non-malicious.** The file is the legitimate AnyDesk application.
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC108 was a **false positive**. The SIEM rule correctly identified the presence of a remote access tool, but the investigation confirmed it was the legitimate AnyDesk application, not a malicious RAT. The behaviors that flagged it as suspicious are part of its normal operation.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive with a note detailing the findings.
2.  **Policy Verification:** The next step is to determine if this is a policy violation. Check with the IT/Security department to confirm if AnyDesk is an approved remote access solution.
    *   **If Approved:** No further action is needed, but consider tuning the detection rule to be less sensitive to the legitimate, signed AnyDesk executable to reduce future false positives.
    *   **If Unapproved:** This becomes an IT policy enforcement issue. The user `Daniel` should be contacted, and the unauthorized software should be uninstalled from the host. This highlights a gap in application control that should be addressed.













