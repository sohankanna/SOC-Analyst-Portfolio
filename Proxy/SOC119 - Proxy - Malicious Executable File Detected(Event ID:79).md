# 	SOC119 - Proxy - Malicious Executable File Detected(Event ID:79)

## Executive Summary

On March 15, 2021, the Security Operations Center (SOC) received an alert for a potentially malicious executable download originating from the host **PentestMachine** (172.16.20.5). The user, logged in as `kali`, was observed accessing the official GitHub repository for **BloodHound**, a well-known Active Directory reconnaissance tool. The `User-Agent` string explicitly stated "Penetration Test - Do not Contain." All evidence points to a planned and authorized penetration testing activity. The alert, while technically correct in identifying a hacking tool, is contextually a **False Positive** as it represents authorized, non-malicious activity.

## Incident Details

The initial alert was triggered by a user downloading a known cybersecurity tool:

<img width="1462" height="564" alt="image" src="https://github.com/user-attachments/assets/faabea46-afdb-4011-a9c7-37f15a23c9f5" />

| | |
| :--- | :--- |
| **Date of Incident**| March 15, 2021 |
| **Source Host**| PentestMachine (172.16.20.5) |
| **Username**| kali |
| **Destination Host**| github.com (140.82.121.4) |
| **Request URL**| `https://github.com/BloodHoundAD/BloodHound/releases` |
| **User Agent**| Penetration Test - Do not Contain |
| **Case Link**| *([Case link ](https://app.letsdefend.io/case-management/casedetail/sohankanna/79))* |

## Investigation and Analysis

### 1. Alert Context and Triage

The investigation focused on several key contextual clues from the alert data itself:
*   **Source Hostname (`PentestMachine`) and Username (`kali`):** Both of these strongly indicate a system set up for security testing. "Kali" is the name of the most popular Linux distribution used for penetration testing.
*   **Tool (`BloodHound`):** The `Request URL` points to the official release page for BloodHound. BloodHound is a legitimate and widely used tool by both red teams (attackers) and blue teams (defenders) to map and analyze Active Directory attack paths. It is not malware but a powerful reconnaissance tool.
*   **User-Agent (`Penetration Test - Do not Contain`):** This is the most definitive piece of evidence. The user or tool has set a custom User-Agent string to explicitly inform any monitoring systems that this is part of an authorized test and that containment actions should not be taken.

### 2. Log Analysis

A review of the network logs confirms the activity described in the alert: a connection from the `PentestMachine` to the official `github.com` IP address for the BloodHound repository.

<img width="656" height="274" alt="image" src="https://github.com/user-attachments/assets/3943d9b0-04b6-466d-a776-89e2fd8c3d81" />

The `Device Action: Allowed` is the correct behavior, as the activity is benign and there is no policy blocking access to GitHub.

### 3. Final Assessment

All indicators point to this being a planned and authorized security assessment. A member of a security team (or a contracted third party) was downloading a standard penetration testing tool onto a designated machine for that purpose. The alert rule correctly identified the download of a "hacking tool," but lacks the context to understand that the activity was authorized.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy Logs
*   - **Skills Demonstrated:** False Positive Analysis, Contextual Triage, Recognition of Pentesting Tools and Procedures.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Non-malicious.** The URL is the official GitHub repository for a legitimate security tool.
*   **Is Traffic Malicious?** **No.** The traffic is authorized and part of a planned security test.
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC119 was a **false positive**. The activity detected was part of a legitimate, authorized penetration test. The SIEM rule worked as designed by flagging a dual-use security tool, but human analysis confirmed the benign context of the event.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive with a note indicating it was related to an authorized penetration test.
2.  **Deconfliction and Communication:** The SOC should have a clear communication channel and deconfliction process with the team conducting the penetration test.
    *   The pentesting team should provide the SOC with the IP addresses of their source machines and the general timing of their activities.
    *   This allows the SOC to create temporary alert suppression rules for these specific IPs to avoid generating unnecessary alerts and wasting analyst time.
3.  **Future User-Agent Rules:** Consider creating a low-priority informational alert for when a User-Agent containing "Penetration Test" is seen. This can help the SOC proactively track authorized testing activity without generating high-severity alerts that require a full investigation.











