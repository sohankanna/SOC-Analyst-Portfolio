# 	SOC105 - Requested T.I. URL address (EventID:16)

## Executive Summary

On September 20, 2020, the Security Operations Center (SOC) received an alert that the user **Mike01** on host **BillPRD** (172.16.17.47) accessed a URL flagged by threat intelligence. The investigation confirmed the user connected to the malicious domain **pssd-ltdgroup.com** and successfully downloaded a file named `Krankheitsmeldung_092020_07.xlsm`. This file is a macro-enabled spreadsheet, a common delivery vector for trojan malware. Given that the connection was allowed and the file was downloaded to the endpoint, the host must be considered potentially compromised. This incident is a **True Positive** and requires immediate escalation for incident response.

## Incident Details

The initial alert was triggered by a connection to a known-malicious URL:

<img width="1458" height="573" alt="image" src="https://github.com/user-attachments/assets/b55f6cb0-2bbf-43a2-8b16-b2de24a49693" />

| | |
| :--- | :--- |
| **Date of Incident** | September 20, 2020 |
| **Source Host** | BillPRD (172.16.17.47) |
| **Username** | Mike01 |
| **Destination Host** | pssd-ltdgroup.com (5.188.0.251) |
| **Malicious File** | Krankheitsmeldung_092020_07.xlsm |
| **File Hash (MD5)** | 14970ce0a3d03c46a4180db69866d0d1 |
| **Case Link** | [View Full Case on LetsDefend.io](https://app.letsdefend.io/case-management/casedetail/sohankanna/16) |

## Investigation and Analysis

### 1. Threat Intelligence Validation

The alert rule `SOC105 - Requested T.I. URL address` indicated that the destination was already on a threat intelligence list. A check of the domain `pssd-ltdgroup.com` on VirusTotal confirmed its malicious reputation, with multiple security vendors flagging it.

<img width="1775" height="806" alt="image" src="https://github.com/user-attachments/assets/bd580059-012b-46b9-af1c-402f47ac905d" />

### 2. Log Analysis and Confirmation of Download

A review of the network logs confirmed two separate connections from the source host to the malicious destination.

<img width="1561" height="365" alt="image" src="https://github.com/user-attachments/assets/4dfbd8ff-c636-4b3e-b48a-c19ac7611d2d" />

Crucially, one of these connections resulted in the download of a file named `Krankheitsmeldung_092020_07.xlsm`. The `.xlsm` extension signifies a macro-enabled Excel file, a highly suspicious file type commonly used to drop malware. The German filename, which translates to "sick report," is a classic social engineering lure.

<img width="638" height="199" alt="image" src="https://github.com/user-attachments/assets/921318ff-0e09-4936-856e-db849080cdd3" />

The `Device Action: Allowed` confirms that security controls did not block the download, meaning the malicious file successfully reached the endpoint.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Log Management, VirusTotal
*   **Skills Demonstrated:** Threat Intelligence Correlation, Log Analysis, Malware Triage, Phishing Vector Recognition.

## Playbook Solution: Incident Classification

*   **Analyze Threat Intel Data:** **Malicious.** The destination URL is confirmed malicious.
*   **Interaction with TI data:** **Accessed.** The user successfully connected to the site and downloaded a file.
*   **Is Traffic Malicious?** **Yes.** It involved the download of a trojan from a known-bad site.
*   **Was the Attack Successful?** **Yes.** The malicious file was successfully delivered to the endpoint.
*   **Do You Need Tier 2 Escalation?** **Yes.** A successful malware download constitutes a potential system compromise and must be escalated.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC105 was a **true positive**. A user was successfully lured to a malicious website and downloaded a trojan dropper disguised as a document. The host **BillPRD** must be considered compromised and treated as an active threat until proven otherwise.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect **BillPRD** (172.16.17.47) from the network to prevent potential C2 communication, lateral movement, or execution of a secondary payload (e.g., ransomware).
2.  **ESCALATE - Activate Incident Response Protocol:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for forensic analysis of the compromised host.
3.  **INVESTIGATION:** The IR team must determine if the user opened the `.xlsm` file and enabled macros. Forensics should be performed to check for persistence, new processes, and any outbound network connections since the time of the incident.
4.  **BLOCK INDICATORS:** Add the file hash (`14970ce0a3d03c46a4180db69866d0d1`), domain (`pssd-ltdgroup.com`), and IP address (`5.188.0.251`) to all relevant security blocklists (EDR, firewall, proxy, DNS).
5.  **REMEDIATE:** Based on the IR team's findings, the host will likely need to be wiped and re-imaged from a known-good source.

