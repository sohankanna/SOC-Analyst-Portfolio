#  SOC282 - Phishing Alert - Deceptive Mail Detected

## Executive Summary

On May 13, 2024, the Security Operations Center (SOC) received an alert for a deceptive email delivered to the user **Felix@letsdefend.io**. The email, with the subject "Free Coffee Voucher," originated from the sender **free@coffeeshooop.com**. Analysis confirmed the email contained a malicious link and a ZIP attachment, both associated with **SILENTBUILDER**, a known malware dropper used by a subgroup of the **Conti** threat actor group. The email security gateway allowed the delivery of the email, and logs indicate the user opened the malicious content. This incident is a **True Positive** for a successful phishing attack, resulting in a potential endpoint compromise that requires immediate escalation to the Incident Response team.

## Incident Details

The initial alert was received from the SIEM dashboard:

<img width="1460" height="539" alt="image" src="https://github.com/user-attachments/assets/e90f2496-e2dd-4c70-bef0-38e5e2deb4cc" />

| | |
| :--- | :--- |
| **Date of Incident** | May 13, 2024 |
| **Source SMTP IP** | 103.80.134.63 |
| **Sender Address** | free@coffeeshooop.com |
| **Recipient Address** | Felix@letsdefend.io |
| **Email Subject** | Free Coffee Voucher |
| **Malware Family** | SILENTBUILDER (Conti) |
| **Case Link** | [View Full Case on LetsDefend.io](https://app.letsdefend.io/case-management/casedetail/sohankanna/257) |

## Investigation and Analysis

### 1. Initial Alert and Log Confirmation

The investigation began with the SIEM alert, which indicated a deceptive email was **Allowed** by the security controls. Log management was used to confirm the delivery details of the email from the source to the destination.

<img width="1524" height="384" alt="image" src="https://github.com/user-attachments/assets/d926574b-d6e8-4d4e-95af-579dc91777d6" />

### 2. Email Analysis

The raw email was retrieved from the email security platform for analysis. The email used a common social engineering tactic, offering a free voucher to entice the user to click a link or open an attachment.

<img width="863" height="625" alt="image" src="https://github.com/user-attachments/assets/29f72b81-785d-4ab2-bb0d-bf9322150157" />

### 3. Threat Intelligence Analysis

Both the embedded link and the attached file (`59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip`) were analyzed using VirusTotal. The results confirmed that the artifacts were malicious.

<img width="1693" height="846" alt="image" src="https://github.com/user-attachments/assets/32d7b38c-aa45-4ad4-853e-21baa3f5a032" />

VirusTotal provided a critical piece of intelligence linking the artifacts to a known threat actor:
> **"Activity related to SILENTBUILDER - according to source Cluster25 - 1 year ago. This DOMAIN is used by SILENTBUILDER. SilentBuilder is a dropper and downloader used by a subgroup of Conti."**

This confirms the email is not just simple phishing but a delivery mechanism for a dangerous malware dropper, potentially leading to a ransomware attack.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Log Management, Email Security Gateway, VirusTotal
*   **Skills Demonstrated:** Phishing Analysis, Email Header Analysis, Threat Intelligence Correlation, Incident Triage.

## Playbook Solution: Incident Classification

*   **Was the Email Delivered to the User?** **Yes.** Confirmed by logs and the `Device Action: Allowed` status.
*   **Are there URLs or Attachments?** **Yes.** Both a malicious link and a malicious ZIP file were present.
*   **Analyze URL/Attachment:** **Malicious.** Confirmed by VirusTotal as being associated with the SILENTBUILDER malware dropper.
*   **Did the User Open the Malicious Content?** **Yes.** The user opened the malicious file/URL, indicating a likely endpoint compromise.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC282 is a **true positive** for a successful phishing attack. A malicious email containing a dropper for the SILENTBUILDER malware was delivered to and opened by a user. This represents a significant security breach and an active threat to the network, requiring immediate escalation and response.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the user's machine (Felix's device) from the network to prevent any malware from spreading or communicating with C2 servers.
2.  **ESCALATE - Activate Incident Response Protocol:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for forensic analysis of the compromised endpoint.
3.  **REMEDIATE - Delete Malicious Email:** Use the email security gateway to find and delete this email from the recipient's inbox and search for and purge any similar emails sent to other users in the organization.
4.  **BLOCK INDICATORS:** Add the sender's email (`free@coffeeshooop.com`), domain (`coffeeshooop.com`), IP address (`103.80.134.63`), and the malicious URL/attachment hash to the organization's blocklists.
5.  **INVESTIGATE:** The IR team must determine if SILENTBUILDER successfully downloaded a secondary payload (e.g., Cobalt Strike, Conti ransomware) and check for signs of persistence or lateral movement.

