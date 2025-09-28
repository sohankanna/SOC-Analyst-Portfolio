# SOC120 - Phishing Mail Detected - Internal to Internal

## Executive Summary

On February 7, 2021, the Security Operations Center (SOC) received an alert for a potential internal phishing email sent from `john@letsdefend.io` to `susie@letsdefend.io`. An investigation was launched to determine if the sender's account (`john@letsdefend.io`) had been compromised and was being used for a lateral phishing attack. Analysis of the email content revealed a benign, text-only message regarding a business meeting, with no malicious links, attachments, or suspicious language. The activity is consistent with normal business communication. The alert is therefore classified as a **False Positive**, likely triggered by an overly sensitive detection rule.

## Incident Details

The initial alert was triggered by a rule designed to detect internal-to-internal phishing:

<img width="1521" height="546" alt="image" src="https://github.com/user-attachments/assets/057a4cb1-e943-47c5-b1ee-b912b8cc7c8f" />

| | |
| :--- | :--- |
| **Date of Incident**| February 7, 2021 |
| **Source Address**| john@letsdefend.io |
| **SMTP Address**| 172.16.20.3 (Internal Exchange) |
| **Destination Address**| susie@letsdefend.io |
| **Email Subject**| Meeting |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/52))* |

## Investigation and Analysis

### 1. Alert Context: Internal-to-Internal Phishing

The rule `SOC120 - Phishing Mail Detected - Internal to Internal` is an important one. It is designed to detect a scenario where an attacker has already compromised an internal user's account (e.g., through a previous phishing attack) and is now using that trusted, internal account to send phishing emails to other employees. Emails from a known colleague are far more likely to be trusted, making this a dangerous attack vector. Therefore, all such alerts must be investigated.

### 2. Email Content Analysis

The investigation focused on analyzing the actual email that triggered the alert. The email was retrieved from the email security platform.

<img width="1576" height="605" alt="image" src="https://github.com/user-attachments/assets/4e8c6805-3dcc-4ad7-b89b-59239717f63d" />

The analysis revealed a complete lack of any phishing indicators:
*   **No Malicious Links:** The email body did not contain any URLs, malicious or otherwise.
*   **No Attachments:** There were no files attached to the email.
*   **Benign Content:** The subject ("Meeting") and the body ("Hi, Could you please give me a time for our meeting tomorrow?") are consistent with standard, professional business communication.
*   **No Urgency or Threats:** The email did not use common phishing tactics like creating a false sense of urgency, making threats, or requesting sensitive information.

### 3. Final Assessment

The evidence overwhelmingly indicates that this was a legitimate email sent between two colleagues. The `Device Action: Allowed` is the correct and expected behavior for normal email flow. The security rule likely triggered based on a very broad or poorly tuned set of criteria, leading to a false positive.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Email Security Gateway
*   **Skills Demonstrated:** False Positive Analysis, Phishing Triage, Understanding of Lateral Phishing TTPs.

## Playbook Solution: Incident Classification

*   **Analyze Malware/Email:** **Non-malicious.** The email is legitimate business correspondence.
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC120 was a **false positive**. The investigation confirmed that a legitimate internal email was incorrectly flagged as phishing by an automated detection rule. No malicious activity occurred, and no user accounts are compromised.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive, with a note explaining that the email was verified as benign.
2.  **Rule Tuning:** The SOC team should review the logic for the rule `SOC120 - Phishing Mail Detected - Internal to Internal`. To reduce the number of false positives, the rule should be tuned to require more specific indicators of phishing (e.g., the presence of a URL, specific keywords associated with scams, or an unusual sending pattern) before generating a high-priority alert.


