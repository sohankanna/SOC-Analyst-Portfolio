# SOC102 - Proxy - Suspicious URL Detected (Event ID:66)


## Executive Summary

On February 22, 2021, the Security Operations Center (SOC) received an alert for a "Suspicious URL Detected" originating from the host **ChanProd** (172.16.17.150). The investigation confirmed that the user `Chan` was accessing a legitimate and well-known cybersecurity news website, **threatpost.com**. The alert was triggered because the URL slug of the article being read contained keywords such as "malformed-url" and "phishing-attacks." Threat intelligence analysis confirms the domain is clean and the activity is benign. The alert is therefore classified as a **False Positive** caused by an overly broad keyword-matching rule.

## Incident Details

The initial alert was triggered by keywords within a legitimate URL:

<img width="1452" height="495" alt="image" src="https://github.com/user-attachments/assets/8cf1572b-a972-4740-9e0c-bd5336155590" />

| | |
| :--- | :--- |
| **Date of Incident**| February 22, 2021 |
| **Source Host**| ChanProd (172.16.17.150) |
| **Username**| Chan |
| **Destination Host**| threatpost.com (35.173.160.135) |
| **Request URL**| `https://threatpost.com/malformed-url-prefix-phishing-attacks-spike-6000/164132/` |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/66))* |

## Investigation and Analysis

### 1. Alert Context and Triage

The rule `SOC102 - Proxy - Suspicious URL Detected` is likely designed to use pattern or keyword matching to identify URLs that contain terms commonly associated with malicious activity. In this case, the URL slug `/malformed-url-prefix-phishing-attacks-spike-6000/` contains the strings "phishing-attacks" and "malformed-url," which almost certainly caused the rule to trigger.

### 2. Threat Intelligence and Contextual Analysis

The investigation focused on verifying the legitimacy of the destination and the context of the user's activity.
*   **Domain Analysis (VirusTotal):** A check of the requested hostname, `threatpost.com`, on VirusTotal shows **zero detections**. Threatpost is a widely recognized and reputable source for cybersecurity news and research.
    <img width="1750" height="788" alt="image" src="https://github.com/user-attachments/assets/8bc6dc9d-1deb-43db-b89b-212114a35f5c" />
*   **Contextual Analysis:** The full URL path indicates the user was not visiting a phishing site but was reading an *article about* phishing attacks. This is a benign, and often encouraged, activity for an employee staying current on security threats. The `Device Action: Allowed` is the correct behavior for traffic to a legitimate news site.

### 3. Final Assessment

The evidence confirms that this was a benign event. A security-conscious user was reading a relevant news article, and the SIEM rule generated a false positive due to its inability to differentiate between a URL that *is* malicious and a URL that is *about* something malicious.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy Logs, VirusTotal
*   **Skills Demonstrated:** False Positive Analysis, Contextual Triage, Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Non-malicious.** The URL is for a legitimate news article on a reputable website.
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC102 was a **false positive**. The investigation confirmed that a user was accessing a legitimate cybersecurity news article. The alert was triggered by a naive keyword-matching rule that lacked the context to understand the nature of the content.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive, with notes detailing the findings.
2.  **Rule Tuning:** This event highlights a clear need for rule tuning to reduce alert fatigue. The SOC team should modify the `SOC102` rule by creating an "allowlist" or exception for well-known, reputable cybersecurity news domains. This list should include sites like:
    *   `threatpost.com`
    *   `bleepingcomputer.com`
    *   `krebsonsecurity.com`
    *   `thehackernews.com`
    *   `darkreading.com`

    By whitelisting these domains, the rule can continue to find genuinely suspicious URLs without generating false positives when employees are conducting security-related research.
