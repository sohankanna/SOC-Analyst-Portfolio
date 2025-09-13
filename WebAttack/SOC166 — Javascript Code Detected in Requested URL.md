# SOC166 — Javascript Code Detected in Requested URL

## Executive Summary

On February 26, 2022, the Security Operations Center (SOC) detected and investigated a series of web attacks targeting **WebServer1002** (172.16.17.17). The attacks, originating from the external IP address **112.85.42.13**, were identified as Cross-Site Scripting (XSS) attempts. The attacker tried to inject malicious JavaScript code through a URL query parameter. Log analysis revealed that the web server consistently responded with an HTTP 302 redirect and a response size of zero, indicating that the malicious payloads were never processed or reflected back to a client. Threat intelligence confirmed the source IP has a history of malicious activity. The incident is classified as a **True Positive**, but the attack was **unsuccessful** and required no escalation.

## Incident Details

The initial alert was triggered by a suspicious URL request:

<img width="1225" height="418" alt="image" src="https://github.com/user-attachments/assets/14aef6b4-f2e7-465b-a2be-5eace3d99f12" />

| | |
| :--- | :--- |
| **Date of Incident** | February 26, 2022 |
| **Source IP Address** | 112.85.42.13 |
| **Destination Host** | WebServer1002 (172.16.17.17) |
| **Attack Type** | Cross-Site Scripting (XSS) |
| **Malicious Payload** | `https://172.16.17.17/search/?q=<$script>javascript:$alert(1)<$/script>` |

## Investigation and Analysis

### 1. Initial Alert and Payload

The alert was triggered by a URL containing a clear attempt to inject JavaScript. The payload, `javascript:$alert(1)`, is a classic proof-of-concept used in XSS attacks. If successful, it would execute in a user's browser, demonstrating a vulnerability. The attacker used malformed tags (`<$script>`) in an attempt to bypass basic security filters.

### 2. Log Analysis

A review of the network logs for the source IP address revealed a pattern of repeated XSS attempts against the web server.

<img width="1370" height="600" alt="image" src="https://github.com/user-attachments/assets/d154431b-932d-4aae-8d65-c6715b712d09" />


Several variations of the payload were observed across multiple log entries:
<img width="597" height="318" alt="image" src="https://github.com/user-attachments/assets/c82561b4-5e67-4682-a126-69b5a56f4ba0" />

<img width="630" height="361" alt="image" src="https://github.com/user-attachments/assets/9c3df134-aafa-42aa-ab6a-2df31ecc9b51" />
<img width="621" height="351" alt="image" src="https://github.com/user-attachments/assets/b1352be3-7d23-4718-940f-bfa95ce00c14" />

Crucially, the server's response to each of these malicious requests was an **HTTP Status Code 302 (Redirect)** with a **Response Size of 0**. This is key evidence that the attack failed for two reasons:
1.  **302 Redirect:** The server instructed the client to navigate to a different page *before* it processed and rendered the content containing the malicious payload. The XSS code was never in a position to be executed.
2.  **Zero Response Size:** A zero-byte response body confirms that no content, especially the attacker's injected script, was sent back to the client. For a reflected XSS attack to succeed, the malicious code must be "reflected" in the server's response.

### 3. Threat Intelligence

The source IP address `112.85.42.13` was analyzed using AbuseIPDB to assess its reputation. The platform confirmed that the IP has been reported multiple times for malicious activities.

<img width="1012" height="650" alt="image" src="https://github.com/user-attachments/assets/2b91dac7-d561-4dd0-b981-f4c3bfac6306" />

This confirms the malicious intent of the traffic and that the attack was not an accidental or benign event.

## Skills and Tools Utilized

*   **Tools Used:** SIEM / Log Management, AbuseIPDB
*   **Skills Demonstrated:** Web Attack Analysis (XSS), Log Correlation, HTTP Protocol Analysis, Threat Intelligence.

## Playbook Solution: Incident Classification

*   **Is the Traffic Malicious?** **Yes.** The traffic contained clear and repeated XSS payloads.
*   **What Is the Attack Type?** **Cross-Site Scripting (XSS).**
*   **Was the Attack Successful?** **No.** The server's redirect mechanism and zero-byte response prevented the malicious script from being executed.
*   **Do You Need Tier 2 Escalation?** **No.** The attack was automatically thwarted by the server's configuration, and no compromise occurred.
*   **Incident Classification:** **True Positive.** The alert correctly identified a genuine web attack attempt.

## Conclusion and Recommendations

The alert for SOC166 was a **true positive** for a series of attempted XSS attacks originating from a known malicious IP address. The investigation confirmed that the web application's configuration, which issued a redirect in response to the malformed requests, effectively neutralized the threat. The attack was unsuccessful, and no systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention of the attack by the current server configuration. This behavior should be confirmed as an intended security feature.
2.  **Block Malicious IP:** Add the source IP address `112.85.42.13` to the network firewall's blocklist to prevent any further attempts from this actor.
3.  **Review WAF Rules:** While the attack failed, it provides an opportunity to ensure that the Web Application Firewall (WAF) has specific rules in place to detect and block XSS patterns proactively.
