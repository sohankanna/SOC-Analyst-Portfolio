# SOC102 - Proxy - Suspicious URL Detected (Event ID:35)


## Executive Summary

On December 6, 2020, the Security Operations Center (SOC) received an alert for a suspicious URL accessed from the host **Aldo** (172.16.17.51). The investigation confirmed that the user `aldo` downloaded a PowerShell script (`swiftcopy.ps1`) from the domain `interalliance.org`. While initial reputation checks on the domain were inconclusive, dynamic sandbox analysis of the downloaded script confirmed it was malicious. Endpoint security logs provided the "smoking gun," showing the execution of `iexplore.exe` as a child process of the initial download, a behavior matching the sandbox report. The `Device Action: Allowed` confirms the script was successfully downloaded. The host is compromised.

## Incident Details

The initial alert was triggered by a URL request for a PowerShell script:

<img width="1462" height="559" alt="image" src="https://github.com/user-attachments/assets/e73bde0e-e802-4fcc-b462-ed7df0ef5fa0" />

| | |
| :--- | :--- |
| **Date of Incident**| December 6, 2020 |
| **Source Host**| Aldo (172.16.17.51) |
| **Username**| aldo |
| **Malicious Domain**| interalliance.org (66.198.240.56) |
| **Malicious File**| `swiftcopy.ps1` |
| **Attack Type**| Malware Download / Script Execution |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/35))* |

## Investigation and Analysis

### 1. Alert Triage and Log Analysis

The investigation began by analyzing the alert details, which pointed to the download of a PowerShell script, a common vector for "fileless" or "living-off-the-land" attacks.
*   **Log Confirmation:** A review of the proxy logs confirmed that the user's `chrome.exe` process made a GET request for the URL `https://interalliance.org/come2/holme/folde/swiftcopy.ps1`. The `Device Action: Allowed` indicates the download was successful.
    <img width="1493" height="223" alt="image" src="https://github.com/user-attachments/assets/89651bc2-ede0-43b0-876d-12f314c2a076" />

### 2. Threat Intelligence (Static vs. Dynamic)

Initial threat intelligence checks were misleading, highlighting the importance of deep analysis.
*   **Static Analysis (VirusTotal):** A check of the domain `interalliance.org` on VirusTotal showed **zero detections**. The domain itself appears to be legitimate ("INTERalliance Of Greater Cincinnati"), suggesting it was likely **compromised** by an attacker to host their malicious script, rather than being a purpose-built malicious domain.
    <img width="1633" height="779" alt="image" src="https://github.com/user-attachments/assets/1fb93d66-7b00-4745-a6a7-9fda5bc4af0d" />
*   **Dynamic Analysis (Hybrid Analysis):** Submitting the script for sandbox analysis revealed its true malicious nature. The report shows the script, once executed, contacted other hosts and spawned an `iexplore.exe` process. This is a highly suspicious behavior for a script and is a strong indicator of compromise.
    <img width="1804" height="861" alt="image" src="https://github.com/user-attachments/assets/886ae6b5-a4ac-4f87-9e4e-bab7752c89af" />

### 3. Confirmation of Successful Execution

Endpoint security logs provided the definitive proof that the downloaded script was executed.
*   **Endpoint Logs:** The EDR logs show the execution of `iexplore.exe` on the host "Aldo." The MD5 hash of this process, `b015ecd030da9a979e6d1a3d25f8fd8`, matches indicators of malicious activity. This action directly correlates with the behavior observed in the Hybrid Analysis sandbox, confirming that the downloaded `swiftcopy.ps1` script successfully ran and executed its payload.
    <img width="1034" height="172" alt="image" src="https://github.com/user-attachments/assets/63286548-1749-496d-9948-259a6daa29b6" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Proxy Logs, VirusTotal, Hybrid Analysis
*   **Skills Demonstrated:** Log Correlation, Differentiating Static vs. Dynamic Analysis, Compromised Website Triage, Script-Based Attack Analysis.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It involved the download and execution of a confirmed malicious PowerShell script.
*   **What Is The Attack Type?** **Malware / Script-Based Attack.**
*   **Was the Attack Successful?** **Yes.** The script was downloaded and successfully executed its payload on the endpoint.
*   **Do You Need Tier 2 Escalation?** **Yes.** A successful malware execution on a host is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC102 was a **true positive**. A user downloaded and executed a malicious PowerShell script hosted on a compromised but otherwise legitimate website. The host **Aldo** is compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **Aldo** (172.16.17.51) from the network to prevent any further C2 communication or lateral movement.
2.  **CREDENTIALS - Disable and Reset:** Immediately disable the `aldo` user account and reset their password.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full forensic investigation.
4.  **INVESTIGATION:** The IR team must perform a full forensic analysis to determine the ultimate goal of the malware. What did the `iexplore.exe` process do? Did it establish persistence? Was data exfiltrated?
5.  **RECOVERY:** The compromised host must be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:**
    *   **URL:** Block the full malicious URL `https://interalliance.org/come2/holme/folde/swiftcopy.ps1` at the web proxy.
    *   **Hash:** Add the hash of the malicious `iexplore.exe` process (`b015ecd030da9a979e6d1a3d25f8fd8`) to the EDR blocklist.
7.  **NOTIFICATION:** It is good practice to notify the legitimate owners of `interalliance.org` that their website has been compromised and is being used to host malware.























