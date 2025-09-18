# SOC342 - CVE‑2025‑53770 SharePoint ToolShell Auth Bypass and RCE

## Executive Summary

On July 22, 2025, the Security Operations Center (SOC) detected the successful exploitation of **CVE-2025-53770**, a critical zero-day vulnerability in SharePoint Server known as **"ToolShell."** The investigation confirmed that an external attacker from IP **107.191.58.76** achieved unauthenticated Remote Code Execution (RCE) against the **SharePoint01** server (172.16.20.17). Post-exploitation activity, captured by endpoint security logs, reveals the attacker deployed a web shell, compiled custom code, and exfiltrated critical cryptographic MachineKeys from the server. This is a **True Positive** for a full system compromise by a sophisticated actor and requires immediate, full-scale incident response.

## Incident Details

The initial alert was triggered by a request matching the specific exploit pattern for the ToolShell vulnerability:

<img width="1561" height="585" alt="image" src="https://github.com/user-attachments/assets/f6099579-7b50-4436-af6a-716eb47d07aa" />

| | |
| :--- | :--- |
| **Date of Incident**| July 22, 2025 |
| **Attacker IP**| 107.191.58.76 |
| **Destination Host**| SharePoint01 (172.16.20.17) |
| **Attack Type**| Auth Bypass & Remote Code Execution (CVE-2025-53770) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/320))* |

## Investigation and Analysis

### 1. Vulnerability Profile: CVE-2025-53770 (ToolShell)

**CVE-2025-53770**, nicknamed **"ToolShell"**, is a critical zero-day vulnerability in on-premises SharePoint Server deployments. It is a chained exploit that combines an authentication bypass with a remote code execution flaw.

*   **How it Works:** The attacker sends a specially crafted POST request to the `/ToolPane.aspx` endpoint. Key indicators of the exploit, as seen in the alert, are a spoofed `Referer` of `/_layouts/SignOut.aspx` (to trick the server into treating the request as unauthenticated) and a large `Content-Length`. This request allows the attacker to bypass authentication and upload a payload that is then executed by the server's IIS worker process (`w3wp.exe`) with the permissions of the application pool user.
*   **Impact:** Successful exploitation results in full RCE, giving the attacker the ability to run arbitrary commands, deploy web shells, steal data, and pivot deeper into the network.

### 2. Attack Chain Reconstruction: From Exploit to Data Theft

The investigation reveals a clear, multi-stage attack chain confirmed by network, endpoint, and threat intelligence data.

**Stage 1: The Initial Exploit**
The raw log shows the malicious POST request that triggered the vulnerability. The `Device Action: Allowed` confirms it was not blocked.

<img width="641" height="504" alt="image" src="https://github.com/user-attachments/assets/4c304bd8-208a-4bcc-9c60-4bec7a6f0410" />

**Stage 2: Post-Exploitation Activity (Confirmed by EDR)**
The endpoint security logs show exactly what the attacker did immediately after gaining RCE.

<img width="1177" height="526" alt="image" src="https://github.com/user-attachments/assets/2bacb6ad-cea2-4928-b7a1-1624fe7ac3f8" />

*   **Action 1: Web Shell Deployment:**
    *   **Command:** `cmd.exe /c echo <form...> > C:\...LAYOUTS\spinstall0.aspx`
    *   **Explanation:** The attacker used `cmd.exe` to write an ASPX file named `spinstall0.aspx` into a web-accessible SharePoint directory. This file is a web shell, a backdoor that allows the attacker to easily execute commands in the future by simply visiting the page in a browser. This matches the TTPs described in the CTI report for this threat actor.

*   **Action 2: Custom Code Compilation (Living-off-the-Land):**
    *   **Command:** `csc.exe /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs`
    *   **Explanation:** The attacker used the legitimate Microsoft C# compiler (`csc.exe`) to compile a C# source file (`payload.cs`) into an executable (`payload.exe`). This is a common LOLBin (Living-off-the-Land Binaries) technique used to create malicious tools on the fly and evade detection that relies on known-bad file hashes.

*   **Action 3 & 4: Exfiltration of Cryptographic Keys:**
    *   **Commands:** The PowerShell command `[System.Web.Configuration...GetApplicationConfig()]` and the decoded C# code from the payload.
    *   **Explanation:** Both of these commands are designed to perform the same critical action: steal the ASP.NET **MachineKeys**. These cryptographic keys (`ValidationKey`, `DecryptionKey`) are used by SharePoint to encrypt and validate session state (like ViewState cookies). By stealing these keys, the attacker can forge valid session cookies for any user, including administrators, allowing them to maintain persistent, authenticated access to the SharePoint farm even if passwords are changed or the initial vulnerability is patched. This is the ultimate goal of the attack, as described in the CTI.
    <img width="1546" height="857" alt="image" src="https://github.com/user-attachments/assets/ca17b422-3e85-4074-82d5-2b2b3946d409" />

### 3. Threat Intelligence and Attribution

The provided CTI correlates this activity with a threat actor cluster tracked as **CL-CRI-1040** (which overlaps with Microsoft's **Storm-2603**).
*   **Systematic Targeting:** The CTI shows the attacker uses a systematic approach, first performing reconnaissance from one set of IPs (often privacy networks like SPN) before launching the actual exploit from a different set of IPs, including the one in this alert (`107.191.58.76`).
*   **Payload Evolution:** The actor is known to be adaptive, switching between .NET modules and web shells like `spinstall0.aspx` to achieve their goal of stealing MachineKeys. The activity in this alert perfectly matches "Variation 2" described in the CTI.
*   **IP Reputation:** VirusTotal confirms the attacker's IP is malicious, with 15 vendors flagging it.
    <img width="1654" height="846" alt="image" src="https://github.com/user-attachments/assets/4ba05240-fc70-4a44-b294-43751129cebf" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, VirusTotal, CyberChef
*   **Skills Demonstrated:** RCE Analysis, Vulnerability Triage (CVE-2025-53770), CTI Synthesis, LOLBin Technique Recognition, Post-Exploitation Analysis.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It's a successful zero-day RCE from a known-bad IP.
*   **What Is The Attack Type?** **Remote Code Execution (RCE).**
*   **Was the Attack Successful?** **Yes.** Confirmed RCE, web shell deployment, and data exfiltration.
*   **Do You Need Tier 2 Escalation?** **Yes.** This is a full compromise of a critical server by a sophisticated actor.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC342 was a **true positive** for a successful RCE attack exploiting the ToolShell zero-day (CVE-2025-53770). The attacker has compromised the SharePoint server, established a web shell for persistence, and exfiltrated critical cryptographic keys that grant them long-term access. The server and all its data are compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Server Immediately:** Disconnect the **SharePoint01** server (172.16.20.17) from the network to prevent further attacker activity.
2.  **PATCH IMMEDIATELY:** Apply the security patches released by Microsoft for CVE-2025-53770 and related vulnerabilities to this and all other SharePoint servers.
3.  **ROTATE MACHINEKEYS:** This is **CRITICAL**. As recommended by Microsoft and the CTI, the ASP.NET MachineKeys **must** be rotated. Failure to do so will allow the attacker to maintain access even after patching and password resets.
4.  **ESCALATE:** Immediately escalate to the Tier 2/Incident Response team for a full forensic investigation.
5.  **INVESTIGATION:** The IR team must assume the attacker has had full control. They need to hunt for the `spinstall0.aspx` web shell, any other dropped files, and evidence of lateral movement or further data exfiltration.
6.  **ERADICATION & RECOVERY:** The server cannot be trusted and must be rebuilt from a known-good backup from *before* the incident date.
7.  **BLOCK INDICATORS:** Block the attacker's IP address `107.191.58.76` and any other IPs identified in the CTI report at the network perimeter.
