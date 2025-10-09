# SOC202 - FakeGPT Malicious Chrome Extension

## Executive Summary

On May 29, 2023, the Security Operations Center (SOC) received a high-severity alert for the installation of a suspicious Chrome extension, `hacfaophiklaeolhnmckojjjjbnappen.crx`, on the host **Samuel** (172.16.17.173). Initial automated threat intelligence scans of the file hash were inconclusive. However, a deeper investigation confirmed that the user was lured by a phishing site (`www.chatgptforgoogle.pro`) into installing the **"ChatGPT for Google"** extension. Further research and context from security vendors revealed this extension is a malicious **information stealer**, specifically designed to harvest Facebook session cookies and exfiltrate them to an attacker's server. The `Device Action: Allowed` and confirmed network connections to attacker-controlled infrastructure indicate a successful compromise and data breach.

## Incident Details

The initial alert was triggered by the installation of a suspicious browser extension:

<img width="1468" height="569" alt="image" src="https://github.com/user-attachments/assets/ca31c490-becd-47a4-8376-c5aa1a4b8304" />

| | |
| :--- | :--- |
| **Date of Incident**| May 29, 2023 |
| **Phishing Site**| `www.chatgptforgoogle.pro` |
| **Exfiltration C2**| `version.chatgpt4google.workers.dev` |
| **Destination Host**| Samuel (172.16.17.173) |
| **Malicious Extension**| "ChatGPT for Google" (`hacfaophiklaeolhnmckojjjjbnappen.crx`) |
| **File Hash (SHA256)**| `7421f9abe5e618a0d517861f4709df53292a5f137053a227bfb4eb8e152a4669` |
| **Attack Type**| Information Stealer / Malicious Browser Extension |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/153))* |

## Investigation and Analysis

### 1. The Lure and Initial Access

The attack began with a user navigating to a convincing but malicious website.
*   **Browser History:** Endpoint logs show that the user `Samuel` visited `www.chatgptforgoogle.pro`. This site likely advertised a fake "ChatGPT for Google" extension, promising to integrate AI features into search results.
    <img width="1506" height="601" alt="image" src="https://github.com/user-attachments/assets/98fe2e63-1592-42ae-ad3c-5c4abc0c6e9b" />
*   **Installation:** The user then downloaded and installed the `.crx` file (a Chrome extension package) from this site. The `Command Line` in the alert shows `chrome.exe` being launched with the path to the downloaded file, which is how a user would manually install a sideloaded extension.

### 2. The Weapon: "FakeGPT" Information Stealer

The core of the attack is the malicious Chrome extension.
*   **Initial Analysis (Misleading):** Initial checks of the file hash on VirusTotal and Hybrid Analysis returned zero detections. This is a common challenge with new or polymorphic threats, especially those that are not traditional executables.
    <img width="1768" height="880" alt="image" src="https://github.com/user-attachments/assets/fb83d793-4936-4bac-8910-87aa0e89a446" />
*   **Deeper Context (The Truth):** Further research revealed the true nature of this extension. Security vendor reports (like the one from Exodia Labs) and historical data from the Chrome Web Store confirm its malicious purpose.
    *   **Functionality:** The extension's code uses the `chrome.cookies.getAll` API to specifically target and collect all active session cookies for `facebook.com`.
    *   **Exfiltration:** It then encrypts these cookies and sends them in a custom HTTP header (`X-Cached-Key`) to a hardcoded C2 server (`version.chatgpt4google.workers.dev`).
    *   **Impact:** Stealing these cookies allows an attacker to bypass passwords and MFA to hijack the victim's Facebook account.
    *   **Takedown:** The extension was later removed from the official Chrome Web Store for containing malware, confirming its malicious status.
        <img width="1865" height="850" alt="image" src="https://github.com/user-attachments/assets/e9b809a2-7d72-4373-a5c6-a1def2cb9017" />

### 3. Confirmation of Success

The investigation confirmed that the extension was installed and began its malicious activity.
*   **Execution:** The alert itself shows the `Device Action: Allowed` and the command line for the installation.
*   **C2 Communication:** Endpoint network logs show `chrome.exe` making connections to multiple attacker-controlled domains immediately after the installation, including the initial phishing site (`www.chatgptforgoogle.pro`) and a related domain (`www.chatgptgoogle.org`). This confirms the extension was active and communicating with its infrastructure.
    <img width="1518" height="582" alt="image" src="https://github.com/user-attachments/assets/b32d3aba-ea1b-42b4-a2a0-e7800e494526" />
    <img width="1343" height="551" alt="image" src="https://github.com/user-attachments/assets/0aae074d-af6d-43f8-914e-59d4c932c182" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Browser History, VirusTotal, Hybrid Analysis
*   **Skills Demonstrated:** Malware Triage (Browser Extensions), Phishing Analysis, Log Correlation, Recognizing limitations of automated scanning.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** The host connected to a phishing site and C2 infrastructure.
*   **What Is The Attack Type?** **Information Stealer / Data Leakage.**
*   **Was the Attack Successful?** **Yes.** The malicious extension was installed and activated.
*   **Do You Need Tier 2 Escalation?** **Yes.** A confirmed data breach (stolen cookies) and an active implant on an endpoint requires escalation.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC202 was a **true positive** for a successful compromise via a malicious Chrome extension. An attacker lured a user into installing a "FakeGPT" extension that acted as an information stealer, specifically targeting Facebook session cookies. The host is compromised, and the user's Facebook account must be considered breached.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **Samuel** (172.16.17.173) from the network to prevent further data exfiltration or C2 communication.
2.  **ERADICATION - Remove Extension and Reset Browser:**
    *   Guide the user or use EDR to manually remove the malicious "ChatGPT for Google" extension from their Chrome browser.
    *   Clear all cookies, cache, and browsing data from the user's Chrome profile.
3.  **CREDENTIALS - Secure Social Media:** Instruct the user to immediately go to Facebook, log out of all active sessions, and change their password. This will invalidate the stolen session cookies.
4.  **ESCALATE:** Escalate this incident to the Tier 2/Incident Response (IR) team for a deeper review.
5.  **INVESTIGATION:** The IR team should analyze the host for any additional malicious activity and review the user's other accounts for signs of compromise, in case other cookies were stolen.
6.  **BLOCK INDICATORS:** Block the following indicators at the perimeter:
    *   **Domains:** `chatgptforgoogle.pro`, `chatgptgoogle.org`, `chatgpt4google.workers.dev`.
    *   **IPs:** `52.76.101.124`, `18.140.6.45`.
    *   **Hash:** `7421f9...4669`.
7.  **USER AWARENESS:** Use this incident to create an awareness bulletin about the dangers of sideloading browser extensions and impersonations of popular AI tools.













