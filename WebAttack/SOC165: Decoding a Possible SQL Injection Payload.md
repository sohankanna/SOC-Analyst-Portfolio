# SOC165: Analysis of a Failed SQL Injection Attack

<img width="1473" height="587" alt="Screenshot 2025-09-12 210445" src="https://github.com/user-attachments/assets/4e353c22-d24d-4576-a194-149e241f45da" />


## Executive Summary

On February 25, 2022, the Security Operations Center (SOC) identified and analyzed a failed SQL injection attempt against webserver1001. The attack originated from the IP address 167.99.169.17 and targeted the server at 172.16.17.18. The server's response with an HTTP 500 Internal Server Error, coupled with the absence of any subsequent malicious activity, confirms that the attack was unsuccessful. Threat intelligence analysis of the source IP revealed a history of suspicious behavior, reinforcing the malicious intent of the request.

## Incident Details

| | |
| :--- | :--- |
| **Date of Incident** | February 25, 2022 |
| **Source IP Address** | 167.99.169.17 |
| **Destination IP Address** | 172.16.17.18 (webserver1001) |
| **Attack Type** | SQL Injection |
| **Payload (URL Encoded)** | `https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20` |
| **Payload (Decoded)** | `https://172.16.17.18/search/?q=" OR 1 = 1 -- ` |

## Investigation and Analysis

### Malicious Payload
<img width="1538" height="644" alt="Screenshot 2025-09-12 210511" src="https://github.com/user-attachments/assets/158c10cc-665c-4c01-a29d-be58a7f1fc89" />
<img width="664" height="368" alt="Screenshot 2025-09-12 210605" src="https://github.com/user-attachments/assets/a093a910-37da-449a-994f-1faeac9e4a41" />

The investigation began with the analysis of a suspicious URL request. The decoded payload, `" OR 1 = 1 -- `, is a classic and well-known SQL injection technique. This string is designed to manipulate the logic of a database query, often to bypass authentication or extract sensitive information. The `OR 1=1` clause creates a condition that is always true, potentially causing the database to return all records from a table. The `--` sequence acts as a comment in SQL, neutralizing the rest of the original query.

### Attack Outcome

Log analysis confirmed that webserver1001 responded to the malicious request with an **HTTP 500 Internal Server Error**. This response indicates that the server encountered an unexpected condition that prevented it from fulfilling the request. In the context of an SQL injection attempt, a 500 error often signifies that the injected query was malformed and could not be executed by the database, effectively thwarting the attack. A thorough review of network logs showed no evidence of further communication from the attacker, such as connections to command-and-control (C2) servers, which further supports the conclusion that the attack was unsuccessful.

### Threat Intelligence

To assess the reputation of the source IP address, it was analyzed using two threat intelligence platforms:

*   **VirusTotal:** This platform showed that only a few security vendors had flagged the IP as malicious. This suggests the IP may not have been widely recognized as a significant threat at the time of the incident.
*   **AbuseIPDB:** In contrast, AbuseIPDB provided multiple reports of malicious activities associated with 167.99.169.17, confirming a history of suspicious behavior. The IP address was traced to DigitalOcean, LLC, in Santa Clara, California, USA. This information provides valuable context about the origin and potential intent of the attacker.

<img width="1844" height="741" alt="image" src="https://github.com/user-attachments/assets/e002fe3a-7900-4710-896b-2ab746a02722" />
<img width="1606" height="831" alt="image" src="https://github.com/user-attachments/assets/f168b391-4de9-4972-b611-c0a9b3d9966c" />


## Playbook Solution: Incident Classification

Based on the investigation, the incident was classified as follows:

*   **Is the Traffic Malicious?** **Yes.** The presence of a clear SQL injection payload indicates malicious intent.
*   **What Is the Attack Type?** **SQL Injection.** The payload is a classic example of this attack vector.
*   **What Is the Direction of Traffic?** **Internet to Company Network.** The request originated from an external IP targeting an internal server.
*   **Was the Attack Successful?** **No.** The HTTP 500 error and lack of further malicious activity confirm the attack failed.
*   **Do You Need Tier 2 Escalation?** **No.** The attack was unsuccessful and contained, negating the need for escalation.
*   **Incident Classification:** **True Positive.** The alert correctly identified a genuine security threat.

## Conclusion

The SOC's detection and analysis capabilities successfully identified and investigated a SQL injection attempt. The server's robust configuration prevented a successful breach, highlighting the importance of secure coding practices and proper error handling. The use of threat intelligence platforms like VirusTotal and AbuseIPDB provided crucial context for a comprehensive incident assessment.
