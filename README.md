# Phishing Email Analysis Report

## Introduction <a id="introduction"></a>
This project involved a detailed analysis of a suspicious email claiming to originate from Binance with the subject "Binance cybersecurity". It states that the recipient’s email was found in a database of leaked personal data from crypto projects.  The Cybersecurity Department detected over 120 leaks involving the recipient’s data. A checkbox option prompts the user to "Get Compensated in Bitcoin." As a SOC analyst, I investigated the email's legitimacy using tools like MXToolbox, VirusTotal, and AbuseIPDB. This report documents my methodology, findings, and recommendations showcasing email analysis as one of my SOC skills.

## Objective <a id="objective"></a> 
The goal of the analysis was to determine the emails's authenticity by analyzing its headers, IP origins, authentication status, and content. I examined email headers, authentication protocols, and senders details, discovering multible indicators of spoofing.

## Email Preview <a id="email preview"></a>
 ![wow](https://github.com/user-attachments/assets/c0d87fcd-9770-470c-94c4-4b3f8d05df72)

## Methodology <a id="methodology"></a> 
I conducted a structured analysis of the email in these steps: 
1. Initial triage: quickly assesed and determined the potential impact of this email.
2. Content Examination: analyzed the email content for language, formatting, suspicious elements like reply-to address, undue sense of urgency and other social engineering red flags.
3.  Header Analysis: Extracted and examined email headers to investiage mail transfer agent, trace the message’s path and identify discrepancies. 
4.  sender analysis (IP and Domain Analysis): I used MXToolbox and AbuseIPDB to verify the originating IP and sender domain. carried out email authentication checks by evaluating SPF, DKIM, and DMARC results to assess sender authenticity.
5. Timestamp Verification: Analyzed hop timestamps for anomalies indicating manipulation.

## Tools Used <a id="tools used"></a>
1. Sublime Text for initial email header analysis.
2. MXToolbox: For analyzing headers and email’s server.
3. VirusTotal: To check the domain () Ip address() reputation.
4. AbuseIPDB: To geolocate and assess the originating IP (89.144.44.41).
5. Manual Header Parsing: To extract authentication results and sender details.

## Key Findings <a id="key findings"></a>

### 1. Headers
Subject:Binance Cybersecurity

From:info@libreriacies.es (Non Binace affliated)

Return-Path:info@libreriacies.es (Non Binace affliated)

Domain: 	siapi[.]es (Non Binace affliated)

Sender IP:217[.]18[.]161[.]43 (Defanged IP)

Resolve Host:Trevenque Sistemas De Informacion S.l. (Non Binace affliated)

Message-ID:	<C2C067AE.1670873@libreriacies.es>

### 2. Suspicious Email Routing Path
#### Email Routing Analysis
| Hop | Source | Destination | Status | Notes |
|-----|--------|-------------|--------|-------|
| 1 | `smtp.gmail.com`<br>`43.230.161.16` | `serlogal.arnoia.com` | ❌ Blacklisted | **Spoofed Gmail IP** - Not a valid Google server |
| 2 | `serlogal.arnoia.com`<br>`217.18.161.43` | `BN8NAM12FT011.mail.protection.outlook.com` | ✅ Clean | 6s delay - Suspicious relay before Microsoft |
| 3 | `BN8NAM12FT011...`<br>`2603:10b6:408:106:cafe::a0` | `BN9PR03CA0616.outlook.office365.com` | ✅ Clean | Normal Microsoft internal transfer |
| 4 | `BN9PR03CA0616...`<br>`2603:10b6:408:106::21` | `PH0PR19MB5396.namprd19.prod.outlook.com` | ✅ Clean | Standard Microsoft routing |
| 5 | `PH0PR19MB5396...`<br>`::1` | `MN0PR19MB6312.namprd19.prod.outlook.com` | ❌ Blacklisted | **HTTPS anomaly** - Loopback IP abuse |

### Key Indicators
- 🚩 **Hop 1**: Spoofed Gmail IP (blacklisted)
- 🚩 **Hop 2**: Unverified relay server (`arnoia.com`)
- 🚩 **Hop 5**: Blacklisted destination with HTTPS protocol

### Conclusion
High-confidence phishing attempt with:
- Forged headers
- Suspicious routing path
- Multiple blacklisted nodes	

### 3. Authentication Failures

### 📧 Email Authentication Results

| Check         | Result               | Status Icon | Implications                              |
|--------------|----------------------|-------------|-------------------------------------------|
| **SPF**      | `pass` (217.18.161.43) | ✅          | Sender IP authorized by domain            |
| **DKIM**     | `none` (not signed)  | ❌          | No content integrity protection           |
| **DMARC**    | `bestguesspass`      | ⚠️          | No enforced policy (domain vulnerable)    |
| **Composite**| `pass` (Reason 109)  | ✅          | Microsoft heuristic approval              |

🔍 **Legend**:
- ✅ = Pass
- ❌ = Fail/Missing
- ⚠️ = Partial/Best-Guess

### 4. Suspicious email content
1. The use of Fear and Urgency in Email content
Subject: “Binance Cybersecurity”
Finding: The subject creates a sense of fear and urgency, a strategy to prompt users to click malicious links in the email.
2. The promise of compensation in Bitcoin to bypass critical thinking..
3. Wrong Binance logo.
4. Non-professional content formatting.
5. Generic Greeting.

### 5. Malicious Link

URL: hxxps[://]axobox[.]com/vt/wp-track[.]php (Defanged for safety)

![virus total](https://github.com/user-attachments/assets/8b7e1f4c-3c68-4e15-b941-5976c924724c)
**VirusTotal Report:** - **Detection:** Flagged by multiple vendors as phishing and malicious

## Verdict <a id="verdict"></a> 
This email was confirmed to be a malicious phishing email based on my findings.


## Defense Actions <a id="defense actions"></a>
1. Delete email permanently
2. Immediate Mitigation
Block Malicious Components:
- URLs: `hxxps[://]axobox[.]com/vt/wp-track[.]php`  (phishing link)  
- Domains: `axobox[.]com` , 	siapi[.]es 
- IPs: `217[.]18[.]161[.]43` (sender)  
Quarantine Similar Emails: Filter subjects like [IMPORTANT] Your wallet has been Blocked, Binance or any subject that creates any sense of urgency.

3. At the network level:
- Block Malicious IPs	Block associated IPs (217.18.161.43,43.230.161.16) at the perimeter firewall.
- Sinkhole or Block URLs	Prevent access to hxxps[://]axobox[.]com/vt/wp-track[.]php using proxy filters or DNS sinkholes.
- Monitor for Beaconing Activity	If any user clicked the link, monitor for outbound C2 traffic to related domains/IPs.
- Check for Related IoCs	Search logs for references toserlogal[.]arnoia[.]com, libreriacies[.]es, andaxobox[.]com.

## Recommendations for Users and Organizations <a id="recommendations for users and organizations"></a>
1. Never click links in unsolicited emails.
2. Verify Binance communications via official app only.
3. Train employees to identify urgency-based phishing.


Conclusion
This phishing email analysis project demonstrated my ability to detect and analyze malicious spoofed using industry-standard tools and methodologies. By identifying  indicators of compromise, I confirmed the email as a phishing attempt. The findings exemplifies the value of  email analysis in proactive security measures. I welcome feedback or contributions to improve this analysis, and I’m eager to apply these skills in SOC and  incident response roles.

References
MXToolbox: mxtoolbox.com
VirusTotal: virustotal.com

Disclaimer: This report is for educational purposes only.
