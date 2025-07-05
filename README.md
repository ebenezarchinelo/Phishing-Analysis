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

From:info@libreriacies.es

Return-Path:info@libreriacies.es

Sender IP:217[.]18[.]161[.]43
Resolve Host:Trevenque Sistemas De Informacion S.l.

Message-ID:	<C2C067AE.1670873@libreriacies.es>

URLs
=======================================

hxxps[://]axobox[.]com/vt/wp-track[.]php



Artifact Analysis
======================================
Sender Analysis:


URL Analysis:


Attachment Analysis:



Verdict
======================================



Defense Actions
======================================


