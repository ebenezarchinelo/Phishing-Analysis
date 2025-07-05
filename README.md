# Phishing Email Analysis Report

## Introduction <a id="introduction"></a>
This project involved a detailed analysis of a suspicious email claiming to originate from Binance with the subject "Binance cybersecurity". It states that the recipient’s email was found in a database of leaked personal data from crypto projects.  The Cybersecurity Department detected over 120 leaks involving the recipient’s data. A checkbox option prompts the user to "Get Compensated in Bitcoin." As a SOC analyst, I investigated the email's legitimacy using tools like MXToolbox, VirusTotal, and AbuseIPDB. This report documents my methodology, findings, and recommendations showcasing email analysis as one of my SOC skills.

## Objective <a id="objective"></a> 
The goal of the analysis was to determine the emails's authenticity by analyzing its headers, IP origins, authentication status, and content. I examined email headers, authentication protocols, and senders details, discovering multible indicators of spoofing.

## Methodology <a id="methodology"></a> 


Key Findings
✅ Confirmed Malicious by multiple vendors (VirusTotal)
✅ Spoofed Domain: netwrksecurity.com (not affiliated with MetaMask)
✅ Credential Harvesting: Fake "verification" page mimics MetaMask
✅ Urgency Tactics: Fake deadline (September 12, 2022) to pressure victims

## 2. Headers
Date:
Subject:

To:
From:

Reply-To:
Return-Path:

Sender IP:
Resolve Host:

Message-ID:
Phishing Analysis Report Template

Headers
======================================
Date:
Subject:

To:
From:

Reply-To:
Return-Path:

Sender IP:
Resolve Host:

Message-ID:


URLs
=======================================



Attachments
======================================
Attachment Name:
MD5:
SHA1:
SHA256:


Description
======================================



Artifact Analysis
======================================
Sender Analysis:


URL Analysis:


Attachment Analysis:



Verdict
======================================



Defense Actions
======================================


