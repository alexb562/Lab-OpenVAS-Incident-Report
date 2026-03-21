# Incident Report - Madrid Logistics
## Executive Summary
CVE 2011- 2523 (vsftpd reverse shell backdoor) was exploited after hours at the logistics company Madrid Logistics, allowing an attacker to enter a vulnerable security team machine as a user, exfiltrate data, and create a script that allowed them to track keystrokes. This was due to an outdated service. The analyst on duty quickly responded to the IDS alert about unusual traffic patterns, blocking the IP and isolating the affected machine for further remediation. All malicious processes were wiped from the system and filters were put into place only allowing trusted traffic. Regular scans of systems have been implemented and scheduled to ensure systems and services are quickly updated when necessary.
## Incident Report - August 13 2025
### Detection
At 23:36:49 CET the Intrusion Detection System (IDS) connected to the security team network detected a reverse shell connection from a security team machine Linux Ubuntu 22.04 LTS with IP 187.156.1.47 to suspicious IP 225.1.1.57. The IDS signaled this as a suspicious IP at non-business hours.
### Investigation
- 23:48:51 CET analyst confirms non-whitelisted address
- Analyst checks logs in /var/log/syslog and /var/log/auth.log
- 3 logs of interest
```bash
Aug 13 23:37:49 hostname vsftpd[6200]: [NOTICE] FTP session opened for user 'ftp' from 225.1.1.57
Aug 13 23:38:16 hostname kernel: [123456.789012] OUTBOUND: 187.156.1.47:21 -> 225.1.1.57:4444, 150MB transferred
Aug 13 23:39:48 hostname systemd[1]: Started /usr/bin/python3 /tmp/security.py
```
- Attacker gained access through a vfstpd vulnerability which affects a server that runs FTP (file transfers).
