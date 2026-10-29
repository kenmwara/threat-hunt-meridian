<!-- banner --><a href="https://github.com/kenmwara"><img src="https://raw.githubusercontent.com/kenmwara/kenmwara/main/assets/brand/card-meridian.png?v=25533da69c" width="100%" alt="Meridian: A compromised Linux web server: path traversal, a reused service-account password and a root backdoor. 16/16 flags · full marks."></a>

# Meridian: a hacked Linux web server

**An attacker broke into the Linux web server behind a patient portal. A flaw in one web page let them read files on the server, one of those files held a password, and 57 seconds later they logged in with it. They took full control, exported patient data through the website, and planted a hidden backdoor. The server's own defences flagged the backdoor but never removed it, so the incident was not contained when the logs end.**

**Analyst:** Ken Kariuki · **Live hunt:** 26 September 2026 ([Cyber Range](https://www.skool.com/cyber-range) Hunt 25) · **Result:** all 16 questions answered, full marks (1,675 of 1,675), on time

## Key takeaways

<img src="images/scorecard.png" width="100%" alt="Key takeaways. A website flaw led to full control, and a backdoor was still running at the end. 57 s: From leaked password to login. A website flaw exposed a settings file with a password. 57 seconds later the attacker logged in with it. 73: Attempts to phone home. A hidden backdoor tried 73 times to contact the attacker. The firewall blocked the traffic, not the program. 1: Backdoor never removed. The server's defences flagged it but left it running. The attack wasn't over. 0: Record of running programs. A clean-up routine had switched off the tool that records them, before the attack began. 16 / 16: Every question answered. Full marks, on time.">

## How the attack unfolded

<img src="images/story.png" width="100%" alt="Meridian: how the attack unfolded. 6 February 2026, times in UTC. 03:47 – 03:56, Looking around: 03:47 · The attacker scans the portal's website with four tools; 03:53 · Gets into the website's dashboard; 03:56 · Patient data is exported through the website. 04:07 – 04:09, The leak: 04:07 · A page flaw lets them read files on the server; 04:08 · One file holds a service account's password; 04:09 · 57 seconds later they log in with it. 04:15 – 04:51, Taking over: 04:15 · The account isn't allowed to run admin commands; 04:40 · A hidden copy of the command shell gives full (root) control anyway; 04:51 · A second copy is planted, disguised as a routine health check. 04:48 – 05:30, Still running: 04:48 · The backdoor tries 73 times to reach the attacker; the firewall blocks each try; 05:05 · The server's clean-up removes the first copy but only flags the backdoor; 05:30 · The backdoor is still running when the logs end.">

## What went wrong, and the fix

<img src="images/gaps.png" width="100%" alt="What went wrong, and how to fix it. What went wrong: Nothing recorded which programs ran. Why it mattered: The server's own clean-up removed that recorder (Sysmon) before the attack began. The fix: Restore it, and stop the clean-up from removing it. What went wrong: A web page read any file it was asked for. Why it mattered: It leaked the user list and a file with a password. The fix: Only allow a fixed list of files. What went wrong: A password sat in a file the website could read. Why it mattered: The attacker logged in with it 57 seconds later. The fix: Move passwords out of website files, and change this one. What went wrong: The backdoor was flagged but never removed. Why it mattered: It kept running with full control to the end. The fix: Let the check remove what it finds, or alert a person the first time. What went wrong: Audit rules watched only one folder. Why it mattered: The backdoor was planted somewhere else, unseen. The fix: Also watch permission changes and the app's own folders.">

## What to do now

1. Stop and delete the backdoor (`/opt/meridian/scripts/health_check`), then check the server for others.
2. Change the service account's password and the database password.
3. Keep blocking the attacker's address, in and out.
4. Keep the memory capture the admin took, and analyse it for the backdoor's settings.
5. Treat the patient data export as a reportable breach and start notification.

## The full report

This page is the short version. The full incident report covers the hunt's method, every finding with its evidence,
the attacker techniques seen (MITRE ATT&CK), the new alert rules and how they were tested, and the indicators.

- **[The full report (REPORT.md)](REPORT.md)**, readable on GitHub.
- **[The report as a PDF](Meridian-Threat-Hunt-Report.pdf)**, as submitted.

---

*More hunts: [kenmwara/threat-hunts](https://github.com/kenmwara/threat-hunts).*
