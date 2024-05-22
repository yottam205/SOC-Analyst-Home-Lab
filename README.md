# Practical Exercises of Attack and Defence

###  Introduction
While learning and getting into the field of Cybersecurity, to gain some more practical knowledge, I’ve decided on going through Eric Capuano's blog series, "So You Want to Be a SOC Analyst?". This class gave practical, hands-on experience in cybersecurity, from establishing a secure environment to recognizing and mitigating risks. Here, I document my process and significant activities from each installment of the series.
###  Part 1: Setting Up the Environment

####  Virtualization Setup
To simulate a realistic network environment, I set up a home lab using two virtual machines (VMs):
- **Windows VM**: For testing and simulating attacks.
- **Linux (Ubuntu) VM**: For running various security tools.

####  Disabling Windows Defender
The first step involved disabling Windows Defender on my Windows VM. This was necessary to prevent Defender from interfering with the malware simulations and tests. By modifying Group Policy and registry settings, I ensured that Defender was completely turned off, allowing for unimpeded testing.

![Screenshot (3)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/a1aba564-6bc4-4639-be1a-633688ab15c1)
![Screenshot (4)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/66374add-1e81-42e5-be48-c4052b8979ce)
![Screenshot (6)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/ecf19be4-74d2-43a0-b3ee-261c234afd39)
![Screenshot (8)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/27ad11b9-b41b-4889-bca1-316fe1c6843e)


####  Installing Sysmon
Next, I installed Sysmon on the Windows VM. Sysmon is a powerful system monitoring tool that provides detailed logging of system activities, such as process creations, network connections, and file modifications. This level of logging is crucial for detecting and analyzing suspicious activities within the system.

![Screenshot (10)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/e126aecc-d4e7-481b-9352-9937e917beae)


By setting up this controlled environment, I ensured a stable and secure platform for testing advanced cybersecurity techniques and simulations, establishing the framework for future exploration in the SOC Analyst role.


###  Part 2: Adversary Simulation

In the second part of the series, I focused on simulating adversarial activities to understand how attackers operate and how to detect their actions effectively.

####  Command and Control (C2) Setup
To simulate real-world attacks, I set up a Command and Control (C2) server using Sliver, an open-source C2 framework. This involved generating a payload and deploying it on the Windows VM to establish a communication channel between the attacker (C2 server) and the victim (Windows VM).

####  Executing the Payload
I executed the generated payload on the Windows VM, which initiated a connection back to the C2 server. This setup allowed me to interact with the compromised system through the C2 framework, mimicking the actions of a real attacker.

*Screenshot of C2 setup and payload execution here*
![C2 Setup and Payload Execution](path/to/screenshot4.png)

####  Observing EDR Telemetry
Using the telemetry data from LimaCharlie’s EDR platform, I monitored the activities performed through the C2 connection. This included observing process trees, network connections, and other system behaviors that indicated a compromise.

*Screenshot of EDR telemetry here*
![EDR Telemetry](path/to/screenshot5.png)

Simulating adversarial actions provided me with vital insights into attacker tactics, methods, and procedures (TTPs), allowing me to better recognize and respond to real-world threats.

###  Part 3: Crafting and Detecting Attacks

In the third part of the series, I concentrated on simulating and identifying various attack strategies in order to better understand threat detection.

####  Credential Dumping
To simulate credential theft, I used a tool called `procdump` to dump the `lsass.exe` process memory. This technique is commonly used by attackers to extract credentials from memory.

*Screenshot of credential dumping here*
![Credential Dumping](path/to/screenshot6.png)

####  Detecting Malicious Activities
Using LimaCharlie’s EDR, I analyzed the telemetry data generated from the credential dumping activity. This involved identifying key indicators of compromise (IoCs) and creating detection rules to alert on such activities.

*Screenshot of detecting malicious activities here*
![Detecting Malicious Activities](path/to/screenshot7.png)

By simulating and detecting these attacks, I gained a better understanding of the techniques used by attackers and the methods to effectively detect and respond to such threats.


###  Part 4: Blocking Attacks

In the fourth part of the series, I focused on creating rules to block specific malicious activities and enhance the security posture of the system.

####  Creating Blocking Rules
I developed a rule to detect and block the deletion of Volume Shadow Copies, a common technique used by ransomware to prevent recovery. This involved setting up a detection rule in LimaCharlie to monitor for the `vssadmin delete shadows /all` command and automatically terminate the parent process executing this command.

*Screenshot of blocking rules setup here*
![Blocking Rules Setup](path/to/screenshot8.png)

####  Testing the Blocking Rules
To ensure the rule's effectiveness, I executed the `vssadmin delete shadows /all` command from the Sliver C2 session and observed the detection and response action in LimaCharlie. The rule successfully identified and blocked the activity, demonstrating its effectiveness in mitigating ransomware attacks.

*Screenshot of testing blocking rules here*
![Testing Blocking Rules](path/to/screenshot9.png)

By implementing these blocking rules, I significantly improved the system's defenses against ransomware and other destructive attacks.


###  Part 5: Tuning False Positives

Although I did not participate in the hands-on exercises in Part 5, I watched the accompanying film, which focused on the crucial element of refining detection rules to reduce false positives. This section underlined the need of improving detection mechanisms to enable accurate and reliable threat identification while avoiding overwhelming analysts with unnecessary alarms.

Understanding the video's concepts and techniques provided insights into the ongoing process of improving detection rules, which is critical for maintaining an efficient security monitoring environment.


###  Part 6: Advanced Detection with YARA

In the final part of the series, I delved into advanced detection techniques using YARA rules to identify specific malware signatures.

####  Writing and Testing YARA Rules
I wrote custom YARA rules to detect malicious payloads and tested these rules using LimaCharlie. This involved:
- Creating YARA rules tailored to detect specific characteristics of malware.
- Executing manual YARA scans on the Windows VM to validate the effectiveness of these rules.

*Screenshot of YARA rule testing here*
![YARA Rule Testing](path/to/screenshot10.png)

####  Automating YARA Scans
To ensure continuous monitoring, I automated the YARA scanning process for new executable files in the Downloads directory. This setup allowed for real-time detection of potential threats as soon as new files were added.

*Screenshot of automated YARA scans here*
![Automated YARA Scans](path/to/screenshot11.png)

####  Scanning Processes Launched from Downloads
As part of the automation, I also set up rules to scan any process launched from the Downloads directory. This additional layer of security helps catch any malicious activity that might occur when new executables are run.

*Screenshot of process scanning setup here*
![Process Scanning Setup](path/to/screenshot12.png)

####  Challenges Encountered
While attempting to complete the last part of Part 6, I faced difficulties in stopping the process with:
```
Get-Process [payload_name] | Stop-Process
```
and then running:
```
C:\Users\User\Downloads\[payload_name].exe
```
While everything appeared to execute normally on the system, I was unable to view the expected results in LimaCharlie. This brought to light the difficulties and possible troubleshooting needed for SOC operations in the real world.

I improved my environment's detection capabilities by putting YARA rules into place and automating them. This gave me a strong framework for recognizing and countering malware threats.
