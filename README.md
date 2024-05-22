# Practical Exercises of Attack and Defence

###  Introduction
While learning and getting into the field of Cybersecurity, to gain some more practical knowledge, I’ve decided on going through Eric Capuano's blog series, "So You Want to Be a SOC Analyst?". This class gave practical, hands-on experience in cybersecurity, from establishing a secure environment to recognizing and mitigating risks. Here, I document my process and significant activities from each installment of the series.

Eric Capuano's blog post:
https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro

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

![Screenshot (14)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/a1486004-8dc4-4180-b50d-36bfc2bad9d4)
![Screenshot (16)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/b8f19297-cb39-4f9a-82c9-b850fdd253c6)
![Screenshot (17)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/4d776619-fe1a-489c-a0d3-b44f5415396d)
![Screenshot (18)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/4bafb2b9-1ee4-42f3-b35c-de4d25462a2f)
![Screenshot (19)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/225bc409-700f-4db1-a450-3322cb24e53e)
![Screenshot (20)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/102f3b7d-e0d1-4479-972e-80ceb9065ed8)
![Screenshot (21)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/2e2235ac-b81c-43d1-9799-bfdf3daf855e)
![Screenshot (22)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/f31b6fc3-9ca9-42f0-b9d2-b5c79024c20c)
![Screenshot (23)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/0b32cd92-cf87-4fb6-aff0-acd7c170e224)
![Screenshot (24)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/b76dfc79-6f3d-460a-92fe-47ed43d1c012)


####  Observing EDR Telemetry
Using the telemetry data from LimaCharlie’s EDR platform, I monitored the activities performed through the C2 connection. This included observing process trees, network connections, and other system behaviors that indicated a compromise.

![Screenshot (26)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/3030eb42-76cf-4955-b3de-36f63574c0bb)
![Screenshot (27)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/b87c839e-01cb-4990-810f-51d992ca815b)
![Screenshot (28)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/f854d7ce-515e-4aee-ba94-c6f03e23854c)
![Screenshot (29)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/f71ddb11-154b-4ef8-b1fd-02efc214f748)
![Screenshot (30)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/7770291a-d7b6-480a-beff-f7ec48014eca)
![Screenshot (31)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/70183013-c021-41b3-ae81-a67f6a30d3de)


Simulating adversarial actions provided me with vital insights into attacker tactics, methods, and procedures (TTPs), allowing me to better recognize and respond to real-world threats.

###  Part 3: Crafting and Detecting Attacks

In the third part of the series, I concentrated on simulating and identifying various attack strategies in order to better understand threat detection.

####  Credential Dumping
To simulate credential theft, I used a tool called `procdump` to dump the `lsass.exe` process memory. This technique is commonly used by attackers to extract credentials from memory.

####  Detecting Malicious Activities
Using LimaCharlie’s EDR, I analyzed the telemetry data generated from the credential dumping activity. This involved identifying key indicators of compromise (IoCs) and creating detection rules to alert on such activities.

![Screenshot (34)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/cf493147-2b38-4833-84d4-8add79c08f7a)
![Screenshot (36)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/c08b560b-ab0e-4551-a476-2b75167ba926)
![Screenshot (37)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/47c223d9-0955-43e7-af9e-494c7bb6dd9a)
![Screenshot (38)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/f9cd0d73-a198-47e9-b1fd-ba363a58b968)
![Screenshot (40)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/3ea4bb74-d4ed-49bf-84a8-3b1992439e3a)


By simulating and detecting these attacks, I gained a better understanding of the techniques used by attackers and the methods to effectively detect and respond to such threats.


###  Part 4: Blocking Attacks

In the fourth part of the series, I focused on creating rules to block specific malicious activities and enhance the security posture of the system.

####  Creating Blocking Rules
I developed a rule to detect and block the deletion of Volume Shadow Copies, a common technique used by ransomware to prevent recovery. This involved setting up a detection rule in LimaCharlie to monitor for the `vssadmin delete shadows /all` command and automatically terminate the parent process executing this command.


####  Testing the Blocking Rules
To ensure the rule's effectiveness, I executed the `vssadmin delete shadows /all` command from the Sliver C2 session and observed the detection and response action in LimaCharlie. The rule successfully identified and blocked the activity, demonstrating its effectiveness in mitigating ransomware attacks.

![Screenshot (42)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/538a3c09-c112-4cf1-92c2-fda2ce112572)
![Screenshot (43)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/16ff28fd-767d-4caa-9d71-0c0224e5e368)
![Screenshot (44)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/d2c1a585-9fb2-4b07-a075-7ef000630712)
![Screenshot (45)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/2eb0a316-1eb9-45e4-aee4-f5d9c28c76b8)


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

![Screenshot (46)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/13b12499-8ea9-4c2c-a30f-cab08adc5f3a)
![Screenshot (47)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/8b21c740-a994-498d-8041-5eb4fbe7e64c)


####  Automating YARA Scans
To ensure continuous monitoring, I automated the YARA scanning process for new executable files in the Downloads directory. This setup allowed for real-time detection of potential threats as soon as new files were added.

![Screenshot (49)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/c3a476c4-a663-4b42-ae2f-768c956fba82)
![Screenshot (50)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/b6af46dc-1fb9-4301-b3ca-abde9bfc97fd)
![Screenshot (51)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/d1192568-4aed-45a1-a236-cab4f0dbd2e2)
![Screenshot (52)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/f987d905-7b1a-4452-a56d-d7b3d122a65e)
![Screenshot (53)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/fe41dde3-ccef-426d-9ed5-77741f01d499)
![Screenshot (54)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/9c52a0d3-505c-4f3d-912c-1dd7abde6ddd)


####  Scanning Processes Launched from Downloads
As part of the automation, I also set up rules to scan any process launched from the Downloads directory. This additional layer of security helps catch any malicious activity that might occur when new executables are run.

![Screenshot (56)](https://github.com/yottam205/SOC-Analyst--Practical-Exercises/assets/117525375/9cdf8120-0ba7-449a-9726-8cc5e73bf00d)


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
