## Objective

Analyze a phishing email with a malicious .doc attachment and investigate a workstation compromise that leverages VBA macros, Command and Control (C2) communication, and scheduled tasks for persistence.

### Skills Learned

- Email Analysis
  - Extracting and analyzing email metadata and attachments to identify potential threats.
  - Using tools to detect malicious content embedded in .doc files.
- VBA Macro Analysis
  - Extracting and deobfuscating VBA macros from Microsoft Office documents.
  - Understanding macro behavior to identify malicious actions like C2 communication.
- Memory Forensics
  - Using memory analysis tools to investigate volatile data for evidence of malicious activity.
  - Identifying artifacts such as scheduled tasks, malicious payloads, and persistence mechanisms.
- Threat Actor Profiling
  - Correlating attack findings with threat actor TTPs.
  - Assessing the overall impact of the compromise on organizational security.

### Tools Used

- Olevba: Extract and analyze VBA macros from .doc files.
- Volatility: Analyze memory dumps to identify malicious processes, artifacts, and persistence mechanisms.
- VirusTotal: VirusTotal: Analyze file details, reputation scores, and community feedback.
- AbuseIPDB: IP reputation reports and community feedback.
- IPVoid: IP reputation scores and additional information.
- Mozilla Thunderbird: Email client to open the .eml file.
- Sublime Text: Text editor to open the .eml file.

## Practical Exercises

<p align="center">
<img src="https://imgur.com/MspvDbc.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Get the hash value of the provided artefacts.</b>
<br/>

<p align="center">
<img src="https://imgur.com/26iCGrA.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to see what the email's content.</b>
<br/>

<p align="center">
<img src="https://imgur.com/0eiGxDw.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to text editor.</b>
<br/>

<p align="center">
<img src="https://imgur.com/ZH4aJw4.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Extraction of the .eml for IOCs.</b>
<br/>

<p align="center">
<img src="https://imgur.com/4tLQ6Kn.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>ViruTotal: For file reputation. Indicating that Majority of vendors flag as malicious.</b>
<br/>

<p align="center">
<img src="https://imgur.com/m5VN2w6.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Olevba: Parse .doc file for malicious macro. The tool detected a macro routine, named AutoOpen().
  Where there's a GET request to a C2 server. Which the request retrieves update.png file.</b>
<br/>

<p align="center">
<img src="https://imgur.com/S1mbWrO.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Volatilitiy: What Windows version the dumped raw file. Which is a Windows 10 version 1903.</b>
<br/>

<p align="center">
<img src="https://imgur.com/S9K9jvJ.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/NkfZd3n.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Check the process tree. The wscript.exe process which stands out and looks suspicious.</b>
<br/>

<p align="center">
<img src="https://imgur.com/STRF7cz.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>The URL used to download the malicious binary executed by the stage 2 payload.</b>
<br/>

<p align="center">
<img src="https://imgur.com/lprYJn1.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>The malicious process used to establish the C2 connection.</b>
<br/>

<p align="center">
<img src="https://imgur.com/gdRqAXz.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>The IP address and port of the C2 connection initiated by the malicious binary.</b>
<br/>

<p align="center">
<img src="https://imgur.com/yF5jhn6.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/4ZWiXfY.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>IP reputation check for blacklist status.</b>
<br/>

<p align="center">
<img src="https://imgur.com/6xckL1n.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>The attacker set up a scheduled task to maintain persistence, executing a potentially malicious PowerShell script every day at 9:00 AM.</b>
<br/>

## Outcome

- Email Analysis
  - The phishing email with a .doc attachment was successfully analyzed, and malicious VBA macros were extracted.
- VBA Macro Analysis
  - Malicious macros were deobfuscated, revealing C2 communication and the retrieval of an executable payload.
- Memory Forensics
  - The memory dump was analyzed to identify evidence of the executable payload and persistence mechanisms such as scheduled tasks.
- Threat Assessment
  - A comprehensive assessment of the attack's impact was delivered, linking the attack to the Boogeyman threat group.
  - Recommendations for strengthening security measures and mitigating future attacks were provided.

## Acknowledgements

This project combines ideas and methods from various sources, such as the TryHackMe - Boogeyman 2 room and my IT experience. These resources provided the fundamental information and techniques, which were then modified in light of practical uses.
 - [TryHackMe - Boogeyman 2](https://tryhackme.com/r/room/boogeyman2)
 - [Olevba](https://github.com/decalage2/oletools)
 - [Volatility](https://volatilityfoundation.org/)
 - [VirusTotal](https://www.virustotal.com/gui/home/search)
 - [AbuseIPDB](https://www.abuseipdb.com)
 - [IPVoid](https://www.ipvoid.com)
 - [Mozilla Thunderbird](https://www.thunderbird.net/en-US/)
 - [Sublime Text](https://www.sublimetext.com/)

## Disclaimer

The sole goals of the projects and activities here are for education and ethical cybersecurity research. All work was conducted in controlled environments, such as paid cloud spaces, private labs, and online cybersecurity education platforms. Online learning and cloud tasks adhered closely to all usage guidelines. Never use these projects for improper or unlawful purposes. It is always prohibited to break into any computer system or network. Any misuse of the provided information or code is not the responsibility of the author or authors.
