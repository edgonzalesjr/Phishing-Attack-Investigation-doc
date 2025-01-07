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
- Threat Actor Profiling and Impact Assessment
  - Correlating attack findings with threat actor TTPs.
  - Assessing the overall impact of the compromise on organizational security.

### Tools Used

- Email Analysis Tools
  - Email client or text viewers for inspecting the phishing email.
- VBA Macro Analysis Tools
  - Olevba: Extract and analyze VBA macros from .doc files.
- Memory Forensics Tools
  - Volatility: Analyze memory dumps to identify malicious processes, artifacts, and persistence mechanisms.

## Perform Analysis

<p align="center">
<img src="https://imgur.com/MspvDbc.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Get the hash value of the provided artefacts.</b>
<br/>

<p align="center">
<img src="https://imgur.com/26iCGrA.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to see what the email's content.</b>
<br/>

<p align="center">
<img src="https://imgur.com/0eiGxDw.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to text editor.</b>
<br/>

<p align="center">
<img src="https://imgur.com/ZH4aJw4.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Extraction of the .eml for IOCs.</b>
<br/>

<p align="center">
<img src="https://imgur.com/4tLQ6Kn.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>File Reputation. Indicating that Majority of vendors flag as malicious.</b>
<br/>

<p align="center">
<img src="https://imgur.com/m5VN2w6.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Parse .doc file for malicious macro. The tool detected a macro routine, named AutoOpen().
  Where there's a GET request to a C2 server. Which the request retrieves update.png file.</b>
<br/>

<p align="center">
<img src="https://imgur.com/S1mbWrO.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>What Windows version the dumped raw file. Which is a Windows 10 version 1903.</b>
<br/>

<p align="center">
<img src="https://imgur.com/S9K9jvJ.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/NkfZd3n.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Check the process tree. The wscript.exe process which stands out and looks suspicious.</b>
<br/>

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>.</b>
<br/>

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>.</b>
<br/>

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>.</b>
<br/>

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>.</b>
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
- Adapted from [TryHackMe - Boogeyman 2](https://tryhackme.com/r/room/boogeyman2)
- [Thunderbird](https://www.thunderbird.net/en-US/)
- [Volatility](https://volatilityfoundation.org/)
- [Olevba](https://github.com/decalage2/oletools)

## Disclaimer

The projects and activities within this portfolio are for educational and ethical cybersecurity research purposes only. All work was performed in controlled environments, including isolated, personally owned laboratories, subscription-based cloud environments, and through engagement with online cybersecurity learning platforms. Any cloud-based activities and participation in online learning platforms were conducted in full compliance with their respective terms of service and acceptable use policies. These projects should not be used for any illegal or unethical activities. Unauthorized access to any computer system or network is strictly prohibited. The author(s) are not responsible for any misuse of the information or code provided.
