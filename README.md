[![defcon](https://img.shields.io/badge/DEFCON27-DEMOLABS-green.svg)](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html#Hachi)

![Hachi Logo](https://github.com/Kart1keya/Hachi/blob/master/images/Hachi-Logo-Final-3.png)

ATT&CK framework has become a benchmark in the security domain. ATT&CK provides data about each technique used across different attack stages. Hachi was created to contribute to the ATT&CK community. Hachi is based on the radare2 framework and uses data provided by ATT&CK to map the symptoms of malware on ATT&CK matrix.

Following modules of Hachi make this tool a great addition to an analyst’s or company’s armaments:

• Threat Intel: Hachi provides threat intelligence data like a possible parent campaign or author of a malware file.
• Malware behavior: It uncovers core malware behaviors using automated static analysis coupled with symbolic execution to explore multiple execution paths and maps it on ATT&CK matrix.
• RESTful API: Hachi provides RESTful API which enables this tool to seamlessly integration with malware processing frameworks.
• Visualization: It allows for the creation of detailed visual reports.

#### Hachi User Interface
![Hachi User Interface](https://github.com/Kart1keya/Hachi/blob/master/images/User_Interface.PNG)

#### Hachi Report Page
![Hachi Report Page](https://github.com/Kart1keya/Hachi/blob/master/images/Report_Snap.PNG)

#### MITRE Mapping
![MITRE Mapping](https://github.com/Kart1keya/Hachi/blob/master/images/mitre_mapping.PNG)

#### Dependecies:
1. Download radare2 and add its path in system path.
2. Download and install Graphviz2.38 and add its path in system path.
3. Enable MSMQ feature on the system and create a pipe and add its name in Hachi.config file.
4. Install python packages mentioned in requirements.txt.
5. Run hachi.py and scanda.py

#### References: <br/>
https://attack.mitre.org/<br/>
https://www.radare.org/get/THC2018.pdf<br/>
https://github.com/pinkflawd/r2graphity<br/>
https://github.com/Yara-Rules/rules<br/>
