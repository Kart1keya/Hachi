# Hachi: An Intelligent threat mapper


ATT&CK framework has become a benchmark in the security domain. ATT&CK provides data about each technique used across different attack stages. Hachi was created to contribute to the ATT&CK community. Hachi is based on the radare2 framework and uses data provided by ATT&CK to map the symptoms of malware on ATT&CK matrix.

Following modules of Hachi make this tool a great addition to an analyst’s or company’s armaments:

• Threat Intel: Hachi provides threat intelligence data like a possible parent campaign or author of a malware file.
• Malware behavior: It uncovers core malware behaviors using automated static analysis coupled with symbolic execution to explore multiple execution paths and maps it on ATT&CK matrix.
• RESTful API: Hachi provides RESTful API which enables this tool to seamlessly integration with malware processing frameworks.
• Visualization: It allows for the creation of detailed visual reports.


References:
https://attack.mitre.org/
https://www.radare.org/get/THC2018.pdf
https://github.com/pinkflawd/r2graphity
https://github.com/Yara-Rules/rules