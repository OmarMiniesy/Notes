### General Notes

YARA is a tool used by SOC analysts to enhance threat detection and incident response capabilities, such as:
- File and memory analysis in Digital Forensics, by matching on file formats, types, versions, metadata, or packers.
- Analysts can create specific patterns or signatures that correspond to known [[Malware]] traits or behaviors, by matching to malware signatures, behaviors, or file properties.
- Also used to detect suspicious files and IoCs (Indicators of Compromise), by matching against specific patterns, file names, Windows Registry keys, or network artifacts.
- Used for incident response to quickly identify relevant artifacts.
- Can be used to perform proactive searches to identify threats, or [[Threat Hunting]].

YARA rules utilize a standard format for rule structures, encouraging collaboration and knowledge sharing.
- [Summary](https://miro.medium.com/v2/resize:fit:875/1*gThGNPenpT-AS-gjr8JCtA.png) - Describes the anatomy of YARA rules. 

GitHub repos with examples for YARA rules: 
- [Yara-Rules](https://github.com/Yara-Rules/rules/tree/master/malware).
- [Open-Source-YARA-rules](https://github.com/mikesxrs/Open-Source-YARA-rules/tree/master).
- [DFIR Report, Yara-Rules](https://github.com/The-DFIR-Report/Yara-Rules).

YARA rules can be integrated with security tools such as [[SIEM]]s, log analysis systems, and incident response platforms.
- This integration enables automation, correlation, and enrichment of security events, allowing SOC analysts to incorporate the rules into their existing security infrastructure.

> The YARA [documentation](https://yara.readthedocs.io/en/stable/writingrules.html).

---
### YARA Rules

Rule files are used to scan target files or directories and trigger alerts when matches are found.
- Can identify suspicious information using binary and textual patterns.

> The `.yar` or `.yara` extension is used for rule files.

Rules starts with the keyword `rule` followed by the name of that rule.
- Inside the rule are several sections.

The `meta` section can be used to insert descriptive information by the author to summarize what the rule does.
- Similar to comments.

The `strings` definition section is where the strings that will be part of the rule are defined. These are like the variables.
- Each string has an identifier consisting of a `$` character followed by its name.
- These identifiers can be used in the `condition` section to refer to the corresponding string.
- The value of these strings can be:
	- Hex strings are enclosed in curly braces `{}`.
	- Text strings are enclosed in double quotes `"`.
	- [[Regular Expressions]] are enclosed in forward slashes `/`.

The `condition` section is where the logic of the rule resides, and it contains a Boolean expression that checks whether the target file/directory/process satisfy the rule.

> Can use the keyword `any of them` in the `condition` to match for all the strings defined in the `strings` section. More of these keywords can be found [here](https://yara.readthedocs.io/en/stable/writingrules.html#conditions). 

Modules can be imported and used within rules to extend their functionality like  [PE module](https://yara.readthedocs.io/en/stable/modules/pe.html#pe-module) and the [Cuckoo module](https://yara.readthedocs.io/en/stable/modules/cuckoo.html#cuckoo-module).
- To import a module, follow this syntax outside a rule definition:
```
import "pe"
```
- The `pe` module allows access to a set of functions and structures that can inspect and analyze the details of `PE` files.

Nice resources for writing YARA rules:
- [Kaspersky](https://www.slideshare.net/KasperskyLabGlobal/upping-the-apt-hunting-game-learn-the-best-yara-practices-from-kaspersky).
- [How to Write Simple but Sound Yara Rules - Part 1](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)
- [How to Write Simple but Sound Yara Rules - Part 2](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)
- [How to Write Simple but Sound Yara Rules - Part 3](https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)

#### Running YARA Rules

To run YARA rules against a target, we can use the following syntax:
```
yara yara_rule_file.yar target_directory
```

---
### Tools for YARA

- [yarAnalyzer](https://github.com/Neo23x0/yarAnalyzer/) is a tool that gives statistics on the YARA rules in a given directory.
- [Loki](https://github.com/Neo23x0/Loki), [THOR](https://www.nextron-systems.com/thor-lite/), and [Fenrir](https://github.com/Neo23x0/Fenrir) are all IOC scanners that utilize YARA rules.
- [Valhalla](https://www.nextron-systems.com/valhalla/) is a tool that can be used to do perform lookups on matches for YARA rules.
#### **yarGen**
YARA rules can be created using the tool [yarGen](https://github.com/Neo23x0/yarGen), which takes a malware file and creates detection rules for it, while excluding any strings that are not malicious.
- It uses a database of strings and opcodes that are not malicious to create rules that match on malicious strings.

After installing, we install all dependencies and then install the needed built-in databases to be used:
```
pip install -r requirements.txt
python yarGen.py --update
```

To use the tool, we need to specify the path to the directory that contains the malware or files to have YARA rules generated for:
```bash
python3 yarGen.py -m </path/to/files> -o output_file.yar
```

---
