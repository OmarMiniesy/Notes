### General Notes

This is a pattern matching tool for [[Malware]].
- Can identify information about malware using binary and textual patterns.
- *YARA rules* are created to analyze these patterns and determine if a file is malicious or not.

To run a YARA rule, simply specify the file with the rule, and the target file/directory/process.
```bash
yara myrule.yar targetdirectory
```
- The `.yar` is the default extension for YARA rule files.

> The YARA [documentation](https://yara.readthedocs.io/en/stable/writingrules.html).

---
### YARA Rules

> [Summary ](https://miro.medium.com/v2/resize:fit:875/1*gThGNPenpT-AS-gjr8JCtA.png) - Describes the anatomy of YARA rules. 

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

> Can use the keyword `any of them` in the `condition` to match for all the strings defined in the ` strings` section.

Modules can be imported and used within rules to extend their functionality like  [PE module](https://yara.readthedocs.io/en/stable/modules/pe.html#pe-module) and the [Cuckoo module](https://yara.readthedocs.io/en/stable/modules/cuckoo.html#cuckoo-module).
- To import a module, follow this syntax outside a rule definition:
```
import "pe"
```

---
### Tools for YARA

[Loki](https://github.com/Neo23x0/Loki), [THOR](https://www.nextron-systems.com/thor-lite/), and [Fenrir](https://github.com/Neo23x0/Fenrir) are all IOC scanners that utilize YARA rules.

YARA rules can be created using the tool [yarGen](https://github.com/Neo23x0/yarGen), which takes a malware file and creates detection rules for it, while excluding any strings that are not malicious.
- It uses a database of strings and opcodes that are not malicious to create rules that match on malicious strings.

[yarAnalyzer](https://github.com/Neo23x0/yarAnalyzer/) is a tool that gives statistics on the YARA rules in a given directory.

[Valhalla](https://www.nextron-systems.com/valhalla/) is a tool that can be used to do perform lookups on matches for YARA rules.

---
