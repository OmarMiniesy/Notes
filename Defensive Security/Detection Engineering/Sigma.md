### General Notes

This is a [[SIEM]] agnostic, YAML, detection engineering language.
- It is used to describe detection rules that can be easily shared and used across log analysis and SIEM systems.
- Sigma offers a unified format to represent patterns found in log events that correlate with malicious activity.
- `sigmac`(now obsolete) and `pySigma` are converter tools that can be used to convert sigma rules into queries or configurations for SIEMs and other solutions.

Sigma rules are used to define and detect security events by analyzing log data.
- Can include conditions, filters, and parameters to determine alert triggering.

As such, the usages of Sigma include:
- **Universal Log Analytics Tool**: Write detection rules once and then convert them to various SIEM and log analytics tool formats
- **Community-driven Rule Sharing**
- **Incident Response**: Enables analysts to quickly search and analyze logs for specific patterns or indicators.
- **[[Threat Hunting]]**: By leveraging specific patterns, we can comb through our datasets to pinpoint anomalies or signs of adversarial activity.
- **Seamless Integration with Automation Tools**: Integrate them with SOAR platforms and other automation tools, enabling automated responses.
- **Gap Identification**: By aligning our rule set with the broader community, we can perform gap analysis, identifying areas where our detection capabilities might need enhancement.

---
### Rule Structure

The structure of a Sigma rule is defined in the Sigma Specification Repo [here](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) and follows this high level guide [here](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-High%E2%80%90Level-Guide).

Here is an example of a Sigma rule and below it is each field explained.
```
title: Title
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects [specific behavior or technique]
references:
    - https://example.com/reference
tags:
    - attack.execution
    - attack.t1059
author: Your Name
date: 2025-11-19
logsource:
    category: process_creation
    product: windows
    service: security
    definition: 
detection:
    selection1:
        FieldName: 'Value'
        FieldName|modifier: 'Value'
	selection2:
        FieldName: 'Value'
        FieldName|modifier: 'Value'
    condition: selection1 or selection2
falsepositives:
    - Legitimate administrative activity
level: medium
```

The `title` is used to give a brief title of what the rule is supposed to detect.
The `id` is an *optional* globally unique identifier.
The `status` is *optional*, and it can have on of these values:
- `stable`: The rule didn't produce any obvious false positives in multiple environments over a long period of time
- `test`: The rule doesn't show any obvious false positives on a limited set of test systems
- `experimental`: A new rule that hasn't been tested outside of lab environments and could lead to many false positives
- `deprecated`: The rule is to replace or cover another one. The link between rules is made via the related field.
- `unsupported`: The rule can not be used in its current state (special correlation log, home-made fields, etc.)
The `description` is an *optional* short description of the rule and the malicious activity it can detect.
The `references` are an *optional* citation from which the rule was inspired.
The `author` and `date` are *optional*.

The `logsource` is the log data where the detection is to be applied to. It describes the log source, the platform, and the application required in the detection. It can include an arbitrary number of these *optional* elements:
- `category`: This is used to select all log files written by a logical group. This is basically the source of information. Examples include firewall, web, antivirus.
- `product`: This is used to select the log output of a certain product. Can be an OS, or the name of a software package. Examples include windows, which includes all windows event logs and more, Apache, ...
- `service`: This is then used to select a more specific subset of logs from the `product` value. For example, security from Windows. Can be ignored to make the detection generic.

> `category`, `product`, and `service` values are in lower case, and spaced are replaced by `_`; `.` and `-` characters are allowed.

The `detection` is a set of search identifiers and a condition.
- A search identifier is a definition that can consist of *lists* and *maps*.
	- Maps contain key-value pairs that are grouped using the logical AND.
	- Lists contain a set of strings or maps that grouped using the logical OR.
	- Any items that are part of a list are grouped using OR, and any maps are grouped using AND. If a map contains several values, then it contains a list, so the items in that map are grouped using OR.
- A condition defines how the search identifiers are related and are to be used.

Conditions can use various operators:

| Operator                           | Example                                   |
| ---------------------------------- | ----------------------------------------- |
| Logical AND/OR                     | `keywords1 or keywords2`                  |
| 1/all of them                      | `all of them`                             |
| 1/all of search-identifier-pattern | `all of selection*`                       |
| 1/all of search-id-pattern         | `all of filter_*`                         |
| Negation with 'not'                | `keywords and not filters`                |
| Brackets - Order of operation '()' | `selection1 and (keywords1 or keywords2)` |

Values, which are used in search identifiers, can be modified using *value modifiers* which are appended after the field name using a pipe `|` character and can be changed. 
```YAML
fieldname|modifier: value
```

The value modifiers are:

| Value Modifier | Explanation                                                                     | Example                                            |
| -------------- | ------------------------------------------------------------------------------- | -------------------------------------------------- |
| contains       | Adds wildcard (`*`) characters around the value(s)                              | CommandLine\|contains                              |
| all            | Links all elements of a list with a logical "AND" (instead of the default "OR") | CommandLine\|contains\|all                         |
| startswith     | Adds a wildcard (`*`) character at the end of the field value                   | ParentImage\|startswith                            |
| endswith       | Adds a wildcard (`*`) character at the begining of the field value              | Image\|endswith                                    |
| re:            | This value is handled as regular expression by backends                         | CommandLine\|re: '\[String\]\s*\$VerbosePreference |
| exists         | Checks if the field exists.                                                     | PasswordLastSet\|exsits: true                      |

More on values:
- All values are treated as case insensitive strings.
- Wildcard characters can be used; `* ?`. The asterisk for an unbounded length, and the question mark for a single character.
- Plain backslash not followed by a wildcard can be expressed as single `\` or double backslash `\\`. For simplicity reasons the single notation is recommended.
- A wildcard has to be escaped to be handled as a plain character. e.g.: `\*`, `\?`.
- The backslash before a wildcard has to be escaped to handle the value as a backslash followed by a wildcard: `\\*`.
- Three backslashes are necessary to escape both, the backslash and the wildcard and handle them as plain values: `\\\*`.
- Three or four backslashes are handled as double backslash. Four is recommended for consistency reasons: `\\\\` results in the plain value `\\`.

---
### Sigma Tools

Sigma rules should be combined with tools like [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and [Zircolite](https://github.com/wagga40/Zircolite) to speed up detection in large heaps of logs and information.
- These tools allow scanning Sigma rules on multiple `.evtx` files concurrently.