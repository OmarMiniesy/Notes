### General Notes

Threat intelligence is the grouping of data, called _IOC_s, or _Indicators of Compromise_, and is distributed by _ISAC_s, or _Information and Sharing Analysis Centers_.
- This data is used by teams and companies to be able to detect threats, or build their defenses upon this information.

Indicators of Compromise are traces that are left by attackers that could indicate that they were present.
- This includes [[IP]] addresses, domains, files, or even strings.

The red team uses Threat Intelligence to analyze and emulate the behavior of adversaries through collected IOCs.
- They also collect TTPs for such adversaries to understand how they operate.

**Threat Intelligence**:
- Information collected, processed, and analyzed to understand adversarial threats.
- Includes details on threat actors, their motivations, capabilities, and actions.
- Often categorized as **strategic**, **operational**, or **tactical** intelligence. **TTPs**:
- **Tactics**: High-level objectives adversaries aim to achieve (e.g., data exfiltration, persistence).
- **Techniques**: Specific methods adversaries use to accomplish their tactics (e.g., phishing, lateral movement).
- **Procedures**: Step-by-step sequences or workflows adversaries follow to execute their techniques.

---
### TTP Mapping

Collecting this Threat Intelligence helps in understanding and defending against adversaries.
- In combination with this information, TTPs from attack frameworks like [[MITRE ATT&CK Framework]] or the TIBER-EU framework helps to understand how attackers operate.

Once an attacker is chosen, the goal is identify the TTPs used by this attacker and map it to a [[Cyber Kill Chains|Cyber Kill Chain]].
- This helps in understanding how the attacker moves and how to simulate the attacker.

Mapping the threat intelligence to the TTPs in the cyber kill chain, or framework of choice, helps the Red Team to properly emulate a threat by a certain attacker or adversary.
- This way, the defensive team can see if they can defend against such an attacker, or similar attackers that follow the same kill chain tactics or use the same TTPs.

---
