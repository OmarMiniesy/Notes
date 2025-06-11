### General Notes

This is a model used to analyze and understand *APT*s (Advanced Persistent Threats) and their malicious attempts to:
- Aid in intrusion analysis
- Strengthen defense using intelligence
- Better classify and correlate events 
- Forecast adversarial operations

The diamond model is composed of 4 features that are used to represent cyber attacks:
- **Adversary**
- **Infrastructure**
- **Capability**
- **Victim**

Each corner of the diamond is a feature, and each line connecting these features is a relationship.
- Understanding these features and their relationships help to track and detect attack patterns.
- There is also 2 other features, which are the *social-political* (needs and intent of the adversary) and *technology* components.

---
### The 4 Corners

**Adversary**: This is the attacker who stands behind the cyber attack. There are 2 types of adversaries, *Adversary Operators* and *Adversary Customers*.
- *Operators* are those that actually conduct the cyber attack.
- *Customers* are those that benefit from the cyber attack. Can be the same as the operator.

**Victim**: This is the target of the adversary, which can be the organization, a person, an email address, an [[IP]] address, a domain, etc... These are *Victim Personae* or *Victim Assets*.
- *Victim Personae* are the people and organizations that are being exploited.
- *Victim Assets* include the attack surface which the adversary will exploit.

**Capability**: These are the skills, tools, techniques, and TTPs used by the adversary. All of the capabilities that are used by an adversary are part of its arsenal - the *Adversary Arsenal*.
- The *Capability Capacity* is all of the vulnerabilities that a single capability can target and use.

**Infrastructure**: This includes all of the software and hardware *controlled or used* by the adversary to deliver and control their capabilities. There are several types of infrastructure:
- *Type 1 Infrastructure* is the infrastructure controlled or owned by the adversary. 
- *Type 2 Infrastructure* is the infrastructure controlled by an intermediary that might or might not be aware of it. This has the purpose of obfuscating the source of the activity.
- *Service Providers* are organizations that provide services critical for the adversary availability of Type 1 and Type 2 Infrastructures.

---
### Meta Features

**Meta-Features** are used by the diamond model to add extra information and intelligence:
- *Timestamp*: The date and time of the event
- *Phase*: The phase of the attack, likely part of the [[Cyber Kill Chains]]. Every malicious activity needs 2 or more phases to be conducted successfully in succession.
- *Result*: Either success, fail, or unknown result of the attack. Can also be the impact on CIA, or the result of a single phase of the attack.
- *Direction*: This represents the direction of the attack.
	- Victim-to-Infrastructure
	- Infrastructure-to-Victim
	- Infrastructure-to-Infrastructure
	- Adversary-to-Infrastructure
	- Infrastructure-to-Adversary
	- Bidirectional
	- Unknown
- *Methodology*: The classification of the intrusion or attack.
- *Resources*: The resources used by the adversary:
	- Software
	- Knowledge (the attacker's ability and knowledge to do the attack)
	- Information
	- Hardware
	- Funds
	- Facilities
	- Access

---
