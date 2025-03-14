### General Notes

Network devices that are used to enhance network security.
##### Intrusion Detection Systems (IDS)

A passive monitoring network device that can detect malicious packets and alerts administrators.
- Similar to a [[Firewall]], but it cannot take action against these packets.
- It can only detect, monitor, and create logs.

There are several types of IDS such as:
- [[#Network Intrusion Detection Systems (NIDS)]]
- [[#Host-Based Intrusion Detection Systems (HIDS)]]
- [[#Logging Systems]]

However, these systems aren't perfect, and they suffer from misclassification of packets.
- For instance, some packets can be flagged as malicious when they are normal packets, and vice versa.
- There is a detection rate for these systems that outlines the probabilities of correct detection.
- Hence, there are different detection mechanisms in place.

##### Intrusion Prevention Systems (IPS)

An extra step above IDS, that can take action, instead of just analyzing and reporting malicious activity.
- They can block and drop packets.

There are several types of IPS:
- *Network Intrusion Prevention Systems (NIPS)*: If a malicious signature is identified, the connection is terminated.
- *Behavior-Based Intrusion Prevention Systems (Network Behavior Analysis NBA)*: The system is first in a training period to understand the normal behavior of the network (baselining). Once abnormal behavior is detected, the connections are terminated.
- *Wireless Intrusion Prevention Systems (WIPS)*: Connections are terminated in wireless networks if malicious behavior is detected.
- *Host-Based Intrusion Prevention Systems (HIPS)*: Protects the traffic flow for a single endpoint device, and terminates connection if signatures of malicious activity are identified.

---
### Network Intrusion Detection System (NIDS)

This is a detector that is put between the router and the internal network to monitor the traffic, as well as analyze it.
- This NIDS for better performance should be stateful, that is manage packets into different connections for better analysis.
	- The packets are analyzed, everything, even their data is taken into account.
	- These packets are used to detect if attacks are taking place.
- A single IDS is sufficient for an entire network, and it doesn't affect any of the network resources.

> NIDS can sometimes interpret packets differently from the end-hosts the packets are destined to. For instance, attackers can use [[Web Encoding]] to obfuscate data that might be flagged by an NIDS by default. But once this obfuscated data reaches the end host, the attacker has succeeded in bypassing the IDS. Moreover, sometimes, the packets sent might signal different things between the NIDS and the host.

To combat these **evasion techniques** by attackers to bypass the NIDS:
1. Enforce using the same interpretation techniques by both NIDS and host, but this is very difficult given the context of information present at the host, but not at the NIDS.
2. Enforce that all inputs that are entered are in a normalized format, such that no obfuscation is allowed.

However, these are drawbacks of utilizing NIDS, and it is hard to overcome them.
- Another issue, is if the data is using a secure end-end [[Encryption]] for communication, such as using SSL/[[Transport Layer Security (TLS)]]. 
- This means that NIDS cannot understand the data in the packets, unless the private keys of the users are shared with the NIDS. (Not favorable)

---
### Host-Based Intrusion Detection System (HIDS)

These are placed on the end hosts themselves.
- This can solve many of the issues faced with NIDS as they can interpret the data correctly now without inconsistency.
- It also works for understanding encrypted messages, such as those generated by [[HTTPS]].

> However, these HIDS must be present on every end host, which is expensive. Moreover, they also can be bypassed by using **evasion techniques** such as obfuscation of attack commands.

---
### Logging Systems

This type of detection is where logs generated are analyzed by a device.
- These logs can be scanned through to look for any attacks that have taken place.
- They are cheap, and can be implemented for all end hosts.
- Moreover, they are similar to *HIDS*, where they can understand packets.

> Logging is not done in real time, hence, attacks are discovered a while after they actually take place. Attackers can also modify the logs, so as to remove any trace they leave.

---
### Detection Strategies

There are multiple types of detection strategies that are used by intrusion detection systems, similar to [[Malware]] detection strategies.
1. **Signature detection**
2. **Anomaly detection**
3. **Specification detection**
4. **Behavioral detection**
#### 1. Signature Detection

The packets are analyzed, and patterns or activities that match the structure of a known attack is flagged.
- A **blacklist** is maintained, and any structure that matches anything on the list is flagged.
- These blacklists are obtained from previous or known attacks.
###### Advantages
- Easy to implement.
- Good at detecting *known* attacks.
###### Disadvantages
- Bad at detecting *new* attacks, needs to be constantly updated.
- Using simple obfuscation and evasion can evade and bypass this mechanism.

#### 2. Anomaly Detection

Have an idea and a model that can describe and recognize normal activity.
- Any packet activity that goes away from this standard is flagged.
- In other terms, a **whitelist** is maintained that describes allowed activity.
###### Advantages
- Can detect new variants of attacks.
###### Disadvantages
- A poorly trained model might fail at detecting both, normal and not normal activity.
- An academic subject that isn't fully implemented.

#### 3. Specification Detection

Normal activity is manually specified in a **whitelist**.
- Any activity that deviates from this is flagged.
###### Advantages
- Can catch new attacks.
- A well maintained whitelist can significantly reduce the false positive rate. (will not flag regular activity)
###### Disadvantages
- Hard to maintain an effective whitelist.

#### 4. Behavior Detection

Instead of looking and analyzing the input, this strategy observes the actions that are executed by the packets.
- If any actions are performed that raise suspicion, a flag is raised.
- These actions can themselves be analyzed by using whitelists and blacklists of allowed and disallowed actions.
###### Advantages
- New attacks can be detected.
- A low false positive rate can be maintained as some actions are very rare to happen in normal activities.
###### Disadvantages
- The attack will be conducted when the system realizes that it is targeted.
- New attack patterns can be devised that can bypass these behavior detections.

---
### Detection Accuracy

Given these detection methods, there are calculations that can be made regarding their efficiency which can be made using these metrics:
- **True positives**: When the detector alerts correctly for an attack.
- **False positives**: When the detector alerts incorrectly when there is no attack.
- **True negative**: When the detector stays silent when there is no attack.
- **False negative**: When the detector stays silent even though there is an attack.

> A positive means that the detector alerts, and a negative means that the detector stays silent. Therefore, a true positive is when the detector correctly alerts, and a false positive is when the detector incorrectly alerts. The same logic can be applied for negatives.

These 4 metrics can be used to assess whether the detector can correctly identify if there is an attack, and when to allow packets to pass through in case of regular traffic.
- The detector's efficiency is based mostly on the **false positive** and **false negative** rates.
- A good balance between those 2 rates is most favorable.

> A detector with 0% false positive is possible if it never reports an attack, similarly, a detector with 0% false negative is possible if it always reports an attack. 

The quality of the detector and this balance largely depends on the rate of attacks. 
- The larger the number of attacks, the easier it is to detect an attack.
- This is explained through the base rate fallacy.

To combat this, multiple detectors can be combined:
1. **Parallel combination:** An alert is generated if either detector is activated.
	 - Increases false positive chances.
	 - Reduce false negative chances.
2. **Serial combination:** An alert is generated only if both detectors are activated.
	- Increases false negative chances.
	- Reduce false positive.

---
