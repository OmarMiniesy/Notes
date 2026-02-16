### General Notes

[Bloodhound](https://github.com/SpecterOps/BloodHound) is a tool that utilizes graph theory to identify hidden and unintended relationships across identity and access management systems.
- Can be used by attackers to identify sophisticated attack paths, and by defenders to mitigate these risks.
- Used in [[Active Directory]] environments.
- [Sharphound](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound) is the data collector used by Bloodhound.

> [Bloodhound Documentation](https://bloodhound.specterops.io/home).

---
### Detecting Bloodhound Usage

Since Bloodhound utilizes [[Lightweight Directory Access Protocol (LDAP)]], we can monitor for the usage of Bloodhound by using the [[Windows Events Log]] event with ID `1644`.
- However, this technique is not the best.

We can utilize the [[Event Tracing for Windows (ETW)]] provider `Microsoft-Windows-LDAP-Client` to get better view of BloodHound usage.
- Using a tool like [[SilkETW]] to interact with this provider and visualize exact LDAP queries.
- Can also be integrated with [[YARA]].
- This then outputs the data into the `SilkService-Log` [[Windows Events Log]] channel.

Some of the LDAP queries used by recon tools and their filters to be used in a [[SIEM]].

|                                                                                                                                                                                                          |                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **Recon tool**                                                                                                                                                                                           | **Filter**                                                                                                                    |
| [enum_ad_user_comments](https://github.com/rapid7/metasploit-framework/blob/76954957c740525cff2db5a60bcf936b4ee06c42/modules/post/windows/gather/enum_ad_user_comments.rb#L31) (Metasploit)              | (&(&(objectCategory=person)(objectClass=user))(\|(description=*pass*)(comment=*pass*)))                                       |
| [enum_ad_computers](https://github.com/rapid7/metasploit-framework/blob/76954957c740525cff2db5a60bcf936b4ee06c42/modules/post/windows/gather/enum_ad_computers.rb#L52) (Metasploit)                      | (&(objectCategory=computer)(operatingSystem=*server*))                                                                        |
| [enum_ad_groups](https://github.com/rapid7/metasploit-framework/blob/76954957c740525cff2db5a60bcf936b4ee06c42/modules/post/windows/gather/enum_ad_groups.rb#L49) (Metasploit)                            | (&(objectClass=group))                                                                                                        |
| [enum_ad_managedby_groups](https://github.com/rapid7/metasploit-framework/blob/76954957c740525cff2db5a60bcf936b4ee06c42/modules/post/windows/gather/enum_ad_managedby_groups.rb#L53)<br><br>(Metasploit) | (&(objectClass=group)(managedBy=*)),<br><br>(&(objectClass=group)(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648)) |
| [Get-NetComputer](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Recon/PowerView.ps1#L4029) (PowerView)                                                    | (&(sAMAccountType=805306369)(dnshostname=*))                                                                                  |
| [Get-NetUser](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Recon/PowerView.ps1#L2602) - Users (Powerview)                                                | (&(samAccountType=805306368)(samAccountName=*)                                                                                |
| [Get-NetUser](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Recon/PowerView.ps1#L2605) - SPNs (Powerview)                                                 | (&(samAccountType=805306368)(servicePrincipalName=*)                                                                          |
| [Get-DFSshareV2](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Recon/PowerView.ps1#L6007) (Powerview)                                                     | (&(objectClass=msDFS-Linkv2))                                                                                                 |
| [Get-NetOU](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Recon/PowerView.ps1#L4747)<br><br>(PowerView)                                                   | (&(objectCategory =organizationalUnit)(name=*))                                                                               |
| [Get-DomainSearcher](https://github.com/EmpireProject/Empire/blob/24adb55b3404e1d319b33b70f4fd6b7448ca407c/data/module_source/credentials/Invoke-Kerberoast.ps1#L57) (Empire)                            | (samAccountType=805306368)                                                                                                    |


---
