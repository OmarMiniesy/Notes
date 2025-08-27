### General Notes

Every domain user can read most of the properties of [[Objects]], including the `Description` and `Info` properties.

This attack abuses the fact that some properties that are viewable by all domain users can include passwords or secret strings.

---
### Attack Path

This can be done by writing a script that takes as arguments the target domain and the string to be searched for, like `pass` or `password`. The function is called `SearchUserClearTextInformation`, and this is what it does:
- To run the script below, the PowerShell instance should be opened as administrator and the execution policy should be set to unrestricted:
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

To run this, `SearchUserClearTextInformation -Terms "pass, password`.
```powershell
Function SearchUserClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()
    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') }| 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}
```

The first block for the parameters, `param`, is used to take in the command line arguments.
- `$Terms` this is an array of the keywords to look for, and it is mandatory.
- `$Domain` is the target domain that will be searched in, and it is an optional argument.

The second block is used to specify the [[Domain Controller]] that is to be queried to obtain the information. 
- It identifies the Domain Controller by obtaining the *RID Master* of the domain (either specified or not), which is Domain Controller that has to exist.

Then, a variable called `$list` is initialized to hold all of the search queries themselves.
- For each item in the input `$Terms` array, a query is made on the `Description` and `Info` properties.
- It puts asterisks around the search term to see if it exists anywhere in the `Desription` or `Info` properties.
```powershell
($_.Description -like "*pass*")
($_.Info -like "*pass*")
```

Finally, the `Get-ADUser` command is run which grabs all of the users with the properties specified from the specified Domain Controller.
- Then, the `Invoke-Expression` command joins all of the conditions in the `$list` array using an `OR` expression.
- Now, the command obtains all users with the identified properties and it matches the values of these properties with the conditions in the `$list` variable.
- Finally, it only outputs the `Select`ed fields from the matched users.
- `fl` is used to format the list to make it look easier to read.

---
### Prevention & Detection

Automate user creation to ensure that administrators don't store sensitive data in the properties, and performing continuous assessments to check for stored credentials in the properties of objects.

Having the baseline activity of users known, and checking for weird or suspicious logins can be used to detect that a user account's password was stolen.
- Monitoring on successful and failed logons, as well as *TGT* request events.
- [[Windows Events Log]] Events with IDs `4624, 4625, 4768` respectfully.

Having a *honeypot* account with incorrect credentials stored in easy to find fields, and then monitoring for the failed login attempts of that specific user.

---
