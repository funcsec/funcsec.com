+++
title = "Migrate Windows Shares Fast"
author = ["funcsec"]
date = 2021-12-21
publishDate = 2021-12-21
lastmod = 2021-12-21T20:00:05-08:00
tags = ["windows"]
categories = ["blueteam"]
draft = false
description = "Minimize downtime by migrating Windows Shares fast!"
toc = "true +"
featured_image = "images/henry-hyman-sayen_scheherazade.jpg"
images = ["images/henry-hyman-sayen_scheherazade.jpg"]
omit_header_text = "false +"
background_color_class = "bg-black-60"
+++

In this post, we're going to learn how to migrate network shares using Windows command prompt commands for fast share migration.
Often the data in Windows shares outgrow the underlying hard disk space and need to be migrated to new, larger hard drives.
This post will show how to do just that, FAST!

This is for modern Windows versions with modern Powershell, like Windows 10 and Server 2016 and above.
Might work on earlier version (certainly the CMD commands will), but I have not tested it on End of Life versions (will probably work on 2012 R2).

All the following code needs to be run as with administrator privilege, in either CMD or Powershell terminal prompts.

**ALWAYS** make a backup before large changes and **CHECK** your backups.


## Environment {#environment}

For this migration, we will be moving the data from `D:\oldshare` which is a 4TB disk that is full, to `E:\newshare` which is a 12TB disk.
Quick note, important data should be on RAID arrays, I'll refer to storage as disks but in reality they are RAID arrays of disks.


## Warming the share {#warming-the-share}

To lessen the time required to have the network shares down, we first copy all the data to the new share.
The data copy will be done with `robocopy` which is as close to `rsync` for Linux as the Windows environment has to offer.
The following command can be run on a CMD or powershell prompt.

First we need to create the destination folder, if it has not been created already.

```bat
mkdir "E:\newshare"
```

Once the destination directory has been created, we can use `robocopy` to copy the data to the new share location.

```bat
robocopy "D:\oldshare" "E:\newshare" /MIR /NP /FFT /NDL /XJD /R:2 /W:1
```

Breaking down the flags

`/MIR`
: Mirror a directory and delete any files no at source

`/NP`
: Don't display progress

`/FFT`
: Assume FAT file times (can prevent bogus errors)

`/NDL`
: Don't list Directories in output

`/XJD`
: Exclude symbolic links for directories (junction points)

`/R:2`
: Retry copy twice if file is locked

`/W:1`
: Wait 1 second between retries

The output will list all the files copied.
The summary at the bottom will indicate the amount of time it took and the size of the files in total.

```text
------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :    136069    136068         1         0         0         0
   Files :   1772366   1772365         0         0         1         1
   Bytes :   3.161 t   3.161 t         0         0     4.0 k       381
   Times :  13:46:44  10:31:09                       0:00:01   3:15:34


   Speed :            91778595 Bytes/sec.
   Speed :            5251.613 MegaBytes/min.
```

From the example above, 3.161TB of data was copied by `robocopy` in 13 hours and 46 minutes.
The `robocopy` command above can be run again if there is some time between the initial run and the actual migration.
It will update the files that have changed, delete any that no longer exist, and add any new files.

```text
------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :    136089       147    135942         0         0         6
   Files :   1772805       740   1772065         0         0        19
   Bytes :   3.161 t  938.76 m   3.160 t         0         0    1.27 m
   Times :   0:10:21   0:00:13                       0:00:00   0:10:07


   Speed :            71731072 Bytes/sec.
   Speed :            4104.484 MegaBytes/min.
```

This subsequent run of `robocopy` indicates that 938MBs were changed.


## Migrating Shares {#migrating-shares}

The next steps will be to:

-   notify the users that the share is going down
-   stop disconnect the share
-   copy the data to the new location again
-   copy over the ACL permissions
-   reconnect the share

First we will need to check the existing share to make sure we have the correct name.
The following was a listing of the shares on the server.

This is run in a command prompt with administrator privilege.

```bat
net share
```

```text
Share name   Resource                        Remark

-------------------------------------------------------------------------------
ADMIN$       C:\Windows                      Remote Admin
C$           C:\                             Default share
D$           D:\                             Default share
E$           E:\                             Default share
print$       C:\Windows\system32\spool\drivers
                                             Printer Drivers
IPC$                                         Remote IPC
NETLOGON     C:\Windows\SYSVOL\sysvol\example.local\SCRIPTS
                                             Logon server share
Share        D:\oldshare
SYSVOL       C:\Windows\SYSVOL\sysvol        Logon server share
The command completed successfully.
```

We can see our share is at `D:\oldshare` is called `Share`.

Before we disconnect the network share from the users, it's nice to give them a heads up to prevent accidental data loss.

This command only works in an Active Directory environment. Run as powershell.

```powershell
(Get-ADComputer -Filter *).Name | Foreach-Object {Invoke-Command -ComputerName $_ {msg * 'Please close all open files. The file server will be offline in 3 minutes for routine maintenance. --IT Team'}}
```

To prevent device changes while the share is being migrated, we will need to disconnect the share.

```bat
net share Share /DELETE
```

You may get some prompts that users are still connected to the drive with files open, it is at your discretion what to do.

Now we run the same `robocopy` above to sync the share locations.

```bat
robocopy "D:\oldshare" "E:\newshare" /MIR /NP /FFT /NDL /XJD /R:2 /W:1
```

```text
------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :    136089         0    136089         0         0         6
   Files :   1772806         0   1772806         0         0        38
   Bytes :   3.161 t         0   3.161 t         0         0   33.32 m
   Times :   0:11:13   0:00:00                       0:00:00   0:11:13
```

Above we can see that the final migration was a fast 11 minutes and 13 seconds, instead of 13 hours.


## Setting ACL permissions {#setting-acl-permissions}

The following powershell command is now run to copy the ACL permissions between the new and old locations.

```powershell
Get-Acl D:\oldshare | Set-Acl E:\newshare
```

This command only took a couple of minutes to run, and technically can be run beforehand as well, but it should be run at this step regardless.


## Recreation of the shares {#recreation-of-the-shares}

Now that the data and permissions are replicated, the shares can be re-enabled.
Note that the ACL migration above is what controls user access, not the below `/GRANT:everyone,FULL`.
Hopefully you have modified the NTFS permissions of the data to give least privilege to users, and utilize security groups.

```bat
net share Share=E:\newshare /GRANT:everyone,FULL
```

Now the share can be enumerated to ensure that they are pointing to the new location.
The users should automatically connect to the share again as it has the same name `Share` as it did before.

```bat
net share
```

```text
Share name   Resource                        Remark

-------------------------------------------------------------------------------
ADMIN$       C:\Windows                      Remote Admin
C$           C:\                             Default share
D$           D:\                             Default share
E$           E:\                             Default share
print$       C:\Windows\system32\spool\drivers
                                             Printer Drivers
IPC$                                         Remote IPC
NETLOGON     C:\Windows\SYSVOL\sysvol\example.local\SCRIPTS
                                             Logon server share
Share        E:\newshare
SYSVOL       C:\Windows\SYSVOL\sysvol        Logon server share
The command completed successfully.
```

The following powershell command is a check to see if the NTFS permissions for the new share location are correct.

```powershell
cd E:\
ls | Get-Acl | fl
```

If the permission were incorrect on the old share, they will be incorrect on the new share so you may want to check them.

```text
...
Path   : Microsoft.PowerShell.Core\FileSystem::E:\newshare
Owner  : BUILTIN\Administrators
Group  : EXAMPLE\Domain Users
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         EXAMPLE\example-group Allow  DeleteSubdirectoriesAndFiles, Modify, Synchronize
...

```


## Conclusion {#conclusion}

What we've done in this tutorial is copy the data to the new drive before disconnecting the share to make the transfer faster.
Then we notified the users and disconnected the share, completed a final copy of the data, and set the ACL permissions on the data.
Finally the share was re-enabled and the ACL permissions were verified.

Art by [Henry Lyman Saÿen (American, 1875-1918)](https://artvee.com/dl/scheherazade/) (Public Domain)

This post originally appeared on [Functional Security](https://funsec.com).