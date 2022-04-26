+++
title = "Lag in VMWare Player Absent from Workstation Pro 16"
author = ["funcsec"]
date = 2022-02-04
publishDate = 2022-02-04
lastmod = 2022-02-06T15:50:22-08:00
tags = ["vmware", "kali", "oscp"]
categories = ["tutorial"]
draft = false
toc = "+"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "VMWare Workstation does not have the issues with input lag in OS Kali VM that Player does"
featured_image = "images/ernest-jean-delahaye_les-mutiles-assistent.jpg"
images = ["images/ernest-jean-delahaye_les-mutiles-assistent.jpg"]
+++

A couple weeks ago I had installed [VMWare Player](https://www.vmware.com/products/workstation-player.html) to use the [Offensive Security Kali Virtual Machine](https://help.offensive-security.com/hc/en-us/articles/360049796792-Kali-Linux-Virtual-Machine) to go through the OSCP course.
Upon installing the VM in VMWare player, I immediately began experiencing a bad issue on both my laptop and my desktop that I did not experience on my previous go-to desktop virtualization application [Virtualbox](https://www.virtualbox.org/).

**There was LAG**

Very bad input lag as seen below. The type of lag that kills productivity in a terminal window.

{{< figure src="/ox-hugo/vmware-lag.gif" >}}

The following is how it was solved.


## Installing VMWare Workstation Pro 16 {#installing-vmware-workstation-pro-16}

This is a walk through on how VMWare Workstation Pro 16 Trial was installed.
The underlying operating system was Debian Bullseye.

The initial step was to download VMWare Workstation Pro 16 Trial for Linux from the following URL:

<https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html>

Then the bundle pack was made executable and installation was attempted.

```bash
chmod +x VMware-Workstation-Full-16.2.1-18811642.x86_64.bundle
sudo ./VMware-Workstation-Full-16.2.1-18811642.x86_64.bundle
```

The installation failed due to the presence of VMWare Player.
VMWare Player needed to be removed before VMWare Workstation Pro Trial could be installed.

```bash
sudo vmware-installer --uninstall-product vmware-player
```

Previous configurations were kept in case `vmplayer` would be reinstalled later.
The install was now retried.

```bash
sudo ./VMware-Workstation-Full-16.2.1-18811642.x86_64.bundle
```

The installation appeared successful.

An issue came up with the lack of polkit, which typically comes with a Linux desktop environment.
With most DE environments like gnome, kde, and xfce, polkit is already enabled, but on i3 or openbox it is not.
If polkit is not running, there will be an issue with starting VMWare Workstation Pro under the user account, as the client cannot request super user privilege.

```bash
/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1 &
```

VMWare Workstation Pro Trial was then launched[^fn:1].

```bash
vmware
```

{{< figure src="/ox-hugo/vmplayer-eula.png" >}}

The EULA was accepted.

{{< figure src="/ox-hugo/vmplayer-trial.png" >}}

The trial version was selected.
This launched the UI.

{{< figure src="/ox-hugo/vmware-version.png" >}}

So to recap this section, `vmplayer` was removed and `vmware` which is the name for VMWare Workstation Pro 16 was installed.


## Install the Kali VM {#install-the-kali-vm}

The following script was used to download, check, and uncompress the [Offensive Security's Kali VMWare VM Image](https://help.offensive-security.com/hc/en-us/articles/360049796792-Kali-Linux-Virtual-Machine).

```bash
#!/bin/bash
set -euo pipefail

# Variables
SIG="de78b3f6e1599987934b04c4c1b002c0bde67822591fef0aaf5191e60eef3025"
URL="https://kali.download/virtual-images/kali-2021.3/kali-linux-2021.3-vmware-amd64.7z"
FILE="$(basename $URL)"
DIR="kali-2021.3"

# Make directory for virtual machine image
mkdir -p $DIR
cd ./$DIR
# Download VM image
wget "$URL"
# Verify the download hash of the archive
echo "$SIG $FILE" | sha256sum --check
# Unzip the archive
7zr e "$FILE"
# Remove the archive
rm "$FILE"
```

Then the image was imported into VMWare Workstation Pro 16.
The only setting that was changed from the base image was increasing the Kali VM RAM from 2GB to 4GB.

{{< figure src="/ox-hugo/vmware-ram.png" >}}

An initial snapshot was taken of the Kali VM and then it was started.


## Results: No Lag! {#results-no-lag}

The lag found in VMWare Player **was not** found in VMWare Workstation Pro 16.
So, if you're experiencing lag issues with VMWare Player, they do not seem to be present in VMWare Workstation Pro 16, thankfully.

I'll need to pay for VMWare within 30 days, but it will be worth it to alleviate the frustration of input lag.
Also, having snapshots, complex networking, and the ability to run multiple VM's at the same time will also make Workstation Pro 16 worth the price.

[^fn:1]: Make sure not to use the `vmplayer` command to start Workstation Pro, Player is installed along with Workstation Pro.