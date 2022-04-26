+++
title = "Better pentest reports with linux-util \"script\" command"
author = ["funcsec"]
date = 2022-04-25
publishDate = 2022-04-25
lastmod = 2022-04-25T16:47:20-07:00
tags = ["script"]
categories = ["tutorial"]
draft = false
toc = "+"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "Util-linux 'script' allows replay of terminal sessions there is no loss of pentesting reporting findings"
featured_image = "images/edwin-foley_walnu-inlay-writing-table.jpg"
images = ["images/edwin-foley_walnu-inlay-writing-table.jpg"]
+++

An issue came up where the output of a terminal window was needed
after that terminal was closed. This unfortunate situation can come up
during penetration tests or certification tests like the OSCP.

Some investigation into options revealed the ancient and reviled `script` linux-util
program. It records input, output, and timings to file that allow the
terminal session view to be replayed or grepped at a later time.

The program was added to the `~/.bashrc` file so that it would start
with every terminal session.

```bash
# Script
# Record terminal for playback with scriptreplay
[ ! -d ~/.scriptreplay ] && mkdir "$HOME/.scriptreplay"
if [ -z $SCRIPTF ]; then
    export SCRIPTF="$HOME/.scriptreplay/$(date +"%Y%m%d_%H%M-%S")"
    script -q --log-timing "$SCRIPTF.timing" "$SCRIPTF.commands"
fi
```

This snippet created the directory `~/.scriptreplay`, then
started `script` if it was not already running.

The content could then be replayed with something similar to the following:

```bash
cd ~/.scriptreplay
scriptreplay -t 20220425_1853-33.timing 20220425_1853-33.commands
```

The contents could also be grepped with the following:

```bash
grep $QUERY ~/.scriptreplay/*.commands
```

The addition of this `script` workflow made it easier to have
confidence in the ability to retain data once it was in the terminal.