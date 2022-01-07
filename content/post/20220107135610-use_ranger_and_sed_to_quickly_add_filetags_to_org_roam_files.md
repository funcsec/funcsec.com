+++
title = "Use Ranger and Sed to Quickly Add Filetags to Org-roam files"
author = ["funcsec"]
date = 2022-01-07
publishDate = 2022-01-07
lastmod = 2022-01-07T15:04:43-08:00
tags = ["sed", "ranger", "org-roam", "org-mode"]
draft = false
toc = "true +"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "Use the interface of ranger to selectively and efficiently modify text files using sed"
featured_image = "images/adolphe-appian_well-at-the-side-of-a-road.jpg"
images = ["images/adolphe-appian_well-at-the-side-of-a-road.jpg"]
+++

Here is how I used `ranger` to add a filetag to org files in a fast and efficient way.
I used this when I had to retroactively tag a bunch of [org-roam](https://www.orgroam.com/) files after a decision to split up my roam files in a different way.
It makes adding a tag easy and fast!
I modified hundreds of files in just a few minutes, files that I could not pragmatically modify due to no consistency in their content.
Hope it will help you too.


## Add a line in the middle of a text file {#add-a-line-in-the-middle-of-a-text-file}

First I used an org file at `/tmp/file.org` to test on.

<a id="code-snippet--orgFile"></a>
```bash
cat <<EOF > /tmp/file.org
:PROPERTIES:
:ID:       45c20818-f221-4846-a0ab-6e3d3177b593
:END:
#+title: Test file
this is an example file
we will be trying to add a filetag above the title
EOF
```

I needed it to add a line around the `#+title:` part.
Luckily this [Stack Overflow answer](https://stackoverflow.com/questions/6739258/how-do-i-add-a-line-of-text-to-the-middle-of-a-file-using-bash) let me know what I needed from my `sed` command.
The command that worked added the new tag line above the existing line, which is fine for this purpose.

The code that worked was

```bash
sed -n 'H;${x;s/^\n//;s/#+title\: .*$/\#\+filetags\:\ \:tag\:\n&/;p;}' /tmp/file.org
```

Which resulted in:

```text
:PROPERTIES:
:ID:       45c20818-f221-4846-a0ab-6e3d3177b593
:END:
#+filetags: :tag:
#+title: Test file
this is an example file
we will be trying to add a filetag after title
```

Success!
The filetag was added above the title.


## Writing as a script {#writing-as-a-script}

Next I made it into a shell script in the home bin `$HOME/bin` so I could call it with `ranger` for our org files.

```bash
#!/usr/bin/env bash
#
# ./org-tag-add
#   Add tag before the #+title: in an org file

FILE="$1"

sed -n -i 'H;${x;s/^\n//;s/#+title\: .*$/\#\+filetags\:\ \:tag\:\n&/;p;}' "$FILE"
```

Make sure to add whatever filetag you want to the above script at `\:tag\:` if you want to use this.
I added the `sed` flag `-i` so that it would overwrite the file.


## Modify the ranger config {#modify-the-ranger-config}

To make `ranger` open `.org` files with the new script, I modified `$HOME/.config/ranger/rifle.conf` with the following code near the top.
I placed it on line 79 before the main rules.

```text

ext org = $HOME/bin/org-tag-add "$@"

```

`ranger` reads the `rifle.conf` file to know how to open files with certain file extensions, like opening `.txt` in `vim` or `nano` depending on how your `$EDITOR` bash variable is set.

What this did is open `.org` files in the script, which adds the tag and close it.


## Conclusion {#conclusion}

Next, I opened `ranger`, navigated to the directory with my org files and began "opening" files where I wanted to add the filetag specified in the script.
Hitting the `l` on each of the files opened, add the tag, and then closed the file.
Much simpler than opening each in `vim` or `emacs` and copy pasting the line in.
Much faster too.

When I was done I removed the line from `$HOME/.config/ranger/rifle.conf` so org files would again open in `$EDITOR`.

Image by [Adolphe Appian](https://artvee.com/dl/well-at-the-side-of-a-road/)