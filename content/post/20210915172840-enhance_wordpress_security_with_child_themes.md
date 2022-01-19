+++
title = "Enhance Wordpress Security with a Twenty Twenty-One Child Theme"
author = ["funcsec"]
date = 2021-12-15
publishDate = 2021-12-15
lastmod = 2022-01-18T16:45:40-08:00
tags = ["wordpress"]
categories = ["blueteam"]
draft = false
description = "Make your Wordpress website more secure and future-proof by using a child theme build on a default theme"
toc = "true +"
featured_image = "images/jan-miense-molenaer_the-five-sensestouch.jpg"
images = ["images/jan-miense-molenaer_the-five-sensestouch.jpg"]
+++

You can find the code for this on Github at [funcsec/twentytwentyone-child](https://github.com/funcsec/twentytwentyone-child)


## The issue {#the-issue}

One of the issues that I notice in maintaining and supporting Wordpress sites is that plug-ins and themes not only are they chronically out of date, but are often no longer supported.
It's a common problem.
This leaves clients stuck on an old, potentially insecure version of wordpress because they're theme cannot be updated, and their theme is bundled with a score of updates that also can no longer be updated.
The move from PHP5.6 to PHP7+ highlighted this a bit.


## A potential solution {#a-potential-solution}

One solution that I've used to mitigate this issue is to use the well supported WordPress default themes, as in the boring one that Automattic comes out with every year.
The default theme receives:

-   routine updates for years
-   supported by most, if not all, of the current plug-ins
-   typically a stellar example of Wordpress best practices

However the default theme is the default theme, it looks, well ~~boring~~ default.
So to customize and spruce things up we'll need to make some changes and the best way to make changes that will not break future updates is to use a child theme.
The following will be the files necessary to create a twentytwentyone child theme for a LAMP stack (but this will work on other hosts too).
First you'll need A new WordPress install and remote access to the web server to create the needed files and folders.
There are many tutorials online already on the subject and your web host might provide WordPress out of the box with a one quick install in cPanel or Wordpress pre-build into a virtual machine image.


## What is a child theme {#what-is-a-child-theme}

A child theme is a way to add additional code and styling to a WordPress theme without modifying the themes core files which would be overwritten by future updates of that theme.
In short, it enables you to update themes with customized code.
WordPress will read the modified code prior to reading the underlying themes code.
Please note that you should still take a look at the underlying code changes to make sure that your child theme code does not reflect older underlying theme code that may have been updated due to a security issue or bug.
This is because any files replaced by custom code are no run.
An example would be code in `twentytwentyone-child/custom.php` overrides code in `twentytwentone/custom.php`.


## Installing the child theme {#installing-the-child-theme}

Log into your server with whatever means provided to you, I'll be using SSH but I will give descriptions for a graphical user interface like Filezilla (FTP/FTPS/SFTP).
From the webroot where wordpress is installed, move into the install directory containing the WordPress software, on a typical Debian based server, this will be `/var/www/html/`, or somewhere around there.
Then change directories into the themes directory, add a new folder called `twentytwentyone-child`, and add the following files.

```bash
cd $WORDPRESSROOT  # webroot will be defined by your server

cd ./wp-content/themes/
mkdir twentytwentyone-child
cd twentytwentyone-child
```


## style.css {#style-dot-css}

From here you'll need to Copy paste the following into a new file called `style.css`. You can use `nano` or `vim` commands, maybe `cat` or `echo` if you're that brave. Or just grab the

```css
/*
Theme Name: Twenty Twenty-One Child
Theme URI: https://wordpress.org/themes/twentytwentyone/
Author: the WordPress team
Author URI: https://wordpress.org/
Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. With new block patterns, which allow you to create a beautiful layout in a matter of seconds, this theme’s soft colors and eye-catching — yet timeless — design will let your work shine. Take it for a spin! See how Twenty Twenty-One elevates your portfolio, business website, or personal blog.
Requires at least: 5.3
Tested up to: 5.8
Requires PHP: 5.6
Template: twentytwentyone
Version: 1.4
License: GNU General Public License v2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Text Domain: twentytwentyone-child
Tags: one-column, accessibility-ready, custom-colors, custom-menu, custom-logo, editor-style, featured-images, footer-widgets, block-patterns, rtl-language-support, sticky-post, threaded-comments, translation-ready
*/
```

You're welcome to change any of the values in that file to suit your needs however leave `Template: twentytwentone` alone


## functions.php {#functions-dot-php}

Do the same for this file, but name it `functions.php`.
This file is required to pull the correct parent style sheets.

```php
<?php

function my_theme_enqueue_styles() {
    $parenthandle = 'twentytwentyone-style';
    $theme = wp_get_theme();
    wp_enqueue_style( $parenthandle, get_template_directory_uri() . '/style.css',
	array(),  // if the parent theme code has a dependency, copy it to here
	$theme->parent()->get('Version')
    );
    wp_enqueue_style( 'twentytwentyone-style', get_stylesheet_uri(),
	array( $parenthandle ),
	$theme->get('Version') // this only works if you have Version in the style header
    );
}
add_action( 'wp_enqueue_scripts', 'my_theme_enqueue_styles' );

```

To recap, you should have two files in the `twentytwentyone-child` directory at `./wp-content/themes/`, `style.css` and `functions.php`. If you want to also have a image for the WordPress backend to Paul, add a `screenshot.png` file in the same directory.


## Enable the theme {#enable-the-theme}

Now login to your WordPress installation and navigate to `Appearance>Themes` to activate your new child theme.
And you're done, You now have a better future proofed website that you can build a custom theme on top of which will still get support for longer than many other themes!

You can find the code for this on Github at [funcsec/twentytwentyone-child](https://github.com/funcsec/twentytwentyone-child)