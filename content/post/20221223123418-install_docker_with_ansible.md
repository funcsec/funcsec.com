+++
title = "Install Docker with Ansible on Debian Bullseye"
author = ["funcsec"]
date = 2022-12-23
publishDate = 2022-12-23
lastmod = 2022-12-23T19:15:10-08:00
tags = ["ansible", "docker"]
categories = ["tutorial"]
draft = false
toc = "+"
omit_header_text = "+"
background_color_class = "bg-black-60"
description = "How to use install Docker using Ansible for larger deployment on Debian Bullseye"
featured_image = "images/edward-henry-potthast_boat-at-dock.jpg"
images = ["images/edward-henry-potthast_boat-at-dock.jpg"]
+++

The following was how Docker was added to Debian Bullseye using
Ansible. This could be helpful when adding Docker to a fleet of
servers. Otherwise it's much easier to copy paste commands from the
official Docker install documentation and save from creating
unnecessary automation.

Code for this project is on github at [ansible-docker](https://github.com/funcsec/ansible-docker).


## A new Docker group {#a-new-docker-group}

The first step was to create a new role for Ansible, this was so
Docker could be added to specific systems specified in the `hosts`
file of the Ansible project that contained many other types of
systems not related to Docker.

A new group file was created in a larger project so that dependencies
can be tied into the `site.yml`.

```yaml
---
- hosts: dockergrp
  roles:
    - docker
...
```

The following was added to `site.yml` file to hook the new
configuration into the larger Ansible playbook.

```yaml
- import_playbook: docker.yml
```

Ansible was now able to see the new group.

```bash
ansible-playbook -i hosts site.yml
```

The new Docker groups was created and connected into the larger
Ansible project.


## A Docker Role {#a-docker-role}

The following file and directory structure was created in a new
`roles/docker` folder. This structure was used for every role in this
larger Ansible playbook project for consistency among roles. You can
read more about the layout on the [Ansible Best Practice](https://docs.ansible.com/ansible/2.8/user_guide/playbooks_best_practices.html#directory-layout) Documentation
page.

```text
├── defaults
│   └── main.yml
├── files
├── handlers
│   └── main.yml
├── tasks
│   ├── docker.yml
│   └── main.yml
├── templates
└── vars
    └── main.yml
```

The `roles/docker/tasks/main.yml` file acted as a pointer to the
`docker.yml` file. This structure comes in handy with larger more
complicated roles where `main.yml` can act as a router to split up
what could be very large Ansible playbook files.

```cfg
---
#
# Tasks to be applied to all servers
#

# Add further tasks for the common role (applied to all servers) to this playbook...

- name: Include docker tasks
  include_tasks: docker.yml
  tags: docker

...
```

That finished the plumbing to connect the new role into the larger
Ansible project. The next step was to add tasks to automate the
installation of Docker.


## Creating tasks {#creating-tasks}

Any previous versions of Docker that might have been on the machine
needed to be removed. This task was created in the
`roles/docker/tasks/docker.yml` file along with most other tasks in
this section.

<a id="code-snippet--task-removeprevious"></a>
```cfg

- name: Remove legacy packages
  apt:
    pkg:
    - docker
    - docker-engine
    - docker.io
    - containerd
    - runc
    state: absent
  tags: docker

- name: Install required packages
  apt:
    pkg:
    - ca-certificates
    - curl
    - gnupg
    - lsb-release
  tags: docker
```

Default variables were added to specify the Docker apt locations in
`roles/docker/defaults/main.yml`. This was so they could be changed
easier in a DRY type way. If the gpg key used by Docker changes in the
future, or if something malicious happens, the checksum will fail and
indicate that there is a problem or an update has happened.

<a id="code-snippet--defaults-keys"></a>
```cfg
docker_key_url: "https://download.docker.com/linux/debian/gpg"
docker_asc_path: "/etc/apt/keyrings/docker.asc"
docker_asc_checksum: "sha256:1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
docker_key_path: "/usr/share/keyrings/docker.gpg"
docker_list_path: "/apt/source.list.d/docker.list"
```

The next trick was to install the apt repository key for Docker via
Ansible. This was simply a translation of the [Docker installation
guide](https://docs.docker.com/engine/install/debian/) for Debian to Ansible. These were placed in
`roles/docker/tasks/docker.yml`.

The Ansible module [apt key](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/apt_key_module.html) had been depreciated so the new solution
was to do the following to add repo keys for apt. In summary, it was
download the key, convert it to binary format, move it where the other
keys are stored, then link to the new key location in the sources list
for the repository.

<a id="code-snippet--task-addkey"></a>
```cfg

- name: Create key folder
  file:
    path: "/etc/apt/keyrings"
    state: directory
  tags: docker

- name: Add Docker key
  ansible.builtin.get_url:
    url: "{{ docker_key_url }}"
    dest: "{{ docker_asc_path }}"
    checksum: "{{ docker_asc_checksum }}"
    mode: 0644
  tags: docker

- name: Dearmor Docker key
  ansible.builtin.command: gpg --dearmor -o "{{ docker_key_path }}" "{{ docker_asc_path }}"
  args:
    creates: "{{ docker_key_path }}"
  tags: docker

- name: Add Docker repository to sources list
  ansible.builtin.apt_repository:
    repo: "deb [arch=amd64 signed-by={{ docker_key_path }}] https://download.docker.com/linux/debian {{ ansible_distribution_release }} stable"
    state: present
    filename: docker
  tags: docker
```

It's not best practice to use bash pipes in Ansible, so the download
and convert off into it's own tasks rather than use pipes with the
`shell` Ansible module.

Once the apt keys were installed, Docker and its dependencies could be
installed with the Ansible apt module. Docker was also enabled on boot
using the systemd Ansible module.

<a id="code-snippet--task-install"></a>
```cfg

- name: Install Docker packages
  apt:
    pkg:
    - docker-ce
    - docker-ce-cli
    - containerd.io
    - docker-compose-plugin
    update_cache: yes
  tags: docker

- name: Start and enable Docker services at boot
  ansible.builtin.systemd:
    name: "{{ item }}"
    enabled: yes
    state: started
  with_items:
  - docker
  - containerd
  tags: docker
```

To finish off the configuration, the `dockergrp` group was added to
the `hosts` file with a single test server.

```cfg
[dockergrp]
docker-server1
```

The Ansible-playbook was then run successfully and Docker was installed on `docker-server1`.

```bash
ansible-playbook -i hosts site.yml
```

```text
PLAY [dockergrp] **********************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************
ok: [docker-server1]

TASK [docker : Include docker tasks] **************************************************************************************************
included: /home/alex/ansible/roles/docker/tasks/docker.yml for docker-server1

TASK [docker : Remove legacy packages] ************************************************************************************************
ok: [docker-server1]

TASK [docker : Install required packages] *********************************************************************************************
ok: [docker-server1]

TASK [docker : Create key folder] *****************************************************************************************************
ok: [docker-server1]

TASK [docker : Add Docker key] ********************************************************************************************************
ok: [docker-server1]

TASK [docker : Dearmor Docker key] ****************************************************************************************************
ok: [docker-server1]

TASK [docker : Add Docker repository to sources list] *********************************************************************************
ok: [docker-server1]

TASK [docker : Install Docker packages] ***********************************************************************************************
ok: [docker-server1]

TASK [docker : Start and enable Docker services at boot] ******************************************************************************
ok: [docker-server1] => (item=docker)
ok: [docker-server1] => (item=containerd)
```

Installing docker was now as easy as adding the machine's hostname
under the `dockergrp` group in the `hosts` file in the Ansible project
root folder. That was how Docker was installed and configured using
Ansible on Debian Bullseye.