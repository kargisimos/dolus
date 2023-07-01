# Dolus

## x86_64 LKM linux rootkit for kernel versions 4.x-5.x

## Description

Dolus (greek:δόλος, deception) is a 64-bit LKM rootkit, developed and tested on linux kernel 5.19.0. It runs on kernel-space and provides stealthiness for targeted files and directories, processes, system users and itself. Essentially, it hooks system calls made from user-space and returns it's own modified syscalls. More information about linux rootkits [here](https://linuxsecurity.com/features/what-you-need-to-know-about-linux-rootkit).

Disclaimer:
>This software is provided for educational purposes only. It is intended to demonstrate concepts and techniques related to computer security and should not be used for any malicious actions or illegal activities.

## How to install
* git clone https://github.com/kargisimos/dolus.git
* cd dolus/
* make
* sudo insmod dolus.ko

## Key features

The key features are:

* **hide rootkit**

>command: kill -34 \<any PID>
>
>hides dolus from lsmod, /proc/modules and /proc/kallsyms. To make it unhidden again, type the same command.

* **hide process**

>command: kill -35 \<PID>
>
>makes a process invisible based on the process ID. Cannot be listed by ps command.

* **hide directories**

>when dolus is run, it hides all directories that start with the "dolus_" prefix from commands such as ls. Removing the rootkit makes those directories unhidden again. Although hidden, directories can be normally accessed if someone knows that they do exist. 

* **hide files**

>when dolus is run, it hides all files that start with the "dolus_" prefix from commands such as ls. Removing the rootkit makes those files unhidden again. Although hidden, files can be normally accessed if someone knows that they do exist. 

* **privilege escalation**

>command: kill -33 \<any PID>
>
>grants root privileges to current user.