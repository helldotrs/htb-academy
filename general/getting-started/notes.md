

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
