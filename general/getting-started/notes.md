

## nmap:
### flags:
[non]: Top 1000. TCP (not UDP)
-sC parameter to specify that Nmap scripts should be used to try and obtain more detailed information
-sV parameter instructs Nmap to perform a version scan. The version scan is underpinned by a comprehensive database of over 1,000 service signatures.  
-p- tells Nmap that we want to scan all 65,535 TCP ports.

### indicator ports: 
 port 3389 default for Remote Desktop Services --> indicates Windows OS
 port 22, SSH --> indicates Linux/Unix


