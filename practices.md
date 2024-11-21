# Lesson 5.1: ICMP, IP routing and iptables
**NOTE** You can open this file in VSCode or other editor to have better commands highlight.

### 0. Lesson goals and grading scope
The main goal of this lesson is to work with IP routing, ip forwarding and filtering of trafic with iptables. Also we will use Wireshark to monitor the behavior of the network

**Grading:**
`0.5 points` - presence on the lesson
`0.25 points` - setup of custom routing(Task 2)
`0.25 points` - setup ip filtering rules using iptables based on the requirements(Task 3)

### 1. Warming up
**Knowledgebase START**
ICMP=Internet Control Message Protocol
DHCP=Dynamic Host Configuration Protocol
**Knowledgebase END**

0. Open Powershell on Windows or Terminal for MacOS and linux.
1. Start your virtual machine for example `multipass start noble` and get its IP address.
2. Open Wireshark and choose the interface that corresponds to connection between Host and virtual machine. Use `icmp` word in the filter line at the top. 
3. Open one more instance of Powershell on Windows or Terminal on MacOS and Linux. For Windows use `ping /n 10 <IP of virtual machine>` or for MacOS/Linux `ping -c 10 <IP of virtual machine>` command to ping the virtual machine.
4. Switch to Wireshark and review the package. Select some echo request first and review ICMP related info at the bottom of Wireshark window. Do the same for reply. Try to map the data to the information dispayed by the ping command.
5. Now let's change Wireshark filter from `icmp` to `dhcp`. And let's restart virtual machine
`multipass stop noble && multipass start noble`
6. After start of VM you can open shell with `multipass shell noble` and run `ip a` command there.
7. Now open Wireshark and review DHCP Discover/Offer/Request/ACK packets. Try to analyze `User Datagram Protocol` and `Dynamic Host configuration Protocol` sections at the bottom of the window to find some properties of the VM's network.


### 2. IPv4 routing.

1. For this task you will need 2 virtual machines. Therefore in addition to existing `noble` VM you can create one helper VM or reuse existing one if any.

2. Go to the shell of your `noble` VM and run `ip route` and `traceroute 8.8.8.8` commands. This allows you to show current rules for ip routes. Also check whether ip forwardng is enabled with command `sysctl net.ipv4.ip_forward`. The first task is to enable ip forwarding using this value.

3. Let's open the shell in the helper VM. Run `ip route` and `traceroute 8.8.8.8` commands. Now let's use `ip route add` command to add ip of `noble` VM as a default route. Check https://access.redhat.com/sites/default/files/attachments/rh_ip_command_cheatsheet_1214_jcs_print.pdf for some examples and current output of `ip route` that points to a default gateway.

4. Run `traceroute 8.8.8.8` and check the difference of the output.

5. Use `ip route delete` command to remove added route. Check `traceroute 8.8.8.8` one more time.

### 3. iptables.
**Knowledgebase START**
iptables is an utility that allows to filter ip packets based on the criteria.
It contains three chains INPUT, FORWARD and OUTPUT. You can add your own chain if needed.
**NOTE:** Rules are applied SEQUENTIALLY until the first match is found
`sudo iptables -L` or `sudo iptables -S` - show all the rules
`sudo iptables -A INPUT -p icmp -j DROP` - append new rule to the end of the table. in this example we want to DROP all the packets related to icmp protocol. You can check it by trying ping from host to the VM. There are other parameters for example you can ACCEPT instead of DROP and so on.
`sudo iptables -I INPUT -p icmp -s 192.168.105.1 -j DROP` - insert the rule to the beginning of the table. in this case we have -s flag that allows us to apply this rule only for single IP.
`sudo iptables -D INPUT -p icmp -j DROP` - delete already existing rule. Note if you have multiple copies
`sudo iptables -C INPUT -p icmp -j DROP`
`--dport 4242` - option that allows to apply the rule only in case when the destnation port of the packet is 4242.
Read more:
https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/4/html/reference_guide/s2-iptables-options-commands#s2-iptables-options-commands
https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/4/html/reference_guide/s2-iptables-options-parameters#s2-iptables-options-parameters
**Knowledgebase END**

**3.1** Start and login to the helper virtual machine from the task 2.
**3.2** Create some simple script that wll produce any output and use `socat TCP-LISTEN` command to run it on port 7373.
**3.2** Check that your server is accessible from both `noble` VM and the host system.
**3.2** Open one more shell in helper VM. Use iptables to disable access for everyone to the tcp port that was opened in item 3.2.
**3.3** Add some rule to allow access ONLY for ip that belong to host machine.

### 4. Other tasks
1. Use OUTPUT keychain to disable an ability of ping from your VM.
2. Use OUTPUT to disable an ability of virtual machine to access tcp port on other virtual machine.
3. Let's suppose you have some simple script running on port 7373 of some VM. Try to use https://medium.com/@zomev/linux-port-forwarding-with-iptables-294116643a50 to automatically redirect all the traffic targeted to port 4242 of the same machine so it will be handled by our socat solution on 7373.

---

# Lesson 6.1: TCP and UDP protocols
**NOTE** You can open this file in VSCode or other editor to have better commands highlight.

### 0. Lesson goals and grading scope
The main goal of this lesson is to work with TCP & UDP protocols and review the general structure of coresponding headers during data transfer with Wireshark.

**Grading:**
`0.5 points` - presence on the lesson
`0.5 points` - TODO(Task 2)

### 1. Warming up
0. Open Powershell on Windows or Terminal for MacOS and linux.
1. Start your virtual machine for example `multipass start noble` and get its IP address.
2. Open Wireshark and choose the interface that corresponds to connection between Host and virtual machine.
NOTE: to find the correct interface you can hover on interface name and it will show a network mask
Choose the one which corresponds to IP of your VM.
3. Login to VM with `multipass shell noble` and let's open udp port for listening `nc -ul 2024`
4. Open Wireshark and select the interface that corresponds to network of your VM. Filter by `udp.port==2024`
5. Open Terminal(MacOS/Linux) or PowerShell(Windows) and run command to send data via UDP
`nc -u <IP of VM> 2024` (MacOS/Linux)
`ncat -u <IP of VM> 2024` (Windows)
6. You can send some data from both Host to VM and vice versa. Let it be string test from host shell. Find corresponding udp segment in Wireshark.
7. Review information about segment: select it and then at the bottom of the screen expand `User Datagram Protocol` and `Data` subsections.
Also notice test substring as a part of hexadecimal representation in the bottom-right area.
8. Try to send another data using Host and repeat step 7.
And then just press enter within Host shell(it should send an empty string with newline).
In the last case we will have length 9 that consists of src port(2 bytes), dst port(2 bytes), length(2 bytes), checksum(2 bytes) and payload(1 byte)
9. Good job! Now we can run `cmatrix`.


### 2. TCP analysis

1. Now in addition to udp port we can open tcp port inside VM. Use another shell to start it:
`socat - TCP-LISTEN:2025,fork`

2. Adjust Wireshark filter so it will filter all the segments that belong to either tcp or udp ports 2024 `tcp.port==2024 || udp.port==2024`

3. Use new host shell to connect to the TCP port
`nc <IP of VM> 2024` (MacOS/Linux)
`ncat <IP of VM> 2024` (Windows)

4. Send some data(for example `TCPTest` string) from host via TCP and review the segment in Wireshark.
Your task is to find all the information related to TCP handshake and data transfer(flags, sequence numbers, acks) and write it down to some file.
Analyse TCP segment that corresponds to sent data and write down sequence, ack and port information.

5. Send the data(for example `TCPResponse`) from VM TCP shell with socat command to Host. Monitor Wireshark and write down information about corresponding TCP segment.

6.  Let's back to UDP and send some data from host to VM. Review output in Wireshark.
You should note that TCP 2024 and UDP 2024 are managed in parallel as they are independent.

7. Close TCP connection and analyse the segments observed in Wireshark - flags, ack, sequence numbers and write down this info.

8. Close all the commands and shells.

### 3. Other tasks.
Use the API server you wrote for one of the previous practices and analyse corresponding data exchange with Wireshark.
You can also use Wireshark menu Statistics => TCP stream graphs =>  time sequence ptrace. Then find the proper Stream number to view the data.

---

# Lesson 7.1: 

### 0. Lesson goals and grading scope
The main goal of this lesson is to work with TCP protocols and review the general structure of coresponding headers during data transfer with Wireshark, also increase knowledge about usage of netcat utility.

**Grading:**
`0.5 points` - presence on the lesson
`0.5 points` - (Task 2)

### 1. Warming up
0. Open Powershell on Windows or Terminal for MacOS and linux.
1. Start your virtual machine for example `multipass start noble` and get its IP address.
2. Open Wireshark and choose the interface that corresponds to connection between Host and virtual machine.
NOTE: to find the correct interface you can hover on interface name and it will show a network mask.
Choose the one which corresponds to IP of your VM.
3. Login to VM with `multipass shell noble`
4. Start a simple http server by using the following comand on `socat`
`sudo socat -T 1 -d  -d  TCP-L:80,reuseaddr,fork,crlf  SYSTEM:"echo -e  \"\\\"HTTP/1.0  200  OK\\\nDocumentType: text/plain\\\n\\\ndate: \$\(date\)\\\nserver:\$SOCAT_SOCKADDR:\$SOCAT_SOCK- PORT\\\nclient: \$SOCAT_PEERADDR:\$SOCAT_PEERPORT\\\n\\\"\"; cat; echo -e \"\\\"\\\n\\\"\""`
	
5. Try to scan virtual network with nmap from another VM for open http ports, observe TCP communication between machines.
`nmap <VM network ID>/<VM Network CIDR>`

6. Do 4-5 steps with a 443 port and scan for open https ports.


### 2. Reverse shell
**NOTE** You may need to install ncat on VM `sudo apt install ncat` 

1. Let's listen on some port of our machine(either Host or helper VM):
`ncat -lnvp 1715`

2. Adjust Wireshark filter so it will filter all traffic in between machines

3. Create some files inside your VM:
```bash
mkdir ~/test7_1
cd ~/test7_1
touch test.txt
echo "Jump" > bingo.txt
mkdir new
echo "Run" > new/1.txt
```
4. Use VM shell to connect to the TCP port of Host machine or helper VM:
`ncat -e /bin/bash <IP of host or helper VM> 1715`

4. Now our VM exposed it's shell and that shell is accessible on the host machine or helper VM.
Let's execute `ls` command and `pwd` in the shell with socat command which was started in Item 1.

5. Monitor Wireshark and write down information about corresponding connections. You should find some segments with the output commands execution.

6. Let's run command `grep Jump *` in the reeverse shell. We should file with that Jump word. But where it's placed. `find -name bingo.txt`

6. Close TCP connection and analyse the segments observed in Wireshark - flags, ack, sequence numbers and write down this info.

7. Close all the commands and shells.

### 3. Other tasks
Practice your skills and learn more about find command https://www.redhat.com/en/blog/linux-find-command

---

# Lesson 8.1: WiFi security profile and filtering clients by MAC. Work with Linux find utility.
**NOTE** You can open this file in VSCode or other editor to have better commands highlight.

### 0. Lesson goals and grading scope
The main goal of this lesson is to work with WiFi security setup on real routers. Also we will practice our find and grep skills a bit.

**Grading:**
`0.5 points` - presence on the lesson
`0.25 points` - proper setup of the network on the real router including WiFi security profiles.
`0.25 points` - work with find and grep utilities

### 1. Routers
**Knowledgebase START**
It is important to set a good encryption to the WiFi network as this allows to decrease a possibility of some attack types. To manage security parameters easily MikroTik RouterOS uses security profiles.
Therefore you can save different parameters of security to different named entities and then you can use them as a part of wlan configuration. Note that we can use different profiles for wlan1 and wlan2 interfaces. Let's try to practice such an approach on the real router.
**Knowledgebase END**

**Routers list:**
Router 1. `MikroTik-7DDA0C` or `MikroTik-7DDA0D`. 10.31.41.2/20
Router 2. `MikroTik-7DDBFD` or `MikroTik-7DDBFE`. 10.32.52.34/20
Router 3. `MikroTik-7DD892` or `MikroTik-7DD893`. 10.33.73.42/20
Router 4. `MikroTik-7DDA4B` or `MikroTik-7DDA4C`. 10.34.44.73/20
Router 5. `MikroTik-7DDC3C` or `MikroTik-7DDC3D`. 10.35.65.115/20
Router 6. `MikroTik-7DDAFA` or `MikroTik-7DDAFC`. 10.36.76.137/20
Router 7. `MikroTik-7DEA5C` or `MikroTik-7DEA5D`. 10.37.107.200/20
Router 8. `MikroTik-7DFE2A` or `MikroTik-7DFE2B`. 10.38.78.222/20
Router 9. `MikroTik-7DEA1E` or `MikroTik-7DEA1D`. 10.39.21.240/20


**1.1** During this task students will be split into groups(2-3 people in every group). Each group will get its own `Router N`. For every router we have a subnet(see Router list) that should be used for further router setup.

**1.2** Find corresponding WiFi network based on the number *N* and router list from above. Login to the router via IP 192.168.88.1 and setup your own password for admin user.

**1.3** Go to **WebFig -> Wireless -> Security Profiles**. Your goal is to add 2 new profiles with `profile1` and `profile2` names. Both profiles whould use `Dynamic Keys` with `WPA2 PSK`. Choose some password for wifi network but append suffix `1` for `profile1` and suffix `2` for `profile2`

**1.4** Go to **WebFig -> Wireless** and go to wlan1 interface. Your task is to change Wireless part of options. Change WiFi SSID to `Router N 1` and ensure that `profile 1` will be used for this network. Apply and reconnect to router if needed.

**1.5** Go to **WebFig -> Wireless** and go to wlan1 interface. Your task is to change Wireless part of options. Change WiFi SSID to `Router N 2` and ensure that `profile 2` will be used for this network.

**1.6** Try to connect to both of the networks using corresponding passwords provided in corresponding profiles.

**1.7** Let's limit access to wifi based on mac address. If your devices are connected to the router WiFi then the easiest way to find your mac address is to open Quick Set on router and review Local clients list.
We need at least 2 devices for this task.

**1.8** Go to WebFig => Wireless => Access list and add one rule for the first mac address and wlan1 - Authenticate should be on.
Add another rule for another mac address and wlan2 - Authenticate should be on.

**1.9** Go to Interfaces => Wireless => wlan1 and in Wireless section uncheck Default Authenticate and apply. Try to connect to `Router N 1` network from both devices you specified in access list. One should connect while other will be rejected.
*NOTE* By default interface allows any connection but if we disable that behavior then it rely on access list.

**1.10** Use `Router N 2` to disable Default Authentication for wlan2 and perform the same check of avaliability on both devices.

**NOTE** You can create different rules with access list. For example, if you will omit MAC address field then the rule will be applied to all and the behavior will depend on Autenticate checkmark.
You can add few rules and they will work like iptables for example to reject only two mac addreses you can use:
MAC=mac1 Authenticate=no
MAC=mac2 Authenticate=no
MAC=    Authenticate=true

**1.11** Don't forget to reset router after teacher's check.

### 2. Find utility
**2.1** Login to your virtual machine for example `multipass shell noble`. Create folder ~/task8.1 and cd to it.

**2.2** Use nano to create file generate_files.sh with the following content:
```bash
#!/bin/bash

function gen_random() {
   shuf -i 1-50000 -n 1
}

function get_random_name {
   VALUE=$(cat /usr/share/dict/words | head -$(gen_random) | tail -1 | sed "s/'//g")
   echo "${VALUE}" 
} 

FILE_COUNT=1000
TOP_DIR=`pwd`/test_random

rm -rf ${TOP_DIR}
mkdir ${TOP_DIR}
cd ${TOP_DIR}

apt list --installed | grep wamerican
if [ $? -ne 0 ]; then
   sudo apt install -y wamerican
fi

for((i=0;i<=${FILE_COUNT};i++))
do
    if [ $((i % 100)) -eq 0 ]; then
       NEW_DIR=${TOP_DIR}/"$(get_random_name)"
       mkdir -p ${NEW_DIR}
       cd ${NEW_DIR} > /dev/null
    fi
    if [ $((i % 100)) -eq 20 ]; then
       NEW_SUBDIR="$(get_random_name)"
       mkdir -p ${NEW_SUBDIR}
       cd ${NEW_SUBDIR}
    fi
    if [ $((i % 3)) -eq 0 ]; then
      EXT="sh"
    else
      EXT="txt"
    fi
    RANDOM_FILE="$(get_random_name)".${EXT}
    CUR_VALUE=$(gen_random)
    for((j=0; j < $(($CUR_VALUE % 5)); j++)); do
       echo "$(get_random_name)" >> ${RANDOM_FILE}
    done
    echo -e -n "\rFile ${i}/${FILE_COUNT}"
done

echo ""

```
**NOTE** This script uses dictionary from wamerican package and randomly generated numbers to create directories, files and file content.

**2.3** Use find command to find files with names that match some pattern for example for files that contains the first 2 letters of your name or surname or try other combinations if nothing was found, search for some files with extension:
`find ./test_random -name "*jo*\.txt"`
`find ./test_random -name "*tr*\.sh"`

**2.4** Search through the file content for random word of sequence of letters
`grep -Ri "du" ./test_random`
`grep -Ri "inf" ./test_random`
and so on

**2.5** Use cat command on some of the files to view the content.

**2.6** Choose random word and check whether it is present either in file/folder names or inside file content.

---

# Lesson 9.1: 

### 0. Lesson goals and grading scope
The main goal of this lesson is to work with SSH local and remote port forwardind.

**Grading:**
`0.5 points` - presence on the lesson
`0.25 points` - ssh local port forwarding(Task 2).
`0.25 points` - ssh remote port forwarding(Task 3).

### 1. Warming up
0. Open Powershell on Windows or Terminal for MacOS/Linux.
1. Start your virtual machine for example `multipass start noble`.
2. Login to VM with `multipass shell noble`
3. We need to install `apache2` package.
4. Check whether apache2 is running by scanning ports with `nmap localhost`
5. Check whether your public SSH key is present on VM if not then copy it from your host OS:
`cat ~/.ssh/authorized_keys`
6. Exit from VM shell.
7. Use command `ssh ubuntu@<VM_ip>` to check that ssh works fine.


### 2. SSH local port forwarding aka SSH tunneling
# KNOWLEDGE_BASE_START
The main idea of port forwarding is to get access to some resources on machine with firewall rules using ssh tunnel. In the case of local port forwarding ssh allows to map remote port to local port of your machine so you will be able to access the resource as long as corresponding command is running.
View more: https://www.youtube.com/watch?v=AtuAdk4MwWw
Read more: https://builtin.com/software-engineering-perspectives/ssh-port-forwarding
# KNOWLEDGE_BASE_END

2.1. As we already checked that apache2 is running on VM then let's open browser on host system to access http server on VM. Use ip address in address line. You should see the default page from apache2 server.

2.2. Use iptables on VM to allow access to the port 80 only from localhost, all other input connections to that port should be rejected.
Ensure that rules works fine: check on host that http server is not available, while inside VM you can use `nc localhost 80` command and after typing any line to nc console http server sends a response.

2.3. Open Powershell on Windows or Terminal for MacOS/Linux. Let's do some magic with ssh port forwarding. We want to map our local port 12000  to the remote port 80. Run the command
`ssh -N -L localhost:12000:localhost:80 ubuntu@<IP of VM>`
**NOTE:** -N - non-interactive;
          -L local forwarding e.g. the first 2 components localhost:12000 belongs to our host, localhost:80 belongs to the remote machine.

2.4. Let's open browser and type http://localhost:12000 if everything was executed properly then you should be able to view apache2 page.

2.5. Return to PowerShell or Terminal and cancel command from step 3 of this task.
Go back to the browser and try to open http://localhost:12000 one more time.
Ensure also that direct IP to port is not working by checking http://<noble IP>:80

2.6. Keep calm: We will use that firewall rules and blocked access to the port 80 for the task 3.


### 3. SSH remote port forwarding aka SSH reverse tunneling
# KNOWLEDGE_BASE_START
Let's suppose we have a local network and 2 machines:
- Machine1 is running service on some port but has no public ip address or even no access to internet.
- Machine2 has public ip address.
The task is to expose service from Machine1 to be accessible via Machine2 ip address. To do that we can run the following command on Machine1:
`ssh -N -R <IP of Machine2>:<port to be mapped on Machine2>:localhost:<Port with service on Machine1> <user on machine 2>@<IP of Machine2>`
Example: map port 80 of Machine1 to port 8080 of Machine2(192.168.0.105)
`ssh -N -R 192.168.0.105:8080:localhost:8080 ubuntu@192.168.0.105`

View more: https://www.youtube.com/watch?v=AtuAdk4MwWw
Read more: https://builtin.com/software-engineering-perspectives/ssh-port-forwarding
# KNOWLEDGE_BASE_END

3.1. To perform this task you will need another VM. Let's call it `helperVM`(you can reuse any existing one) - create a new one if needed.

3.2. Let's login to our old VM `multipass shell noble` and generate SSH key(use defaults, do not set password)
`ssh-keygen -t ed25519`

3.3. Copy public part of generated SSH key so you can use it for further steps
`cat ~/.ssh/id_ed25519.pub`

3.4. Use another PowerShell/Terminal window to login to helperVM `multipass shell helperVM` and add public key from step 3.3 to authorized_keys
`mkdir -p ~/.ssh`
`nano ~/.ssh/authorized_keys`
Save the document(Ctrl + O) and exit(Ctrl+X).

3.5. Let's edit ssh config of helperVM to allow remove port forwarding:
`sudo nano /etc/ssh/sshd_config`
and find options, uncomment them if needed and ensure that both are set to yes:
GatewayPorts yes
AllowTCPForwarding yes

3.6. Save the document(Ctrl + O) and exit(Ctrl+X) and restart sshd service to reload config:
`sudo systemctl restart ssh`
*NOTE* your connection to helperVM may be dropped after that command. In that case just re-login to helperVM.

3.7. Find the ip address of `helperVM` with `ip a` and ensure that this address can be pinged from noble VM.

3.8. Open shell in noble VM or reuse existing one and try to check ssh connection from noble to helperVM:
`ssh ubuntu@<IP address of helperVM>`
then exit from ssh shell with Ctrl+D.

3.9. Let's do some magic with reverse ssh tunneling inside terminal of noble VM.
`ssh -N -R <IP of helperVM>:8000:localhost:80 ubuntu@<IP of helperVM>`

**NOTE** We want to expose our http server(port 80 of noble VM) to the port 8000 on helperVM
 -N is just to open non-interactive connection e.g. without login to VM and terminal access.
 -R is to create a remote tunnel that will expose our server on remote port 8000.
 <IP of helperVM>:8000:localhost:80
 |____________________||_____________|
  helperVM port          noble port

3.10. Open browser and try to access http server on helperVM port 8000 with http://<IP of helperVM>:8000

3.11. In shell of noble VM stop command execution from step 3.9.
Also remove iptables rules created during step 2 of the task 2 and ensure that http://<IP of noble> is now reachable.


### 4. Other tasks
To practice your skills with ssh local and remove tunnels you can try to do the following tasks:
1. Local port forwarding:
    a. use socat and some script to listen on port 7777.
    b. ensure that port 7777 is accessible from host(Windows/MacOS/Ubuntu) via nc/ncat command.
    c. use iptables to block port 7777.
    d. try to access port 7777 from the browser on your host.
    e. setup ssh tunnel to port 7777 from the VM and use port 15000 on the host.
    f. try to access port 7777 from the browser on your host.
    g. try to access localhost:15000 from the browser on your host.
    h. stop ssh tunnel from item e.
    h. cleanup iptables rules to unblock port 7777 inside VM.
2. Remote port forwarding:
    a. use socat and some script to listen on port 7777 of helperVM VM
    b. ensure that port 7777 is accessible from host(Windows/MacOS/Ubuntu) via nc/ncat command.
    c. use iptables to block port 7777.
    d. try to access port 7777 from the telnet on your host.
    e. in helperVM setup a ssh tunnel to expose 7777 port from noble as a port 9000 on the helperVM.
    f. try to access port 7777 with nc/ncat on your host(Windows/Mac/Linux).
    g. try to access <helperVM IP>:9000 from the browser on your host.
    h. stop ssh tunnel from item e.
    h. cleanup iptables rules to unblock port 7777 inside VM.


---

# Lesson 10.1: 

### 0. Lesson goals and grading scope
The main goal of this lesson is to work with custom socket for SSH and analysis of https traffic.

**Grading:**
`0.5 points` - presence on the lesson.
`0.25 points` - cutom ssh port setup (Task 1).
`0.25 points` - analysis of HTTPS traffic in Wireshark(Task 2).

### Task 1. Custom ssh port.
1.0. Start virtual machine for example `multipass shell noble`

1.1. Ensure that you have nmap installed on your host system(MacOS/Windows/Linux). Scan ip address of VM for open ports:
`sudo nmap localhost -p 0-1000` (MacOS/Linux)
`nmap localhost -p 0-1000` (Windows)

1.2. Check that you can login via ssh
`ssh ubuntu@<ip of VM>`
if no - check that public key `~/.ssh/id_ed25519.pub` from your host was added to `~/.ssh/authorized_keys` on VM

1.3. Now let's edit configuration of ssh:
`sudo systemctl edit ssh.socket`
And place or update the following block of code
```
[Socket]
ListenStream=2222
```

1.4. Save the file and perform the following commands:
```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
```

1.5. Use nmap command on the host to check what ports are open. You should see both 22 and 2222 bind to ssh.

1.6. Check access via ssh using:
`ssh ubuntu@<ip of VM> -p 22`
`ssh ubuntu@<ip of VM> -p 2222`

1.7. To remove default port we should use `sudo systemctl edit ssh.socket` and edit the file:
```
[Socket]
ListenStream=
ListenStream=2222
```
**NOTE** The first empty assignment is important as it signal that systemd should discard all the ports that were used before.
Without it we will have both 22 and 2222 are listening for ssh.

1.8. Save the file and perform the following commands:
```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
```

1.9. Repeat 1.5 and 1.6 and compare the results.

1.10. Let's generate a random port for VM ssh and apply it instead of 2222
```bash
PORT=$(shuf -i 2000-2500 -n 1)
sudo sed -i 's,2222,'$PORT',g' /etc/systemd/system/ssh.socket.d/override.conf
```

1.11. Logout from VM and try to find the port on which ssh is running.
Use ssh to connect with new port.

1.12. Present results to the teacher.

1.13. Now you should edit configuration to ensure that port 22 is a single port used for ssh access.

### Task 2. Monitoring of HTTPS traffic via Wireshark
**NOTE** For this task you should use Google Chrome or Firefox browser.
**KNOWLEDGE_BASE_START**
HTTPS protocol uses encryption which prevents direct monitoring of requests and responses.
While if you have private key of the client then you will be able to tune Wireshark setting and analyse the traffic.
In most of the browsers it can be achieved with SSLKEYLOGFILE environment variable. That file will store all the information needed by WireShark to do the magic.
**KNOWLEDGE_BASE_END**

2.1. On your Host machine create some folder that will be used for key log file. Let it be for example ~/TestTLS.

2.2. Open Wireshark and choose wifi interface for monitoring.
Go to menu Preferences => Protocols => TLS and set (Pre)-Master-Secret log filename to <path to home>/TestTLS/sslkeys.log or in case of Windows <path to home>\TestTLS\sslkeys.log
Click OK.

2.3. Use Terminal/PowerShell to perform nslookup for https://kernel.org to find the ip of the server.
Add the ip to Wireshark filter ip.addr == ip.you.just.found.

2.4. Open browser and go to the site https://kernel.org and check the output in wireshark. We are interested mostly in TLSv1.3 parts of the output.
Analyse the handshake and find the first encrypted message after handshake. It should contain Encrypted Application Data inside TLS section.

2.5. Let's close the browser and clear Wireshark log. In case of MacOS you may need go to the Dock and click to open menu for browser application and then Quit to completely close the application.

2.6. Open Terminal/PowerShell and run your browser from it with specifiying SSLKEYLOGFILE variable and the browser you want to run, for example:
*MacOS:*
SSLKEYLOGFILE=$HOME/TestTLS/sslkeys.log "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
*Windows:*
[System.Environment]::SetEnvironmentVariable('SSLKEYLOGFILE', "$HOME/TestTLS/sslkeys.log"); & "C:\Program Files\Google\Chrome\Application\chrome.exe"
*Linux:*
SSLKEYLOGFILE=$HOME/TestTLS/sslkeys.log google-chrome
SSLKEYLOGFILE=$HOME/TestTLS/sslkeys.log firefox

2.7. Ensure that new file was created in TestTLS folder. Open it with text editor and review the content.

2.8. Now let's open https://kernel.org in browser and monitor WireShark logs. If everything works fine you should see rows with HTTP2 highlighted with a green background.
Analyse the content of the rows.

2.9. Present teacher the results of the steps from above.

2.10. Close browser and remove folder TestTLS.

### Other tasks(Preparation to exam)
1. Organisation A wants to build a single wifi network. The regular count of devices is 240 devices but during different events it may reach up to 350 devices.
Calculate the smallest subnet(ip range, network address, broadcast address) which matches the organisation needs if we want a router to use address 10.3.115.1.
2. As a company's owner you want to restrict access of your employees to https://linux.org site as it takes a lot of their working time to hang on that time.
Provide bash commands that should allow to block that access.
3. Use traceroute command to find the first 5 hops to kernel.org.


---

# Lesson 11.1: 

### 0. Lesson goals and grading scope
The main goal of this lesson is to prepare for practical part of the Final Exam.

**Grading:**
`0.5 points` - presence on the lesson.
`0.25 points` - ssh setup to access shell with password(Task 1).
`0.25 points` - calculation of networks and work with find utility(Task 2).

### Task 1. SSH access with password.
**NOTE** SSH access with password is nor recommended for the real tasks as it has weak protection in compare to ssh key approach. But during exam we will use such an approach to simplify the scenario. Also it is important to know that such authorization is present and it can be applied for some types of tasks.


1.0. Start virtual machine, for example `multipass shell noble`

1.1. Let's add new user with the name `test`(choose any password you like and all other values can be skipped by pressing Enter)
`sudo adduser test`

1.2. Let's try to open secure shell for the new user from your host. Open Terminal/PowerShell and use the following command:
`ssh test@<ip of vm>`
It should return error like Permission denied(publickey)

1.3. Let's edit ssh config to allow access with password.
`sudo nano /etc/sshd_config`
and ensure that the following line is uncommented and set to yes(You can use Ctrl+W combination to search for that lines)
`PasswordAuthentication yes`
`KbdInteractiveAuthentication yes`

1.4. To apply config we should restart ssh service:
`sudo systemctl restart ssh`

1.5. Now let's repeat step 1.2. If everything is fine then you should be prompted to enter password for user test. Enter password.

1.6. Use commands `whoami` and `pwd` to ensure that you just logined as the user `test`.

1.7. Exit from that ssh session. Now let's open `multipass shell noble` and change ssh.socket to listen ssh clients on some port from the interval 3000-4000 - choose any you like.

1.8. Return back to Terminal/PowerShell and try to login as the user `test` and new port.

1.9. Ask teacher to check the results of the previous steps.

1.10. Revert back configuration e.g. configs from steps 1.7 and 1.3.

1.11. Ensure that password authentication is not working.

1.12. Present result of 1.11 to the teacher.


### Task 2. Network calculation and find utility usage.
2.1. Organisation has 3 departments. Here is the table with the data

Department  | People Count  | Max device count per user
Dep1        |       40      |       3
Dep2        |       10      |       10
Dep3        |       20      |       2

Calculate the smallest subnet which will satisfy the organisation needs if we know that IP 10.13.27.1 should be a part of the netowrk. Result should be in form: subnet mask, IP address range, network address and broadcast address.

2.2. Company wants to block access to FTPS server for all hosts except localhost and 10.12.24.5. Propose iptables rules that may be used to perform that task.

2.3. Use find command to get the list of all files from /usr/bin folder that contain `star` in the name.
Find all the files from /usr/lib folder that contain  `sky` in the name.

2.4. Run cmatrix and relax.
