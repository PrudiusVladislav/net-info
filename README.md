Preparing for the “Networking Concepts” Practical Exam: Comprehensive Guide

This guide covers a wide range of commands and concepts that will help you excel in your upcoming practical exam. The tasks are similar to those you’ve encountered in lessons 10.1 and 11.1, focusing on SSH configuration, port management, network scanning, file searching, network calculations, and traffic analysis.

1. SSH Configuration and Custom Ports
------------------------------------
Logging into a Remote Server via SSH:
  • Basic SSH command:
    ssh username@server_ip
  • Specifying a custom port (if SSH is not on the default port 22):
    ssh username@server_ip -p custom_port

Editing SSH Configuration:
  • The SSH server configuration file is located at /etc/ssh/sshd_config:
    sudo nano /etc/ssh/sshd_config
  • Important directives in sshd_config:
    - Port: Specifies the port number that SSH listens on.
    - PasswordAuthentication: Enables or disables password authentication.
    - PermitRootLogin: Controls whether root can log in via SSH.

Changing the SSH Port:
  1. Open the SSH configuration file:
     sudo nano /etc/ssh/sshd_config
  2. Modify the Port directive:
     Port 2222
  3. Save the file and restart the SSH service:
     sudo systemctl restart ssh

Using systemd to Manage SSH Sockets:
  • Edit the SSH socket configuration:
    sudo systemctl edit ssh.socket
  • Add or modify the [Socket] section:
    [Socket]
    ListenStream=2222
  • Reload systemd and restart the SSH socket:
    sudo systemctl daemon-reload
    sudo systemctl restart ssh.socket

Generating a Random SSH Port:
  • Generate a random port between 2000 and 2500:
    PORT=$(shuf -i 2000-2500 -n 1)
  • Update the SSH socket configuration:
    sudo sed -i 's/ListenStream=.*/ListenStream='$PORT'/' /etc/systemd/system/ssh.socket.d/override.conf
  • Reload systemd and restart the SSH socket:
    sudo systemctl daemon-reload
    sudo systemctl restart ssh.socket

2. Network Scanning with nmap
-----------------------------
Installing nmap:
  • Update package lists and install:
    sudo apt update
    sudo apt install nmap

Scanning Ports:
  • Scan a host for open ports:
    nmap server_ip
  • Scan specific port ranges:
    nmap server_ip -p 0-1000
  • Scan localhost:
    nmap localhost -p 0-65535

Understanding nmap Output:
  • Open ports will be listed along with their associated services.
  • Use flags for more detailed scans (-A, -sV, etc.).

3. Searching for Files with find
--------------------------------
Basic Usage:
  • Syntax:
    find [path] [expression]

Examples:
  • Find files starting with “am” in a directory:
    find ~/exam/task -type f -name "am*"
  • Find files containing “star” in /usr/bin:
    find /usr/bin -type f -name "*star*"
  • Find files containing “sky” in /usr/lib:
    find /usr/lib -type f -name "*sky*"

Other Useful find Options:
  • Search by file size:
    find /path -size +50M
  • Search by modification time:
    find /path -mtime -1

4. Network Calculations and Subnetting
--------------------------------------
Calculating Host Requirements:
  • Department 1: 40 people × 3 devices = 120 devices
  • Department 2: 10 people × 10 devices = 100 devices
  • Department 3: 20 people × 2 devices = 40 devices
  • Total devices: 260

Determining Subnet Masks:
  • Find the smallest subnet that can accommodate 260 devices.
  • The next highest power of 2: 512 hosts (2^9).
  • Subnet mask: /23 (since 32 - 9 = 23).
  • Subnet mask in decimal: 255.255.254.0

Calculating Network Addresses:
  • Use subnetting techniques to allocate IP ranges for each department.
  • Ensure each department has its own subnet.

5. Analyzing HTTPS Traffic with Wireshark
-----------------------------------------
Setting Up SSLKEYLOGFILE:
  • Define the environment variable:
    export SSLKEYLOGFILE=~/sslkeys.log

Launching a Browser with SSLKEYLOGFILE:
  • For Firefox:
    SSLKEYLOGFILE=~/sslkeys.log firefox

Capturing Traffic in Wireshark:
  • Start capturing on the appropriate network interface.
  • Apply display filters to narrow down the traffic:
    ip.addr == kernel.org_ip

Importing SSL/TLS Keys into Wireshark:
  • Go to Edit → Preferences → Protocols → TLS.
  • Set the (Pre)-Master-Secret log filename to ~/sslkeys.log.

Analyzing TLS Handshake:
  • Look for packets like Client Hello and Server Hello.
  • Decrypted application data will be visible if keys are imported correctly.

6. User Management and SSH Password Authentication
---------------------------------------------------
Adding a New User:
  • Create a user and set a password:
    sudo adduser testuser

Enabling Password Authentication in SSH:
  • Edit the SSH configuration file:
    sudo nano /etc/ssh/sshd_config

  • Modify the following directives:
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes

  • Restart the SSH service:
    sudo systemctl restart ssh

Testing SSH Login:
  • Log in using the new user credentials:
    ssh testuser@server_ip

7. Miscellaneous Commands and Tips
----------------------------------
Installing Packages:
  • Update package lists:
    sudo apt update

  • Install a package (e.g., cmatrix):
    sudo apt install cmatrix

File Operations:
  • View file contents:
    cat filename
    less filename

  • Redirect output to a file:
    command > file.txt  # Overwrites file
    command >> file.txt # Appends to file

Editing Files with nano:
  • Open a file:
    nano filename

  • Save changes: Ctrl + O, then Enter
  • Exit nano: Ctrl + X

Using man Pages:
  • Access the manual for a command:
    man command_name

8. Systemctl Commands
----------------------
Service Management:
  • Check the status of a service:
    sudo systemctl status service_name

  • Start a service:
    sudo systemctl start service_name

  • Stop a service:
    sudo systemctl stop service_name

  • Restart a service:
    sudo systemctl restart service_name

Reloading Daemon and Services:
  • Reload systemd manager configuration:
    sudo systemctl daemon-reload

9. Security Considerations
--------------------------
SSH Key Management:
  • Generate an SSH key pair:
    ssh-keygen -t ed25519 -C "your_email@example.com"

  • Copy the public key to the server:
    ssh-copy-id username@server_ip

Firewall Management with ufw:
  • Check the firewall status:
    sudo ufw status

  • Allow a port through the firewall:
    sudo ufw allow port_number

  • Reload ufw to apply changes:
    sudo ufw reload

10. Network Utilities
---------------------
Checking Network Interfaces:
  • Display all network interfaces and IP addresses:
    ip a

Testing Connectivity:
  • Ping a host:
    ping server_ip

  • Traceroute to a host:
    traceroute server_ip

DNS Lookup:
  • Using dig:
    dig example.com

  • Using nslookup:
    nslookup example.com

11. Shell Tips and Shortcuts
----------------------------
Command History:
  • View command history:
    history

  • Repeat the last command:
    !!

  • Run a specific command from history:
    !n  # Where n is the command number

Auto-completion:
  • Use the Tab key to auto-complete commands or filenames.

Stopping a Running Command:
  • Press Ctrl + C to interrupt a command.

Clearing the Terminal Screen:
  • Clear the screen:
    clear

12. File and Directory Management
----------------------------------
Creating Directories:
  • Create a new directory:
    mkdir directory_name

  • Create nested directories:
    mkdir -p parent_directory/child_directory

Copying Files and Directories:
  • Copy a file:
    cp source_file destination_file

  • Copy a directory:
    cp -r source_directory destination_directory

Moving and Renaming:
  • Move or rename a file/directory:
    mv old_name new_name

Deleting Files and Directories:
  • Delete a file:
    rm filename

  • Delete a directory and its contents:
    rm -r directory_name

13. Environment Variables
--------------------------
Setting Environment Variables:
  • Temporary for the session:
    export VARIABLE_NAME=value

  • Permanent (add to ~/.bashrc or ~/.profile):
    echo 'export VARIABLE_NAME=value' >> ~/.bashrc

Viewing Environment Variables:
  • Display all environment variables:
    printenv

  • Display a specific variable:
    echo $VARIABLE_NAME

14. Redirecting and Piping Output
---------------------------------
Redirecting Standard Output and Error:
  • Redirect standard output:
    command > output.txt

  • Redirect standard error:
    command 2> error.txt

  • Redirect both standard output and error:
    command > output.txt 2>&1

Using Pipes to Chain Commands:
  • Pipe the output of one command to another:
    command1 | command2

  • Example:
    ls -la | grep '^d'

15. Scheduling Tasks with cron
------------------------------
Editing the Crontab:
  • Open the crontab editor:
    crontab -e

Crontab Format:
  • Syntax:
    * * * * * command_to_execute
    The five asterisks represent minute, hour, day of month, month, and day of week.

Example:
  • Run a script every day at 2 AM:
    0 2 * * * /path/to/script.sh

16. Process Management
----------------------
Viewing Running Processes:
  • Use top to display real-time process information:
    top

  • Use ps to snapshot current processes:
    ps aux

Managing Processes:
  • Kill a process by PID:
    kill PID

  • Kill a process by name:
    killall process_name

Stop tracking history for current session:
 - unset HISTFILE

rustscan -a 192.168.65.6 --range 1-1000
