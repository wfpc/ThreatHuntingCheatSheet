# ThreatHunting-CheatSheat For Linux

Simple usefull threat hunting cheat sheet for Linux environments, keep in mind these notes is usefull in newly enviroments not old Linux versions.

This cheatsheet is more usefull when you don't access/not permited to use your tools in the case/eviroment or the time you reach to incidents.

## **System Information**

| **Location**           | **Purpose (excerpt from `man hier`)**                                  |
|------------------------|-------------------------------------------------------------------------|
| `/etc`                 | System‑wide configuration files                                         |
| `/var/log`             | Default log directory                                                   |
| `/tmp`, `/`, `/dev/shm`| Temporary & RAM‑backed storage (often abused)                           |
| `/var/www/html`        | Web‑server document root (common web‑shell target)                      |


- **View Kernel and OS Version:**
  ```bash
  uname -r  # View kernel version
  cat /etc/os-release  # View OS version

* **User Information:**

  ```bash
  sudo cut -d: -f1 /etc/passwd  # Show only usernames
  getnet passwd  # If using LDAP/NSS, view networked user details
  
  #passwd reading format : username:password:UID:GID:GECOS:home_directory:shell
  ```
  


## **Services & Systemd**

* **Service Locations:**

  * `/etc/systemd/system/` - Custom systemd services
  * `/lib/systemd/system/` - Default systemd services
  * `~/.config/systemd/user` - User-specific systemd services

* **Managing and Viewing Services:**

  ```bash
  systemctl list-unit-files --type=service  # List all service unit files
  systemctl list-timers  # List active timers
  systemctl list-units --type=service  # List active services
  systemctl cat <service-name>.service  # View configuration of a specific service
  ls /etc/systemd/system/  # View custom services directory
  ```

* **Security (SELinux & Auditd):**

  ```bash
  sestatus  # Check SELinux status (enabled/disabled)
  systemctl auditd status --no-pager  # Check status of audit daemon for logging. -- no-pager for avoid paging.
  journalctl -xe  # View recent system logs (systemd)
  ```

---

## **Startup & Cron Jobs**

* **Example of How to read a cronjob :**
```bash
m=minute, h=hour, dom=day of month,
mon=month, dow=day of week, *=none

# m   h  dom  mon  dow    user     command
  30  2   1    *    1   user_one   /usr/local/bin/backup.sh 

Runs /usr/local/bin/backup.sh as user user_one at 02:30 AM on the 1st day of every month but only if that day is a Monday (dow = 1).
```

* **Boot-Time Scripts:**

  * `/etc/rc.local` - Scripts run at boot time (if present)
  * `/etc/init.d/` - Initialization scripts (may be used by old init systems)

* **Cron Jobs:**

  * `/etc/cron*` - Cron configuration directories (daily, hourly, etc.)
  * `/var/spool/cron/` - Cron job files for system users
  * `/var/spool/cron/crontabs/` - Crontab directory for users

* **User Profile Configurations (Potential Attack Surface):**

  ```bash
  ~/.bashrc        # User-specific bash configurations
  ~/.bash_profile  # Another user-specific configuration file
  ~/.profile       # User profile file
  ~/.bash_login    # Another user login profile
  /etc/profile     # Global login script for all users
  /etc/profile.d/  # Directory for additional global profile configurations
  ```

* **Autostart Programs:**

  ```bash
  /etc/xdg/autostart/  # Auto-start applications, similar to Windows startup
  ~/.config/autostart  # User-specific autostart programs
  ```

---

## **Log Files**

**Default Linux Log Locations**

| **Category**         | **Path(s)**                                                                                      | **Typical Contents**                                      |
|----------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| **System**           | `/var/log/syslog`, `/var/log/messages`, `/var/log/kern.log`, `/var/log/dmesg`                    | Kernel & init messages, driver events, boot logs.         |
| **Authentication**   | `/var/log/auth.log`, `/var/log/secure`                                                           | SSH, sudo, PAM success/fail, useradd/usermod.              |
| **Hardware**         | `/var/log/kern.log`, `dmesg`                                                                     | USB insert/removal, drivers, hardware errors.              |
| **User Activity DBs**| `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp`, `~/.bash_history`                              | Current logins, historical logins, failed logins, shell history. |
| **Application**      | `/var/log/apache2/*`, `/var/log/mysql/error.log`, `/var/log/vsftpd.log`, etc.                    | Service-specific access & error logs.                      |


## Auditd

One of the commmon options for logging on linux is Auditd if enabled in system we can use for hunting : 

```bash
systemctl auditd status  # check if auditd is enabled

auditctl -l # list of rules

#rule example Detect commands run withelevated privs.: 
auditctl -a always,exit -F arch=b64 -C euid!=uid -S execve -k sudo-abuse
```
**Note:** Rules can be made persistent in /etc/audit/rules.d/*.rules.

```bash
# Searching 

ausearch -k user-modify # Search by key


aureport -x --summary # Summary of executed binaries
# Syscall statistics
aureport -s
ausyscall 42          # map number -> 'connect'
ausearch -sc connect
```
---

## **Process Management & Resource Usage**

* **Viewing Running Processes:**

  ```bash
  ps auxf            # View running processes (including hierarchy)
  top                # Display system resource usage (interactive)
  htop               # Interactive process viewer (better UI than top)
  pstree -p          # Display process tree with PID
  ```

* **Viewing Open Files by PID:**

  ```bash
  sudo lsof -p <pid>  # Check opened files for a specific process
  ```

---

## **Network & Traffic Analysis**

* **Network Information:**

  ```bash
  ss -tuln                    # Display active sockets (TCP/UDP)
  sudo netstat -plant         # Show network connections, routing, listening ports
  sudo lsof -i                # List all open network connections
  lsof -i TCP/ lsof -i :22    # by port/tcp/udp
  sudo tcpdump -i any         # Capture network traffic (use with caution)
  ```

---

## **Miscellaneous**

* **Check kernel modules:**
  ```bash
  # list loaded kernel modules
  lsmod
  ```

* **File Integrity:**

  ```bash
  md5sum <file>        # Generate md5 hash for a file
  sha256sum <file>     # Generate SHA256 hash for a file
  ```

* **Memory & System Info:**

  ```bash
  free -h              # Display memory usage (human-readable)
  lscpu                # Display detailed CPU information
  ```


# Hunting Suspicious Files & Directories

This section covers commands and strategies to hunt for suspicious files and directories, focusing on hidden paths, immutable flags, user/group anomalies, and executable camouflage.

---

## Hidden Paths & Immutable Flags

### Suspicious hidden directories
Suspicious directories are often hidden by using dot-prefixed names (e.g., `..hidden`), which are harder to spot.

```bash
# Find directories with names beginning with two dots (e.g. '..secret')
find / -type d -name '..*'  # includes '...'
````

### Files locked with `chattr +i` (immutable flag)

Files that are marked as immutable (`chattr +i`) cannot be modified or deleted unless the flag is removed. This can indicate persistence mechanisms.

```bash
# Recursively list attributes and filter immutable files (look for the 'i' flag)
lsattr -R / | grep -- '----i'
```

---

## User / Group Anomalies

### Files owned by deleted accounts

Files with no matching user or group (`nouser`, `nogroup`) may have been created by deleted or unprivileged accounts, indicating suspicious activity.

```bash
# Find files with no matching user or group (nouser OR nogroup)
find / -type f -nouser -o -nogroup
```

### Files created by the `www-data` user inside user home directories

Sometimes webserver users (like `www-data`) create files in user home directories, which may indicate an attack or webshell.

```bash
# Find files in home directories that are owned by the webserver user 'www-data'
find ~ -user www-data
```

# Executable Discovery & Camouflage + (WebShell Detection)

### ELF binaries anywhere

ELF (Executable and Linkable Format) binaries can be used by attackers to deploy malicious programs. Searching for them across the system can reveal hidden malware.

```bash
# Find ELF binaries across the filesystem
find / -type f -exec file -p '{}' \; | grep ELF
```

## Images that are actually executables (Webshells)

Attackers may disguise executables as image files, often in webroots like `/var/www/html`. Checking for hidden executables masquerading as images can uncover such threats. this may happen using file uploaders.

```bash
# Find files that have an image extension but are identified as executables
find /var/www/html -regex '.*\.\(jpg\|png\)' -type f -exec file -p '{}' \; | grep -v image

# find files can execute commands with eval() function, check more in php language and apache.
grep -r "eval(" /var/www/html/
```

### Mismatch‑File Detection (PDF Add‑On)
Files whose header does not match their extension are called mis‑match files. The fastest hunt is:
```bash 
find . -type f -exec file --brief --mime-type '{}' \; -print | grep -vE 'valid_mime_regex'

find . -type f -exec file -p '{}' \; | grep ELF | cut -d: -f1
```
Quick Reference :
```bash
# Enumerate everything newer than reference dir
find /evidence -newer /tmp/baseline
# Sort files by access time
ls -lt --time=atime /evidence
# Count recent .txt
find . -iname '*.txt' -mmin -30 | wc -l
# Carve suspicious executable images
find . -regex '.*\.\(jpg\|gif\|png\)' -exec file {} \; | grep -v image
```


