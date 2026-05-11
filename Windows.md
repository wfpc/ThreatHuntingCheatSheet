# Detailed ThreatHunting-CheatSheat For Windows

Simple usefull threat hunting cheat sheet for Windows environments, keep in mind these notes is usefull in newly enviroments not old windows versions.

This cheatsheet in more usefull when you don't access/not permited to use your tools in the case/eviroment or the time you reach to incidents.

---

**important Registry keys :**

| **Registry Key**                       | **Description**                                                                                                                                     |
|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Lists applications that run at system startup. Useful for identifying persistence mechanisms.                                                     |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Similar to the above but for user-specific applications.                                                                                          |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Contains information about services installed on the system, including their startup type and status.                                              |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | Contains the Local Security Authority settings. Look for any unusual modifications.                                                              |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | Lists installed applications, which can help identify rogue software.                                                                              |
| `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core` | Information about Terminal Services licensing. Modifications here can indicate unauthorized access attempts.                                      |
| `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\Run` | User-specific auto-start programs at login, useful for detecting user-specific persistence mechanisms.                                            |
| `HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout\Preload` | Lists keyboard layouts being used. Anomalies can indicate potential compromise in scenarios involving keyloggers.                                    |
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath` | Contains the path to the executable for each service. Unusual paths can indicate malicious activity.                                               |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers` | Contains settings related to code integrity policies. Check for any unauthorized changes.                                                          |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Includes settings for Windows logon behavior. Look for keys like `AutoAdminLogon` for unusual logon configurations.                               |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management` | Includes settings affecting how memory management is executed, can reveal tampering.                                                             |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI` | Contains settings for the logon user interface. Changes here may indicate unauthorized access attempts.                                           |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies` | User-specific security policies that can reveal suspicious configurations when modified.                                                         |

---

### ThreatHunting with Powershell

**WebshellHunting**

```powershell
Get-Childitem -Path "<Files_path>" -Include *.aspx,*.asp -Recurse | Select-String -Pattern "IOC_Pattern" | Select-Object LineNumber,FileName,Path,Pattern 
```

_Recommended patterns for ebove command :_

<Files_path> = IIS web hosted enviroment path

IOC_Pattern  = cmd, System.Io, shell, password= , XOR, decode, base64, sha256, \\^, powershell, System.Diagnostics etc...

Common webshell imports in .aspx (Use as IOC_pattern) : 

| **Library/Namespace**                      | **Description**                                                                                   |
|--------------------------------------------|---------------------------------------------------------------------------------------------------|
| `System.IO`                                | Provides functionality for file and directory manipulation (e.g., reading/writing files).       |
| `System.Diagnostics`                        | Allows execution of external processes, useful for command-line execution.                       |
| `System.Net`                               | Contains classes for network operations, including HTTP requests and responses.                  |
| `System.Web`                               | Includes classes for web applications, handling HTTP requests, and sessions.                      |
| `System.Security`                           | Provides access to security-related functions and classes, sometimes used for bypassing security restrictions. |
| `System.Reflection`                        | Allows inspection of types in managed assemblies; often used for dynamic code loading.          |
| `Microsoft.AspNet`                        | Part of the ASP.NET framework for accessing web application functionalities.                     |
| `System.Text`                              | Used for text manipulation, commonly for encoding and decoding data.                             |
| `System.Threading`                         | Provides classes and interfaces for managing concurrent operations and threading.                |


Common file extensions associated with ASP.NET web applications : 

| **File Extension** | **Description**                                                                          |
|--------------------|------------------------------------------------------------------------------------------|
| `.asp`             | ASP.NET contains script commands that are processed by the Web server before being sent to the client's browser |
| `.aspx`            | ASP.NET Web Forms page; contains server-side code to render HTML dynamically.           |
| `.ascx`           | ASP.NET User Control; reusable components that can be embedded in .aspx pages.         |
| `.ashx`            | ASP.NET HTTP handler; processes HTTP requests and can return custom responses.          |
| `.asmx`            | ASP.NET Web Service; used to expose methods over HTTP, commonly for SOAP services.      |
| `.asax`            | ASP.NET Application file; contains event handlers for application-level events.         |
| `.config`          | Configuration files for ASP.NET applications, often used to store settings.            |
| `.axd`            | ASP.NET HTTP handler for various services, commonly used for web resources.             |
| `.dll`             | Compiled .NET assemblies used in ASP.NET applications; can contain server-side logic.   |
| `.svc`             | WCF Service file; defines services for web service calls in .NET.                       |
| `.json`            | Often used for configuration or data interchange, could be targeted in attacks.         |


**File signing check :** 

```powershell
Get-AuthenticodeSignature -FilePath "C:\Windows\system32\*"

#for ignoring errors like "The process cannot access the file because it is being usedby another process."
Get-ChildItem "C:\Windows\system32\*" | ForEach-Object { try { Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction Stop } catch {} }

```

**common directories that malware typically uses to store files, execute malicious code, or maintain persistence:**

**recommendation:** check These pathes for suspicous files if you see some executables dlls check the sign

**_A Quick trick:_** you can use sort by "Access Modified" when viewing files by hand or script, many .dmp files like the ones mimikatz generates can found quickly because user often doesn't access these types of files. time is the key but keep in mind is not important in first look cause can be edited easily by attackers and should be checked more detailed in forensic and specific tools.


| **Directory**                                       | **Description**                                                                                         |
|----------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **`%TEMP%` or `%TMP%`**                            | Temporary directories used by the operating system where malware can store or execute temporary files.  |
| **`%APPDATA%`**                                    | Commonly used by malware to store configuration files and executable payloads, hiding in user profiles. |
| **`%PROGRAMDATA%`**                                | A shared space for applications to store data; malware often uses it for persistence across users.      |
| **`C:\Windows\System32`**                          | System directory where some malware places malicious DLLs or executable files to blend in with legitimate files. |
| **`C:\Windows\Temp`**                              | Similar to the TEMP directory, often used for temporary file storage by malware.                       |
| **`C:\Users\<Username>\AppData\Local\Temp`**      | User-specific temp folder commonly exploited for dropping malicious files that are executed.              |
| **`C:\Program Files`**                             | Malware may hide its payloads among legitimate software installations.                                 |
| **`C:\Users\<Username>\Documents`**                | Some malware uses user documents folders to disguise their presence or store harmful scripts.            |
| **`C:\Users\<Username>\Downloads`**                | Frequently used for dropping malicious executables disguised as legitimate downloads.                    |
| **`C:\Windows\Installer`**                         | Malware may manipulate or place files within this directory to execute during software installation processes. |
| **`C:\Windows\INF`**                               | Contains driver installation files; can be manipulated to install malicious drivers.                    |
| **`C:\Windows\System32\drivers`**                  | Directory for system drivers; malware may place malicious drivers here to gain low-level access.       |
| **`C:\Program Files (x86)`**                       | Similar to the Program Files directory, used for 32-bit applications on 64-bit systems; malware may hide here. |
| **`C:\Users\<Username>\AppData\Roaming`**         | Often used for storing application settings; can be exploited by malware to maintain persistence.      |
| **`C:\Windows\SysWOW64`**                          | Used for 32-bit binaries on 64-bit systems; similar threats as System32, where malware may reside.    |
| **`C:\Program Files\Microsoft Office\root\OfficeXX`** | Default installation path for Microsoft Outlook (replace "XX" with the version number, e.g., Office16 for Outlook 2016). |
| **`C:\Program Files\Microsoft\Exchange\`**        | Default installation path for Microsoft Exchange Server.                                              |



**Users and Groups information**

```powershell

# Get local users and groups :

Get-LocalUser -SID s-1-5-21-xxx
# show local users
Net User
# See specific Local Groups
Get-LocalGroup "Remote Desktop Users"

#For Domain Users:

# show domain users
Net user /domain
# show details about specific domain user (Check for last password set for ciritical accounts)
Net user /domain <username>
# show domain groups
Net Groups /domain
```
---

### Checking Processes

First We should Remember these Windows Core Processes:

| Process                   | PID  | Function                                                   | Normal Parent            | Suspicious Signs                                                   |
|---------------------------|------|-----------------------------------------------------------|--------------------------|-------------------------------------------------------------------|
| **System**                | 4    | Manages system operations, kernel tasks, memory, resources | System Idle Process (0) | Different parent, multiple instances, PID other than 4            |
| **smss.exe**              | N/A  | Creates user sessions; first user-mode process             | System (4)              | Multiple persistent instances, unusual parent                      |
| **csrss.exe**             | N/A  | Manages GUI operations and system shutdown                  | smss.exe                | Different parent, multiple instances per session                   |
| **wininit.exe**           | N/A  | Initializes system and starts services                      | smss.exe                | Different parent, multiple instances                                |
| **winlogon.exe**          | N/A  | Manages user logon and loads profiles                      | smss.exe                | Different parent, multiple instances per session                   |
| **lsass.exe**             | N/A  | Manages security policies and authentication                | wininit.exe             | Different parent, multiple instances, unusual outbound connections   |
| **services.exe**          | N/A  | Manages Windows services                                    | wininit.exe             | Different parent, multiple instances                                |
| **explorer.exe**          | N/A  | Provides Windows shell (desktop, Start Menu)               | userinit.exe            | Different parent, multiple instances, unusual locations            |
| **svchost.exe**           | N/A  | Hosts multiple Windows services                              | services.exe            | Different parent, unusual command line arguments, unexpected connections |


Usefull Commands for this part :
```powershell
Get-process
tasklist
```
common indicators for identifying suspicious processes in Windows using the `tasklist` and `Get-Process` commands in PowerShell:

| **Indicator**                    | **Description**                                                                                                           |
|----------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| **Unusual Process Names**        | Look for processes with names that seem out of context or are similar to legitimate processes but slightly altered.        |
| **High CPU or Memory Usage**     | Processes that consume an unusually high percentage of CPU or memory resources may indicate malicious activity.            |
| **Unexpected Parent Processes**  | Processes spawned by unfamiliar or suspicious parent processes can indicate exploitation or injection.                    |
| **Running from Uncommon Paths**  | Processes located in temporary directories (`%TEMP%`, `%APPDATA%`) or non-standard folders may be suspect.               |
| **No Digital Signature**         | Check if the process is unsigned or has an invalid signature, especially for system-critical processes.                    |
| **Network Activity**             | Processes initiating unexpected network connections (identified by using `Netstat` alongside process information).        |
| **Unexpected User Context**      | Processes running under unfamiliar user accounts or SYSTEM privileges can be suspicious.                                  |
| **File Modifications**           | Processes modifying system files or registry entries unexpectedly can indicate malicious behavior.                        |
| **High I/O Operations**          | High disk input/output activity from a process may suggest unauthorized data exfiltration or system compromise.           |
| **Multiple Instances**           | Multiple instances of the same process running simultaneously can be a sign of malware behavior.                         |

---

### Network Auditing

```powershell
Netstat -ano  # for check connections Established/listening ports and check IP addresses for suspicous connections,ports etc...
```

common indicators of suspicious connections that may warrant further investigation in a network environment:

| **Connection Type**             | **Description**                                                                                   |
|---------------------------------|---------------------------------------------------------------------------------------------------|
| **Unusual Remote IP Addresses** | Connections to known malicious IPs, suspicious geolocations, or previously unauthorized addresses.|
| **High Frequency Connections**   | Rapid or excessive outbound connections to the same or different IPs, indicating possible exfiltration or scanning activities.|
| **Uncommon Ports**              | Traffic on non-standard ports (not typical for HTTP, HTTPS, FTP) can signify bypass attempts or exploitation.                     |
| **Peer-to-Peer Traffic**        | Connections involving P2P protocols may indicate the use of file-sharing malware or unauthorized data transfer.                  |
| **Connections to Known C2 Servers** | Traffic to command and control (C2) servers known for distributing malware or controlling compromised systems.               |
| **Frequent DNS Lookups**       | Excessive DNS queries to specific domains, especially by a single application, can indicate the presence of DNS tunneling or malware. |
| **Localhost Connections**       | Unexpected connections from external IPs to localhost (127.0.0.1) can indicate loopback exploitation or tunneling. |
| **Unencrypted Traffic**         | Sensitive information transmitted over unencrypted connections (HTTP instead of HTTPS) can lead to data leaks or man-in-the-middle attacks. |
| **Connections During Odd Hours** | Traffic during unusual times (outside of normal operating hours) can signify malicious activity or unauthorized access attempts. |
| **Suspicious User-Agent Strings** | Unexpected or uncommon user-agent strings in HTTP traffic might indicate automated scripts or malware attempting to communicate. |


## Event IDs 

Keep in mind This is one of the most important parts of threat hunting in windows evniroments.

You can use tools like `DeepBlueCLI`/`APT-Hunter` for automated checking...

```powershell
# Detecting RDP BruteForce using 4625 EventID from Security logs (Also check this on SIEM)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Measure-Object
Get-WinEvent -LogName Security -InstanceId 4625 | Select-Object * | Measure-Object

# Filter by time
Get-winEvent -FilterHashTable @{ logname="Security"; starttime="9/9/2021" endtime="9/10/2021" }

# Check for encoded powershell commands
Get-Winevent -LogName 'Windows Powershell' | Where-Object { $_.Message -match '(--EncodedCommand| -enc| FromBase64String| Encoded)' | Select-Object *

# Check for script downloaders
Get-winevent -LogName 'Windows Powershell' | Where-Object { $_.Message -match 'Invoke-WebRequest| Invoke-RestMethod| curl| wget' } | Select-Object *
```



## **Top Common Event-IDs you check:**

### **1. Logon/Logoff Events**

| **EVENT ID** | **Description**                                                             |
| ------------ | --------------------------------------------------------------------------- |
| `4624`       | An account was successfully logged on.                                      |
| `4625`       | An account failed to log on.                                                |
| `4634`       | An account was logged off.                                                  |
| `4647`       | User initiated logoff.                                                      |
| `4648`       | A logon attempt was made using explicit credentials.                        |
| `4672`       | Special privileges assigned to new logon.                                   |
| `4740`       | A user account was locked out.                                              |
| `4771`       | Kerberos pre-authentication failed.                                         |
| `4776`       | The domain controller attempted to validate the credentials for an account. |

---

### **Types of Logon Events (Event-ID 4624)**

| **Logon Type** | **Description**                                                                                                         |
| -------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `2`            | **Interactive** – A user logged on locally at the console (direct logon).                                               |
| `3`            | **Network** – A user logged on remotely over the network (e.g., file sharing).                                          |
| `4`            | **Batch** – A logon by a scheduled task (e.g., Task Scheduler).                                                         |
| `5`            | **Service** – A service started by the Service Control Manager (SCM).                                                   |
| `7`            | **Unlock** – A user unlocked a workstation after it was locked.                                                         |
| `8`            | **NetworkCleartext** – A logon that occurs over a network connection (cleartext password sent).                         |
| `9`            | **NewCredentials** – A logon type used when credentials are passed in for an existing session (e.g., Run As).           |
| `10`           | **RemoteInteractive** – A logon from a Remote Desktop session.                                                          |
| `11`           | **CachedInteractive** – A logon attempt when a user is logging in with cached credentials (when the DC is unavailable). |

---

### **Common Logon Failure Status Codes (Event-ID 4625)**

| **Status Code** | **Description**                                                                |
| --------------- | ------------------------------------------------------------------------------ |
| `0xC0000064`    | **The specified user does not exist.**                                         |
| `0xC000006A`    | **The specified user account has been disabled.**                              |
| `0xC0000071`    | **The account is currently locked out and may not be logged on to.**           |
| `0xC000006D`    | **The attempted logon is for an account that is currently disabled.**          |
| `0xC0000133`    | **The time zone is not synchronized with the client computer.**                |
| `0xC0000234`    | **The user account has expired.**                                              |
| `0xC0000225`    | **The account has expired, or the user has failed to log on for a long time.** |
| `0xC0000072`    | **Account is locked.**                                                         |
| `0xC0000193`    | **The user’s password must be changed.**                                       |
| `0xC0000300`    | **Logon attempt from an unsupported workstation.**                             |
| `0xC000000F`    | **Invalid logon type.**                                                        |
| `0xC0000192`    | **The user does not have the necessary privileges to log on.**                 |
| `0xC000018C`    | **The password has expired.**                                                  |
| `0xC0000205`    | **The account has not been initialized or registered with the domain.**        |
| `0xC0000070`    | **The account is locked due to multiple failed logon attempts.**               |

---

### **2. Account Management Events**

| **EVENT ID** | **Description**                                            |
| ------------ | ---------------------------------------------------------- |
| `4720`       | A user account was created.                                |
| `4722`       | A user account was enabled.                                |
| `4723`       | An attempt was made to change an account's password.       |
| `4724`       | An attempt was made to reset an account's password.        |
| `4725`       | A user account was disabled.                               |
| `4726`       | A user account was deleted.                                |
| `4728`       | A user was added to a group.                               |
| `4732`       | A member was added to a security-enabled local group.      |
| `4729`       | A member was removed from a security-enabled global group. |
| `4735`       | A security-enabled local group was changed.                |
| `4731`       | A security-enabled local group was created.                |
| `4767`       | A user account's password was changed.                     |
| `4871`       | A security-enabled global group was modified.              |

---

### **3. Object Access Events**

| **EVENT ID** | **Description**                          |
| ------------ | ---------------------------------------- |
| `4656`       | A handle to an object was requested.     |
| `4663`       | An attempt was made to access an object. |
| `5140`       | A network share was accessed.            |
| `5145`       | A network share object was accessed.     |
| `4616`       | The audit log was cleared.               |

---

### **4. System/Service Events**

| **EVENT ID** | **Description**                                   |
| ------------ | ------------------------------------------------- |
| `1100`       | The audit log was cleared.                        |
| `1102`       | The audit log was cleared.                        |
| `4103`       | The security event log was cleared.               |
| `4104`       | A script block was logged.                        |
| `4105`       | A script block was executed.                      |
| `4106`       | Windows PowerShell received a suspicious command. |
| `4719`       | System audit policy was changed.                  |
| `4698`       | A scheduled task was created.                     |
| `4702`       | A scheduled task was updated.                     |
| `4703`       | The permissions on an object were changed.        |
| `4704`       | A job was created.                                |
| `7045`       | A service was installed on the system.            |
| `7034`       | A service terminated unexpectedly.                |
| `104`        | Audit log was cleared.                            |

---

### **5. Network/Connection Events**

| **EVENT ID** | **Description**                                  |
| ------------ | ------------------------------------------------ |
| `5156`       | Windows Filtering Platform blocked a connection. |
| `5140`       | A network share was accessed.                    |
| `5145`       | A network share object was accessed.             |

---

### **6. Windows Defender Events**

| **EVENT ID** | **Description**                                              |
| ------------ | ------------------------------------------------------------ |
| `5001`       | Windows Defender Antivirus has started.                      |
| `5002`       | Windows Defender Antivirus real-time protection has stopped. |
| `5004`       | Windows Defender Antivirus detected a threat.                |
| `5007`       | Windows Defender Antivirus completed a scan.                 |
| `5010`       | Windows Defender Antivirus quarantined a threat.             |
| `5012`       | Windows Defender Antivirus restored a quarantined threat.    |

---

### **7. Registry Manipulation Events**

| **EVENT ID** | **Description**                                                                                                                                                                                                    |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `4657`       | **A registry value was modified** – This event logs when a registry value is changed, created, or deleted.                                                                                                         |
| `4663`       | **An attempt was made to access an object** – This event logs when a registry key (or value) is accessed, which can include both reads and writes to registry keys.                                                |
| `4660`       | **An object was deleted** – If a registry key or value is deleted, this event will be logged.                                                                                                                      |
| `4703`       | **Permissions on an object were changed** – If the permissions of a registry key are modified, this event logs the change.                                                                                         |
| `4722`       | **A user account was enabled** – Although this event is primarily related to user account status, it can indicate a change in system settings, which may indirectly include registry changes that enable accounts. |
| `5145`       | **A network share object was accessed** – While more related to file system shares, it can also indirectly affect registry keys tied to network settings or resources.                                             |

---

### **8. Time Manipulation Events (Event ID 1)**

| **EVENT ID** | **Description**                                                                                |
| ------------ | ---------------------------------------------------------------------------------------------- |
| `1`          | **System time was changed** – This event is logged whenever a time change occurs in the system |


clock, often used by attackers to alter the system time to evade logging and audits. |

---

### **9. SYSMON Events**

| **Sysmon EVENT ID** | **Description**                                                                                             |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| `1`                 | Process creation, useful for detecting unusual or malicious processes.                                      |
| `3`                 | Network connection detected, valuable for identifying unauthorized network activity.                        |
| `5`                 | Process terminated, important for monitoring unexpected terminations.                                       |
| `6`                 | Driver loaded, useful for detecting malicious drivers.                                                      |
| `7`                 | Image loaded, helps identify suspicious or malicious DLLs.                                                  |
| `11`                | File created, crucial for detecting suspicious file creation.                                               |
| `12`                | Registry object added or modified, useful for identifying persistence mechanisms and configuration changes. |
| `15`                | File deleted, important for tracking suspicious deletions.                                                  |
| `21`                | Process command line changed, useful for identifying attempts to modify running command lines.              |
| `22`                | Driver unloaded, helpful for monitoring the removal of potentially malicious drivers.                       |
| `23`                | Process tampering, indicates unauthorized changes to processes.                                             |
| `24`                | DNS query, valuable for identifying suspicious DNS activity, such as lookups related to C2 servers.         |


---

## Windows USB Device Profiling

### 1. Registry Keys for USB Device Profiling

| **Registry Key Path**                                       | **Description**                                                                                                  |
|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB`       | Contains information about USB devices connected to the system, including device IDs, device names, and configuration. |
| `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR` | Manages the USB storage drivers and stores information about USB storage devices.                               |
| `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\Vid_xxxx&Pid_xxxx` | Device-specific entries for USB devices (e.g., vendor ID and product ID), used to identify the device.         |
| `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USB`   | Stores information about USB device drivers and services (e.g., USB controllers).                               |
| `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\Root_Hub` | Contains registry keys for USB hubs, which provide information on the connected devices.                         |
| `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DevicePath` | Specifies paths for devices, including USB devices, useful for identifying storage device locations.           |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Tracks the device mounts for USB devices, such as when a USB flash drive or external drive is plugged in.       |

## 2. USB Shell Items

| **Shell Item**                                         | **Description**                                                                                          |
|--------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Stores history and metadata of connected USB storage devices (e.g., USB sticks, external drives).         |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Tracks USB devices and their usage, as well as other user activities.                                     |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Tracks recently opened documents, including those accessed from USB devices.                             |
| `Shell:::{b6e5a93c-4d34-4bc3-bbe0-dcd3a64bdb26}`       | The shell object for external USB storage devices, especially if the device is connected via USB ports.  |

## 3. USB Device Event Logs

| **Event ID** | **Description**                                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------------------------------|
| `20001`      | A USB device has been inserted into the system (DeviceConnect). This event logs when a USB device is connected to the system. |
| `20003`      | A USB device has been removed from the system (DeviceDisconnect). This event logs when a USB device is removed from the system. |
| `7000`       | A driver for the USB device could not be loaded, or there is a driver issue. Logs error related to USB device connectivity. |
| `7001`       | A USB device driver has successfully loaded.                                                                              |
| `2102`       | A USB device driver has been removed from the system. Logs when a USB device’s driver is uninstalled or unregistered.     |
| `4100`       | Windows PowerShell script or a similar script has executed USB-related commands (script execution).                        |
| `104`        | System audit logs cleared, which may involve the clearing of USB device history for malicious activity.                   |
| `4001`       | Logs failed attempts to install or configure a USB device (likely indicating unauthorized device installation attempts).   |

## 4. USB Event Logs in Windows Event Viewer

USB-related events are typically logged under **System**, **Security**, or **Application** logs. You can use the **Event Viewer** to check for events related to USB devices.

| **Log Category**    | **Event ID** | **Description**                                                                                                      |
|---------------------|--------------|----------------------------------------------------------------------------------------------------------------------|
| **System**          | `20001`      | USB device insertion event, indicating when a device has been connected to a USB port.                               |
| **System**          | `20003`      | USB device removal event, logged when a USB device is disconnected from the system.                                   |
| **System**          | `7011`       | Timeout error related to USB device initialization or response issues.                                               |
| **System**          | `7036`       | A USB device driver or service has successfully started.                                                              |
| **Security**        | `4624`       | Successful logon event (may contain USB-related logon if a USB device was used for authentication).                    |
| **Security**        | `4625`       | Failed logon event (may be logged if a USB security token or smart card is used and fails).                           |
| **Application**     | `1001`       | Application event (can be logged when a program interacts with a USB device).                                         |
| **Application**     | `1002`       | Application crash event (often involving interaction with USB-connected devices).                                     |

## 5. PowerShell Cmdlets for USB Device Profiling

Using PowerShell, you can profile and manage USB devices. Here are some useful cmdlets for USB device management:

```powershell
# Retrieve all USB hubs
Get-WmiObject -Class Win32_USBHub

# Retrieve all devices, including USB devices
Get-WmiObject -Class Win32_PnPEntity

# Retrieve USB controllers and their associated device IDs
Get-WmiObject -Class Win32_USBControllerDevice

# Retrieve detailed information about the USB devices connected to the system
Get-WmiObject -Class Win32_USBDevice

# Retrieve USB-related events from the System log
Get-EventLog -LogName System -Source USB
```

## 6. USB Device Driver Information (via Device Manager)

You can also gather USB device details through **Device Manager** for detailed information:

| **Location**       | **Description**                                                                                                                  |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| **Device Manager** | Under **Universal Serial Bus Controllers**, you will find information about each connected USB device and hub.                   |
| **Device Manager** | Right-click on a device and select **Properties** to see detailed information such as **Driver**, **Resources**, and **Events**. |

## 7. USB Device GUIDs for Profiling

You can also use **GUIDs (Globally Unique Identifiers)** for device classes to better profile USB devices:

| **Device Class** | **GUID**                                 |
| ---------------- | ---------------------------------------- |
| **USB Devices**  | `{36FC9E60-C465-11CF-8056-444553540000}` |
| **USB Storage**  | `{A5DCBF10-6530-11D2-901F-00C04FB951ED}` |
| **USB Hubs**     | `{F2A1B809-5E5A-464E-BD4E-2107F85D9A35}` |

---

Note that You can Check Many scenarios using these mentioned commands, as a hacker/hunter use your Creativity here too...

**GoodLuck!** **:)**









