# Ransomware
This project is a Windows ransomware that encrypts all the user files with a strong encryption scheme.

This project is open source, feel free to study and contribute.

> [!WARNING]
> ### This project is only for education and research purposes. Use at your own risk. Maintainers and contributors to this project are not liable for any outcome when using or modifying this software.

# How it works
## Overview
This software uses the symmetric & asymmetric scheme[^1] to encrypt files.
The symmetric encryption algorithm used[^2] is [HC-128](https://www.ecrypt.eu.org/stream/e2-hc128.html), and the asymmetric one is [Curve25519](http://cr.yp.to/ecdh.html)

### Evasion
The program avoids local and remote debuggers. To avoid virtual machines it checks for user input, running processes, services, and hardware information.

### Pre-Encryption
When launched, the program uses a mutex to ensure only one instance is running, Then if the process doesn't have admin privileges, it attempts to get it using UAC bypass. In addition, the software disables default errors, changes token privileges and denies access to its process.
The program also mounts volumes to find devices that can be encrypted even though they cannot be accessed through the file explorer.
Before the encryption starts, the software generates a unique public-private Curve25519. the public key will be used to encrypt files and the private key will be encrypted with the server's public key.

### Encryption
After finding the amount of processors the CPU has, the software spawns that[^3] amount of threads whose job is to encrypt files, Then each available drive is iterated using a different thread to split the work between the iterators and achieve the best speed. The data is passed between the iterators and the encryptors using an [I/O Completion Port Object](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports).

Once the encryption thread receives a file, it attempts to open it. if it fails because other processes are using it, the program attempts to shut them down to get access to that file using the [Restart Manager](https://learn.microsoft.com/en-us/windows/win32/rstmgr/restart-manager-portal).

Once the file is ready to be encrypted, a unique key & iv are generated for the HC-128 algorithm and the file is encrypted, Then the encrypted key & iv are stored at the end of the file as file metadata.

### Decryption
To decrypt the files, the victim must send the generated encrypted private key file[^4] to the attacker. The attacker will decrypt the private key using the **PrivateDecryptor** application with its unique private key [^5]. Once the key is decrypted, the attacker will send the decrypted private key to the victim, which will use the **Decrypt** application to decrypt the files.

## In-Depth
### Evasion
* Local debugging is checked using IsDebuggerPresent **OR** PEB->BeingDebugged.
* Remote debugging is checked using CheckRemoteDebuggerPresent WinAPI function.
* Debugging is also checked using Hardware breakpoint checks.

To check for VMs:
* Mouse movement in 10 seconds.
* Accelerated sleep.
* CPU fans[^6].
* Blacklisted loaded DLLs.
* Blacklisted usernames & hostnames.
* Number of CPU cores (== 1).
* RAM size (<= 4GB).
* Disk size (<= 80GB).
* Blacklisted vendor ID's.
* Existing files & registries.
* Running processes & services.

### Persistence
There are two ways the program uses for persistence.
* Task Scheduler (System)
* Registry (Autorun)

### Pre-Encryption
* The one instance mutex's name is `ef223080-f09c-413a-89db-62d675d90f56`.
* the process masquerades explorer.exe, then performs UAC bypass using ColorDataProxy/CCMMLoaUtil COM interfaces.
* The software denies access to its process by modifying its ACL.
* The process disables the following errors:
    - SEM_FAILCRITICALERRORS - The system does not display critical error message boxes.
    - SEM_NOGPFAULTERRORBOX - The system does not display the Windows Error Reporting dialog.
    - SEM_NOALIGNMENTFAULTEXCEPT - The system automatically fixes alignment faults.
* The process enables SE_TAKE_OWNERSHIP_PRIVILEGE to be able to take ownership of files during encryption.
* When a volume is found, it will be mounted **only if** it hasn't been mounted before and is larger than `0x40000000`. The mount location will be the first available drive, starting from `Z` all the way down to `A`.

### Encryption
* Each encryption thread will run on a specific processor so that the cache use will be more efficient[^7].
* To avoid corrupting the system after the encryption, some directories will be skipped:
https://github.com/mr9h0st/Ransomware/blob/de0bbe056f553a148d0b6b4076c3e32200963d59/Encryptor/encryptor.c#L20-L28
* Furthermore, some files will be skipped:
https://github.com/mr9h0st/Ransomware/blob/de0bbe056f553a148d0b6b4076c3e32200963d59/Encryptor/encryptor.c#L30-L31
* Finally, all files with the following extension will be skipped:
https://github.com/mr9h0st/Ransomware/blob/de0bbe056f553a148d0b6b4076c3e32200963d59/Encryptor/encryptor.c#L33-L34
* A random 32-byte array is generated and acts as the user's private key. using that, public and shared keys are generated. The public key will be written in the file metadata, while the SHA512 of the shared key will be the Key & IV for the HC-128 algorithm.
* To avoid reading entire large files, the software divides files into 3 categories: Large (above `0x1400000`), Medium (above `0x500000`) and Small. Large and Medium files are divided into chunks so not all the file is encrypted. Small files are entirely encrypted.

### Extra
The software modifies the Registry so that the default icon of the encrypted files will be a custom one.

# Getting Started
Clone the repository.

## Development
### Ransomware Extension
To change the ransomware extension, edit the following file:
https://github.com/mr9h0st/Ransomware/blob/1f328ef352e553e46b0530e896e466e57d601b93/crypt/other/settings.h#L2
### Program Behaviour
To change the program behaviour edit this file:
https://github.com/mr9h0st/Ransomware/blob/de0bbe056f553a148d0b6b4076c3e32200963d59/Encryptor/debug.h#L6-L9
* When the first is enabled (```DEBUG```), it will disable any execution of code that can harm the system. so volumes will not be mounted, files will not be encrypted and processes will not be stopped in an attempt to open a file.
* When the second is enabled (```DEBUGMSG```), it will print debug messages.

**If you want to develop the ransomware on _your_ system, you can enable the following**
```c
#define DEBUG
#define DEBUGMSG
```
then you can freely run the ransomware on your system without it causing any harm while displaying logs.
> [!IMPORTANT]
> With these configurations, the program will still iterate the entire system, open and read the files into a buffer, and encrypt that buffer but without writing it back to the file.

### Speed
To achieve the best speed, build the files using -O2 as gcc parameter.

## Generating Public-Private keys
To set the public key, you will find its declaration at
https://github.com/mr9h0st/Ransomware/blob/1f328ef352e553e46b0530e896e466e57d601b93/Encryptor/encryptor.c#L13-L16
To set the private key, you will find its declaration at
https://github.com/mr9h0st/Ransomware/blob/1f328ef352e553e46b0530e896e466e57d601b93/PrivateDecryptor/entry.c#L23-L26

> [!NOTE]
> The current public-private keys are valid and will encrypt/decrypt files.

# Objectives
- [x] Disable errors in case the program crashes.
- [x] Get admin privileges using UAC bypass.
- [x] Deny access to the ransomware's process.
- [x] Persistence in case of a system shutdown.
- [x] Mount volumes.
- [x] Avoid debuggers & virtual machines.
- [ ] Host discovery & Network shares.
- [x] Network drives.

# Speed
It took the ransomware `7.32` minutes to encrypt `67.984 GB` on Windows 11 / Intel i7-8565U CPU @ 1.80GHz / 16 GB.

[^1]: You can read more about this scheme here: https://medium.com/@tarcisioma/ransomware-encryption-techniques-696531d07bb9
[^2]: Most ransomware choose RSA as the asymmetric encryption algorithm, but nowadays elliptic curve algorithms are better because they are faster on Key generation and encryption and don't have a plaintext size limit.
[^3]: As suggested on Microsoft's website, to achieve better performance, we should create a thread for each processor: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread#remarks
[^4]: Stored at `<Desktop>\pk.dat`. Name defined here:
https://github.com/mr9h0st/Ransomware/blob/1f328ef352e553e46b0530e896e466e57d601b93/crypt/other/settings.h#L4
[^5]: As described at Generating keys section, that is the private key.
[^6]: Sandboxes and Virtual machines will fail to return data about the CPU's fans while real operating systems will return information.
[^7]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask  