Run local Local Service accounts without System

Update Windows Services to Use Least Privilege Accounts


Its standard for applications services to run with System. In many cases this is excessive and leaves the Operating System vulnerable to escalation attacks particularly if there is a unquoted path or an unpatched vulnerability.


The following is a script deployable from MDT for use on standalone systems as it reliant on local accounts. The script creates a service account without any elevated privileges and adds to the 'Logon as Service' Right and then updates the Windows Service for the targeted application. 


The password for each svc account is unique to prevent one compromised password allowing all systems with that account and password combination being compromised. Passwords are not written out to disk, otherwise its possible recovery the files and password with recovery tools. 

https://www.tenaka.net/localsvcaccounts
