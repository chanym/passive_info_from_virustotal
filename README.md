# passive_info_from_virustotal

This python script allow one to retrive passive information from virustotal using a public key

Usage:
  ./passiveInfo.py <file containing either IP or domain per line>
  
Can use interactively in python shell by calling the vt function 

>>> import passiveinfo
>>> print passiveinfo.vt.__doc__
Get passive info from virustotal - 
    Usage: passiveinfo.vt(['<domain or IP>'])
    example passviveinfo.vt(['www.github.com', '8.8.8.8'])
