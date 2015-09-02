# passive_info_from_virustotal

This python script allow one to retrive passive information from virustotal using a public key

Usage:
  ./passiveInfo.py <file containing either IP or domain per line>
  
Can use interactively in python shell by calling the vt function 

import passiveinfo

passiveinfo.vt(['<domain or ip>'])

example :

passiveinfo.vt(['www.github.com', '8.8.8.8'])
