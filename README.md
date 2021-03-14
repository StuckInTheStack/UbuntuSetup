# UbuntuSetup
Setup script for pentesting from Ubunbtu

This script configures Ubuntu with pentesting tools and directory modifications. I've left many commented out sections that can be uncommented for customization. I also typically copy some of my own private tools from a network share, but functionality for github or direct download is included.                                                                

Please edit it and make it your own.

Note that BurpSuite, and potentially Autorecon, MSF, and Seclists may needs to be installed manually. 

 1. Update USER, HOME, and ROOT near the top of the code for your username, home and root directories.                                                 
 2. Run as root after a clean install of Linux.                           
    *  Create a clone or snapshot prior to any changes.                   
 3. You will need 15GB free HDD space before running.                     
 4. Command line arguments:                                               
     -keepdirs = Stops deletion of the Public,Videos,Templates,and Music  
     -dns      = Use OpenDNS and locks permissions                        
     -osx      = Changes to Apple keyboard layout                         
     -keyboard <value> = Change the keyboard layout language (default US )  
     -timezone <value> = Change the timezone location (default geolocated)  
                               "US/Pacific"                            
                             ---                                           
Usage# ./setup.sh -keepdirs -dns                                      
