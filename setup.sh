#!/bin/bash
#-METADATA------------------------------------------------------------------#
#  Filename: .setup.sh            (Update: 3/15/2021)                       #
#-AUTHOR(S)-----------------------------------------------------------------#
#  Creator   : StuckInTheStack ~ https://github.com/StuckInTheStack         #
#  This script is an adaptation that heavily relied on prior scripts by:    #
#         g0tmilk ~ https://blog.g0tmi1k.com/                               #
#         drkpasngr ~ https://drkpasngr.github.io/                          #
#-TARGET OPERATING SYSTEM---------------------------------------------------#
#  Designed for: Ubuntu VMWare                                              #
#  Tested on:  Kubunutu 20.4 LTS                                            #
#-LICENSE-------------------------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT                         #
#-INSTRUCTIONS--------------------------------------------------------------#
#                                                                           #
#  This script configures Ubuntu with pentesting tools.  How I like it.     #
#  I've left many commented out sections that can be uncommented for        #
#  Customization. I also typically copy some of my own private tools from   #
#  a network share, but functionality for github or direct download is      #
#  included.                                                                #
#  Please edit it and make it your own.                                     #
#                                                                           #
#  Note that BurpSuite, and potentially Autorecon, MSF, and Seclists may    #
#  need to be installed manually.                                           #
#                                                                           #
#  1. Update USER, HOME, and ROOT directly below for your username, home    #
#     and root directories.                                                 #
#  2. Run as root after a clean install of Linux.                           #
#     *  Create a clone or snapshot prior to any changes.                   #
#                             ---                                           #
#  3. You will need 15GB free HDD space before running.                     #
#  4. Command line arguments:                                               #
#      -keepdirs = Stops deletion of the Public,Videos,Templates,and Music  #
#      -dns      = Use OpenDNS and locks permissions                        #
#      -osx      = Changes to Apple keyboard layout                         #
#    -keyboard <value> = Change the keyboard layout language (default US )  #
#    -timezone <value> = Change the timezone location (default geolocated)  #
#                                   "US/Pacific"                            #
#                             ---                                           #
#  Use with# ./setup.sh -keepdirs -dns                                      #
#                                                                           #
#---------------------------------------------------------------------------#

#-Defaults-------------------------------------------------------------#
##### Kali home directories and your Github tools information
USER="gardog"                 #                          CHANGE ME
HOME="/home/"$USER            #                          CHANGE ME
ROOT="/root"                  #                          CHANGE ME
#GITHUBURL="http://github.com/StuckInTheStack"  # used potentially to download your own tools


##### Location information
keyboardApple=false         # Using a Apple/Macintosh keyboard (non VM)?                [ --osx ]
keyboardLayout="us"           # Set keyboard layout, default=us                         [ --keyboard us]
timezone=""                 # Set timezone location                                     [ --timezone US/Chicago ]

##### Optional steps
hardenDNS=false       # Set static & lock DNS name server                               [ --dns ]
KeepDirs=false        # Prevent deletion of Public,Videos,Templates,Music directories   [ -keepdirs ]   

##### Set Start time to output total time to run script
start_time=$(date +%s)

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

STAGE=0                                                         # Where are we up to
TOTAL=$( grep '(${STAGE}/${TOTAL})' $0 | wc -l );(( TOTAL-- ))  # How many things have we got todo
TOTAL=TOTAL -6 # adapting for the 5 commented out stages and the line directly above 

#-Arguments------------------------------------------------------------#


##### Read command line arguments
while [[ "${#}" -gt 0 && ."${1}" == .-* ]]; do
  opt="${1}";
  shift;
  case "$(echo ${opt} | tr '[:upper:]' '[:lower:]')" in
    -|-- ) break 2;;

    -osx|--osx )
      keyboardApple=true;;
    -apple|--apple )
      keyboardApple=true;;

    -dns|--dns )
      hardenDNS=true;;

    -keepdirs|--keepdirs )
      KeepDirs=true;;

    -keyboard|--keyboard )
      keyboardLayout="${1}"; shift;;
    -keyboard=*|--keyboard=* )
      keyboardLayout="${opt#*=}";;

    -timezone|--timezone )
      timezone="${1}"; shift;;
    -timezone=*|--timezone=* )
      timezone="${opt#*=}";;

    *) echo -e ' '${RED}'[!]'${RESET}" Unknown option: ${RED}${x}${RESET}" 1>&2 \
      && exit 1;;
   esac
done


##### Check user inputs
if [[ -n "${timezone}" && ! -f "/usr/share/zoneinfo/${timezone}" ]]; then
  echo -e ' '${RED}'[!]'${RESET}" Looks like the ${RED}timezone '${timezone}'${RESET} is incorrect/not supported (Example: ${BOLD}Europe/London${RESET})" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
  exit 1
elif [[ -n "${keyboardLayout}" && -e /usr/share/X11/xkb/rules/xorg.lst ]]; then
  if ! $(grep -q " ${keyboardLayout} " /usr/share/X11/xkb/rules/xorg.lst); then
    echo -e ' '${RED}'[!]'${RESET}" Looks like the ${RED}keyboard layout '${keyboardLayout}'${RESET} is incorrect/not supported (Example: ${BOLD}gb${RESET})" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
    exit 1
  fi
fi


#-Start----------------------------------------------------------------#


##### Check if we are running as root - else this script will fail (Hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" This script must be ${RED}run as root${RESET}" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
  exit 1
else
  echo -e " ${BLUE}[*]${RESET} ${BOLD}Pentest-installation script for Ubuntu Linux.${RESET}"
  sleep 3s
fi


##### Checking if there is at least 10Mb of space availale on the disk, feel free to change the limit if your modifications use less.
DiskNeeded="15000000";
if [[  $(df | grep /dev/s  | head -n 1 | tr -s [:space:] " " | cut -d " " -f 4) -lt "${DiskNeeded}" ]]; then
  echo -e ' '${RED}'[!]'${RESET}" There may not 10Gb space available on the disk to install everything."
  echo -e ' '${RED}'[!]'${RESET}" Quitting..."
  exit 1
else
  echo -e " ${GREEN}[i]${RESET} You have at least 10Gb default of available space on the disk..."
fi


##### Check Internet access
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}Internet access${RESET}"
#--- Can we ping google?
for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
#--- Run this, if we can't
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Will try and use ${YELLOW}DHCP${RESET} to 'fix' the issue" 1>&2
  chattr -i /etc/resolv.conf 2>/dev/null
  dhclient -r
  #--- Second interface causing issues?
  ip addr show eth1 &>/dev/null
  [[ "$?" == 0 ]] \
    && route delete default gw 192.168.155.1 2>/dev/null
  #--- Request a new IP
  dhclient
  dhclient eth0 2>/dev/null
  dhclient wlan0 2>/dev/null
  #--- Wait and see what happens
  sleep 15s
  _TMP="true"
  _CMD="$(ping -c 1 8.8.8.8 &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}No Internet access${RESET}" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
  fi
  _CMD="$(ping -c 1 www.google.com &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
  fi
  if [[ "$_TMP" == "false" ]]; then
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} VM Detected"
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Try switching network adapter mode${RESET} (e.g. NAT/Bridged)"
    echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
    exit 1
  fi
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
fi


##### Updating the cache and Upgrading the OS
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}the cache and upgrading${RESET}"
apt update 
apt upgrade -y


##### Making my own preset directories for my preset tools to be downloaded later ( and ssh keys )
#   I'm particular about how I like my directories, please change to your taste.
#   /wintools      =privilege escalation tools I would always upload to a windows host
#   /linuxtools    =privilege escalation tools I would always upload to a linux host
#   /toolslinuxall =linux tools I use, but don't want to upload every time
#   /toolswinall   =windows tools I use, but don't want to upload every time
#   /.local/bin    =scripts and binaries I want to incude on PATH
#   /shells        =easy access to a collections of shell scripts and binaries 
#   /lists         =collections of custom lists for enumeration and cracking
#   /logs          =log files for saving bash output and input
#   /Pictures/Wallpapers =gotta brand yourself
#
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Creating tools directories and deleting unused directories..."
mkdir $HOME/.ssh 2>/dev/null
mkdir $HOME/linuxtools 2>/dev/null
mkdir $HOME/toolslinuxall  2>/dev/null
mkdir $HOME/wintools 2>/dev/null
mkdir $HOME/toolswinall  2>/dev/null
mkdir $HOME/shells 2>/dev/null
mkdir $HOME/lists  2>/dev/null
mkdir $HOME/logs  2>/dev/null
mkdir $HOME/Pictures/Wallpapers 2>/dev/null
mkdir $HOME/.local/bin 2>/dev/null
mkdir $ROOT/.ssh  2>/dev/null
if [[ "${KeepDirs}" = "false" ]]; then
  echo "Removing Public, Templates, Vidoes, and Music home directories..."
  rmdir $HOME/Public 2>/dev/null
  rmdir $HOME/Templates 2>/dev/null
  rmdir $HOME/Videos 2>/dev/null
  rmdir $HOME/Music 2>/dev/null
  rmdir $ROOT/Public 2>/dev/null
  rmdir $ROOT/Templates 2>/dev/null
  rmdir $ROOT/Videos 2>/dev/null
  rmdir $ROOT/Music 2>/dev/null;
else
  echo "Keeping the Public, Templates, Vidoes, and Music home directories...";
fi


##### Mounting my local host machine share that I can use for file transfers ( also can use github or other internet facing storage )  
#   If you have some tools that have your own passwords or privately obfuscated tools, then I use
#       a local file share to upload them into kali. This can be replaced with in internet facing private cloud, etc...
#   It is preferable to load tools directly from the source so you're always getting the latest updated tool.
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Mounting host OS share onto /mnt/hgfs..."
mkdir /mnt/hgfs 2>/dev/null 
apt install cifs-utils  # nfs-common for nfs shares  
mount -t cifs //192.168.1.99/Shared /mnt/hgfs 1>&2 


##### Downloading my preset tools, lists, and wallpapers from the host OS share  
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Downloading local tools from localshare and internet..." 1>&2

cp -r /mnt/hgfs/lists/* $HOME/lists
cp -r /mnt/hgfs/shells/* $HOME/shells
cp -r /mnt/hgfs/wallpapers/* $HOME/Pictures/Wallpapers 

cp -r /mnt/hgfs/linuxtools/* $HOME/linuxtools
cp -r /mnt/hgfs/toolslinuxall/* $HOME/toolslinuxall 
cd $HOME/linuxtools
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32s 
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s 
chmod +x *
cd $HOME/toolslinuxall
chmod +x *

cp -r /mnt/hgfs/wintools/* $HOME/wintools
cp -r /mnt/hgfs/toolswinall/* $HOME/toolswinall
cd $HOME/wintools/
wget "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASany.exe" 1>&2
wget https://github.com/carlospolop/winPE/tree/master/binaries/watson/WatsonNet3.5AnyCPU.exe 
wget https://github.com/carlospolop/winPE/tree/master/binaries/watson/WatsonNet4AnyCPU.exe 
curl -LJ https://eternallybored.org/misc/wget/1.20/32/wget.exe > $HOME/wintools/wget.exe 
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe


##### Downloading my aliases and scripts from the host OS share then adding aliases from this script
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Downloading tools from localshare then adding aliases from this script..." 1>&2
file=$HOME/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
cp -r /mnt/hgfs/.scripts/* $HOME/.local/bin                         #copies my custom scripts to .local/bin to be in PATH
export PATH=$HOME/.local/bin:$PATH 


if [ ! -f "$HOME/.bash_aliases" ]; then      # copy over my standard /linuxtools/aliases if no .bash_aliases
cp $HOME/linuxtools/aliases $HOME/.bash_aliases;
fi
#if [ -f "$HOME/.bashrc" ]; then #These commands should not be necessary as std .bashrc includes .bash_aliases
#echo  ". \"$HOME/.bash_aliases\" " >> $HOME/.bashrc; 
#fi
if [ -f "$ROOT/.bashrc" ]; then
echo  ". \"$HOME/.bash_aliases\" " >> $ROOT/.bashrc; # for root to source $HOME/.bash_aliases
fi

if [ -n "$(grep "### ALIASES LOADED" $HOME/.bash_aliases )" ]; then   ### ALIASES LOADED signals that these aliases are already in .bash_aliases
  echo -e ' '${YELLOW}'[!]'${RESET}" The aliases have already been appended to .bash_aliases.  Skipping bulk copy..." 1>&2;
else
  cat $HOME/linuxtools/aliases >> $HOME/.bash_aliases  1>&2
  echo -e ' '${YELLOW}'[!]'${RESET}" The aliases have been bulked copied to $HOME/.bash_aliases...";
fi

if  cat $HOME/.bash_aliases | grep -q "### ALIASES LOADED" ; then   ### ALIASES LOADED signals that these aliases are already in .bash_aliases
  echo -e ' '${YELLOW}'[!]'${RESET}" The aliases have already been appended to .bash_aliases.  Skipping script alias write...";
else
  echo -e ' '${YELLOW}'[!]'${RESET}" Writing aliases to .bash_aliases..." 1>&2
  echo -e '### ALIASES LOADED\n' >> "${file}" 
  echo -e 'alias ll="ls -l --block-size=1 --color=always "\n' >> "${file}"
  echo -e 'alias la="ls -altrh --color=always "\n' >> "${file}" 
  echo -e 'alias sur="sudo su root "\n' >> "${file}"
  echo -e 'alias grep="grep --color=always "\n' >> "${file}"
  echo -e 'alias sp="searchsploit "\n' >> "${file}"
  echo -e 'alias spm="searchsploit -m "\n' >> "${file}"
  echo -e 'alias spx="searchsploit -x "\n' >> "${file}"
  echo -e 'alias mp="mousepad "\n' >> "${file}"
  echo -e 'function mcd () { mkdir -p $1; cd $1;} \n' >> "${file}"
  echo -e 'function me () { chmod +x $1;} \n' >> "${file}"
  echo -e 'alias listen="netstat -antp | grep LISTEN "\n' >> "${file}"
  echo -e 'alias responder="python3 /opt/responder/Responder.py "\n' >> "${file}"
  echo -e 'alias dirbuster="java -Xmx256M -jar /opt/dirbuster/DirBuster-1.0-RC1.jar "\n' >> "${file}"
  echo -e 'alias nmap="nmap --reason --open --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit "\n' >> "${file}"
  echo -e 'alias ports="netstat -tulanp "\n' >> "${file}"
  echo -e 'alias httpup="python3 -m http.server " # quick http server usage: httpup [port=8000]\n' >> "${file}"
  echo -e 'alias ftpup="python3 -m pyftpdlib -wV -p "   # quick anonymous ftp server usage: ftpup 21\n' >> "${file}"
  echo -e 'alias smbup="python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support " # quick smb share usage: smbup [-smb2support] <name> <path>\n' >> "${file}"
  echo -e '\n' >> "${file}"
  echo -e 'function rg() {\n' >> "${file}"
  echo -e 'if [ -z $1 ]; then\n' >> "${file}"
  echo -e 'echo "Bash script to recursively search from the current directory for given search term in all files."\n' >> "${file}"
  echo -e 'echo "Use with:  rg <term> [term, term, ...]"; \n' >> "${file}"
  echo -e 'return 1  \n' >> "${file}"
  echo -e 'fi\n' >> "${file}"
  echo -e 'search=""\n' >> "${file}"
  echo -e 'for string in "$@" \n' >> "${file}"
  echo -e 'do\n' >> "${file}"
  echo -e '  if [ -z $search ]; then\n' >> "${file}"
  echo -e '    search=$string; \n' >> "${file}"
  echo -e '  else\n' >> "${file}"
  echo -e '    search=$search" | "$string;\n' >> "${file}"
  echo -e '  fi\n' >> "${file}"
  echo -e 'done\n' >> "${file}"
  echo -e 'grep -R -n -i $search . 2>/dev/null;\n' >> "${file}"
  echo -e '}\n' >> "${file}"
  echo -e '\n' >> "${file}"
  echo -e 'function cool() {\n' >> "${file}"
  echo -e 'if [ -z "$1" ]; then \n' >> "${file}"
  echo -e 'echo "Bash script to search a given site with cewl to level set by second argument and mutate with john."\n' >> "${file}"
  echo -e 'echo "Output is stored in cool.lst file."\n' >> "${file}"
  echo -e 'echo "Use with:  cool <website/IPaddr> [depth:3]"; \n' >> "${file}"
  echo -e 'return 1\n' >> "${file}"
  echo -e 'fi\n' >> "${file}"
  echo -e 'if [ -z $2 ]\n' >> "${file}"
  echo -e 'then\n' >> "${file}"
  echo -e '  cewl $1 -d 3 -m 3 -w cool.tmp0 -a --with-numbers\n' >> "${file}"
  echo -e 'else\n' >> "${file}"
  echo -e '  cewl $1 -d $2 -m 3 -w cool.tmp0 -a --with-numbers\n' >> "${file}"
  echo -e 'fi\n' >> "${file}"
  echo -e 'cat cool.tmp0 | sort -u > cool.tmp1\n' >> "${file}"
  echo -e 'john --wordlist=cool.tmp1 --rules --stdout > cool.lst\n' >> "${file}"
  echo -e 'rm cool.tmp0\n' >> "${file}"
  echo -e 'rm cool.tmp1\n' >> "${file}"
  echo -e '}\n' >> "${file}"
  echo -e '\n' >> "${file}"
  echo -e 'extract() {\n' >> "${file}"
  echo -e 'if [ -z "$1" ]; then \n' >> "${file}"
  echo -e 'echo "Bash script to extract any compressed file."\n' >> "${file}"
  echo -e 'echo "Use with:  extract <file>";\n' >> "${file}"
  echo -e 'return 1\n' >> "${file}"
  echo -e 'fi\n' >> "${file}"
  echo -e 'if [[ -f \$1 ]]; then\n' >> "${file}"
  echo -e '  case \$1 in\n' >> "${file}"
  echo -e '    *.tar.bz2) tar xjf \$1 ;;\n' >> "${file}"
  echo -e '    *.tar.gz)  tar xzf \$1 ;;\n' >> "${file}"
  echo -e '    *.bz2)     bunzip2 \$1 ;;\n' >> "${file}"
  echo -e '    *.rar)     rar x \$1 ;;\n' >> "${file}"
  echo -e '    *.gz)      gunzip \$1  ;;\n' >> "${file}"
  echo -e '    *.tar)     tar xf \$1  ;;\n' >> "${file}"
  echo -e '    *.tbz2)    tar xjf \$1 ;;\n' >> "${file}"
  echo -e '    *.tgz)     tar xzf \$1 ;;\n' >> "${file}"
  echo -e '    *.zip)     unzip \$1 ;;\n' >> "${file}"
  echo -e '    *.Z)       uncompress \$1 ;;\n' >> "${file}"
  echo -e '    *.7z)      7z x \$1 ;;\n' >> "${file}"
  echo -e '    *)         echo \$1 cannot be extracted ;;\n' >> "${file}"
  echo -e '  esac\n' >> "${file}"
  echo -e 'else\n' >> "${file}"
  echo -e '  echo \$1 is not a valid file\n' >> "${file}"
  echo -e 'fi\n' >> "${file}"
  echo -e '}\n' >> "${file}";
fi

#--- Apply new aliases ( $ROOT/.bashrc and $HOME/.bashrc already updated to include $HOME/.bashrc at start of this section )
source $HOME/.bash_aliases


##### Set static & protecting DNS name servers.   Note: May cause issues with forced values (e.g. captive portals etc)
if [[ "${hardenDNS}" != "false" ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Setting static & protecting ${GREEN}DNS name servers${RESET}"
  file=/etc/resolv.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
  chattr -i "${file}" 1>&2 
  #--- Use OpenDNS DNS
  #echo -e 'nameserver 208.67.222.222\nnameserver 208.67.220.220' > "${file}"
  #--- Use Google DNS
  echo -e 'nameserver 8.8.8.8\nnameserver 8.8.4.4' > "${file}"
  #--- Protect it
  chattr +i "${file}" 1>&2 
else
  echo -e "\n\n ${YELLOW}[i]${RESET} ${YELLOW}Skipping DNS${RESET} (missing: '$0 ${BOLD}--dns${RESET}')..." 1>&2
fi


##### Update location information - set either value to "" to skip.
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}location information${RESET}"
#--- Configure keyboard layout (Apple)
if [ "${keyboardApple}" != "false" ]; then
  ( (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Applying ${GREEN}Apple hardware${RESET} profile" )
  file=/etc/default/keyboard; #[ -e "${file}" ] && cp -n $file{,.bkup}
  sed -i 's/XKBVARIANT=".*"/XKBVARIANT="mac"/' "${file}"
fi
#--- Configure keyboard layout (location)
if [[ -n "${keyboardLayout}" ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}location information${RESET} ~ keyboard layout (${BOLD}${keyboardLayout}${RESET})"
  geoip_keyboard=$(curl -s http://ifconfig.io/country_code | tr '[:upper:]' '[:lower:]')
  [ "${geoip_keyboard}" != "${keyboardLayout}" ] \
    && echo -e " ${YELLOW}[i]${RESET} Keyboard layout (${BOLD}${keyboardLayout}${RESET}) doesn't match what's been detected via GeoIP (${BOLD}${geoip_keyboard}${RESET})"
  file=/etc/default/keyboard; #[ -e "${file}" ] && cp -n $file{,.bkup}
  sed -i 's/XKBLAYOUT=".*"/XKBLAYOUT="'${keyboardLayout}'"/' "${file}"
else
  echo -e "\n\n ${YELLOW}[i]${RESET} ${YELLOW}Skipping keyboard layout${RESET} (missing: '$0 ${BOLD}--keyboard <value>${RESET}')..." 1>&2
fi
#--- Changing time zone
if [[ -n "${timezone}" ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}location information${RESET} ~ time zone (${BOLD}${timezone}${RESET})"
  echo "${timezone}" > /etc/timezone
  ln -sf "/usr/share/zoneinfo/$(cat /etc/timezone)" /etc/localtime
  dpkg-reconfigure -f noninteractive tzdata
else
  echo -e "\n\n ${YELLOW}[i]${RESET} Skipping time zone set to command.${RESET} (missing: '$0 ${BOLD}--timezone <value>${RESET}')..." 1>&2
fi


##### Update OS from network repositories
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Updating OS${RESET} from network repositories"
echo -e " ${YELLOW}[i]${RESET}  ...this ${BOLD}may take a while${RESET} depending on your Internet connection & OS version/age"
for FILE in clean autoremove; do apt -y -qq "${FILE}" 1>&2 ; done         # Clean up      clean remove autoremove autoclean
export DEBIAN_FRONTEND=noninteractive
apt -qq update && APT_LISTCHANGES_FRONTEND=none apt -o Dpkg::Options::="--force-confnew" -y dist-upgrade --fix-missing  1>&2  \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET}
#--- Cleaning up temp stuff
for FILE in clean autoremove; do apt -y -qq "${FILE}" 1>&2 ; done         # Clean up - clean remove autoremove autoclean
#--- Check kernel stuff
_TMP=$(dpkg -l | grep linux-image- | grep -vc meta)
if [[ "${_TMP}" -gt 1 ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} Detected ${YELLOW}multiple kernels${RESET}"
  TMP=$(dpkg -l | grep linux-image | grep -v meta | sort -t '.' -k 2 -g | tail -n 1 | grep "$(uname -r)")
  if [[ -z "${TMP}" ]]; then
    echo -e '\n '${RED}'[!]'${RESET}' You are '${RED}'not using the latest kernel'${RESET} 1>&2
    echo -e " ${YELLOW}[i]${RESET} You have it ${YELLOW}downloaded${RESET} & installed, just ${YELLOW}not USING IT${RESET}"
    echo -e "\n ${YELLOW}[i]${RESET} You ${YELLOW}NEED to REBOOT${RESET}, before re-running this script"
    exit 1
    sleep 30s
  else
    echo -e " ${YELLOW}[i]${RESET} ${YELLOW}You're using the latest kernel${RESET} (Good to continue)"
  fi
fi


##### Install kernel headers
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}kernel headers${RESET}"
apt -y -qq install make gcc "linux-headers-$(uname -r)"  1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET}
if [[ $? -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" There was an ${RED}issue installing kernel headers${RESET}"
  echo -e " ${YELLOW}[i]${RESET} Are you ${YELLOW}USING${RESET} the ${YELLOW}latest kernel${RESET}?"
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Reboot${RESET} your machine"
  #exit 1
  sleep 30s
fi


##### Install Multiple Basic Tools
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Mutliple Tools${RESET} ~ Basic every day tools and program environments"
apt install -y gedit terminator curl net-tools python3 python3-impacket 2to3 python3-pyftpdlib default-jre apache2 php git tree 1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install multiple tools'${RESET} 1>&2

##### Install Metasploit Framework
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Metasploit Framework${RESET} ~ exploit framework"
cd /opt && curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall \
  || echo -e ' '${RED}'[!] Issue with apt install msfconsole'${RESET} 1>&2

##### Install SecLists
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}SecLists${RESET} ~ many useful lists for discovery and brute forcing"
cd $HOME/lists && wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && unzip SecList.zip && rm -f SecList.zip \
  || echo -e ' '${RED}'[!] Issue with apt install SecLists'${RESET} 1>&2  
  
##### Install AutoRecon
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}AutoRecon${RESET} ~ automated enumeration"
apt install -y python3-pip && \
apt install -y python3-venv && \
python3 -m pip install --user pipx && \
python3 -m pipx ensurepath && \
source $HOME$USER/.bashrc && \
pipx install git+https://github.com/Tib3rius/AutoRecon.git \
  || echo -e ' '${RED}'[!] Issue with apt install AutoRecon'${RESET} 1>&2  

##### Install CrackMapExec
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}CrackMapExec${RESET} ~ Windows execution and hash/password spraying"
cd /opt && git clone -q -b master https://github.com/byt3bl33d3r/CrackMapExec.git /opt/crackmapexec-git/1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install CrackMapExec'${RESET} 1>&2  
  
##### Install Responder
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Responder${RESET} ~ The joy of poisoning LMNR"
cd /opt && git clone https://github.com/lgandx/Responder.git /opt/responder  1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install Responder'${RESET} 1>&2  
  
##### Install exe2hex
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}exe2hex${RESET} ~ easy file transfer agent"
cd /opt && git clone https://github.com/g0tmi1k/exe2hex.git /opt/exe2hex 1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install exe2hex'${RESET} 1>&2  
  
##### Install dirbuster
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}dirbuster${RESET} ~ directory brute forcer GUI"
cd /opt && git clone https://gitlab.com/kalilinux/packages/dirbuster.git /opt/dirbuster 1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install dirbuster'${RESET} 1>&2  

##### Install chisel binary
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}chisel${RESET} ~ http tunneling and pivoting"
curl https://i.jpillora.com/chisel! | bash 1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install chisel'${RESET} 1>&2    

  
  
: <<'BLOCK_COMMENT'    INTENDED TO NOT INSTALL THE FULL WINE/MINGW COMPLIMENT IF NOT NEEDED
##### Install MinGW ~ cross compiling suite
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}MinGW${RESET} ~ cross compiling suite"
for FILE in mingw-w64 binutils-mingw-w64 gcc-mingw-w64 cmake mingw-w64-x86-64-dev mingw-w64-tools gcc-mingw-w64-i686 gcc-mingw-w64-x86-64; do
  apt -y -qq install "${FILE}" 1>&2 
done


##### Install 32 bit Linux libraries
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}32 bit Linux libraries${RESET} ~ compile 32 bit Linux elfs"
apt-get -y -qq install gcc-multilib 1>&2  \
  || echo -e ' '${RED}'[!] Issue with apt install gcc-multilib'${RESET} 1>&2


##### Install WINE
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}WINE${RESET} ~ run Windows programs on *nix"
apt -y -qq install wine winetricks 1>&2  \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#--- Using x64?
if [[ "$(uname -m)" == 'x86_64' ]]; then
  (( STAGE++ )); echo -e " ${GREEN}[i]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}WINE (x64)${RESET}"
  dpkg --add-architecture i386 1>&2 
  apt -qq update 1>&2 
  apt -y -qq install wine32 1>&2  \
    || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
fi
#--- Run WINE for the first time
[ -e /usr/share/windows-binaries/whoami.exe ] && wine /usr/share/windows-binaries/whoami.exe &>/dev/null
#--- Setup default file association for .exe
file=~/.local/share/applications/mimeapps.list; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
echo -e 'application/x-ms-dos-executable=wine.desktop' >> "${file}"


##### Install MinGW (Windows) ~ cross compiling suite
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}MinGW (Windows)${RESET} ~ cross compiling suite"
apt -y -qq install wine 1>&2  \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
timeout 300 curl --no-progress-meter -k -L -f "http://sourceforge.net/projects/mingw/files/Installer/mingw-get/mingw-get-0.6.2-beta-20131004-1/mingw-get-0.6.2-mingw32-beta-20131004-1-bin.zip/download" > /tmp/mingw-get.zip \
  || echo -e ' '${RED}'[!]'${RESET}" Issue downloading mingw-get.zip" 1>&2       #***!!! hardcoded path!
mkdir -p ~/.wine/drive_c/MinGW/bin/
unzip -q -o -d ~/.wine/drive_c/MinGW/ /tmp/mingw-get.zip
pushd ~/.wine/drive_c/MinGW/ >/dev/null
for FILE in mingw32-base mingw32-gcc-g++ mingw32-gcc-objc; do   #msys-base
  wine ./bin/mingw-get.exe install "${FILE}" 2>&1 | grep -v 'If something goes wrong, please rerun with\|for more detailed debugging output'
done
popd >/dev/null
#--- Add to windows path
grep -q '^"PATH"=.*C:\\\\MinGW\\\\bin' ~/.wine/system.reg \
  || sed -i '/^"PATH"=/ s_"$_;C:\\\\MinGW\\\\bin"_' ~/.wine/system.reg
BLOCK_COMMENT

##### Install pyftpdlib
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}pytftpdlib${RESET} ~ quick ftp server"
apt-get install python3-pyftpdlib 1>&2 \
  || echo -e ' '${RED}'[!] Issue with python3-pyftpdlib'${RESET} 1>&2
pip3 install pyftpdlib \
  || echo -e ' '${RED}'[!] Issue with pip3 install pyftpdlib'${RESET} 1>&2


##### Setup tftp client & server
#(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}N/${TOTAL}) Setting up ${GREEN}tftp client${RESET} & ${GREEN}server${RESET} ~ file transfer methods"
#apt -y -qq install tftp atftpd \
#  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#--- Configure atftpd
#file=/etc/default/atftpd; [ -e "${file}" ] && cp -n $file{,.bkup}
#echo -e 'USE_INETD=false\nOPTIONS="--tftpd-timeout 300 --retry-timeout 5 --maxthread 100 --verbose=5 --daemon --port 69 /var/tftp"' > "${file}"
#mkdir -p /var/tftp/
#chown -R nobody\:root /var/tftp/
#chmod -R 0755 /var/tftp/
#--- Setup alias
#file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
#([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
#grep -q '^## tftp' "${file}" 2>/dev/null \
#  || echo -e '## tftp\nalias tftproot="cd /var/tftp/"\n' >> "${file}"
#--- Apply new alias
#source "${file}" || source ~/.zshrc
#--- Remove from start up
#systemctl disable atftpd
#--- Disabling IPv6 can help
#echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
#echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6


# ##### Install Pure-FTPd
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Pure-FTPd${RESET} ~ FTP server/file transfer method"
apt -y -qq install pure-ftpd 1>&2 \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#--- Setup pure-ftpd
mkdir -p /var/ftp/
groupdel ftpgroup 2>/dev/null;
groupadd ftpgroup 2>/dev/null
userdel ftp 2>/dev/null;
useradd -r -M -d /var/ftp/ -s /bin/false -c "FTP user" -g ftpgroup ftp
chown -R ftp\:ftpgroup /var/ftp/
chmod -R 0755 /var/ftp/
pure-pw userdel ftp 2>/dev/null;
echo -e '\n' | pure-pw useradd ftp -u ftp -d /var/ftp/
pure-pw mkdb
#--- Configure pure-ftpd
echo "no" > /etc/pure-ftpd/conf/UnixAuthentication
echo "no" > /etc/pure-ftpd/conf/PAMAuthentication
echo "no" > /etc/pure-ftpd/conf/NoChmod
echo "no" > /etc/pure-ftpd/conf/ChrootEveryone
echo "yes" > /etc/pure-ftpd/conf/AnonymousOnly
echo "no" > /etc/pure-ftpd/conf/NoAnonymous
echo "yes" > /etc/pure-ftpd/conf/AnonymousCanCreateDirs
echo "yes" > /etc/pure-ftpd/conf/AllowAnonymousFXP
echo "no" > /etc/pure-ftpd/conf/AnonymousCantUpload
echo "30768 31768" > /etc/pure-ftpd/conf/PassivePortRange              #cat /proc/sys/net/ipv4/ip_local_port_range
echo "/etc/pure-ftpd/welcome.msg" > /etc/pure-ftpd/conf/FortunesFile   #/etc/motd
echo "FTP" > /etc/pure-ftpd/welcome.msg
ln -sf /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/50pure
#---  MOTD
echo "------ Linux Pure-ftp Server /var/ftp ----------"  > /etc/pure-ftpd/welcome.msg
echo -e " ${YELLOW}[i]${RESET} Pure-FTPd command: service pure-ftpd start"
echo -e " ${YELLOW}[i]${RESET} Pure-FTPd directory: /var/ftp"
echo -e " ${YELLOW}[i]${RESET} Pure-FTPd username: anonymous"
echo -e " ${YELLOW}[i]${RESET} Pure-FTPd password: <anything>"
#--- Apply settings
systemctl restart pure-ftpd 2>/dev/null
#--- Remove from start up, and stop service 
systemctl disable pure-ftpd 2>/dev/null
systemctl stop pure-ftpd 2>/dev/null


# ##### Install samba
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}samba${RESET} ~ file transfer method"
# #--- Installing samba
# apt -y -qq install samba \
  # || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
# apt -y -qq install cifs-utils \
  # || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#--- Create samba user
groupdel smbgroup 2>/dev/null;
groupadd smbgroup 2>/dev/null
userdel samba 2>/dev/null;
useradd -r -M -d /nonexistent -s /bin/false -c "Samba user" -g smbgroup samba 2>/dev/null
#--- Use the samba user
file=/etc/samba/smb.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/guest account = .*/guest account = samba/' "${file}" 2>/dev/null
grep -q 'guest account' "${file}" 2>/dev/null \
  || sed -i 's#\[global\]#\[global\]\n   guest account = samba#' "${file}"
#--- Setup samba paths
grep -q '^\[shared\]' "${file}" 2>/dev/null \
  || cat <<EOF >> "${file}"

[shared]
  comment = Shared
  path = /var/samba/
  browseable = yes
  guest ok = yes
  #guest only = yes
  read only = no
  writable = yes
  create mask = 0777
  directory mask = 0777
EOF
#--- Create samba path and configure it
mkdir -p /var/samba/ 2>/dev/null
chown -R samba\:smbgroup /var/samba/ 2>/dev/null
chmod -R 0777 /var/samba/ 2>/dev/null
#--- Bug fix
touch /etc/printcap
#--- Check
systemctl restart smbd
smbclient -L \\127.0.0.1 -N
mkdir -p /mnt/smb
mount -t cifs -o guest //127.0.0.1/share /mnt/smb
#--- Disable samba at startup
systemctl stop smbd
systemctl disable smbd
echo -e " ${YELLOW}[i]${RESET} Samba command: service smbd start"
echo -e " ${YELLOW}[i]${RESET} Samba directory: /var/smb/"
echo -e " ${YELLOW}[i]${RESET} Samba username: guest"
echo -e " ${YELLOW}[i]${RESET} Samba password: <blank>"


##### Setup SSH
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Setting up ${GREEN}SSH${RESET} ~ CLI access, may take a few minutes..."
apt -y -qq install openssh-server \
  || echo -e ' '${RED}'[!] Issue with apt install openssh-server'${RESET}
#--- Wipe current keys, but leave the host keys
rm -f /etc/ssh/ssh_host_*
find $ROOT/.ssh/ -type f ! -name authorized_keys -delete 1>/dev/null
find $HOME/.ssh/ -type f ! -name authorized_keys -delete 1>/dev/null
#--- Generate new keys
ssh-keygen -b 4096 -t rsa -f /etc/ssh/ssh_host_rsa_key -P "" 1>/dev/null
ssh-keygen -b 1024 -t dsa -f /etc/ssh/ssh_host_dsa_key -P "" 1>/dev/null
ssh-keygen -b 521 -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -P "" 1>/dev/null
ssh-keygen -t rsa -f $ROOT/.ssh/id_rsa -P "" >/dev/null
ssh-keygen -t rsa -f $HOME/.ssh/id_rsa -P "" 1>/dev/null
chmod 600 $ROOT/.ssh/id_rsa 1>/dev/null
chmod 600 $HOME/.ssh/id_rsa  1>/dev/null
chown $USER:$USER $HOME/.ssh/id_rsa  1>/dev/null
#--- Change MOTD
echo "-------------  Welcome to Your Linux SSH Host. -------------" > /etc/motd
sed -i 's/PrintMotd no/PrintMotd yes/g' "${file}"    # Show MOTD
#--- Change SSH settings
file=/etc/ssh/sshd_config; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^\#PermitRootLogin .*/PermitRootLogin yes/g' "${file}"      # Accept password login (overwrite Debian 8+'s more secure default option...)
sed -i 's/\#AuthorizedKeysFile /AuthorizedKeysFile /g' "${file}"    # Allow for key based logins
service sshd restart || echo -e " ${RED}[i] Problem restarting sshd service."


##### Clean the system
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Cleaning${RESET} the system"
#--- Clean package manager
for FILE in clean autoremove; do apt -y -qq "${FILE}"; done
apt -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')   # Purged packages
#--- Update slocate database
updatedb
#--- Reset folder location
cd ~/ &>/dev/null
#--- Remove any history files (as they could contain sensitive info)
history -cw 2>/dev/null
for i in $(cut -d: -f6 /etc/passwd | sort -u); do
  [ -e "${i}" ] && find "${i}" -type f -name '.*_history' -delete
done


##### Changing ownership to USER and lax permissions to all files in $HOME and subdirectories
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Changing owner to USER and lax permissions for all tools in $HOME" 1>&2
chown -R $USER:$USER $HOME
chmod -R 777 /mnt/hgfs


##### Time taken
finish_time=$(date +%s)
echo -e "\n\n ${YELLOW}[i]${RESET} Time (roughly) taken: ${YELLOW}$(( $(( finish_time - start_time )) / 60 )) minutes${RESET}"
echo -e " ${YELLOW}[i]${RESET} Stages skipped: $(( TOTAL-STAGE ))"


#-Done-----------------------------------------------------------------#


##### Done!
echo -e "\n ${YELLOW}[i]${RESET} Don't forget to:"
echo -e " ${YELLOW}[i]${RESET} + Check the above output (Did everything install? Any errors? (${RED}HINT: What's in RED${RESET}?)"
echo -e " ${YELLOW}[i]${RESET} + Manually install: BurpSuite Pro at https://portswigger.net/users"
echo -e " ${YELLOW}[i]${RESET} + ${BOLD}Change default passwords${RESET}: kali, PostgreSQL/MSF, MySQL, OpenVAS, BeEF XSS, etc..."
echo -e " ${YELLOW}[i]${RESET} + ${BOLD}Firefox${RESET}: Sign into your Firefox sync account for all your extensions and bookmarks"
echo -e " ${YELLOW}[i]${RESET} + ${BOLD}Set a password for root if you want.${RESET}"
echo -e " ${YELLOW}[i]${RESET} + ${YELLOW}Reboot${RESET}"
(dmidecode | grep -iq virtual) \
  && echo -e " ${YELLOW}[i]${RESET} + Take a snapshot   (Virtual machine detected)"

echo -e '\n'${BLUE}'[*]'${RESET}' '${BOLD}'Done!'${RESET}'\n\a'
exit 0


