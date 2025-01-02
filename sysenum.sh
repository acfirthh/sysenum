#!/bin/bash

# Set colour variables for text
Red='\033[0;31m'
Yellow='\033[0;33m'
Green='\033[0;32m'
# Underline
URed='\033[4;31m'
# Bold
BGreen='\033[1;32m'
BRed='\033[1;31m'
BPurple='\033[1;35m'
BBlue='\033[1;34m'
BWhite='\033[1;37m'
# Reset Colour
COLOUR_OFF='\033[0m'

# Checks if any output is given from find commands
check_output() {
    output=$(cat)
    if [ -z "$output" ]; then
        echo -e "${BRed}[!] Nothing Found...${COLOUR_OFF}"
    else
        echo "$output"
    fi
}

# Gets the default shell of the current user from /etc/passwd
get_default_shell() {
    local username=$(whoami)
    local default_shell

    if command -v getent &>/dev/null; then
        # Use getent if available
        default_shell=$(getent passwd "$username" | cut -d: -f7 | xargs basename)
    else
        # Fallback to grep if getent is not available
        default_shell=$(grep "^${username}:" /etc/passwd | awk -F: '{print $7}' | xargs basename)
    fi

    echo $default_shell
}

# Displays the tool banner
banner() {
    # Display SYSENUM Banner
    echo -e "${BPurple}
   _______     _______ ______ _   _ _    _ __  __ 
  / ____\ \   / / ____|  ____| \ | | |  | |  \/  |
 | (___  \ \_/ / (___ | |__  |  \| | |  | | \  / |
  \___ \  \   / \___ \|  __| | . \` | |  | | |\/| |
  ____) |  | |  ____) | |____| |\  | |__| | |  | |
 |_____/   |_| |_____/|______|_| \_|\____/|_|  |_|${COLOUR_OFF}"
    echo -e " ${URed}A simple tool for gathering system information.${COLOUR_OFF}"
    echo -e " ${BWhite}Created by: @acfirthh on GitHub${COLOUR_OFF}"
    
    echo -e "\n ${BWhite}KEYS:
    - ${BRed}Bold Red${BWhite} = Important/Possible Priv-Esc
    - ${Yellow}Yellow${BWhite} = Performing Checks
    - ${Green}Green${BWhite} = Success
    - ${Red}Red${BWhite} = Fail
    - ${BBlue}Bold Blue${COLOUR_OFF} and ${BWhite}Bold White = General Information"
    
    echo -e "\n ${BWhite}[!!!] Remember to run ${BRed}'sudo -l'${BWhite} to check for SUDO permissions!${COLOUR_OFF}"
}

# Function to perform checks to see if the machine is a Docker container
is_docker() {
    echo -e "${BBlue}[+] Performing Docker Container Checks...${COLOUR_OFF}"

    local matches=0

    # Checks to see if the .dockerenv file exists
    echo -n -e "${Yellow}[~] Checking for .dockerenv file... ${COLOUR_OFF}"
    if [ -f /.dockerenv ]; then
    	echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi

    # Checks to see if the string 'docker' appears in /proc/1/cgroup
    echo -n -e "${Yellow}[~] Checking for 'docker' within /proc/1/cgroup... ${COLOUR_OFF}"
    if grep -q docker /proc/1/cgroup 2>/dev/null; then
        echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi

    # Checks if the process information of PID 1 contains 'docker' or 'containerd-shim'
    echo -n -e "${Yellow}[~] Checking for 'docker' or 'containerd-shim' within process PID 1... ${COLOUR_OFF}"
    if ps -o comm= -p 1 | grep -qE "docker|containerd-shim" 2>/dev/null; then
        echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi

    # Checks if the string 'docker' appears in /proc/self/mountinfo
    echo -n -e "${Yellow}[~] Checking for 'docker' within /proc/self/mountinfo... ${COLOUR_OFF}"
    if grep -qE "docker" /proc/self/mountinfo 2>/dev/null; then
        echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi

    echo -e "${BWhite}[+] Total Docker Checks Passed: $matches/4${COLOUR_OFF}"

    # Return true if any checks match
    if ((matches > 0)); then
        return 0
    else
        return 1
    fi
}

# Function to perform checks to see if the machine is an LXC container
is_lxc() {
    echo -e "\n${BBlue}[+] Performing LXC Container Checks...${COLOUR_OFF}"
    
    local matches=0

    # Checks to see if the string 'lxc' appears in /proc/1/cgroup
    echo -n -e "${Yellow}[~] Checking for 'lxc' within /proc/1/cgroup... ${COLOUR_OFF}"
    if grep -q lxc /proc/1/cgroup 2>/dev/null; then
        echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi

    # Checks to see if the environment variable 'container' is set to 'lxc' in /proc/1/environ
    echo -n -e "${Yellow}[~] Checking for 'container=lxc' within /proc/1/environ... ${COLOUR_OFF}"
    if grep -qa "container=lxc" /proc/1/environ 2>/dev/null; then
        echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi

    # Checks to see if the /dev/lxc directory exists
    echo -n -e "${Yellow}[~] Checking for /dev/lxc directory... ${COLOUR_OFF}"
    if [ -d /dev/lxc ]; then
        echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi

    # Checks to see if the /sys/fs/cgroup/systemd/lxc directory exists
    echo -n -e "${Yellow}[~] Checking for /sys/fs/cgroup/systemd/lxc directory... ${COLOUR_OFF}"
    if [ -d /sys/fs/cgroup/systemd/lxc ]; then
        echo -e "${Green}[SUCCESS]${COLOUR_OFF}"
        matches=$((matches + 1))
    else
        echo -e "${Red}[FAIL]${COLOUR_OFF}"
    fi
    
    echo -e "${BWhite}[+] Total LXC Checks Passed: $matches/4${COLOUR_OFF}"

    # Return true if any checks match
    if ((matches > 0)); then
        return 0
    else
        return 1
    fi
}


# Lists general information about the machine, OS, and current user
general() {
    # Hostname
    echo -e "\n${BGreen}Hostname:${COLOUR_OFF}"
    hostname 2>/dev/null
    
    # Check Docker or LXC Container
    echo -e "\n${BGreen}Docker or LXC Container?${COLOUR_OFF}"
    if is_docker; then
        echo -e "${BBlue}[*] Docker Container Detected.${COLOUR_OFF}"
    elif is_lxc; then
        echo -e "${BBlue}[*] LXC Container Detected.${COLOUR_OFF}"
    else
        echo -e "\n${BBlue}[*] Not Running Inside of a (recognized) Container.${COLOUR_OFF}"
    fi

    # Whoami
    echo -e "\n${BGreen}Current User:${COLOUR_OFF}"
    whoami | sed "s/\broot\b/$(echo -e "${BRed}&${COLOUR_OFF}")/g" 2>/dev/null

    # id
    echo -e "\n${BGreen}Current User Groups:${COLOUR_OFF}"
    id | sed "s/\broot\b/$(echo -e "${BRed}&${COLOUR_OFF}")/g" 2>/dev/null
    
    # Shell Type
    echo -e "\n${BGreen}Current Shell Type:${COLOUR_OFF}"
    echo $SHELL 2>/dev/null
    
    # Current Directory
    echo -e "\n${BGreen}Current Directory:${COLOUR_OFF}"
    pwd | sed "s/\broot\b/$(echo -e "${BRed}&${COLOUR_OFF}")/g" 2>/dev/null
    
    # PATH 
    echo -e "\n${BGreen}PATH Environment Variable:${COLOUR_OFF}"
    echo $PATH | sed "s/\broot\b/$(echo -e "${BRed}&${COLOUR_OFF}")/g" 2>/dev/null
    
    # Environment Variables
    echo -e "\n${BGreen}Environment Variables:${COLOUR_OFF}"
    env | sed 's/\x1b\[[0-9;]*m//g' 2>/dev/null
    
    # All system users with login capability
    echo -e "\n${BGreen}All Users with Login Capability:${COLOUR_OFF}"
    grep -vE "(/usr/sbin/nologin|/bin/false)" /etc/passwd | awk -F ":" '{print $1}' | sed "s/\broot\b/$(echo -e "${BRed}&${COLOUR_OFF}")/g" 2>/dev/null
}

# Lists the bash, kernel, and sudo version
system_versions() {
    # Linux Version
    echo -e "\n${BGreen}Linux Version:${COLOUR_OFF}"
    cat /proc/version 2>/dev/null
    
    # Distro Release
    echo -e "\n${BGreen}Distribution Release:${COLOUR_OFF}"
    lsb_release -a 2>/dev/null
    
    # All Release Information
    echo -e "\n${BGreen}All Release Information From /etc:${COLOUR_OFF}"
    cat /etc/*release 2>/dev/null
    
    # bash Version
    echo -e "\n${BGreen}Bash Version:${COLOUR_OFF}"
    /bin/bash --version 2>/dev/null

    # Kernel Version
    echo -e "\n${BGreen}Kernel Version:${COLOUR_OFF}"
    uname -a 2>/dev/null

    # Sudo Version
    echo -e "\n${BGreen}SUDO Version:${COLOUR_OFF}"
    sudo -V 2>/dev/null
}

# Reads the /etc/passwd file and the /etc/crontab file
read_files() {
    # /etc/passwd
    echo -e "\n${BGreen}/etc/passwd File:${COLOUR_OFF}"
    cat /etc/passwd | sed "s/\broot\b/$(echo -e "${BRed}&${COLOUR_OFF}")/g" 2>/dev/null
    
    # /etc/crontab
    echo -e "\n${BGreen}/etc/crontab File:${COLOUR_OFF}"
    cat /etc/crontab | sed "s/\broot\b/$(echo -e "${BRed}&${COLOUR_OFF}")/g" 2>/dev/null
    echo -e "\n${BBlue}(Cronjobs can be hidden, use 'pspy' to monitor for hidden processes)${COLOUR_OFF}"
}

# Displays mounted filesystems and drives
filesystem() {
    # List Mounts
    echo -e "\n${BGreen}List Mounted Filesystems:${COLOUR_OFF}"
    findmnt 2>/dev/null
}

# Displays network information
network() {
    # ifconfig
    echo -e "\n${BGreen}Network Interfaces:${COLOUR_OFF}"
    ifconfig 2>/dev/null
    
    # Listening TCP Ports and PID
    echo -e "\n${BGreen}List Open TCP Ports, Connections and PID:${COLOUR_OFF}"
    netstat -plnt 2>/dev/null
}

# Locates backups, KeePass databases, and regular databases
find_interesting() {
    # Backup Files
    echo -e "\n${BGreen}Locate Backup Files:${COLOUR_OFF}"
    find / -type f -name "*backup*" -o -name "*.bak" -o -name "*.bck" -o -name "*.bk" 2>/dev/null | check_output

    # KeePass Databases
    echo -e "\n${BGreen}Locate KeePass Database Files:${COLOUR_OFF}"
    find / -name "*.kdbx" 2>/dev/null | check_output

    # Databases
    echo -e "\n${BGreen}Locate Databases:${COLOUR_OFF}"
    find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null | check_output
}

# Detects which history file to read and uses grep to locate possible passwords
scan_history() {
    echo -e "\n${BGreen}Find Commands in Bash|ZSH History Containing Potential Passwords or Usernames:${COLOUR_OFF}"

    # Use get_default_shell to determine the user's default shell
    local CURRENT_SHELL=$(get_default_shell)

    if [[ "$CURRENT_SHELL" == "bash" ]]; then
        HIST_FILE=~/.bash_history
    elif [[ "$CURRENT_SHELL" == "zsh" ]]; then
        HIST_FILE=~/.zsh_history
    else
        echo -e "${BRed}[!] Could Not Locate History File for Shell Type '${CURRENT_SHELL}'...${COLOUR_OFF}"
        return 1
    fi

    # Check if the history file exists
    if [[ -f "$HIST_FILE" ]]; then
        echo -e "${BBlue}[+] History File Location:${COLOUR_OFF} ${BWhite}'$HIST_FILE'${COLOUR_OFF}"
        # Load the history file
        history -r "$HIST_FILE" 2>/dev/null
        # Grep to search the history file for potential credentials
        history | grep -iE --color=always '\-p|\-pass|\-password|passw|[^[:space:]]+:[^[:space:]]+|[^[:space:]]+@[^[:space:]]+' 2>/dev/null | check_output
    else
        echo -e "${BRed}[!] History File Does Not Exist...${COLOUR_OFF}"
    fi
}

# Lists all processes being run as root
root_processes() {
    # Processes Run as root
    echo -e "\n${BGreen}Find Processes Being Run as root:${COLOUR_OFF}"
    ps aux | grep root 2>/dev/null
    echo -e "\n${BBlue}(Cronjobs can be hidden, use 'pspy' to monitor for hidden processes)${COLOUR_OFF}"
}

# Locates SUID binaries and checks against list of exploitable binaries from GTFOBins
suid_check() {
    # List of SUID and Limited SUID binaries taken from hxxps://gtfobins[.]github[.]io/
    suid_binaries="aa-exec,ab,agetty,alpine,ar,aria2c,arj,arp,as,ascii-xfr,ash,aspell,atobm,awk,awk,base32,base64,basenc,basez,bash,batcat,bc,bridge,busctl,busybox,byebug,bzip2,cabal,capsh,cat,chmod,choom,chown,chroot,clamscan,cmp,column,comm,composer,cp,cpio,cpulimit,csh,csplit,csvtool,cupsfilter,curl,cut,dash,date,dc,dd,debugfs,dialog,diff,dig,distcc,dmsetup,docker,dosbox,dvips,ed,ed,efax,elvish,emacs,env,eqn,espeak,expand,expect,file,find,fish,flock,fmt,fold,gawk,gawk,gcore,gdb,genie,genisoimage,gimp,ginsh,git,grep,gtester,gzip,hd,head,hexdump,highlight,hping3,iconv,iftop,install,ionice,ip,ispell,jjs,joe,join,jq,jrunscript,julia,ksh,ksshell,kubectl,latex,ld.so,ldconfig,less,lftp,links,logsave,look,lua,lua,lualatex,luatex,make,mawk,mawk,minicom,more,mosquitto,msgattrib,msgcat,msgconv,msgfilter,msgmerge,msguniq,multitime,mv,mysql,nano,nasm,nawk,nawk,nc,ncdu,ncftp,nft,nice,nl,nm,nmap,nmap,node,nohup,ntpdate,octave,od,openssl,openvpn,pandoc,pandoc,paste,pdflatex,pdftex,perf,perl,pexec,pg,php,pic,pico,pidstat,posh,pr,pry,psftp,ptx,python,rake,rc,readelf,restic,rev,rlwrap,rpm,rpmdb,rpmquery,rpmverify,rsync,rtorrent,run-parts,runscript,rview,rview,rvim,rvim,sash,scanmem,scp,scrot,sed,setarch,setfacl,setlock,shuf,slsh,socat,soelim,softlimit,sort,sqlite3,sqlite3,ss,ssh-agent,ssh-keygen,ssh-keyscan,sshpass,start-stop-daemon,stdbuf,strace,strings,sysctl,systemctl,tac,tail,tar,taskset,tasksh,tbl,tclsh,tdbtool,tee,telnet,terraform,tex,tftp,tic,time,timeout,tmate,troff,ul,unexpand,uniq,unshare,unsquashfs,unzip,update-alternatives,uudecode,uuencode,vagrant,varnishncsa,view,view,vigr,vim,vim,vimdiff,vimdiff,vipw,w3m,watch,watch,wc,wget,whiptail,xargs,xdotool,xelatex,xetex,xmodmap,xmore,xxd,xz,yash,zip,zsh,zsoelim"
    
    # Find SUID Binaries
    echo -e "\n${BGreen}Locate SUID Binaries:${COLOUR_OFF}"
    output=$(find / -type f -perm -4000 2>/dev/null)
    
    # Check each SUID binary against GTFOBins
    while read -r fullpath; do
        binary=$(basename "$fullpath")
        if echo "$suid_binaries" | grep -wq "\b$binary\b"; then
            echo -e "\n${BWhite}Binary: ${BRed}$binary ${BWhite}- Can Be Abused! Check 'https://gtfobins.github.io/gtfobins/$binary/'!${COLOUR_OFF}\n${BWhite}Full Path: ${BRed}$fullpath${COLOUR_OFF}\n"
        else
            echo "$fullpath"
        fi
    done <<< "$output"
}

# Default function calls
call_default_functions() {
    banner
    general
    system_versions
    read_files
    filesystem
    network
    find_interesting
    scan_history
    root_processes
    suid_check
}

# Function to handle the arguments and call appropriate functions
handle_args() {
    # Check the passed arguments
    while getopts ":hgnfrmSps" opt; do
        case $opt in
            h)  # Option -h
                usage
                exit 0
                ;;
            g)  # Option -g
                general
                system_versions
                ;;
            n)  # Option -n
                network
                ;;
            f)  # Option -f
                find_interesting
                ;;
            r)  # Option -r
                read_files
                ;;
            m)  # Option -m
                filesystem
                ;;
            S)  # Option -h for scan_history
                scan_history
                ;;
            p)  # Option -r for root_processes
                root_processes
                ;;
            s)  # Option -s for suid_check
                suid_check
                ;;
            \?)  # Invalid option
                echo -e "\n${BRed}[!] Invalid option: -$OPTARG${COLOUR_OFF}" >&2
                usage
                exit 1
                ;;
        esac
    done
    
    # If no valid flags were provided, only '-', show usage
    if [[ $OPTIND -eq 1 ]]; then
        usage
        exit 1
    fi
}

# Show usage info
usage() {
    echo -e "\n${BWhite}Usage: $0 [-h] [-g] [-n] [-f] [-r] [-m] [-S] [-p] [-s]${COLOUR_OFF}"
    echo "Run the script with no arguments to enumerate all system information."
    echo -e "\n${BWhite}Optional Arguments:${COLOUR_OFF}"
    echo "  -h    Displays this usage section."
    echo "  -g    Display general information about the machine, OS, current user, and system versions."
    echo "  -n    Display network interfaces and listening TCP ports."
    echo "  -f    Find backup files, KeePass databases, and regular databases."
    echo "  -r    Reads the contents of /etc/passwd and /etc/crontab."
    echo "  -m    Lists mounted filesystems and devices."
    echo "  -S    Scan the bash|zsh history file for potential passwords."
    echo "  -p    Display processes being run by root."
    echo "  -s    Find SUID binaries and check against a list of known exploitable binaries."
}

# Function to validate the arguments
validate_arguments() {
    for arg in "$@"; do
        # Check if the argument starts with a single '-' followed by more than one character
        if [[ "$arg" =~ ^-[^-]*[a-zA-Z]{2,} ]]; then
            echo -e "\n${BRed}[!] Combined arguments like $arg are not allowed. Use separate arguments instead.${COLOUR_OFF}"
            usage
            exit 1
        fi
    done
}

# Main script execution
if [[ $# -gt 0 ]]; then
    # Validate arguments for combined options
    validate_arguments "$@"

    # Display banner
    banner

    # Handle the arguments
    handle_args "$@"
else
    # If no arguments are supplied, call all functions by default
    call_default_functions
fi
