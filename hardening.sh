#!/bin/bash
chvt 3
exec </dev/tty3> /dev/tty3
clear
function set_parameter
{
sed -i -e "s|^$2.*|$2$3|" $1
egrep "^$2*" $1 > /dev/null ||echo "$2$3" >> $1
}
#---------------------------------------------------------------------------------------------------------------
function add_line
{
egrep "^$2" $1 > /dev/null || echo "$2" >> $1
}
#---------------------------------------------------------------------------------------------------------------



echo ------------------------------------------------------------------------
echo Audit rules
sleep 6
add_line /etc/audit/audit.rules "-a exclude,always -F msgtype=CWD"
add_line /etc/audit/audit.rules "-a exit,always -S all -F euid=0 -F perm=wxa -k root"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/var/log/audit -F perm=wra -k audit-logs"
add_line /etc/audit/audit.rules "-w /var/log/auth.log -p wra -k logs"
add_line /etc/audit/audit.rules "-w /var/log/syslog -p wra -k logs"

add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/etc -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/boot -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/usr/lib -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/bin -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/lib -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/lib64 -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/sbin -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/usr/bin -F perm=wa -k system"
add_line /etc/audit/audit.rules "-a always,exit -S all -F dir=/usr/sbin -F perm=wa -k system"
echo ------------------------------------------------------------------------
echo 1.1.6 Bind Mount the /var/tmp directory to /tmp
add_line /etc/fstab "/tmp /var/tmp none bind 0 0"
echo ------------------------------------------------------------------------
echo 1.1.14 Add nodev Option to /dev/shm Partition
echo 1.1.15 Add nosuid Option to /dev/shm Partition
echo 1.1.16 Add noexec Option to /dev/shm Partition
sed -i 's|\(/dev/shm\s*\S*\s*defaults\)\S*|\1,nodev,noexec,nosuid|' /etc/fstab
echo ------------------------------------------------------------------------
echo 1.1.18 Disable Mounting of cramfs Filesystems
add_line /etc/modprobe.d/CIS.conf "install cramfs /bin/true"
echo ------------------------------------------------------------------------
echo 1.1.19 Disable Mounting of freevxfs Filesystems
add_line /etc/modprobe.d/CIS.conf "install freevxfs /bin/true"
echo ------------------------------------------------------------------------
echo 1.1.20 Disable Mounting of jffs2 Filesystems
add_line /etc/modprobe.d/CIS.conf "install jffs2 /bin/true"
echo ------------------------------------------------------------------------
echo 1.1.21 Disable Mounting of hfs Filesystems
add_line /etc/modprobe.d/CIS.conf "install hfs /bin/true"
echo ------------------------------------------------------------------------
echo 1.1.22 Disable Mounting of hfsplus Filesystems
add_line /etc/modprobe.d/CIS.conf "install hfsplus /bin/true"
echo ------------------------------------------------------------------------
echo 1.1.23 Disable Mounting of squashfs Filesystems
add_line /etc/modprobe.d/CIS.conf "install squashfs /bin/true"
echo ------------------------------------------------------------------------
echo 1.1.24 Disable Mounting of udf Filesystems
add_line /etc/modprobe.d/CIS.conf "install udf /bin/true"
echo ------------------------------------------------------------------------
echo 1.2.1 Verify that gpgcheck is Globally Activated - Manually checked
echo ------------------------------------------------------------------------
echo 1.2.2 Verify that gpgcheck is Globally Activated
set_parameter /etc/yum.conf "gpgcheck" "=1"
echo ------------------------------------------------------------------------
echo 1.2.4 Verify Package Integrity Using RPM
rpm -qVa | awk '$2 != "c" { print $0}'
echo ------------------------------------------------------------------------
echo 1.4.4 Remove SETroubleshoot
yum -q -y erase setroubleshoot
echo -------------------------------------------------------------s-----------
echo 1.5.1 Set User/Group Owner on /etc/grub.conf
chown root:root /etc/grub.conf
echo ------------------------------------------------------------------------
echo 1.5.2 Set Permissions on /etc/grub.conf
chmod og-rwx /etc/grub.conf
echo 1.5.2 Set Permissions on /etc/grub.conf
echo ------------------------------------------------------------------------
echo 1.5.3 Set Boot Loader Password - Set automatic
echo ------------------------------------------------------------------------
echo 1.5.4 Require Authentication for Single-User Mode
set_parameter /etc/sysconfig/init "SINGLE" "=/sbin/sulogin"
set_parameter /etc/sysconfig/init "PROMPT" "=no"
echo ------------------------------------------------------------------------
echo 1.5.5 Disable Interactive Boot
set_parameter /etc/sysconfig/init "PROMPT" "=no"
echo ------------------------------------------------------------------------
echo 1.6.1 Restrict Core Dumps
add_line /etc/security/limits.conf "* hard core 0"
set_parameter /etc/sysctl.conf "fs.suid_dumpable" "=0"
echo ------------------------------------------------------------------------
echo 1.6.1 Configure ExecShield
set_parameter /etc/sysctl.conf "kernel.exec-shield" "=1"
echo ------------------------------------------------------------------------
echo 1.6.3 Enable Randomized Virtual Memory Region Placement
set_parameter /etc/sysctl.conf "kernel.randomize_va_space" "=2"
echo ------------------------------------------------------------------------
echo 1.7 Use the Latest OS Release - Skipped
echo ------------------------------------------------------------------------
echo 2.1.1 Remove telnet-server
yum -q -y erase telnet-server
echo ------------------------------------------------------------------------
echo 2.1.2 Remove telnet Clients
yum -q -y erase telnet
echo ------------------------------------------------------------------------
echo 2.1.3 Remove rsh-server
yum -q -y erase rsh-server
echo ------------------------------------------------------------------------
echo 2.1.4 Remove rsh
yum -q -y erase rsh
echo ------------------------------------------------------------------------
echo 2.1.5 Remove NIS Client
echo ------------------------------------------------------------------------
echo 2.1.5 Remove NIS Client
yum -q -y erase ypbind
echo ------------------------------------------------------------------------
echo 2.1.6 Remove NIS Server
yum -q -y erase ypserv
echo ------------------------------------------------------------------------
echo 2.1.7 Remove tftp
yum -q -y erase tftp
echo ------------------------------------------------------------------------
echo 2.1.8 Remove tftp-server
yum -q -y erase tftp-server
echo ------------------------------------------------------------------------
echo 2.1.9 Remove talk
yum -q -y erase talk
echo ------------------------------------------------------------------------
echo 2.1.10 Remove talk-server
yum -q -y erase talk-server
echo ------------------------------------------------------------------------
echo 2.1.11 Remove xinetd
yum -q -y erase xinetd
echo ------------------------------------------------------------------------
echo 2.1.12 Disable chargen-dgram
chkconfig chargen-dgram off
echo ------------------------------------------------------------------------
echo 2.1.13 Disable chargen-stream
chkconfig chargen-stream off
echo ------------------------------------------------------------------------
echo 2.1.14 Disable daytime-dgram
chkconfig daytime-dgram off
echo ------------------------------------------------------------------------
echo 2.1.15 Disable daytime-stream
chkconfig daytime-stream off
echo ------------------------------------------------------------------------
echo 2.1.16 Disable echo-dgram
chkconfig echo-dgram off
echo ------------------------------------------------------------------------
echo 2.1.17 Disable echo-stream
chkconfig echo-stream off
echo ------------------------------------------------------------------------
echo 2.1.18 Disable tcpmux-server
chkconfig tcpmux-server off
echo ------------------------------------------------------------------------
echo 3.1 Set Daemon umask
set_parameter /etc/sysconfig/init "umask" " 027"
echo ------------------------------------------------------------------------
echo 3.2 Remove X Windows - Waiver - required
echo ------------------------------------------------------------------------
echo 3.3 Disable Avahi Server
chkconfig avahi-daemon off
echo ------------------------------------------------------------------------
echo 3.4 Disable Print Server - CUPS
chkconfig cups off
echo ------------------------------------------------------------------------
echo 3.5 Remove DHCP Server
yum -y -q erase dhcp
echo ------------------------------------------------------------------------


echo ------------------------------------------------------------------------
echo 3.7 Remove LDAP
yum -y -q erase openldap-servers
yum -y -q erase openldap-clients
echo ------------------------------------------------------------------------
echo 3.8 Disable NFS and RPC
chkconfig rpcbind off
echo ------------------------------------------------------------------------
echo 3.9 Remove DNS Server
yum -y -q erase bind
echo ------------------------------------------------------------------------
echo 3.10 Remove FTP Server
yum -y -q erase vsftpd
echo ------------------------------------------------------------------------
echo 3.11 Remove HTTP Server
yum -y -q erase httpd
echo ------------------------------------------------------------------------
echo 3.12 Remove Dovecot
yum -y -q erase dovecot
echo ------------------------------------------------------------------------
echo 3.13 Remove Samba
yum -y -q erase sambaroot
echo ------------------------------------------------------------------------
echo 3.14 Remove HTTP Proxy Server
yum -y -q erase squid
echo ------------------------------------------------------------------------
echo 3.15 Remove SNMP Server
yum -y -q erase net-snmp
echo ------------------------------------------------------------------------
echo 3.16 Configure Mail Transfer Agent for Local-Only Mode - Manually checked
echo ------------------------------------------------------------------------
echo 4.1 Configure rsyslog - Waiver - Note network connected
echo ------------------------------------------------------------------------
echo 4.2 Configure System Accounting
echo 4.2.1 Configure Data Retention - Skipped - Using defaults
echo ------------------------------------------------------------------------
echo 4.2.1.2 Disable System on Audit Log Full
set_parameter /etc/audit/auditd.conf "admin_space_left_action" " = halt"
set_parameter /etc/audit/auditd.conf "disk_full_action" " = halt"
set_parameter /etc/audit/auditd.conf "disk_error_action" " = halt"
echo ------------------------------------------------------------------------
echo 4.2.1.3 Keep All Auditing Information
set_parameter /etc/audit/auditd.conf "max_log_file_action" " = keep_logs"
echo ------------------------------------------------------------------------
echo 4.2.2 Enable auditd Service
chkconfig auditd on
echo ------------------------------------------------------------------------
echo 4.2.3 Enable Auditing for Processes That Start Prior to auditd
sed -i -e "s|audit=1||" /etc/grub.conf
sed -i -e "s|kernel[ ]*\([^ ]*\)|kernel \1 audit=1|" /etc/grub.conf
sed -i -e "s|audit=1||" /boot/grub/grub.conf
sed -i -e "s|kernel[ ]*\([^ ]*\)|kernel \1 audit=1|" /boot/grub/grub.conf
echo ------------------------------------------------------------------------
echo 4.2.4 Record Events That Modify Date and Time Information
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S clock_settime -k time-change"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S clock_settime -k time-change"
add_line /etc/audit/audit.rules "-w /etc/localtime -p wa -k time-change"
echo ------------------------------------------------------------------------
echo 4.2.5 Record Events That Modify User/Group Information
add_line /etc/audit/audit.rules "-w /etc/group -p wa -k identity"
add_line /etc/audit/audit.rules "-w /etc/passwd -p wa -k identity"
add_line /etc/audit/audit.rules "-w /etc/gshadow -p wa -k identity"
add_line /etc/audit/audit.rules "-w /etc/shadow -p wa -k identity"
add_line /etc/audit/audit.rules "-w /etc/security/opasswd -p wa -k identity"
echo ------------------------------------------------------------------------
echo 4.2.6 Record Events That Modify the Systems Network Environment
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale"
add_line /etc/audit/audit.rules "-w /etc/issue -p wa -k system-locale"
add_line /etc/audit/audit.rules "-w /etc/issue.net -p wa -k system-locale"
add_line /etc/audit/audit.rules "-w /etc/hosts -p wa -k system-locale"
add_line /etc/audit/audit.rules "-w /etc/sysconfig/network -p wa -k system-locale"
echo ------------------------------------------------------------------------
echo 4.2.7 Record Events That Modify the Systems Mandatory Access Controls
add_line /etc/audit/audit.rules "-w /etc/selinux/ -p wa -k MAC-policy"
echo ------------------------------------------------------------------------
echo 4.2.8 Collect Login and Logout Events
add_line /etc/audit/audit.rules "-w /var/log/faillog -p wa -k logins"
add_line /etc/audit/audit.rules "-w /var/log/lastlog -p wa -k logins"
add_line /etc/audit/audit.rules "-w /var/log/tallylog -p wa -k logins"
echo ------------------------------------------------------------------------
echo 4.2.9 Collect Session Initiation Information
add_line /etc/audit/audit.rules "-w /var/run/utmp -p wa -k session"
add_line /etc/audit/audit.rules "-w /var/log/wtmp -p wa -k session"
add_line /etc/audit/audit.rules "-w /var/log/btmp -p wa -k session"
echo ------------------------------------------------------------------------
echo 4.2.10 Collect Discretionary Access Control Permission Modification Events
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
echo ------------------------------------------------------------------------
echo 4.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
echo ------------------------------------------------------------------------
echo 4.2.12 Collect Use of Privileged Commands
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/fusermount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/Xorg -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
#add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/lib64/nspluginwrapper/plugin-config -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
#add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache -F perm=x -F auid>=500 -F auid!=4294967295 \ -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/pulse/proximity-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/sbin/suexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
#add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
#add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
echo ------------------------------------------------------------------------
echo 4.2.13 Collect Successful File System Mounts
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
echo ------------------------------------------------------------------------
echo 4.2.14 Collect File Deletion Events by User
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
echo ------------------------------------------------------------------------
echo 4.2.15 Collect Changes to System Administration Scope
add_line /etc/audit/audit.rules "-w /etc/sudoers -p wa -k scope"
echo ------------------------------------------------------------------------
echo 4.2.16 Collect System Administrator Actions
add_line /etc/audit/audit.rules "-w /var/log/sudo.log -p wa -k actions"
echo ------------------------------------------------------------------------
echo 4.2.17 Collect Kernel Module Loading and Unloading
add_line /etc/audit/audit.rules "-w /sbin/insmod -p x -k modules"
add_line /etc/audit/audit.rules "-w /sbin/rmmod -p x -k modules"
add_line /etc/audit/audit.rules "-w /sbin/modprobe -p x -k modules"
add_line /etc/audit/audit.rules "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
echo ------------------------------------------------------------------------
echo 4.2.18 Make the Audit Configuration Immutable
add_line /etc/audit/audit.rules "-e 2"
echo ------------------------------------------------------------------------
echo 4.3 Configure logrotate - adding /var/log/boot.log
grep "/var/log/boot.log" /etc/logrotate.d/syslog || sed -i -e "s|/var/log/cron|/var/log/cron\n/var/log/boot.log|" /etc/logrotate.d/syslog
echo ------------------------------------------------------------------------
echo 4.7 Enable IPtables
echo ------------------------------------------------------------------------
chkconfig iptables on
echo ------------------------------------------------------------------------
echo 5.1.1 Disable IP Forwarding
set_parameter /etc/sysctl.conf "net.ipv4.ip_forward" "=0"
echo ------------------------------------------------------------------------
echo 5.1.2 Disable Send Packet Redirects
set_parameter /etc/sysctl.conf "net.ipv4.conf.all.send_redirects" "=0"
set_parameter /etc/sysctl.conf "net.ipv4.conf.default.send_redirects" "=0"
echo ------------------------------------------------------------------------
echo 5.1.4 Create and Set Permissions on rsyslog Log Files


cat > /mnt/sysimage/etc/logrotate.d/syslog << "EOF"
/var/log/cron
/var/log/boot.log
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    create 640 root securegrp
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF

groupadd securegrp
chown -R root:securegrp /mnt/sysimage/var/log
echo ------------------------------------------------------------------------
echo 5.2.1 Disable Source Routed Packet Acceptance
set_parameter /etc/sysctl.conf "net.ipv4.conf.all.accept_source_route" "=0"
set_parameter /etc/sysctl.conf "net.ipv4.conf.default.accept_source_route" "=0"
echo ------------------------------------------------------------------------
echo 5.2.2 Disable ICMP Redirect Acceptance
set_parameter /etc/sysctl.conf "net.ipv4.conf.all.accept_redirects" "=0"
set_parameter /etc/sysctl.conf "net.ipv4.conf.default.accept_redirects" "=0"
echo ------------------------------------------------------------------------
echo 5.2.3 Disable Secure ICMP Redirect Acceptance
set_parameter /etc/sysctl.conf "net.ipv4.conf.all.secure_redirects" "=0"
set_parameter /etc/sysctl.conf "net.ipv4.conf.default.secure_redirects" "=0"
echo ------------------------------------------------------------------------
echo 5.2.4 Log Suspicious Packets
set_parameter /etc/sysctl.conf "net.ipv4.conf.all.log_martians" "=1"
set_parameter /etc/sysctl.conf "net.ipv4.conf.default.log_martians" "=1"
echo ------------------------------------------------------------------------
echo 5.2.5 Enable Ignore Broadcast Requests
set_parameter /etc/sysctl.conf "net.ipv4.icmp_echo_ignore_broadcasts" "=1"
echo ------------------------------------------------------------------------
echo 5.2.6 Enable Bad Error Message Protection
set_parameter /etc/sysctl.conf "net.ipv4.icmp_ignore_bogus_error_responses" "=1"
echo ------------------------------------------------------------------------
echo 5.2.7 Enable RFC-recommended Source Route Validation
set_parameter /etc/sysctl.conf "net.ipv4.conf.all.rp_filter" "=1"
set_parameter /etc/sysctl.conf "net.ipv4.conf.default.rp_filter" "=1"
echo ------------------------------------------------------------------------
echo 5.2.8 Enable TCP SYN Cookies
set_parameter /etc/sysctl.conf "net.ipv4.tcp_syncookies" "=1"
echo ------------------------------------------------------------------------
5.2.12 Collect Use of Privileged Commands
add_line /etc/audit/audit.rules "-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/sbin/netreport -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
add_line /etc/audit/audit.rules "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
echo ------------------------------------------------------------------------
5.2.14 Collect File Deletion Events by User
sleep 5
add_line /etc/audit/audit.rules -F auid!=4294967295 -k delete
add_line /etc/audit/audit.rules -F auid!=4294967295 -k delete
echo ------------------------------------------------------------------------
echo 5.3.1 Deactivate Wireless Interfaces - Manually checked
echo ------------------------------------------------------------------------
echo 5.4.1 Configure IPv6 - Waiver - IPV6 is not used
echo ------------------------------------------------------------------------
echo 5.4.2 Disable IPv6
set_parameter /etc/sysconfig/network "NETWORKING_IPV6" "=no"
set_parameter /etc/sysconfig/network "IPV6INIT" "=no"
set_parameter /etc/modprobe.d/ipv6.conf "options ipv6 disable" "=1"
echo ------------------------------------------------------------------------
echo 5.5.1 Install TCP Wrappers
yum -y -q install tcp_wrappers
echo ------------------------------------------------------------------------
echo 5.5.2 Create /etc/hosts.allow - Skipped - already in place
echo ------------------------------------------------------------------------
echo 5.5.3 Verify Permissions on /etc/hosts.allow
/bin/chmod 644 /etc/hosts.allow
echo ------------------------------------------------------------------------
echo 5.5.4 Create /etc/hosts.deny - Skipped - already in place
echo ------------------------------------------------------------------------
echo 5.5.5 Verify Permissions on /etc/hosts.deny
/bin/chmod 644 /etc/hosts.deny
echo ------------------------------------------------------------------------
echo 5.6.1 Disable DCCP
add_line /etc/modprobe.d/CIS.conf "install dccp /bin/true"
echo ------------------------------------------------------------------------
echo 5.6.2 Disable SCTP
add_line /etc/modprobe.d/CIS.conf "install sctp /bin/true"
echo ------------------------------------------------------------------------
echo 5.6.3 Disable RDS
add_line /etc/modprobe.d/CIS.conf "install rds /bin/true"
echo ------------------------------------------------------------------------
echo 5.6.4 Disable TIPC
add_line /etc/modprobe.d/CIS.conf "install tipc /bin/true"
echo ------------------------------------------------------------------------
echo 5.7 Enable IPtables
service iptables restart
chkconfig iptables on
echo ------------------------------------------------------------------------
echo 5.8 Enable IP6tables - Waiver IPV6 tables not enabled
echo ------------------------------------------------------------------------
echo 6.1.1 Enable anacron Daemon
yum -y -q install cronie-anacron
echo ------------------------------------------------------------------------
echo 6.1.2 Enable crond Daemon
chkconfig crond on
echo ------------------------------------------------------------------------
echo 6.1.3 Set User/Group Owner and Permission on /etc/anacrontab
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
echo ------------------------------------------------------------------------
echo 6.1.4 Set User/Group Owner and Permission on /etc/crontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
echo ------------------------------------------------------------------------
echo 6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
echo ------------------------------------------------------------------------
echo 6.1.6 Set User/Group Owner and Permission on /etc/cron.daily
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
echo ------------------------------------------------------------------------
echo Set User/Group Owner and Permission on /etc/cron.weekly
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
echo ------------------------------------------------------------------------
echo 6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
echo ------------------------------------------------------------------------
echo 6.1.9 Set User/Group Owner and Permission on /etc/cron.d
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
echo ------------------------------------------------------------------------
echo 6.1.10 Restrict at Daemon
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow
echo ------------------------------------------------------------------------
echo 6.1.11 Restrict at/cron to Authorized Users
rm -f /mnt/sysimage/etc/cron.deny
rm -f /mnt/sysimage/etc/cron.allow
touch /mnt/sysimage/etc/cron.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
echo ------------------------------------------------------------------------
echo 6.2.1 Set SSH Protocol to 2
set_parameter /etc/ssh/sshd_config "Protocol" " 2"
echo ------------------------------------------------------------------------
echo 6.2.2 Set LogLevel to INFO
set_parameter /etc/ssh/sshd_config "LogLevel" " INFO"
echo ------------------------------------------------------------------------
echo Set Permissions on /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
echo ------------------------------------------------------------------------
echo 6.2.4 Disable SSH X11 Forwarding
set_parameter /etc/ssh/sshd_config "X11Forwarding" " no"
echo ------------------------------------------------------------------------
echo Set SSH MaxAuthTries to 4 or Less
set_parameter /etc/ssh/sshd_config "MaxAuthTries" " 4"
echo ------------------------------------------------------------------------
echo 6.2.6 Set SSH IgnoreRhosts to Yes
set_parameter /etc/ssh/sshd_config "IgnoreRhosts" " yes"
echo ------------------------------------------------------------------------
echo 6.2.7 Set SSH HostbasedAuthentication to No
set_parameter /etc/ssh/sshd_config "HostbasedAuthentication" " no"
echo ------------------------------------------------------------------------
echo 6.2.8 Disable SSH Root Login
set_parameter /etc/ssh/sshd_config "PermitRootLogin" " no"
echo ------------------------------------------------------------------------
echo 6.2.9 Set SSH PermitEmptyPasswords to No
set_parameter /etc/ssh/sshd_config "PermitEmptyPasswords" " no"
echo ------------------------------------------------------------------------
echo 6.2.10 Do Not Allow Users to Set Environment Options
set_parameter /etc/ssh/sshd_config "PermitUserEnvironment" " no"
echo ------------------------------------------------------------------------
echo 6.2.11 Use Only Approved Cipher in Counter Mode
set_parameter /etc/ssh/sshd_config "Ciphers" " aes128-ctr,aes192-ctr,aes256-ctr"
echo ------------------------------------------------------------------------
echo 6.2.12 Set Idle Timeout Interval for User Login
set_parameter /etc/ssh/sshd_config "ClientAliveInterval" " 900"
set_parameter /etc/ssh/sshd_config "ClientAliveCountMax" " 0"
echo ------------------------------------------------------------------------
echo 6.2.13 Limit Access via SSH - Skipped
echo ------------------------------------------------------------------------
echo 6.2.14 Set SSH Banner
set_parameter /etc/ssh/sshd_config "Banner" " /etc/issue.net"
echo ------------------------------------------------------------------------
echo 6.3.1 Upgrade Password Hashing Algorithm to SHA-512
authconfig --passalgo=sha512 --update
echo ------------------------------------------------------------------------
echo 6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib
set_parameter /etc/pam.d/system-auth "password    required" " pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1"
echo ------------------------------------------------------------------------
echo 6.3.3 Set Lockout for Failed Password Attempts - Skipped
echo ------------------------------------------------------------------------
echo 6.3.4 Limit Password Reuse
set_parameter /etc/pam.d/system-auth "password    sufficient" " pam_unix.so remember=5"
echo ------------------------------------------------------------------------
echo 6.4 Restrict root Login to System Console - Skipped
rm -f /etc/securetty
cat > /etc/securetty << "EOF"
console
tty1
EOF
echo ------------------------------------------------------------------------
echo 6.5 Restrict Access to the su Command - skipped
rm -f /etc/pam.d/su
cat > /etc/pam.d/su << "EOF"

#%PAM-1.0
auth            sufficient      pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth           sufficient      pam_wheel.so trust use_uid
# Uncomment the following line to require a user to be in the "wheel" group.
auth           required        pam_wheel.so use_uid
auth            include         system-auth
account         sufficient      pam_succeed_if.so uid = 0 use_uid quiet
account         include         system-auth
password        include         system-auth
session         include         system-auth
session         optional        pam_xauth.so
EOF


echo ------------------------------------------------------------------------
echo 7.1.1 Set Password Expiration Days
echo 7.1.2 Set Password Change Minimum Number of Days
echo 7.1.3 Set Password Expiring Warning Days
sleep 3
rm -f /etc/login.defs
cat > /etc/login.defs << "EOF"
MAIL_DIR        /var/spool/mail
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_MIN_LEN    5
PASS_WARN_AGE   7
UID_MIN                   500
UID_MAX                 60000
GID_MIN                   500
GID_MAX                 60000
CREATE_HOME     yes
UMASK           077
USERGROUPS_ENAB yes
ENCRYPT_METHOD SHA512
EOF
echo 7.3 Set Default Group for root Account
usermod -g 0 root
echo ------------------------------------------------------------------------
echo 7.4 Set Default umask for Users - skipped
echo ------------------------------------------------------------------------
echo 7.5 Lock Inactive User Accounts
useradd -D -f 35
echo ------------------------------------------------------------------------
echo 8.1 Set Warning Banner for Standard Login Services
touch /etc/motd
echo "This is a private computer system and restricts access and use to authorized persons only.  Use of and/or access to this system and/or any information obtained via this system is subject to policies and procedures governing such use.  Unauthorized or improper use of or access to this system, or any portion of it, either directly or indirectly, or any attempt to deny service to authorized users or to alter, damage or destroy information, or otherwise to interfere with the system or its operation, is strictly prohibited.  Any party using or accessing, or attempting to use or access this system without express authority may be subject to severe disciplinary action and/or civil and criminal penalties in accordance with applicable law.  All access to this system is monitored.  Any person who uses or accesses this system expressly consents to such monitoring and recording.  We may furnish information obtained by its monitoring and recording activity to law enforcement officials if such monitoring and recording reveals possible evidence of unlawful activity." > /etc/issue

echo "This is a private computer system and restricts access and use to authorized persons only.  Use of and/or access to this system and/or any information obtained via this system is subject to policies and procedures governing such use.  Unauthorized or improper use of or access to this system, or any portion of it, either directly or indirectly, or any attempt to deny service to authorized users or to alter, damage or destroy information, or otherwise to interfere with the system or its operation, is strictly prohibited.  Any party using or accessing, or attempting to use or access this system without express authority may be subject to severe disciplinary action and/or civil and criminal penalties in accordance with applicable law.  All access to this system is monitored.  Any person who uses or accesses this system expressly consents to such monitoring and recording.  We may furnish information obtained by its monitoring and recording activity to law enforcement officials if such monitoring and recording reveals possible evidence of unlawful activity." > /etc/issue.net
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
echo ------------------------------------------------------------------------

echo 8.2 Remove OS Information from Login Warning Banners

echo "This is a private computer system and restricts access and use to authorized persons only.  Use of and/or access to this system and/or any information obtained via this system is subject to policies and procedures governing such use.  Unauthorized or improper use of or access to this system, or any portion of it, either directly or indirectly, or any attempt to deny service to authorized users or to alter, damage or destroy information, or otherwise to interfere with the system or its operation, is strictly prohibited.  Any party using or accessing, or attempting to use or access this system without express authority may be subject to severe disciplinary action and/or civil and criminal penalties in accordance with applicable law.  All access to this system is monitored.  Any person who uses or accesses this system expressly consents to such monitoring and recording.  We may furnish information obtained by its monitoring and recording activity to law enforcement officials if such monitoring and recording reveals possible evidence of unlawful activity." > /etc/motd
echo ------------------------------------------------------------------------

echo 8.3 Set GNOME Warning Banner
gconftool-2 -direct -config-source=xml:readwrite:$HOME/.gconf -type bool -set /apps/gdm/simple-greeter/banner_message_enable true
gconftool-2 -direct -config-source=xml:readwrite:$HOME/.gconf -t string -s /apps/gdm/simple-greeter/banner_message_text "Authorized users only. All activity may be monitored and reported."
echo ------------------------------------------------------------------------


echo 9.1.2 Verify Permissions on /etc/passwd
/bin/chmod 644 /etc/passwd
echo ------------------------------------------------------------------------
echo 9.1.3 Verify Permissions on /etc/shadow
/bin/chmod 000 /etc/shadow
echo ------------------------------------------------------------------------
echo 9.1.4 Verify Permissions on /etc/gshadow
/bin/chmod 000 /etc/gshadow
echo ------------------------------------------------------------------------
echo 9.1.5 Verify Permissions on /etc/group
/bin/chmod 644 /etc/group
echo ------------------------------------------------------------------------
echo 9.1.6 Verify User/Group Ownership on /etc/passwd
/bin/chown root:root /etc/passwd
echo ------------------------------------------------------------------------
echo 9.1.7 Verify User/Group Ownership on /etc/shadow
/bin/chown root:root /etc/shadow
echo ------------------------------------------------------------------------
echo 9.1.8 Verify User/Group Ownership on /etc/gshadow
/bin/chown root:root /etc/gshadow
echo ------------------------------------------------------------------------
echo 9.1.9 Verify User/Group Ownership on /etc/group
/bin/chown root:root /etc/group
echo ------------------------------------------------------------------------
echo 9.1.10 Find World Writable Files
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -ls
echo ------------------------------------------------------------------------
echo 9.1.11 Find Un-owned Files and Directories
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls
echo ------------------------------------------------------------------------
echo 9.1.12 Find Un-grouped Files and Directories
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -group -ls
echo ------------------------------------------------------------------------
echo 9.1.13 Find SUID System Executables
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -ls
echo ------------------------------------------------------------------------
echo 9.1.14 Find SGID System Executables
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -ls
echo ------------------------------------------------------------------------
echo 9.2.1 Ensure Password Fields are Not Empty
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}'
echo ------------------------------------------------------------------------
echo 9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File
/bin/grep '^+:' /etc/passwd
echo ------------------------------------------------------------------------
echo 9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File
/bin/grep '^+:' /etc/shadow
echo ------------------------------------------------------------------------
echo 9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File
/bin/grep '^+:' /etc/group
echo ------------------------------------------------------------------------
echo 9.2.5 Verify No UID 0 Accounts Exist Other Than root
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' root
echo ------------------------------------------------------------------------
echo 9.2.6 Ensure root PATH Integrity
if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
 echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | bin/grep :$`" != "" ]; then
 echo "Trailing : in PATH"
fi
p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
 if [ "$1" = "." ]; then
  echo "PATH contains ."
  shift
  continue
 fi
 if [ -d $1 ]; then
  dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
  if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
   echo "Group Write permission set on directory $1"
  fi
  if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
   echo "Other Write permission set on directory $1"
  fi
  dirown=`ls -ldH $1 | awk '{print $3}'`
  if [ "$dirown" != "root" ] ; then
   echo $1 is not owned by root
  fi
  else
   echo $1 is not a directory
 fi
 shift
done
echo ------------------------------------------------------------------------
echo 9.2.7 Check Permissions on User Home Directories
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
 dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
 if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
  echo "Group Write permission set on directory $dir"
 fi
 if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
  echo "Other Read permission set on directory $dir"
 fi
 if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
  echo "Other Write permission set on directory $dir"
 fi
 if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
  echo "Other Execute permission set on directory $dir"
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.8 Check User Dot File Permissions
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
 for file in $dir/.[A-Za-z0-9]*; do
  if [ ! -h "$file" -a -f "$file" ]; then
   fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
   if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
    echo "Group Write permission set on file $file"
   fi
   if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
    echo "Other Write permission set on file $file"
   fi
  fi
 done
done
echo ------------------------------------------------------------------------
echo 9.2.9 Check Permissions on User .netrc Files
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
 for file in $dir/.netrc; do
  if [ ! -h "$file" -a -f "$file" ]; then
   fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
   if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
   then
    echo "Group Read set on $file"
   fi
   if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
    echo "Group Write set on $file"
   fi
   if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]; then
    echo "Group Execute set on $file"
   fi
   if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]; then
    echo "Other Read set on $file"
   fi
   if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
    echo "Other Write set on $file"
   fi
   if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]; then
    echo "Other Execute set on $file"
   fi
  fi
 done
done
echo ------------------------------------------------------------------------
echo 9.2.10 Check for Presence of User .rhosts Files
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
 for file in $dir/.rhosts; do
  if [ ! -h "$file" -a -f "$file" ]; then
   echo ".rhosts file in $dir"
  fi
 done
done
echo ------------------------------------------------------------------------
echo 9.2.11 Check Groups in /etc/passwd
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
 grep -q -P "^.*?:x:$i:" /etc/group
 if [ $? -ne 0 ]; then
  echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.12 Check That Users Are Assigned Valid Home Directories
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
  echo "The home directory ($dir) of user $user does not exist."
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.13 Check User Home Directory Ownership
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
  owner=$(stat -L -c "%U" "$dir")
  if [ "$owner" != "$user" ]; then
   echo "The home directory ($dir) of user $user is owned by $owner."
  fi
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.14 Check for Duplicate UIDs
echo "The Output for the Audit of Control 9.2.15 - Check for Duplicate UIDs is" /bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
  users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | /usr/bin/xargs`
  echo "Duplicate UID ($2): ${users}"
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.15 Check for Duplicate GIDs
echo "The Output for the Audit of Control 9.2.16 - Check for Duplicate GIDs is" /bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c | while read x ;do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
  grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
  echo "Duplicate GID ($2): ${grps}"
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.16 Check for Duplicate User Names
echo "The Output for the Audit of Control 9.2.18 - Check for Duplicate User Names is" cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
  uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
  echo "Duplicate User Name ($2): ${uids}"
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.17 Check for Duplicate Group Names
echo "The Output for the Audit of Control 9.2.19 - Check for Duplicate Group Names is" cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
  gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
  echo "Duplicate Group Name ($2): ${gids}"
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.18 Check for Presence of User .netrc Files
for dir in `/bin/cat /etc/passwd | /bin/awk -F: '{ print $6 }'`; do
 if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
  echo ".netrc file $dir/.netrc exists"
 fi
done
echo ------------------------------------------------------------------------
echo 9.2.19 Check for Presence of User .forward Files
for dir in `/bin/cat /etc/passwd | /bin/awk -F: '{ print $6 }'`; do
 if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
  echo ".forward file $dir/.forward exists"
 fi
done
