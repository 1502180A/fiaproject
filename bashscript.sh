#!/bin/bash

#9.1 Enable anacron Daemon
printf "Checking if anacron is enabled:\n"
if rpm -q cronie-anacron | grep "not installed" ; then # Install the package if it hasnt already been installed
    yum -y install cronie-anacron
    printf "\e[32mAnacron enabled\e[0m\n"
else
    printf "\e[32mNo remediation needed\e[0m\n"
fi

#9.2 Enable crond Daemon
printf "Checking if cron is enabled:\n"
if systemctl is-enabled crond | grep "enabled" ; then # Enable crond if it hasnt been enabled yet
    printf "\e[32mNo remediation needed\e[0m\n"
else
    systemctl enable crond
    printf "\e[32mCron Enabled\e[0m\n"
fi

#9.3  Set User/Group Owner and Permission on /etc/anacrontab
printf "Checking if the /etc/anacrontab file has the correct permissions:\n"
if ls -l /etc/anacrontab | grep -e -rw------- ; then # Modify the file permissions to allow only users to read and write
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/anarontab
    chmod og-rwx /etc/anacrontab
    printf "\e[32mChanged to correct permission\e[0m\n"
fi

#9.4 Set User/Group Owner and Permission on /etc/crontab
printf "Checking if the /etc/crontab file has the correct permissions:\n"
if ls -ld /etc/crontab | grep -e -rw------- ; then # Modify the file permissions to allow only users to read and write
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/crontab
    chmod og-rwx /etc/crontab
    printf "\e[32mChanged to correct permission\e[0m\n"
fi

#9.5 Set User/Group Owner and Permission on /etc/cron.[hourly,daily,weekly,monthly]
printf "Checking if /etc/cron.hourly has the correct permissions:\n"
if ls -ld /etc/cron.hourly | grep -e drwx------ ; then # Modify the file permissions to allow only users to read, write and execute
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/cron.hourly
    chmod og-rwx /etc/cron.hourly
    printf "\e[32mChanged to correct permission\e[0m\n"
fi

printf "Checking if /etc/cron.daily has the correct permissions:\n"
if ls -ld /etc/cron.daily | grep -e drwx------ ; then
     printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/cron.daily
    chmod og-rwx /etc/cron.daily
    printf "\e[32mChanged to correct permission\e[0m\n"
fi

printf "Checking if /etc/cron.weekly has the correct permissions:\n"
if ls -ld /etc/cron.weekly | grep -e drwx------ ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/cron.weekly
    chmod og-rwx /etc/cron.weekly
    printf "\e[32mChanged to correct permission\e[0m\n"
fi

printf "Checking if /etc/cron.monthly has the correct permissions:\n"
if ls -ld /etc/cron.monthly | grep -e drwx------ ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/cron.monthly
    chmod og-rwx /etc/cron.monthly
    printf "\e[32mChanged to correct permission\e[0m\n"
fi


#9.6 Set User/Group Owner and Permission on /etc/cron.d
printf "Checking if the /etc/cron.d directory has the correct permissions:\n"
if ls -ld /etc/cron.d | grep -e drwx------ ; then # Modify the file permissions to allow only users to read, write and execute
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/cron.d
    chmod og-rwx /etc/cron.d
    printf "\e[32mChanged to correct permission\e[0m\n"
fi

#9.7 Restrict at Daemon
printf "Checking if at jobs are restricted:\n"
if ! stat -L /etc/at.deny > /dev/null | grep "No such file or directory" ; then # Remove file if it hasnt been removed
    printf "\e[32mNo remediation needed\e[0m\n"
else
    rm /etc/at.deny
    printf "\e[32m /etc/at.deny has been removed\e[0m\n"
fi

printf "Checking if /etc/at.allow has been created with the correct permissions:\n"
if stat -L -c "%a %u %g" /etc/at.allow | egrep ".00 0 0" ; then # Create file with the correct permissions
    printf "\e[32mNo remediation needed\e[0m\n"
else
    touch /etc/at.allow
    chown root:root /etc/at.allow
    chmod og-rwx /etc/at.allow
    printf "\e[32mChanged to correct permission\e[0m\n"
fi

#9.8 Restrict at/cron to Authorized Users
printf "Checking if /etc/cron.deny has been removed:\n"
if [ -e "cron.deny" ]; then
   printf "\e[32m /etc/at.deny has been removed\e[0m\n"
    /bin/rm /etc/cron.deny
else
     printf "\e[32mNo remediation needed\e[0m\n"
fi

printf "Checking if /etc/at.deny has been removed:\n"
if [ -e "at.deny" ]; then
    printf "\e[32m /etc/at.deny has been removed\e[0m\n"
    /bin/rm /etc/at.deny
else
    printf "\e[32mNo remediation needed\e[0m\n"
fi

if [ -e "cron.allow" ]; then
     printf "\e[32mNo remediation needed\e[0m\n"
else
    touch /etc/cron.allow
     printf "\e[32m /etc/cron.allow has been created\e[0m\n"

fi

printf "Checking if /etc/cron.allow has changed restrictions:\n"
if ls -l /etc/cron.allow | grep -e "-rw-------" ; then
     printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/cron.allow
    chmod og-rwx /etc/cron.allow
     printf "\e[32mChanged restrictions\e[0m\n"
fi

if [ -e "at.allow" ]; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    touch /etc/at.allow
    printf "\e[32m /etc/at.allow has been created\e[0m\n"

fi

printf "Checking if /etc/at.allow has changed restrictions:\n"
if ls -l /etc/at.allow | grep -e "-rw-------" ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/at.allow
    chmod og-rwx /etc/at.allow
    printf "\e[32mChanged restrictions\e[0m\n"
fi


#10.1 Set SSH Protocol to 2
printf "Checking if SSH Protocol is set to 2:\n"
if grep "^Protocol[[:space:]]2" "/etc/ssh/sshd_config"; then 
    printf "\e[32mNo remediation needed\e[0m\n"
else    
    sed -i 's/^#Protocol[[:space:]]2/Protocol 2/' /etc/ssh/sshd_config
    printf "\e[32mSSH Protocol is set to 2\e[0m\n"      
fi

#10.2 Set LogLevelto INFO
printf "Checking if LogLevel is set to INFO:\n"
if grep "^LogLevel INFO" "/etc/ssh/sshd_config"; then
    printf "\e[32mNo remediation needed\e[0m\n"       
else
    sed -i 's/^#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config
    printf "\e[32mLogLevel is set to INFO\e[0m\n"      
fi

#10.3 Set Permissions on /etc/ssh/sshd_config (ROOT & CHMOD600)
printf "Checking if /etc/ssh/sshd_config file's owner and group is set to ROOT:\n"
if ls -l /etc/ssh/sshd_config | grep "root root"; then 
    printf "\e[32mNo remediation needed\e[0m\n"
else 
    chown root:root /etc/ssh/sshd_config 
    printf "\e[32m/etc/ssh/sshd_config file's owner and group is set to ROOT\e[0m\n"  
fi

printf "Checking if /etc/ssh/sshd_config file's permissions is correct:\n"
if ls -l /etc/ssh/sshd_config | grep -e -rw-------; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chmod 600 /etc/ssh/sshd_config
    printf "\e[32m/etc/ssh/sshd_config file's permissions is correct\e[0m\n"
fi

#10.4 Disable X11Forwarding
printf "Checking if X11Forwarding is disabled:\n"
if grep "^X11Forwarding[[:space:]]no" "/etc/ssh/sshd_config"; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    printf "\e[32mX11Fowarding is disabled\e[0m\n"    
fi

#10.5 Set SSH MaxAuthTries to 4 
printf "Checking if SSH MaxAuthTries is set to 4:\n"
if grep "^MaxAuthTries[[:space:]]4" "/etc/ssh/sshd_config"; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i 's/^#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
    printf "\e[32mSSH MaxAuthTries is set to 4\e[0m\n"
fi

#10.6 Set SSH IgnoreRhosts to yes
printf "Checking if SSH IgnoreRhosts is set to yes:\n"
if grep "^IgnoreRhosts[[:space:]]yes" "/etc/ssh/sshd_config"; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i 's/^#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
    printf "\e[32mSSH IgnoreRhosts is set to yes\e[0m\n"
fi

#10.7 Set SSH HostbasedAuthentication to No
printf "Checking if SSH HostbasedAuthentication is set to No:\n"
if grep "^HostbasedAuthentication[[:space:]]no" "/etc/ssh/sshd_config"; then
    printf "\e[32mNo remediation neede\e[0m\n"
else
    sed -i 's/^#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
    printf "\e[32m SSH HostbasedAuthentication is set to No\e[0m\n"
fi

#10.8 Disable SSH Root Login
printf "Checking if SSH Root login is disabled:\n"
if grep "^PermitRootLogin[[:space:]]no" "/etc/ssh/sshd_config"; then       
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    printf "\e[32mSSH Root login is disabled\e[0m\n"
          
fi

#10.9 Set SSH PermitEmptyPasswords to No
printf "Checking if SSH PermitEmptyPasswords is set to No:\n"
if grep "^PermitEmptyPasswords[[:space:]]no" "/etc/ssh/sshd_config"; then    
    printf "\e[32mNo remediation needed\e[0m\n"   
else
    sed -i 's/^#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    printf "\e[32mSSH PermitEmptyPasswords is set to No\e[0m\n"
fi

#10.10 Use only approved cipher in counter mode 
printf "Checking if only approved cipher is used in counter mode:\n"
if grep "^Ciphers aes128-ctr,aes192-ctr,aes256-ctr" "/etc/ssh/sshd_config"; then       
    printf "\e[32mNo remediation needed\e[0m\n"
else
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
    printf "\e[32mOnly approved cipher is used in counter mode\e[0m\n"       
fi

#10.11 Set Idle Timeout Interval for User Login
printf "Checking if ClientAliveInterval is set to 300:\n"
if grep "^ClientAliveInterval[[:space:]]300" "/etc/ssh/sshd_config"; then
    printf "\e[32mNo remediation needed\e[0m\n"       
else
    sed -i 's/^#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
    printf "\e[32mClientAliveInterval is set to 300\e[0m\n"       
fi

printf "Checking if ClientAliveCountMax is set to 0:\n"
if grep  "^ClientAliveCountMax[[:space:]]0" "/etc/ssh/sshd_config"; then   
    printf "\e[32mNo remediation needed\e[0m\n"    
else
    sed -i 's/^#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    printf "\e[32mClientAliveCountMax is set to 0\e[0m\n"
fi

#10.12 Limit Access via SSH 
printf "Checking access via SSH:\n"
remsshalwusrs=`grep "^AllowUsers" /etc/ssh/sshd_config`
remsshalwgrps=`grep "^AllowGroups" /etc/ssh/sshd_config`
remsshdnyusrs=`grep "^DenyUsers" /etc/ssh/sshd_config`
remsshdnygrps=`grep "^DenyGroups" /etc/ssh/sshd_config`

if [ -z "$remsshalwusrs" -o "$remsshalwusrs" == "AllowUsers[[:space:]]" ]
then
    echo "AllowUsers user1" >> /etc/ssh/sshd_config
    echo -e "\e[32m AllowUsers added\e[0m\n"
    echo -e "\e[32m $remsshalwusrs\e[0m"
else
    echo -e "\e[32m $remsshalwusrs\e[0m"
fi

if [ -z "$remsshalwgrps" -o "$remsshalwgrps" == "AllowUsers[[:space:]]" ]
then
    echo "AllowGroups group1" >> /etc/ssh/sshd_config
    echo -e "\e[32m AllowGroups added\e[0m\n"
    echo -e "\e[32m $remsshalwgrps\e[0m"
else
    echo -e "\e[32m $remsshalwgrps\e[0m"
fi

if [ -z "$remsshdnyusrs" -o "$remsshdnyusrs" == "AllowUsers[[:space:]]" ]
then
    echo "DenyUsers user2 user3" >> /etc/ssh/sshd_config
    echo -e "\e[32m DenyUsers Added\e[0m\n"
    echo -e "\e[32m $remsshdnyusrs\e[0m"
else
    echo -e "\e[32m $remsshdnyusrs\e[0m"
fi

if [ -z "$remsshdnygrps" -o "$remsshdnygrps" == "AllowUsers[[:space:]]" ]
then
    echo "DenyGroups group2" >> /etc/ssh/sshd_config
    echo -e "\e[32m DenyGroups Added\e[0m"
    echo -e "\e[32m $remsshdnygrps\e[0m"
else
    echo -e "\e[32m $remsshdnygrps\e[0m"
fi

#10.13 Set SSH Banner
printf "Check if SSH Banner is set:\n"
if grep "^Banner[[:space:]]/etc/issue.net" "/etc/ssh/sshd_config"; then   
    printf "\e[32mNo remediation needed\e[0m\n"   
else
    sed -i 's/^#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    printf "\e[32mBanner is set\e[0m\n"
fi


#11.1 Upgrade Password Hashing Algorithm to SHA-512
printf "Checking if the password-hashing algorithm is set to SHA-512:\n"
if authconfig --test | grep hashing | grep sha512 ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    authconfig --passalgo=sha512 --update
    cat /etc/passwd | awk -F: '($3 >= 1000 && $1 != "nfsnobody") {print $1}' | \xargs -n 1 chage -d 0
    printf "\e[32mPassword-hashing algorthim is set to SHA-512\e[0m\n"
fi

#11.2 Set Password Creation Requirement Parameters using pam_pwquality
printf "Checking the settings in the /etc/pam.d/system-auth file:\n"
if grep "pam_pwquality.so" "/etc/pam.d/system-auth" ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i -e '/#account\trequired\tpam_permit.so/a password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=' /etc/pam.d/system-auth
    printf "\e[32mPam_pwquality.so has been set\e[0m\n"
fi

printf "Checking minlen:\n"
if grep "^minlen[[:space:]]=[[:space:]]14" "/etc/security/pwquality.conf" ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i -e 's/.*minlen.*/minlen = 14/' /etc/security/pwquality.conf
    printf "\e[32mminlen has been set\e[0m\n"
fi

printf "Checking dcredit:\n"
if grep "^dcredit[[:space:]]=[[:space:]]-1" "/etc/security/pwquality.conf" ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i -e 's/.*dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
    printf "\e[32mdcredit has been set\e[0m\n"
fi

printf "Checking ucredit:\n"
if grep  "^ucredit[[:space:]]=[[:space:]]-1" "/etc/security/pwquality.conf" ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i -e 's/.*ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
    printf "\e[32mdcredit has been set\e[0m\n"
fi

printf "Checking ocredit:\n"
if grep  "^ocredit[[:space:]]=[[:space:]]-1" "/etc/security/pwquality.conf" ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i -e 's/.*ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
    printf "\e[32mocredit has been set\e[0m\n"
fi

printf "Checking lcredit:\n"
if grep  "^lcredit[[:space:]]=[[:space:]]-1" "/etc/security/pwquality.conf" ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i -e 's/.*lcredit.*/lcredit = -1/' /etc/security/pwquality.conf
    printf "\e[32mlcredit has been set\e[0m\n"
fi

#11.3  Set Lockout for Failed Password Attempts
printf "Checking for pam_faillock in /etc/pam.d/password-auth:\n"
if grep "pam_faillock" "/etc/pam.d/password-auth"; then  
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i /etc/pam.d/password-auth -e '/# User changes will be destroyed the next time authconfig is run./a auth\trequired\tpam_faillock.so preauth audit silent deny=5 unlock_time=900'
    sed -i /etc/pam.d/password-auth -e '/# User changes will be destroyed the next time authconfig is run./a auth\t[default=die]\tpam_faillock.so authfail audit deny=5'
    sed -i /etc/pam.d/password-auth -e '/# User changes will be destroyed the next time authconfig is run./a auth\tsufficient\tpam_faillock.so authsucc audit deny=5'
    sed -i /etc/pam.d/password-auth -e '/# User changes will be destroyed the next time authconfig is run./a account\trequired\tpam_faillock.so'
    printf "\e[32mpam_faillock added\e[0m\n"
fi
printf "Checking for pam_faillock in /etc/pam.d/system-auth:\n"
if grep "pam_faillock" "/etc/pam.d/system-auth"; then 
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i /etc/pam.d/system-auth -e '/# User changes will be destroyed the next time authconfig is run./a auth\trequired\tpam_faillock.so preauth audit silent deny=5 unlock_time=900'
    sed -i /etc/pam.d/system-auth -e '/# User changes will be destroyed the next time authconfig is run./a auth\t[default=die]\tpam_faillock.so authfail audit deny=5'
    sed -i /etc/pam.d/system-auth -e '/# User changes will be destroyed the next time authconfig is run./a auth\tsufficient\tpam_faillock.so authsucc audit deny=5'
    sed -i /etc/pam.d/system-auth -e' /# User changes will be destroyed the next time authconfig is run./a account\trequired\tpam_faillock.so'
    printf "\e[32mpam_faillock added\e[0m\n"
fi

#11.4 Limit Password Reuse
printf "Checking for Limit Password Reuse:\n"
if grep "remember" /etc/pam.d/system-auth; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    sed -i -e 's/password.*sufficient.*/password\tsufficient\tpam_unix.so sha512 shadow nullok remember=5 try_first_pass use_authtok/' /etc/pam.d/system-auth
    printf "\e[32mLimit password reuse has been set\e[0m\n"
fi

#11.5 Restrict root Login to System Console
printf "Checking if /etc/securetty is empty:\n"
if [ -s "/etc/securetty" ] ; then
    cp /dev/null /etc/securetty
    printf "\e[32m/etc/Removed entries not in a physically secure location\e[0m\n"
else
    printf "\e[32mNo remediation needed\e[0m\n"
fi

#11.6 Restrict Access to the su Command 
printf "Checking for restrict access to su command:\n"
if grep "^auth		required	pam_wheel.so use_uid" "/etc/pam.d/su"; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    echo -e "auth		required	pam_wheel.so use_uid" >> /etc/pam.d/su
    printf "\e[32mRestrict access has been set\e[0m\n"
fi

if cat /etc/group | grep "wheel" | grep "root"; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    usermod -aG wheel root
    printf "\e[32mUser added\e[0m\n"
fi
