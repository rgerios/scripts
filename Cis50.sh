#!/bin/bash

# Script avançado para aplicação das principais recomendações do CIS Benchmark no Ubuntu
# Este script aplica várias configurações de segurança recomendadas. Teste antes de usar em produção.

# Função para garantir que o script está sendo executado como root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Este script deve ser executado como root."
        exit 1
    fi
}

# 1. Configuração de Segurança SSH
configure_ssh() {
    echo "Configurando segurança do SSH..."
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    systemctl restart ssh
}

# 2. Políticas de Senhas
configure_password_policy() {
    echo "Aplicando políticas de senha..."
    sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS   90' /etc/login.defs
    sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS   7' /etc/login.defs
    sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE   14' /etc/login.defs
    apt install libpam-pwquality -y
    sed -i '/pam_pwquality.so/ s/^#//g' /etc/pam.d/common-password
    sed -i '/pam_pwquality.so/ s/retry=3/retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g' /etc/pam.d/common-password
}

# 3. Habilitar UFW Firewall
configure_firewall() {
    echo "Configurando UFW..."
    apt install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# 4. Configurações Sysctl para Segurança de Rede
configure_sysctl() {
    echo "Aplicando configurações sysctl..."
    cat <<EOT >> /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv6.conf.all.disable_ipv6 = 1
EOT
    sysctl -p
}

# 5. Logs e Auditoria
configure_audit() {
    echo "Configurando auditoria..."
    apt install auditd audispd-plugins -y
    systemctl enable auditd
    auditctl -e 1
    echo "-w /etc/ssh/sshd_config -p wa -k ssh_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /var/log/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/passwd -p wa -k user_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/group -p wa -k group_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/shadow -p wa -k shadow_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/gshadow -p wa -k gshadow_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/sudoers -p wa -k sudoers_changes" >> /etc/audit/rules.d/audit.rules
}

# 6. Remover Pacotes Desnecessários
remove_unnecessary_packages() {
    echo "Removendo pacotes não utilizados..."
    apt purge xinetd telnet rsh-server rsh-client ypbind ypserv -y
}

# 7. Proteção contra Core Dumps
disable_core_dumps() {
    echo "* hard core 0" >> /etc/security/limits.conf
}

# 8. Configurar Banner de Login
configure_login_banner() {
    echo "Configuração de banner de login..."
    echo "ALERTA: Acesso Autorizado Somente para Usuários Autorizados" > /etc/issue.net
    echo "ALERTA: Acesso Autorizado Somente para Usuários Autorizados" > /etc/issue
}

# 9. Proteção contra IP Spoofing
configure_ip_spoofing_protection() {
    echo "Proteção contra IP Spoofing..."
    cat <<EOT >> /etc/host.conf
order bind,hosts
nospoof on
EOT
}

# 10. Habilitar Logs Persistentes
enable_persistent_logs() {
    echo "Habilitando logs persistentes..."
    sed -i 's/#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
    systemctl restart systemd-journald
}

# 11. Restringir Uso do Cron
restrict_cron() {
    echo "Restringindo acesso ao cron..."
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    echo "Apenas usuários listados em /etc/cron.allow podem usar o cron."
}

# 12. Restringir Acesso ao comando 'at'
restrict_at() {
    echo "Restringindo acesso ao comando 'at'..."
    touch /etc/at.allow
    chmod 600 /etc/at.allow
}

# 13. Desativar Compartilhamento de Diretórios para Usuários Não-Privilegiados
restrict_user_home_directories() {
    echo "Desativando compartilhamento de diretórios para usuários comuns..."
    chmod -R go-w /home/*
}

# 14. Configuração de Permissões no /var/tmp e /tmp
secure_tmp_directories() {
    echo "Ajustando permissões nos diretórios /var/tmp e /tmp..."
    chmod -R 1777 /var/tmp /tmp
}

# 15. Revisão de Serviços Inseguros
disable_insecure_services() {
    echo "Desabilitando serviços inseguros..."
    systemctl disable rsh.socket rexec.socket rlogin.socket
}

# 16. Configurar SELinux (se aplicável)
configure_selinux() {
    echo "Configurando SELinux..."
    apt install selinux-utils -y
    setenforce 1
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
}

# 17. Configurar Segurança de Kernel
configure_kernel_security() {
    echo "Configurando proteção de kernel..."
    echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    sysctl -p
}

# 18. Configurar Proteções de Arquivos no /boot
protect_boot_directory() {
    echo "Aplicando proteção ao /boot..."
    chmod 600 /boot/grub/grub.cfg
}

# 19. Auditoria de Alterações em Configurações de Rede
audit_network_config_changes() {
    echo "-w /etc/hosts -p wa -k hosts_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/sysconfig/network -p wa -k network_changes" >> /etc/audit/rules.d/audit.rules
}

# 20. Proteção de Sysctl contra ICMP Redirect
configure_icmp_redirect_protection() {
    echo "Configurando proteção contra ICMP Redirect..."
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    sysctl -p
}

# 21. Restringir montagem de sistemas de arquivos desnecessários
restrict_filesystem_mounts() {
    echo "Restringindo montagem de sistemas de arquivos desnecessários..."
    echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
}

# 22. Configurar auditd para monitorar uso de comandos privilegiados
configure_privileged_command_auditing() {
    echo "Auditando uso de comandos privilegiados..."
    for file in $(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f); do
        echo "-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=unset -k privileged" >> /etc/audit/rules.d/audit.rules
    done
}

# 23. Configurar monitoramento de módulos do kernel
configure_kernel_module_monitoring() {
    echo "Configurando monitoramento de módulos do kernel..."
    echo "-w /sbin/insmod -p x -k module_insertion" >> /etc/audit/rules.d/audit.rules
    echo "-w /sbin/rmmod -p x -k module_removal" >> /etc/audit/rules.d/audit.rules
    echo "-w /sbin/modprobe -p x -k module_load" >> /etc/audit/rules.d/audit.rules
}

# 24. Configurar sysctl para reforçar a segurança de IPv6
disable_ipv6_redirects() {
    echo "Desabilitando redirects IPv6..."
    echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    sysctl -p
}

# 25. Restringir permissões em arquivos de senhas importantes
restrict_password_file_permissions() {
    echo "Restringindo permissões em arquivos de senhas..."
    chmod 600 /etc/passwd /etc/group /etc/shadow /etc/gshadow
    chown root:root /etc/passwd /etc/group
    chown root:shadow /etc/shadow /etc/gshadow
}

# 26. Remover contas de usuário desnecessárias
remove_unnecessary_accounts() {
    echo "Removendo contas de usuários desnecessárias..."
    for user in games news; do
        if id "$user" &>/dev/null; then
            userdel -r "$user"
        fi
    done
}

# 27. Configurar limites de uso de recursos
configure_resource_limits() {
    echo "Configurando limites de uso de recursos..."
    echo "* hard nofile 65535" >> /etc/security/limits.conf
    echo "* soft nofile 1024" >> /etc/security/limits.conf
}

# 28. Proteger /etc/fstab contra alterações
protect_fstab() {
    echo "Protegendo /etc/fstab..."
    chattr +i /etc/fstab
}

# 29. Habilitar registro detalhado no rsyslog
configure_rsyslog() {
    echo "Habilitando registro detalhado no rsyslog..."
    apt install rsyslog -y
    systemctl enable rsyslog
    systemctl start rsyslog
}

# 30. Configurar sysctl para evitar ataques de SYN flood
configure_syn_flood_protection() {
    echo "Configurando proteção contra ataques de SYN flood..."
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
    sysctl -p
}

# 31. Configurar limites de sessão para usuários
configure_session_limits() {
    echo "Configurando limites de sessão para usuários..."
    echo "session required pam_limits.so" >> /etc/pam.d/common-session
}

# 32. Desativar USB Storage
disable_usb_storage() {
    echo "Desativando armazenamento USB..."
    echo "install usb-storage /bin/true" >> /etc/modprobe.d/blacklist.conf
}

# 33. Desabilitar IPv6 se não for necessário
disable_ipv6() {
    echo "Desabilitando IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
}

# 34. Remover ferramentas de rede desnecessárias
remove_network_tools() {
    echo "Removendo ferramentas de rede desnecessárias..."
    apt purge netcat nmap -y
}

# 35. Configurar proteção contra spoofing de ARP
configure_arp_spoof_protection() {
    echo "Protegendo contra ARP spoofing..."
    echo "net.ipv4.conf.all.arp_announce = 2" >> /etc/sysctl.conf
    sysctl -p
}

# 36. Configurar timeout para sessão de shell
configure_shell_timeout() {
    echo "Configurando timeout para sessão de shell..."
    echo "TMOUT=600" >> /etc/profile
}

# 37. Configurar monitoramento de atividades do usuário
configure_user_activity_logging() {
    echo "Monitorando atividades do usuário..."
    echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
    echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
}

# 38. Restringir compilações de código para usuários não privilegiados
restrict_code_compilation() {
    echo "Restringindo compilações de código para usuários não privilegiados..."
    echo "hard core 0" >> /etc/security/limits.conf
}

# 39. Desabilitar serviços de impressão
disable_print_services() {
    echo "Desabilitando serviços de impressão..."
    systemctl disable cups
}

# 40. Configurar proteção contra ataques de buffer overflow
configure_buffer_overflow_protection() {
    echo "Protegendo contra ataques de buffer overflow..."
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    sysctl -p
}

# 41. Remover pacotes de desenvolvimento
remove_development_packages() {
    echo "Removendo pacotes de desenvolvimento..."
    apt purge build-essential gcc g++ make -y
}

# 42. Restringir acesso ao comando su
restrict_su_access() {
    echo "Restringindo acesso ao comando su..."
    apt install -y pam
    echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
}



# 43. Proteger a tabela ARP
    protect_arp_table() {
    echo "Protegendo a tabela ARP..."
    iptables -A INPUT -p arp -j DROP
}

# 44. Desativar serviços SNMP
disable_snmp_services() {
    echo "Desativando serviços SNMP..."
    systemctl disable snmpd
}

# 45. Configurar auditoria para alterações no cron
configure_cron_audit() {
    echo "Auditando alterações no cron..."
    echo "-w /etc/crontab -p wa -k cron_changes" >> /etc/audit/rules.d/audit.rules
}

# 46. Configurar proteção para IPv4 forwarding
disable_ipv4_forwarding() {
    echo "Desabilitando IPv4 forwarding..."
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
    sysctl -p
}

# 47. Configurar limites de logs
configure_log_limits() {
    echo "Configurando limites de logs..."
    echo "/var/log/*.log {
    rotate 12
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}" > /etc/logrotate.d/syslog
}

# 48. Configurar proteções para /proc
configure_proc_protections() {
    echo "Configurando proteções para /proc..."
    mount -o remount,hidepid=2 /proc
}

# 49. Monitorar tentativas de mudança de UID e GID
monitor_uid_gid_changes() {
    echo "Monitorando tentativas de mudança de UID e GID..."
    echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
}

# Executa as funções principais
main() {
    check_root
    configure_ssh
    configure_password_policy
    configure_firewall
    configure_sysctl
    configure_audit
    remove_unnecessary_packages
    disable_core_dumps
    configure_login_banner
    configure_ip_spoofing_protection
    enable_persistent_logs
    restrict_cron
    restrict_at
    restrict_user_home_directories
    secure_tmp_directories
    disable_insecure_services
    configure_selinux
    configure_kernel_security
    protect_boot_directory
    audit_network_config_changes
    configure_icmp_redirect_protection
    restrict_filesystem_mounts
    configure_privileged_command_auditing
    configure_kernel_module_monitoring
    disable_ipv6_redirects
    restrict_password_file_permissions
    remove_unnecessary_accounts
    configure_resource_limits
    protect_fstab
    configure_rsyslog
    configure_syn_flood_protection
    configure_session_limits
    disable_usb_storage
    disable_ipv6
    remove_network_tools
    configure_arp_spoof_protection
    configure_shell_timeout
    configure_user_activity_logging
    restrict_code_compilation
    disable_print_services
    configure_buffer_overflow_protection
    remove_development_packages
    restrict_su_access
        protect_arp_table
    disable_snmp_services
    configure_cron_audit
    disable_ipv4_forwarding
    configure_log_limits
    configure_proc_protections
    monitor_uid_gid_changes
    echo "Configurações CIS Benchmark aplicadas."
}

# Executa o script
main
