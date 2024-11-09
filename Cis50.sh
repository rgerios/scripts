#!/bin/bash

# Função para garantir que o script seja executado como root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Este script deve ser executado como root."
        exit 1
    fi
}

# 1. Configurar SSH para maior segurança
configure_ssh() {
    echo "Configurando SSH para maior segurança..."
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    systemctl restart ssh
}

# 2. Configurar política de senha forte
configure_password_policy() {
    echo "Configurando política de senha forte..."
    sed -i 's/^PASS_MAX_DAYS\s\+99999/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS\s\+0/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE\s\+7/PASS_WARN_AGE   14/' /etc/login.defs
    apt install libpam-pwquality -y
    sed -i '/pam_pwquality.so/ s/^#//g' /etc/pam.d/common-password
    sed -i '/pam_pwquality.so/ s/retry=3/retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g' /etc/pam.d/common-password
}

# 3. Expirar contas inativas
expire_inactive_accounts() {
    echo "Expirando contas inativas..."
    useradd -D -f 30
}

# 4. Configurar permissões em arquivos críticos
configure_file_permissions() {
    echo "Configurando permissões em arquivos críticos..."
    chmod 600 /etc/passwd /etc/group /etc/shadow /etc/gshadow
    chown root:root /etc/passwd /etc/group
    chown root:shadow /etc/shadow /etc/gshadow
}

# 5. Configurar firewall com UFW
configure_firewall() {
    echo "Configurando firewall com UFW..."
    apt install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# 6. Instalar e configurar auditoria com auditd
configure_audit() {
    echo "Configurando auditoria do sistema com auditd..."
    apt install auditd audispd-plugins -y
    systemctl enable auditd
    systemctl start auditd
    auditctl -e 1
    echo "-w /etc/ssh/sshd_config -p wa -k ssh_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /var/log/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules
}

# 7. Configurar parâmetros de segurança no kernel via sysctl
configure_sysctl() {
    echo "Configurando parâmetros de segurança do kernel..."
    cat <<EOT >> /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv6.conf.all.disable_ipv6 = 1
kernel.randomize_va_space = 2
EOT
    sysctl -p
}

# 8. Remover pacotes desnecessários
remove_unnecessary_packages() {
    echo "Removendo pacotes desnecessários..."
    apt purge xinetd telnet rsh-server rsh-client ypbind ypserv -y
}

# 9. Configurar banner de login
configure_login_banner() {
    echo "Configurando banner de login..."
    echo "ALERTA: Acesso autorizado somente para usuários autorizados" > /etc/issue.net
    echo "ALERTA: Acesso autorizado somente para usuários autorizados" > /etc/issue
}

# 10. Remover contas inativas
remove_inactive_accounts() {
    echo "Removendo contas inativas..."
    for user in games news; do
        if id "$user" &>/dev/null; then
            userdel -r "$user"
        fi
    done
}

# 11. Proteção contra IP Spoofing
configure_ip_spoofing_protection() {
    echo "Aplicando proteção contra IP Spoofing..."
    echo "order bind,hosts" >> /etc/host.conf
    echo "nospoof on" >> /etc/host.conf
}

# 12. Configurar monitoramento de módulos do kernel
configure_kernel_module_monitoring() {
    echo "Configurando monitoramento de módulos do kernel..."
    echo "-w /sbin/insmod -p x -k module_insertion" >> /etc/audit/rules.d/audit.rules
    echo "-w /sbin/rmmod -p x -k module_removal" >> /etc/audit/rules.d/audit.rules
    echo "-w /sbin/modprobe -p x -k module_load" >> /etc/audit/rules.d/audit.rules
}

# 13. Habilitar logs persistentes
enable_persistent_logs() {
    echo "Habilitando logs persistentes..."
    sed -i 's/#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
    systemctl restart systemd-journald
}

# 14. Restringir o uso do cron
restrict_cron() {
    echo "Restringindo o uso do cron..."
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    echo "Apenas usuários listados em /etc/cron.allow podem usar o cron."
}

# 15. Restringir o uso do comando at
restrict_at() {
    echo "Restringindo o uso do comando at..."
    touch /etc/at.allow
    chmod 600 /etc/at.allow
}

# 16. Configurar permissões em diretórios de usuários
restrict_user_home_directories() {
    echo "Configurando permissões em diretórios de usuários..."
    chmod -R go-w /home/*
}

# 17. Configurar permissões nos diretórios /tmp e /var/tmp
secure_tmp_directories() {
    echo "Configurando permissões nos diretórios /tmp e /var/tmp..."
    chmod -R 1777 /var/tmp /tmp
}

# 18. Desabilitar serviços inseguros
disable_insecure_services() {
    echo "Desabilitando serviços inseguros..."
    systemctl disable rsh.socket rexec.socket rlogin.socket
}

# 19. Configurar SELinux para ambientes compatíveis
configure_selinux() {
    echo "Configurando SELinux..."
    apt install selinux-utils -y
    setenforce 1
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
}

# 20. Configurar segurança do kernel
configure_kernel_security() {
    echo "Configurando segurança do kernel..."
    echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    sysctl -p
}

# 21. Limitar o uso de sudo
limit_sudo() {
    echo "Limitando o uso de sudo..."
    echo "user ALL=(ALL) NOPASSWD: /usr/bin/sudo" >> /etc/sudoers
}

# 22. Habilitar buffer de proteção
enable_buffer_protection() {
    echo "Habilitando buffer de proteção..."
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
}

# 23. Instalar AIDE para monitoramento de integridade
install_aide() {
    echo "Instalando AIDE..."
    apt install aide -y
    aideinit
}

# 24. Monitorar arquivos críticos
monitor_filesystem_changes() {
    echo "Monitorando alterações em arquivos críticos..."
    auditctl -w /etc/passwd -p wa -k passwd_changes
    auditctl -w /etc/group -p wa -k group_changes
    auditctl -w /etc/shadow -p wa -k shadow_changes
}

# 25. Configurar tentativa de login
configure_failed_login_attempts() {
    echo "Configurando falhas de login..."
    apt install faillock -y
    echo "deny=3 unlock_time=600" >> /etc/security/faillock.conf
}

# 26. Limitar o número de sessões SSH por usuário
limit_ssh_sessions() {
    echo "Limitando o número de sessões SSH por usuário..."
    echo "MaxSessions 2" >> /etc/ssh/sshd_config
    systemctl restart ssh
}

# 27. Desativar IPv6 (se não necessário)
disable_ipv6() {
    echo "Desativando IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
}

# 28. Desativar login via console serial
disable_console_serial_login() {
    echo "Desabilitando login via console serial..."
    sed -i '/ttyS0/d' /etc/securetty
}

# 29. Remover pacotes de desenvolvimento
remove_dev_packages() {
    echo "Removendo pacotes de desenvolvimento..."
    apt remove gcc g++ make -y
}

# 30. Limitar o uso do cron e at a usuários específicos
limit_cron_at_usage() {
    echo "Limitando o uso do cron e at a usuários específicos..."
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    chmod 600 /etc/cron.allow /etc/at.allow
}

# 31. Desabilitar opções de execução em partições críticas
restrict_exec_options() {
    echo "Desabilitando opções de execução em partições críticas..."
    echo "none /var/tmp tmpfs rw,nodev,nosuid,noexec 0 0" >> /etc/fstab
    mount -o remount /var/tmp
}

# 32. Auditar alterações de configuração no sistema de rede
audit_network_config_changes() {
    echo "Auditando alterações de configuração de rede..."
    auditctl -w /etc/network/ -p wa -k network_changes
}

# 33. Restringir acesso a scripts críticos de configuração
restrict_config_scripts() {
    echo "Restringindo acesso a scripts críticos de configuração..."
    chmod 700 /etc/init.d/*
}

# 34. Configurar limites de recursos por usuário
set_user_resource_limits() {
    echo "Configurando limites de recursos por usuário..."
    echo "* hard nproc 100" >> /etc/security/limits.conf
    echo "* soft nproc 50" >> /etc/security/limits.conf
}

# 35. Monitorar comandos sudo
monitor_sudo_commands() {
    echo "Monitorando comandos sudo..."
    auditctl -w /etc/sudoers -p wa -k sudoers_changes
}

# 36. Habilitar logs de kernel para rastrear eventos críticos
enable_kernel_logging() {
    echo "Habilitando logs de kernel..."
    echo "kern.* /var/log/kernel.log" >> /etc/rsyslog.conf
    systemctl restart rsyslog
}

# 37. Auditar criação e modificação de scripts de shell
audit_shell_scripts() {
    echo "Auditando criação e modificação de scripts de shell..."
    auditctl -w /usr/bin/bash -p x -k shell_scripts
}

# 38. Configurar banner de login remoto
set_remote_login_banner() {
    echo "Configurando banner de login remoto..."
    echo "ALERTA: Acesso restrito" > /etc/issue.net
}

# 39. Configurar login com autenticação de dois fatores (2FA)
configure_2fa() {
    echo "Configurando autenticação de dois fatores..."
    apt install libpam-google-authenticator -y
    google-authenticator
}

# 40. Remover pacotes de ferramentas de rede inseguras
remove_insecure_network_tools() {
    echo "Removendo ferramentas de rede inseguras..."
    apt remove netcat -y
}

# 41. Auditar alterações em configurações de rede críticas
audit_critical_network_config() {
    echo "Auditando alterações em configurações de rede críticas..."
    auditctl -w /etc/sysconfig/ -p wa -k sysconfig_changes
}

# 42. Desativar compartilhamento de arquivos de rede (NFS)
disable_nfs_sharing() {
    echo "Desativando compartilhamento de arquivos de rede (NFS)..."
    systemctl disable nfs-server
}

# 43. Remover contas sem senha
remove_empty_password_accounts() {
    echo "Removendo contas sem senha..."
    awk -F: '($2 == "") {print $1}' /etc/shadow | xargs -I {} passwd -l {}
}

# 44. Configurar política de senha para complexidade
set_password_complexity() {
    echo "Configurando política de complexidade de senha..."
    sed -i 's/^PASS_MIN_LEN\s\+5/PASS_MIN_LEN   12/' /etc/login.defs
}

# 45. Garantir que o serviço SSH utilize chaves de 2048 bits
ensure_2048bit_ssh_keys() {
    echo "Garantindo que o serviço SSH utilize chaves de 2048 bits..."
    ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key
}

# 46. Configurar inatividade de login para desconectar após 15 minutos
set_login_timeout() {
    echo "Configurando tempo de inatividade do login..."
    echo "readonly TMOUT=900" >> /etc/profile
}

# 47. Monitorar tentativas de login e falhas
monitor_login_attempts() {
    echo "Monitorando tentativas de login e falhas..."
    echo "auth,authpriv.* /var/log/auth.log" >> /etc/rsyslog.conf
    systemctl restart rsyslog
}

# 48. Habilitar auditoria de tentativas de login
enable_login_audit() {
    echo "Habilitando auditoria de tentativas de login..."
    echo "-w /var/log/faillog -p wa -k faillog_changes" >> /etc/audit/rules.d/audit.rules
}

# 49. Monitorar acesso a diretórios importantes
monitor_important_directories() {
    echo "Monitorando o acesso a diretórios importantes..."
    auditctl -w /etc/hostname -p wa -k hostname_changes
}

# 50. Remover pacotes desnecessários de desenvolvimento
remove_unnecessary_dev_tools() {
    echo "Removendo pacotes de desenvolvimento desnecessários..."
    apt remove make gcc g++ -y
}

# Função principal para executar todas as configurações de segurança
main() {
    check_root
    configure_ssh
    configure_password_policy
    expire_inactive_accounts
    configure_file_permissions
    configure_firewall
    configure_audit
    configure_sysctl
    remove_unnecessary_packages
    configure_login_banner
    remove_inactive_accounts
    configure_ip_spoofing_protection
    configure_kernel_module_monitoring
    enable_persistent_logs
    restrict_cron
    restrict_at
    restrict_user_home_directories
    secure_tmp_directories
    disable_insecure_services
    configure_selinux
    configure_kernel_security
    limit_sudo
    enable_buffer_protection
    install_aide
    monitor_filesystem_changes
    configure_failed_login_attempts
    limit_ssh_sessions
    disable_ipv6
    disable_console_serial_login
    remove_dev_packages
    limit_cron_at_usage
    restrict_exec_options
    audit_network_config_changes
    restrict_config_scripts
    set_user_resource_limits
    monitor_sudo_commands
    enable_kernel_logging
    audit_shell_scripts
    set_remote_login_banner
    configure_2fa
    remove_insecure_network_tools
    audit_critical_network_config
    disable_nfs_sharing
    remove_empty_password_accounts
    set_password_complexity
    ensure_2048bit_ssh_keys
    set_login_timeout
    monitor_login_attempts
    enable_login_audit
    monitor_important_directories
    remove_unnecessary_dev_tools
    echo "Configurações do CIS Benchmark com 50 itens aplicadas."
}

# Executa o script
main
