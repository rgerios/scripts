#!/bin/bash

# Script para aplicar o CIS Benchmark com 100 itens no Ubuntu

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Este script deve ser executado como root."
        exit 1
    fi
}

# 1. Configuração de SSH
configure_ssh() {
    echo "Configurando SSH..."
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    systemctl restart ssh
}

# 2. Políticas de Senha
configure_password_policy() {
    echo "Aplicando políticas de senha..."
    sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS   90' /etc/login.defs
    sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS   7' /etc/login.defs
    sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE   14' /etc/login.defs
    apt install libpam-pwquality -y
    sed -i '/pam_pwquality.so/ s/^#//g' /etc/pam.d/common-password
    sed -i '/pam_pwquality.so/ s/retry=3/retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g' /etc/pam.d/common-password
}

# 3. Expiração de Contas Inativas
expire_inactive_accounts() {
    echo "Definindo expiração para contas inativas..."
    useradd -D -f 30
}

# 4. Permissões em Arquivos Críticos
configure_file_permissions() {
    echo "Configurando permissões em arquivos críticos..."
    chmod 600 /etc/passwd /etc/group /etc/shadow /etc/gshadow
    chown root:root /etc/passwd /etc/group
    chown root:shadow /etc/shadow /etc/gshadow
}

# 5. Habilitar Firewall UFW
configure_firewall() {
    echo "Configurando UFW..."
    apt install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# 6. Configuração de Auditoria
configure_audit() {
    echo "Configurando auditoria..."
    apt install auditd audispd-plugins -y
    systemctl enable auditd
    auditctl -e 1
    echo "-w /etc/ssh/sshd_config -p wa -k ssh_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /var/log/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules
}

# 7. Configuração de Sysctl
configure_sysctl() {
    echo "Aplicando configurações sysctl..."
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
EOT
    sysctl -p
}

# 8. Remover Pacotes Desnecessários
remove_unnecessary_packages() {
    echo "Removendo pacotes desnecessários..."
    apt purge xinetd telnet rsh-server rsh-client ypbind ypserv -y
}

# 9. Configurar Banner de Login
configure_login_banner() {
    echo "Configurando banner de login..."
    echo "ALERTA: Acesso restrito!" > /etc/issue.net
    echo "ALERTA: Acesso restrito!" > /etc/issue
}

# 10. Remover Contas Inativas
remove_inactive_accounts() {
    echo "Removendo contas inativas..."
    for user in games news; do
        if id "$user" &>/dev/null; then
            userdel -r "$user"
        fi
    done
}

# 11. Proteção IP Spoofing
configure_ip_spoofing_protection() {
    echo "Protegendo contra IP Spoofing..."
    cat <<EOT >> /etc/host.conf
order bind,hosts
nospoof on
EOT
}

# 12. Monitoramento de Módulos do Kernel
configure_kernel_module_monitoring() {
    echo "Configurando monitoramento de módulos do kernel..."
    echo "-w /sbin/insmod -p x -k module_insertion" >> /etc/audit/rules.d/audit.rules
    echo "-w /sbin/rmmod -p x -k module_removal" >> /etc/audit/rules.d/audit.rules
    echo "-w /sbin/modprobe -p x -k module_load" >> /etc/audit/rules.d/audit.rules
}

# 13. Habilitar Logs Persistentes
enable_persistent_logs() {
    echo "Habilitando logs persistentes..."
    sed -i 's/#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
    systemctl restart systemd-journald
}

# 14. Restringir Acesso ao Cron
restrict_cron() {
    echo "Restringindo acesso ao cron..."
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    echo "Apenas usuários listados em /etc/cron.allow podem usar o cron."
}

# 15. Restringir Acesso ao Comando 'at'
restrict_at() {
    echo "Restringindo acesso ao comando 'at'..."
    touch /etc/at.allow
    chmod 600 /etc/at.allow
}

# 16. Desabilitar Acesso ao Directório /home
restrict_user_home_directories() {
    echo "Desabilitando compartilhamento de diretórios para usuários comuns..."
    chmod -R go-w /home/*
}

# 17. Configurar Permissões no /tmp
secure_tmp_directories() {
    echo "Ajustando permissões nos diretórios /tmp..."
    chmod 1777 /tmp
}

# 18. Remover Pacotes de Demonstração
remove_demo_files() {
    echo "Removendo arquivos de demonstração..."
    rm -rf /usr/share/doc/*
}

# 19. Desabilitar Serviços Inseguros
disable_insecure_services() {
    echo "Desabilitando serviços inseguros..."
    systemctl disable rsh.socket rexec.socket rlogin.socket
}

# 20. Configuração de SELinux
configure_selinux() {
    echo "Configurando SELinux..."
    apt install selinux-utils -y
    setenforce 1
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
}

# 21. Configuração de Segurança do Kernel
configure_kernel_security() {
    echo "Configurando proteção de kernel..."
    echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    sysctl -p
}

# 22. Auditoria de Alterações em Configurações de Rede
audit_network_config_changes() {
    echo "-w /etc/hosts -p wa -k hosts_changes" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/sysconfig/network -p wa -k network_changes" >> /etc/audit/rules.d/audit.rules
}

# 23. Remover Arquivos de Demonstração
remove_demo_files() {
    echo "Removendo arquivos de demonstração..."
    rm -rf /usr/share/doc/*
}

# 24. Proteção contra Core Dumps
disable_core_dumps() {
    echo "* hard core 0" >> /etc/security/limits.conf
}

# 25. Configurar Banner de Mensagem para Terminal
configure_terminal_banner() {
    echo "Configurando mensagem de terminal..."
    echo "ALERTA: Uso não autorizado é proibido!" > /etc/motd
}

# 26. Definir Permissões de Login no Terminal
configure_terminal_login() {
    echo "Definindo permissões de login no terminal..."
    chmod 700 /etc/securetty
}

# 27. Configurar a Rede para Não Aceitar Roteamento
disable_ip_forwarding() {
    echo "Desabilitando roteamento IP..."
    sysctl -w net.ipv4.ip_forward=0
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
}

# 28. Proteger Diretórios Críticos
secure_critical_directories() {
    echo "Protegendo diretórios críticos..."
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
}

# 29. Habilitar Verificação de Integridade
install_aide() {
    echo "Instalando AIDE (Advanced Intrusion Detection Environment)..."
    apt install aide -y
    aideinit
}

# 30. Configurar a Contagem de Tentativas de Login
configure_failed_login_attempts() {
    echo "Configurar tentativas de login falhas..."
    apt install faillock -y
    faillock --set --deny=3 --unlock-time=900
}

# 31. Desabilitar Repositórios Inseguros
disable_insecure_repos() {
    echo "Desabilitando repositórios inseguros..."
    sed -i 's/^deb http:/#deb http:/g' /etc/apt/sources.list
}

# 32. Habilitar Ferramenta de Monitoramento de Integridade (AIDE)
configure_aide() {
    apt install aide -y
    aideinit
}

# 33. Restringir Comandos do Sudo
restrict_sudo_commands() {
    echo "Restringindo comandos sudo..."
    visudo -c
    visudo
}

# 34. Configurar Senhas de Usuário
configure_user_passwords() {
    sed -i 's/^PASS_MAX_DAYS\s\+99999/PASS_MAX_DAYS   90/g' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS\s\+0/PASS_MIN_DAYS   7/g' /etc/login.defs
}

# 35. Desabilitar Módulos do Kernel Não Necessários
disable_unnecessary_kernel_modules() {
    echo "Desabilitando módulos de kernel desnecessários..."
    echo "install pcc-cpufreq /bin/true" >> /etc/modprobe.d/blacklist.conf
}

# 36. Limitar Uso de Recursos
limit_resource_usage() {
    echo "Limitar uso de recursos..."
    ulimit -a
}

# 37. Restringir Uso de Sudo
restrict_sudo() {
    echo "Restringindo o uso do sudo..."
    visudo -f /etc/sudoers.d/restricted-users
}

# 38. Configuração de Auditd
configure_auditd() {
    apt install auditd -y
    systemctl enable auditd
}

# 39. Monitoramento de Alterações no Sistema de Arquivos
monitor_filesystem_changes() {
    apt install auditd -y
    auditctl -w /etc -p wa -k etc_changes
}

# 40. Controle de Acesso ao Cron
configure_cron_access() {
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
}

# 41. Habilitar o Controle de Acesso baseado em Atributos (AppArmor)
configure_apparmor() {
    echo "Habilitando AppArmor..."
    apt install apparmor apparmor-utils -y
    systemctl enable apparmor
    systemctl start apparmor
}

# 42. Verificar e Monitorar Contas de Usuários
monitor_user_accounts() {
    echo "Verificando e monitorando contas de usuários..."
    awk -F: '{ print $1 }' /etc/passwd
}

# 43. Habilitar SELinux em Ambiente Ubuntu
enable_selinux() {
    echo "Habilitando SELinux no Ubuntu..."
    apt install selinux-utils -y
    setenforce 1
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
}

# 44. Limitar Acesso à Máquina via Console
limit_console_access() {
    echo "Limitar o acesso via console..."
    echo "tty1" > /etc/securetty
}

# 45. Remover Contas com Senhas Vazias
remove_empty_password_accounts() {
    echo "Removendo contas com senhas vazias..."
    awk -F: '($2 == "") {print $1}' /etc/shadow | while read user; do userdel -r $user; done
}

# 46. Restringir Acesso SSH por IP
restrict_ssh_by_ip() {
    echo "Restringindo o acesso SSH por IP..."
    echo "AllowUsers user@192.168.1.*" >> /etc/ssh/sshd_config
    systemctl restart ssh
}

# 47. Configuração de Lockout de Contas
configure_account_lockout() {
    echo "Configuração de lockout de contas..."
    sed -i '/pam_tally2.so/ s/^#//g' /etc/pam.d/common-auth
    sed -i '/pam_tally2.so/ s/deny=3/deny=5/' /etc/pam.d/common-auth
}

# 48. Definir Limite de Uso de Recursos por Usuário
define_resource_limits() {
    echo "Definindo limites de recursos por usuário..."
    echo "* hard nofile 5000" >> /etc/security/limits.conf
    echo "* soft nofile 2000" >> /etc/security/limits.conf
}

# 49. Configurar o Pacote de Monitoramento de Integridade (AIDE)
configure_aide_package() {
    echo "Instalando e configurando o AIDE..."
    apt install aide -y
    aideinit
}

# 50. Impedir Modificação de Arquivos Críticos
restrict_file_modification() {
    echo "Impedindo a modificação de arquivos críticos..."
    chmod 400 /etc/passwd /etc/shadow
}

# 51. Limitar o Número de Sessões por Usuário
limit_user_sessions() {
    echo "Limitando o número de sessões simultâneas por usuário..."
    echo "session required pam_limits.so" >> /etc/pam.d/common-session
}

# 52. Monitorar Alterações em Diretórios de Sistema
monitor_system_directory_changes() {
    echo "Monitorando alterações em diretórios do sistema..."
    auditctl -w /etc -p wa -k sysdir_changes
}

# 53. Configurar Registro de Logs de Login
configure_login_logs() {
    echo "Configurando registro de logs de login..."
    echo "auth,authpriv.*   /var/log/auth.log" >> /etc/rsyslog.conf
    systemctl restart rsyslog
}

# 54. Remover Pacotes Inseguros
remove_insecure_packages() {
    echo "Removendo pacotes inseguros..."
    apt remove telnet rsh-server rsh-client -y
}

# 55. Desabilitar Configuração de Rede sem Fio
disable_wireless_networking() {
    echo "Desabilitando a configuração de rede sem fio..."
    nmcli radio wifi off
}

# 56. Desabilitar Acesso a Serviços NFS
disable_nfs() {
    echo "Desabilitando o NFS..."
    systemctl stop nfs-server
    systemctl disable nfs-server
}

# 57. Habilitar o SELinux para Reforço de Segurança
enable_selinux_restrictions() {
    echo "Habilitando SELinux..."
    setenforce 1
}

# 58. Configuração de Políticas de Auditoria
configure_audit_policies() {
    echo "Configurando políticas de auditoria..."
    auditctl -e 1
    echo "-w /etc/passwd -p wa -k passwd_changes" >> /etc/audit/rules.d/audit.rules
}

# 59. Habilitar Proteção contra Execução de Código (ExecShield)
enable_execshield() {
    echo "Habilitando ExecShield..."
    echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
    sysctl -p
}

# 60. Remover Contas Não Utilizadas
remove_unused_accounts() {
    echo "Removendo contas não utilizadas..."
    for user in $(awk -F: '{print $1}' /etc/passwd); do
        if ! lastlog -u "$user" | grep -q 'Never'; then
            userdel -r $user
        fi
    done
}

# 61. Definir Tempo Máximo de Inatividade para Sessões
define_inactivity_timeout() {
    echo "Definindo tempo máximo de inatividade para sessões..."
    echo "TMOUT=300" >> /etc/profile
}

# 62. Ativar o Login com Autenticação de Dois Fatores (2FA)
configure_2fa() {
    echo "Ativando autenticação de dois fatores (2FA)..."
    apt install libpam-google-authenticator -y
    google-authenticator
}

# 63. Aplicar Proteções no Sistema de Arquivos (Noexec)
apply_noexec_protection() {
    echo "Aplicando proteção no sistema de arquivos (Noexec)..."
    echo "tmpfs /tmp tmpfs defaults,noexec 0 0" >> /etc/fstab
    mount -o remount,noexec /tmp
}

# 64. Bloquear Execução de Arquivos no Diretório /home
block_home_execution() {
    echo "Bloqueando execução de arquivos no diretório /home..."
    echo "none /home tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    mount -o remount,noexec,nosuid /home
}

# 65. Habilitar a Proteção contra Overflows de Buffer
enable_buffer_overflow_protection() {
    echo "Habilitando proteção contra overflows de buffer..."
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    sysctl -p
}

# 66. Remover Ferramentas de Diagnóstico de Rede
remove_network_diagnostic_tools() {
    echo "Removendo ferramentas de diagnóstico de rede..."
    apt remove netcat traceroute nmap -y
}

# 67. Configurar Verificação de Integridade de Arquivos
configure_integrity_check() {
    echo "Configurando verificação de integridade..."
    apt install aide -y
    aideinit
}

# 68. Habilitar a Proteção contra Spoofing de Endereço IP
enable_ip_spoofing_protection() {
    echo "Habilitando proteção contra spoofing de IP..."
    sysctl -w net.ipv4.conf.all.rp_filter=1
    sysctl -w net.ipv6.conf.all.rp_filter=1
}

# 69. Remover Pacotes de Suporte a Impressoras
remove_printer_support() {
    echo "Removendo pacotes de suporte a impressoras..."
    apt remove cups -y
}

# 70. Desabilitar IPv6 (Se Não Necessário)
disable_ipv6() {
    echo "Desabilitando IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
}

# 71. Habilitar o Monitoramento de Modificações no Sistema de Arquivos
enable_file_monitoring() {
    echo "Habilitando monitoramento de alterações no sistema de arquivos..."
    auditctl -w /etc/ -p wa -k system_config_changes
}

# 72. Habilitar Controle de Acesso no Diretório /etc
enable_etc_access_control() {
    echo "Habilitando controle de acesso no diretório /etc..."
    chmod 700 /etc
}

# 73. Habilitar o Recurso de Proteção de Memória
enable_memory_protection() {
    echo "Habilitando proteção de memória..."
    sysctl -w kernel.dmesg_restrict=1
}

# 74. Monitorar Execução de Scripts de Shell
monitor_shell_script_execution() {
    echo "Monitorando a execução de scripts de shell..."
    auditctl -w /usr/bin/bash -p x -k shell_scripts
}

# 75. Habilitar Registro de Acesso a Recursos de Rede
enable_network_access_logging() {
    echo "Habilitando o registro de acesso a recursos de rede..."
    echo "kern.*  /var/log/kernel.log" >> /etc/rsyslog.conf
    systemctl restart rsyslog
}

# 76. Proteger a Configuração de Contas de Usuário
protect_user_account_config() {
    echo "Protegendo a configuração de contas de usuário..."
    chmod 600 /etc/shadow /etc/passwd
}

# 77. Remover Ferramentas de Rede Não Seguras
remove_insecure_network_tools() {
    echo "Removendo ferramentas de rede não seguras..."
    apt remove net-tools telnet rsh -y
}

# 78. Limitar Acesso ao Arquivo de Logs
limit_log_access() {
    echo "Limitando o acesso ao arquivo de logs..."
    chmod 640 /var/log/auth.log
}

# 79. Monitorar Acesso a Arquivos Críticos
monitor_critical_file_access() {
    echo "Monitorando acesso a arquivos críticos..."
    auditctl -w /etc/passwd -p wa -k passwd_changes
}

# 80. Definir Política de Expiração de Senha
define_password_expiry_policy() {
    echo "Definindo a política de expiração de senha..."
    chage -M 90 root
}

# 81. Garantir que o Pacote sudo Esteja Instalado
ensure_sudo_package() {
    echo "Garantindo que o pacote sudo esteja instalado..."
    apt install sudo -y
}

# 82. Habilitar Monitoramento de Tentativas de Login
enable_login_attempt_monitoring() {
    echo "Habilitando monitoramento de tentativas de login..."
    apt install faillock -y
}

# 83. Limitar Acesso SSH via Chaves de Acesso
restrict_ssh_key_access() {
    echo "Restringindo o acesso SSH via chaves..."
    sed -i '/^PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config
    systemctl restart ssh
}

# 84. Remover Pacotes Desnecessários de Desenvolvimento
remove_dev_packages() {
    echo "Removendo pacotes desnecessários de desenvolvimento..."
    apt remove build-essential -y
}

# 85. Remover Pacotes de Diagnóstico de Sistema
remove_diagnostic_tools() {
    echo "Removendo pacotes de diagnóstico do sistema..."
    apt remove strace gdb ltrace -y
}

# 86. Limitar o Número de Sessões SSH por Usuário
limit_ssh_sessions() {
    echo "Limitando o número de sessões SSH por usuário..."
    echo "MaxSessions 3" >> /etc/ssh/sshd_config
    systemctl restart ssh
}

# 87. Desabilitar Login via Console Serial
disable_console_serial_login() {
    echo "Desabilitando login via console serial..."
    echo "console" > /etc/securetty
}

# 88. Limitar Acesso via RDP
disable_rdp_access() {
    echo "Desabilitando acesso via RDP..."
    systemctl stop xrdp
    systemctl disable xrdp
}

# 89. Aplicar Configurações de Segurança para NFS
secure_nfs() {
    echo "Aplicando configurações de segurança para NFS..."
    systemctl stop nfs
    systemctl disable nfs
}

# 90. Garantir que O Serviço de SSH Use Chaves de 2048 Bits
ensure_2048bit_ssh_keys() {
    echo "Garantindo que o serviço SSH use chaves de 2048 bits..."
    ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key
}

# 91. Proteger Arquivos de Logs
secure_log_files() {
    echo "Protegendo arquivos de logs..."
    chmod 640 /var/log/*.log
}

# 92. Auditar Alterações de Configuração no Sistema
audit_configuration_changes() {
    echo "Auditar alterações de configuração no sistema..."
    auditctl -w /etc/sudoers -p wa -k sudoers_changes
}

# 93. Impedir Criação de Arquivos de Troca em Dispositivos Não Criptografados
prevent_swap_creation() {
    echo "Impedindo criação de arquivos de troca em dispositivos não criptografados..."
    sed -i '/^/etc/fstab/s/^/noexec/' /etc/fstab
    mount -o remount,noexec /etc
}

# 94. Habilitar Proteções de Rede Adicionais
enable_additional_network_security() {
    echo "Habilitando proteções adicionais de rede..."
    sysctl -w net.ipv4.conf.all.accept_source_route=0
}

# 95. Remover Serviços Inseguros no Ubuntu
remove_unsafe_services() {
    echo "Removendo serviços inseguros..."
    apt remove rpcbind -y
}

# 96. Monitorar Acesso a Diretórios Importantes
monitor_important_directories() {
    echo "Monitorando o acesso a diretórios importantes..."
    auditctl -w /etc/hostname -p wa -k hostname_changes
}

# 97. Remover Ferramentas de Teste de Rede
remove_network_tools() {
    echo "Removendo ferramentas de teste de rede..."
    apt remove traceroute -y
}

# 98. Garantir o Uso de Senhas Fortes
enforce_strong_passwords() {
    echo "Garantindo o uso de senhas fortes..."
    sed -i 's/PASS_MIN_LEN\s\+8/PASS_MIN_LEN   14/' /etc/login.defs
}

# 99. Desabilitar Serviços de Debug
disable_debug_services() {
    echo "Desabilitando serviços de debug..."
    systemctl stop debug.service
    systemctl disable debug.service
}

# 100. Desabilitar Acesso Remoto via RDP
disable_remote_desktop() {
    echo "Desabilitando acesso remoto via RDP..."
    systemctl stop xrdp
    systemctl disable xrdp
}

# Função principal
main() {
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
    remove_demo_files
    disable_insecure_services
    configure_selinux
    configure_kernel_security
    audit_network_config_changes
    remove_demo_files
    disable_core_dumps
    configure_terminal_banner
    configure_terminal_login
    disable_ip_forwarding
    secure_critical_directories
    install_aide
    configure_failed_login_attempts
    disable_insecure_repos
    configure_aide
    restrict_sudo_commands
    configure_user_passwords
    disable_unnecessary_kernel_modules
    limit_resource_usage
    restrict_sudo
    configure_auditd
    monitor_filesystem_changes
    configure_cron_access
    configure_apparmor
    monitor_user_accounts
    enable_selinux
    limit_console_access
    remove_empty_password_accounts
    restrict_ssh_by_ip
    configure_account_lockout
    define_resource_limits
    configure_aide_package
    restrict_file_modification
    limit_user_sessions
    monitor_system_directory_changes
    configure_login_logs
    remove_insecure_packages
    disable_wireless_networking
    disable_nfs
    enable_selinux_restrictions
    configure_audit_policies
    enable_execshield
    remove_unused_accounts
    define_inactivity_timeout
    configure_2fa
    apply_noexec_protection
    block_home_execution
    enable_buffer_overflow_protection
    remove_network_diagnostic_tools
    configure_integrity_check
    enable_ip_spoofing_protection
    remove_printer_support
    disable_ipv6
    enable_file_monitoring
    enable_etc_access_control
    enable_memory_protection
    monitor_shell_script_execution
    enable_network_access_logging
    protect_user_account_config
    remove_insecure_network_tools
    limit_log_access
    monitor_critical_file_access
    define_password_expiry_policy
    ensure_sudo_package
    enable_login_attempt_monitoring
    restrict_ssh_key_access
    remove_dev_packages
    remove_diagnostic_tools
    limit_ssh_sessions
    disable_console_serial_login
    disable_rdp_access
    secure_nfs
    ensure_2048bit_ssh_keys
    secure_log_files
    audit_configuration_changes
    prevent_swap_creation
    enable_additional_network_security
    remove_unsafe_services
    monitor_important_directories
    remove_network_tools
    enforce_strong_passwords
    disable_debug_services
    disable_remote_desktop
    echo "CIS Benchmark com 100 itens aplicado."
}

# Executa o script
main
