#!/bin/sh
# Firewall System
# Author - Paulo Cabral
# Mail - paulocdc@gmail.com
#
internet="eth1 "
redelocal="eth0"
 
echo "####################ATIVANDO IPTABLES#######################"
### Passo 1: Limpando as regras ###
iptables -F INPUT
iptables -F OUTPUT
iptables -F FORWARD
iptables -F POSTROUTING -t nat
iptables -F PREROUTING -t nat
iptables -F -t nat
echo "Limpando as regras ..................................[ OK ]"
 
# Definindo a Politica Default das Cadeias
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
echo "Politica Default das Cadeias ........................[ OK ]"
 
### Passo 2: Desabilitar o trafego IP entre as placas de rede ###
echo "0" > /proc/sys/net/ipv4/ip_forward
echo "Desabilitar o trafego IP entre as placas ............[ OK ]"
 
# Configurando a Protecao anti-spoofing
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
#for spoofing in /proc/sys/net/ipv4/conf/*/rp_filter; do
#        echo "1" > $spoofing
#done
echo "Protecao anti-spoofing ..............................[ OK ]"
 
# Impedimos que um atacante possa maliciosamente alterar alguma rota
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "Impedimos alterar alguma rota .......................[ OK ]"
 
# Utilizado em diversos ataques, isso possibilita que o atacante determine o "caminho" que seu
# pacote vai percorrer (roteadores) ate seu destino. Junto com spoof, isso se torna muito perigoso.
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "Impossibilita que o atacante determine o "caminho" ....[ OK ]"
 
# Protecao contra responses bogus
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
echo "Protecao contra responses bogus .....................[ OK ]"
 
# Protecao contra ataques de syn flood (inicio da conexao TCP). Tenta conter ataques de DoS.
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo "Protecao contra ataques de syn ......................[ OK ]"
 
### Passo 3: Carregando os modulos do iptables ###
# Ativa modulos
# -------------------------------------------------------
/sbin/modprobe iptable_nat
/sbin/modprobe ip_conntrack
/sbin/modprobe ip_conntrack_ftp
/sbin/modprobe ip_nat_ftp
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_REJECT
/sbin/modprobe ipt_MASQUERADE
echo "Carregando os modulos ...............................[ OK ]"
 
#################################################
# FIM DA Tabela FILTER
#################################################
 
# Proteção contra port scanners
iptables -N SCANNER
iptables -A SCANNER -m limit --limit 15/m -j LOG --log-prefix "FIREWALL: port scanner: "
iptables -A SCANNER -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -i  $internet -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL NONE -i  $internet -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL ALL -i  $internet -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN -i  $internet -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -i  $internet -j SCANNER
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -i  $internet -j SCANNER
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i  $internet -j SCANNER
echo "Scaner de Portas ....................................[ OK ]"
 
# Libera acesso externo a determinadas portas
 
##Algumas portas devem ser negadas.
iptables -A INPUT -p tcp --dport 1433 -j DROP
iptables -A INPUT -p tcp --dport 6670 -j DROP
iptables -A INPUT -p tcp --dport 6711 -j DROP
iptables -A INPUT -p tcp --dport 6712 -j DROP
iptables -A INPUT -p tcp --dport 6713 -j DROP
iptables -A INPUT -p tcp --dport 12345 -j DROP
iptables -A INPUT -p tcp --dport 12346 -j DROP
iptables -A INPUT -p tcp --dport 20034 -j DROP
iptables -A INPUT -p tcp --dport 31337 -j DROP
iptables -A INPUT -p tcp --dport 6000  -j DROP
echo "Negando portas invalidas ............................[ OK ]"
 
#Traceroutes caindo
 
iptables -A INPUT -p udp --dport 33434:33523 -j DROP
iptables -A INPUT -p tcp --dport 113 -j REJECT
iptables -A INPUT -p igmp -j REJECT
iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -A INPUT -p tcp --dport 443 -j REJECT
echo "Rejeitando lixo :....................................[ OK ]"
 
 
### Passo 4: Agora, vamos definir o que pode passar e o que nao ###
# Cadeia de Entrada
##ips que nao passam pelo proxy
##notebook paulo
iptables -A FORWARD -p tcp -s 192.168.1.90 -j ACCEPT
echo "Computadores que nao passam pelo proxy...............[ OK ]"
 
#ips q podem acessar msn
   #fulano
   iptables -A FORWARD -p tcp -s 192.168.1.15 --dport 1863 -j ACCEPT
   #paulo
   iptables -A FORWARD -p tcp -s 192.168.1.90 --dport 1863 -j ACCEPT
echo "Regras msn...........................................[ OK ]"
 
# porta para contabilidade
  #DCTF
  iptables -A FORWARD -p tcp --dport 3456 -j ACCEPT
  #DPI
  iptables -A FORWARD -p tcp --dport 24001 -j ACCEPT
  #ted
  iptables -A FORWARD -p tcp --dport 8017 -j ACCEPT
echo "Regras comtabilidade.................................[ OK ]"
 
#portas para departamento pessoal
 #sefip
 iptables -A FORWARD -p tcp  --dport 2004 -j ACCEPT
 iptables -A FORWARD -p tcp  --dport 2631 -j ACCEPT
 iptables -A FORWARD -p tcp  --dport 1494 -j ACCEPT
 iptables -A FORWARD -p tcp  --dport 5017 -j ACCEPT
 iptables -A FORWARD -p tcp -s 192.168.1.49 --dport 9090 -j ACCEPT
echo "Regras DP ...........................................[ OK ]"
 
#cadastro
 iptables -A FORWARD -p tcp --dport 25777 -j ACCEPT
 iptables -A FORWARD -p tcp --dport 5432 -j ACCEPT
 
 #datasiga
  iptables -A FORWARD -p tcp --dport 20650 -j ACCEPT
  iptables -A FORWARD -p tcp --dport 10650 -j ACCEPT
echo "Regras Cadastro .....................................[ OK ]"
 
#vnc
  iptables -A FORWARD -p tcp --dport 5700 -j ACCEPT
  iptables -A INPUT -p tcp --dport 5700 -j ACCEPT
echo "Regras Vnc .... .....................................[ OK ]"
  
#terminal server
  iptables -A INPUT -p tcp --dport 3389 -j ACCEPT
 iptables -A FORWARD -p tcp --dport 3389 -j ACCEPT
echo "Regras terminal serv ................................[ OK ]"
 
######
 
######
# PORTA 3128 - ACEITA PARA A REDE LOCAL
iptables -A FORWARD -i  $redelocal -p tcp --dport 3128 -j ACCEPT
 
# Redireciona porta 80 para 3128 (squid)
#iptables -t nat -A PREROUTING -i  $redelocal -p tcp --dport 80 -j REDIRECT --to-port 3128
 
 
# PORTA 53 - ACEITA PARA A REDE LOCAL
 
iptables -A FORWARD -i  $redelocal -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -i  $redelocal -p udp --dport 53 -j ACCEPT
 
# PORTA 110 - ACEITA PARA A REDE LOCAL
iptables -A FORWARD -i  $redelocal -p tcp --dport 110 -j ACCEPT
iptables -A FORWARD -i  $redelocal -p udp --dport 110 -j ACCEPT
 
# PORTA 25 - ACEITA PARA A REDE LOCAL
iptables -A FORWARD -i  $redelocal -p tcp --dport 25 -j ACCEPT
 
# identd
iptables -A INPUT -p tcp --dport 113 -j ACCEPT
iptables -A INPUT -p udp --dport 113 -j ACCEPT
 
# https
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 443 -j ACCEPT
iptables -A FORWARD -i  $redelocal -p tcp --dport 443 -j ACCEPT
 
# PORTA 20 - ACEITA PARA A REDE LOCAL
iptables -A FORWARD -p tcp --dport 20 -j ACCEPT
iptables -A INPUT -p tcp --syn --dport 22 -m recent --name sshattack --set
iptables -A INPUT -p tcp --dport 22 --syn -m recent --name sshattack --rcheck --seconds 60 --hitcount 3 -j LOG --log-prefix 'SSH REJECT: '
iptables -A INPUT -p tcp --dport 22 --syn -m recent --name sshattack --rcheck --seconds 60 --hitcount 3 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -p tcp --syn --dport 22 -m recent --name sshattack --set
iptables -A FORWARD -p tcp --dport 22 --syn -m recent --name sshattack --rcheck --seconds 60 --hitcount 3 -j LOG --log-prefix 'SSH REJECT: '
iptables -A FORWARD -p tcp --dport 22 --syn -m recent --name sshattack --rcheck --seconds 60 --hitcount 3 -j REJECT --reject-with tcp-reset
 
# PORTA 21 - ACEITA PARA A REDE LOCAL
#iptables -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -A FORWARD -p tcp --dport 21 -j ACCEPT
 
# PORTA 22 - ACEITA PARA A REDE INTERNET
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -p tcp --dport 22 -j ACCEPT
 
 
###vpn criar estas regras para todas vpns
iptables -A INPUT -p tcp --dport 5001 -j ACCEPT
iptables -A FORWARD -p tcp --dport 5001 -j ACCEPT
iptables -A INPUT -p udp --dport 5001 -j ACCEPT
iptables -A FORWARD -p udp --dport 5001 -j ACCEPT
iptables -I FORWARD -i tun0 -j ACCEPT
iptables -I FORWARD -o tun0 -j ACCEPT
#########################
 
 
#bloqueia  qualquer tentativa de nova conexao de fora para esta maquina
#iptables -A INPUT -i  $internet -m state --state ! ESTABLISHED,RELATED -j LOG --log-level 6 --log-prefix "FIREWALL entrada "
iptables -A INPUT -i  $internet -m state --state ! ESTABLISHED,RELATED -j DROP
 
#no iptables, temos de dizer quais sockets sao validos em uma conexao
   iptables -A INPUT -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
   echo "Cadeia de Entrada ...................................[ OK ]"
 
################################
# Cadeia de Reenvio (FORWARD).
# Primeiro, ativar o mascaramento (nat).
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -o  $internet -j MASQUERADE
echo "Ativando o mascaramento .............................[ OK ]"
 
# Agora dizemos quem e o que podem acessar externamente
# O controle do acesso a rede externa e feito na cadeia "FORWARD"
iptables -A FORWARD -i  $internet -j ACCEPT
iptables -A FORWARD -o  $internet -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "Ativando o acesso ftp.. .............................[ OK ]"
 
###################
###BLOQUEANDO TODAS AS SAIDAS E PORTAS
 
iptables -A INPUT -p all -j DROP
iptables -A FORWARD -p all -j DROP  
 
echo "Rejeitando saida e entrada ..........................[ OK ]"
########################
 
# No iptables, temos de dizer quais sockets sao validos em uma conexao
 
iptables -A FORWARD -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
echo "Quais sockets sao validos ...........................[ OK ]"
 
#################################################
# Tabela FILTER
#################################################
 
# Proteção contra tronjans
# -------------------------------------------------------
iptables -A INPUT -p TCP -i  $internet --dport 666 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 4000 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 6000 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 6006 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 16660 -j DROP
 
# Proteção contra trinoo
# -------------------------------------------------------
iptables -A INPUT -p TCP -i  $internet --dport 27444 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 27665 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 31335 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 34555 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 35555 -j DROP
echo "Proteção contra trinoo ............................. [ OK ]"
 
# Protecao contra acesso externo squid
iptables -A INPUT -p TCP -i  $internet --dport 3128 -j DROP
iptables -A INPUT -p TCP -i  $internet --dport 8080 -j DROP
echo "Proteção contra squid externo....................... [ OK ]"
 
# Protecao contra telnet
iptables -A INPUT -p TCP -i  $internet --dport telnet -j DROP
echo "Proteção contra telnet       ....................... [ OK ]"
 
# Dropa pacotes TCP indesejaveis
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP
 
# Dropa pacotes mal formados
iptables -A INPUT -i  $internet -m unclean -j DROP
 
# Protecao contra worms
iptables -A FORWARD -p tcp --dport 135 -i  $internet -j REJECT
 
# Protecaocontra syn-flood
iptables -A FORWARD -p tcp --syn -m limit --limit 2/s -j ACCEPT
 
# Protecao contra ping da morte
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
#Allow ALL other forwarding going out
iptables -A FORWARD -o  $internet -i  $redelocal -j ACCEPT
echo "Caregado tabela filter ............................ [ OK ]"
# Finalmente: Habilitando o trafego IP, entre as Interfaces de rede
echo "1" > /proc/sys/net/ipv4/ip_forward
#echo "Habilitar o trafego IP entre as placas: .............[ OK ]"
 
echo "##################FIM DE REGRAS IPTABLES####################"
exit 0
