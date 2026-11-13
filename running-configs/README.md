# Running-configs

Archivos previstos:
- `R1-running-config.txt`
R1#show running-config
Building configuration...

Current configuration : 1433 bytes
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname R1
!
boot-start-marker
boot-end-marker
!
!
!
no aaa new-model
no ip icmp rate-limit unreachable
!
!
!
!
!
!
no ip domain lookup
ip domain name cis-lab.local
ip cef
no ipv6 cef
!
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
username adelacruz privilege 15 secret 5 $1$I.eO$LIQYUQN8J0F/BoeY4W4Tc1
!
!
!
!
!
ip tcp synwait-time 5
ip ssh time-out 60
ip ssh version 2
!
!
!
!
!
!
!
!
!
interface Ethernet0/0
 no ip address
 shutdown
 duplex auto
!
interface GigabitEthernet0/0
 ip address 10.23.13.130 255.255.255.252
 media-type gbic
 speed 1000
 duplex full
 negotiation auto
!
interface GigabitEthernet1/0
 ip address 10.23.13.1 255.255.255.128
 negotiation auto
!
interface GigabitEthernet2/0
 no ip address
 shutdown
 negotiation auto
!
interface GigabitEthernet3/0
 no ip address
 shutdown
 negotiation auto
!
interface GigabitEthernet4/0
 no ip address
 shutdown
 negotiation auto
!
ip forward-protocol nd
!
!
no ip http server
no ip http secure-server
ip route 0.0.0.0 0.0.0.0 10.23.13.129
!
!
!
!
control-plane
!
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 exec-timeout 5 0
 login local
 transport input ssh
line vty 5 15
 exec-timeout 5 0
 login local
 transport input ssh
!
!
end

- `SW1-running-config.txt`

Switch#show running-config
Building configuration...

Current configuration : 2960 bytes
!
! Last configuration change at 19:06:34 UTC Fri Nov 13 2026
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
service compress-config
!
hostname Switch
!
boot-start-marker
boot-end-marker
!
!
!
username adelacruz privilege 15 secret 5 $1$26sO$KIGxWmAxnVMaF2Mup108y0
no aaa new-model
!
!
!
!
!
!
!
!
ip domain-name cis-lab.local
ip cef
no ipv6 cef
!
!
!
spanning-tree mode pvst
spanning-tree extend system-id
!
!
!
!
!
!
!
!
!
!
!
!
!
!
!
interface GigabitEthernet0/0
 negotiation auto
!
interface GigabitEthernet0/1
 negotiation auto
!
interface GigabitEthernet0/2
 negotiation auto
!
interface GigabitEthernet0/3
 negotiation auto
!
interface Vlan1
 ip address 10.23.13.2 255.255.255.128
!
ip default-gateway 10.23.13.1
ip forward-protocol nd
!
ip http server
ip http secure-server
!
ip ssh time-out 60
ip ssh version 2
ip ssh server algorithm encryption aes128-ctr aes192-ctr aes256-ctr
ip ssh client algorithm encryption aes128-ctr aes192-ctr aes256-ctr
!
!
!
!
!
!
control-plane
!
banner exec ^C
IOSv - Cisco Systems Confidential -


Supplemental End User License Restrictions


This IOSv software is provided AS-IS without warranty of any kind. Under no circumstances may this software be used separate from the Cisco Modeling Labs Software that this software was provided with, or deployed or used as part of a production environment.


By using the software, you agree to abide by the terms and conditions of the Cisco End User License Agreement at http://www.cisco.com/go/eula. Unauthorized use or distribution of this software is expressly prohibited.
^C
banner incoming ^C
IOSv - Cisco Systems Confidential -


Supplemental End User License Restrictions


This IOSv software is provided AS-IS without warranty of any kind. Under no circumstances may this software be used separate from the Cisco Modeling Labs Software that this software was provided with, or deployed or used as part of a production environment.


By using the software, you agree to abide by the terms and conditions of the Cisco End User License Agreement at http://www.cisco.com/go/eula. Unauthorized use or distribution of this software is expressly prohibited.
^C
banner login ^C
IOSv - Cisco Systems Confidential -


Supplemental End User License Restrictions


This IOSv software is provided AS-IS without warranty of any kind. Under no circumstances may this software be used separate from the Cisco Modeling Labs Software that this software was provided with, or deployed or used as part of a production environment.


By using the software, you agree to abide by the terms and conditions of the Cisco End User License Agreement at http://www.cisco.com/go/eula. Unauthorized use or distribution of this software is expressly prohibited.
^C
!
line con 0
line aux 0
line vty 0 4
 exec-timeout 5 0
 login local
 transport input ssh
line vty 5 15
 exec-timeout 5 0
 login local
 transport input ssh
!
!
end

Switch#

  


