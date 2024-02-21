# IPsec-Cisco-Router
Let's connect Branch A and Branch B using IPsec VPN tunnel

![image](https://github.com/xtrikerpd/IPsec-Cisco-Router/assets/77069512/be37ad81-8f7d-405b-8c77-c5df4a511f94)

### Configuration of IKE Phase1 also called ISAKMP (Internet Security Association and Key Management Protocol) on R1
```
R1>enable
R1#configure terminal
R1(config)#crypto isakmp policy 1
R1(config-isakmp)#hash sha
R1(config-isakmp)#authentication pre-share
R1(config-isakmp)#group 5
R1(config-isakmp)#lifetime 86400
R1(config-isakmp)#encryption aes 256
```
### Verification of IKE Phase1 
```
R1#show crypto isakmp policy

Global IKE policy
Protection suite of priority 1
        encryption algorithm:   AES - Advanced Encryption Standard (256 bit keys).
        hash algorithm:         Secure Hash Standard
        authentication method:  Pre-Shared Key
        Diffie-Hellman group:   #5 (1536 bit)
        lifetime:               86400 seconds, no volume limit
```
### Configuration of pre-shared key used to authenticate against peer - R2
```
Router(config)#crypto isakmp key 0 cisco address 10.10.10.2
```
### Verification of key used against R2
```
Router#show crypto isakmp key
Keyring      Hostname/Address                            Preshared Key

default      10.10.10.2                                  cisco
```
Note that "0" in the above command, it indicates that preshared key will be stored in running configuration as plain-text, in order to use encryption use 6
Now it's time to define the "interesting" traffic that should be encrypted before it's sent, this can be defined by extended ACL
```
Router(config)#ip access-list extended ACL
Router(config-ext-nacl)#permit ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255
```
### Configuration of IKE Phase2 also called IPsec on R1
```
R1(config)# crypto ipsec transform-set TS esp-256-aes esp-sha-hmac
```
### Verification of transform-set IKE Phase2
```
Router#show crypto ipsec transform-set
Transform set TS: { esp-256-aes esp-sha-hmac  }
   will negotiate = { Tunnel,  },
```
So now we have prepared IKE Phase1, preshared key and defined a traffic that should be encrypted and IKE Phase2 now we need to put this together into crypto map.
### Cryptomap configuration on R1
```
Router(config)#crypto map cryptomap 1 ipsec-isakmp
% NOTE: This new crypto map will remain disabled until a peer
        and a valid access list have been configured.
Router(config-crypto-map)#set peer 10.10.10.2
Router(config-crypto-map)#set transform-set TS
Router(config-crypto-map)#match address ACL
```
Very last step on R1 is to apply previously configured cryptomap to interface, in this case fa0/0
### Applying cryptomap to interface
```
Router(config)#int fa0/0
Router(config-if)#crypto map cryptomap
*Mar  1 00:51:05.987: %CRYPTO-6-ISAKMP_ON_OFF: ISAKMP is ON
```
Let's now verify 
```
Router#show crypto ipsec sa

interface: FastEthernet0/0
    Crypto map tag: cryptomap, local addr 10.10.10.1

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.168.10.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (192.168.20.0/255.255.255.0/0/0)
   current_peer 10.10.10.2 port 500
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 0, #pkts encrypt: 0, #pkts digest: 0
    #pkts decaps: 0, #pkts decrypt: 0, #pkts verify: 0
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 0, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0

     local crypto endpt.: 10.10.10.1, remote crypto endpt.: 10.10.10.2
     path mtu 1500, ip mtu 1500, ip mtu idb FastEthernet0/0
     current outbound spi: 0x0(0)
```
Now its time to configure R2, it will be very similar, just few adjustments are needed like change the peer address and reversed entry in ACL
```
R1>enable
R1#configure terminal
R1(config)#crypto isakmp policy 1
R1(config-isakmp)#hash sha
R1(config-isakmp)#authentication pre-share
R1(config-isakmp)#group 5
R1(config-isakmp)#lifetime 86400
R1(config-isakmp)#encryption aes 256

Router(config)#crypto isakmp key 0 cisco address 10.10.10.1

Router(config)#ip access-list extended ACL
Router(config-ext-nacl)#permit ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255

R1(config)# crypto ipsec transform-set TS esp-256-aes esp-sha-hmac

Router(config)#crypto map cryptomap 1 ipsec-isakmp
% NOTE: This new crypto map will remain disabled until a peer
        and a valid access list have been configured.
Router(config-crypto-map)#set peer 10.10.10.1
Router(config-crypto-map)#set transform-set TS
Router(config-crypto-map)#match address ACL
```
Now let's ping from PC1 from PC2
![image](https://github.com/xtrikerpd/IPsec-Cisco-Router/assets/77069512/e154f023-56a2-477d-a33d-e431710b2847)

To verify if the packets were actually encrypted we can repeat the command show crypto ipsec sa on one of the routets and we will see that count of encypted/decrypted packets were increased
![image](https://github.com/xtrikerpd/IPsec-Cisco-Router/assets/77069512/5d77b9e6-50bc-4a66-8556-cecbad483489)
