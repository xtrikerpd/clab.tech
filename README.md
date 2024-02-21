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
