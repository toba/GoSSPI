# GoSSPI
*GoSSPI* is a Go version of [NodeSSPI](https://github.com/abbr/nodesspi) allowing automatic login for users in Windows domains by reading the `WWW-Authenticate` header value and validating it with the *Security Support Provider Interface* in Windows.

It is possible this project will simply become a pull request to add an example to [alexbrainman/sspi](https://github.com/alexbrainman/sspi).

# Development

   1. Download [Windows Server 2008 VHD](https://www.microsoft.com/en-us/download/details.aspx?id=2227)
   1. Run self-extracting RAR
   1. Select `Actions\New\Virtual Machine` in the Hyper-V Manager
   1. Provide a name like "Domain Controller"
   1. Choose *Generation 1*
   1. Select `Default Switch` for the connection
      - Hardcode the host IPv4 address to 192.168.12.1 (or something)
      - Subnet 255.255.255.0
      - DNS and Gateway can remain blank
   1. Select the downloaded VHD as an "existing virtual hard disk"
   1. Launch machine and add Active Directory Services role
      - run `oobe` to show Configuration Tasks if needed
      - default credentials are `Administrator`/`pass@word1`
   1. Update IPv4 settings for virtual LAN
      - *IP address*: 192.168.12.10
      - *Subnet mask*:  255.255.255.0
      - *Default gateway*: 192.168.12.1 (or whatever matches host)
      - *DNS*: 192.168.12.1
   1. Run `dcpromo` ([note](http://stef.thewalter.net/how-to-create-active-directory-domain.html))
      - Choose Create a new domain in a new forest
      - Enter base domain
      - Choose the Forest functional level
      - Choose Windows Server 2008 R2
      - Ensure DNS server is selected
      - Choose `Yes` when warned about delegation
      - Accept default file paths
   1. Open Active Directory Users and Computers and add logins
      - Optionally reduce password security by running `gpmc.msc`
      - Example user: `ldap`/`password` as Toba Service


https://technet.microsoft.com/en-us/library/ee256063(v=ws.10).aspx
https://www.petri.com/test-connectivity-to-an-active-directory-domain-controller-from-pc
