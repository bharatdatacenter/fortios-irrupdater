
# fortios-irrupdater

Update IRR Routing Filters on FortiOS 7+ Firewalls using SSH and Prefix Lists

#### Prerequisites

- FortiOS 7+ firewall(s) with SSH access enabled
- SSH credentials configured on your FortiOS device(s)
- Python 3 with [Paramiko SSH library](https://pypi.org/project/paramiko/) installed (`pip install paramiko`)
- BGPQ4 installed on the host where you plan to run these scripts (Debian/Ubuntu: `apt-get install bgpq4`)
- FortiOS firewall(s) running BGP

#### What is this for?

You want to run strict IRR filters on your customer/peer BGP sessions and have a Fortinet firewall. This collection of scripts wraps around BGPQ4 to generate prefix lists, then builds FortiOS prefix-list configurations that can be pushed to your firewall using SSH.

The python scripts generate FortiOS configuration in the format:

```
config router prefix-list
    edit "as35008-fcix"
        config rule
            edit 10
                set prefix 194.246.109.0/24
                unset ge
                unset le
                set action permit
            next
        end
    next
end
```

#### How do I configure it?

This collection has everything you need in one place. You'll need to install this into `/usr/share/fortios-irrupdater/` on your host;

- **`config/routers.conf`** - Specify the SSH username, password, and port required to connect to your FortiOS devices
  ```ini
  [SSH]
  username=admin
  port=22
  
  # Authentication method - uncomment ONE of the following:
  # Option 1: Password authentication
  password=your_password_here
  
  # Option 2: SSH key authentication (uncomment and specify path to private key)
  #key_file=/home/user/.ssh/id_rsa
  #key_passphrase=
  ```

- **`config/peers.conf`** - Specify the ASN and AS-SET of your peers (comma-separated). Update this every time you add a new peer that requires filters.
  ```
  35008,as-kerfuffle
  32934,as-facebook
  ```

- **`config/sessions.conf`** - Contains the combination of ASN, slug (e.g., IXP name or custom identifier), router hostname/IP, and address family (AFI). The AFI parameter is mandatory and must be either `ipv4` or `ipv6`. Update this every time you setup a new peer on an IX/PNI/New Router.
  ```
  35008,sfmix,firewall1.example.com,ipv4
  32934,sfmix,firewall1.example.com,ipv6
  16509,sfmix,firewall1.example.com,ipv4
  ```

#### Automate it?

Once you've got the configuration set, you can schedule these scripts in cron:

- **`buildprefixes.sh`** - Run this on a schedule. It uses bgpq4 to build the prefix lists and generates FortiOS prefix-list configurations. Runtime depends on the number of peers and prefixes. It pulls prefixes based on `config/peers.conf`.

- **`pushfilters.sh`** - Run this on a schedule or directly after buildprefixes.sh. This calls the Python code to push the prefix-lists to your FortiOS devices via SSH. It automatically loops through everything in `config/sessions.conf`.

Example crontab:
```bash
# Update prefix databases from IRR daily at 2 AM
0 2 * * * /usr/share/fortios-irrupdater/buildprefixes.sh

# Push updates to firewalls daily at 3 AM
0 3 * * * /usr/share/fortios-irrupdater/pushfilters.sh
```
#### How do I use it on the firewall?

You'll need to reference these prefix-lists in your BGP neighbor configuration. In FortiOS 7, you can apply prefix-lists in your route-map:

```
config router route-map
    edit "sfmix-facebook-in"
        config rule
            edit 10
                set match-ip-address "as32934-sfmix"
                set set-local-preference 120
                # Add other attributes as needed
            next
        end
    next
end

config router bgp
    config neighbor
        edit "192.0.2.1"
            set remote-as 32934
            set route-map-in "sfmix-facebook-in"
        next
    end
end
```

#### What else?

- Similar tools available for other platforms:
  - Juniper: [Edgenative/junos-irrupdater](https://github.com/edgenative/junos-irrupdater)
  - MikroTik: [Edgenative/mikrotik-irrupdater](https://github.com/edgenative/mikrotik-irrupdater)

#### Installation

```bash
# Install required packages
apt-get install bgpq4 python3 python3-pip

# Install Python dependencies
pip3 install paramiko

# Clone and install
git clone https://github.com/bharatdatacenter/fortios-irrupdater.git
sudo mkdir -p /usr/share/fortios-irrupdater
sudo cp -r fortios-irrupdater/* /usr/share/fortios-irrupdater/

# Configure your settings
sudo nano /usr/share/fortios-irrupdater/config/routers.conf
sudo nano /usr/share/fortios-irrupdater/config/peers.conf
sudo nano /usr/share/fortios-irrupdater/config/sessions.conf

# Make scripts executable
sudo chmod +x /usr/share/fortios-irrupdater/*.sh
```

#### Security Considerations

- **SSH key authentication is strongly recommended over passwords**
  - Generate SSH keys: `ssh-keygen -t ed25519 -C "fortios-irrupdater"`
  - Copy public key to FortiOS: `config system admin; edit <username>; set ssh-public-key1 "<your-public-key>"; end`
- Restrict SSH access to management networks only
- Consider using a dedicated BGP management VDOM on FortiOS
- Review and test prefix-list changes in a lab environment first
- Monitor configuration changes using FortiOS logging

#### Was this useful?

Let me know, I'd love to hear from you!


#### What else?

- Similar tools available for other platforms:
  - Juniper: [Edgenative/junos-irrupdater](https://github.com/edgenative/junos-irrupdater)
  - MikroTik: [Edgenative/mikrotik-irrupdater](https://github.com/edgenative/mikrotik-irrupdater)



