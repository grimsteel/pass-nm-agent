# pass-nm-agent

NetworkManager agent for [`pass`](https://www.passwordstore.org/)

Allows NetworkManager connection secrets to be stored inside gpg-encrypted files

## Supported network security schemes

* WPA-PSK 
  * Pre-shared key
* WPA-EAP
  * Client cert password
  * Private key password
  * Password
  
## Building

Prebuilt binaries are provided on each GH release

```shell
cargo build
```

Building may require `libdbus` to be installed
  
## Installation

1. Copy the binary to `/usr/local/bin/`
2. Copy the systemd service (in the `systemd` folder in this repo) to `/usr/local/lib/systemd/user/`
3. Enable and start the systemd service:
   ```shell
   systemctl --user enable --now pass-nm-agent
   ```
   (or just find some way to run `pass-nm-agent agent` at boot/login
   
Right now, the only ways to get a secret into `pass-nm-agent` is to import it from a plaintext secret stored in NetworkManager or to add it manually.

To move any secrets that exist in plaintext in NetworkManager for a certain network, execute:
```shell
pass-nm-agent add $NETWORK_NAME
```

