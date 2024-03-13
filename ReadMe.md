#### <div> $Copyright: Copyright (c) 2024 Veritas Technologies LLC. All rights reserved VT25-0977-2658-84-51-3 $ </div>

# Scan Host Configuration
    Version: 1.0

## Description
- This utility installs the prerequisites required to run a malware scan on the scan-host(RHEL(8.x, 9.x)/Windows Server 2016 and above).
- Additionally, this utility can be used to install `NetBackup Malware Scanner` on the scan-host.
- The following would be installed by the utility on the scan-hosts
    1. Linux scan-hosts:  Non root user, libnsl, NetBackup_Malware_Scanner using non root user.
    2. Windows scan-hosts:  Non Administrator User, OpenSSH (9.4), NFS-Client, VC Runtime, Configure NetBackup_Malware_Scanner using non Administrator user.

## Prerequisites to be present on the ansible controller node(node on which this utility runs)
- RHEL Version = 8.x, 9.x
- ansible      = 2.16.2 and above
- python       = 3.11.x(required to run ansible 2.16.x)
- sshpass      = 1.x
- pywinrm      = 0.4.x
- requests     = 2.31.x (optional)

> **_NOTE:_** Run `install_ansible.sh` for installing above prerequisites on the ansible controller node.

## Steps to Configure scan-host
    1. Clone the repository from GitHub and move it to your Ansible Control Host:
		git clone https://github.com/scan-host-configuration-using-ansible.git
    2. By default, the host key checking would happen before configuring the scan-host.
        To add the fingerprint of the scan-host for <b>linux</b> hosts do the following:
            1. `ssh-keyscan -H {{HOST}} >> ~/.ssh/known_hosts` or Do SSH to the scan-host
    3. Provide the scan-host details in the `inventory/hosts.yml` file.
        `avira_package_path`: Local absolute path to the `NetBackup_Malware_Scanner` zip package.
        `ansible_user`: scan-host username, This user should be a user with root/Administrator privileges.
        `ansible_ssh_pass`: scan-host password
     > **_NOTE:_** If only the prerequisites are to be installed then set `install_avira` to `False` and you can remove the `avira_package_path` from the `inventory/hosts.yml`.
	4. Run the following command to run the playbook
        ansible-playbook playbook.yml


## Minimal hosts.yml file for Linux
```
all:
  vars:
    install_avira: True
    avira_package_path: /home/avira/NBAntiMalwareClient_2.4.zip
    scan_user: scanuser
    scan_group: scangroup
    scan_user_password: scanUserPassw0rd

linuxScanHosts:
  vars:
    add_entry_in_sshd_config: True
    configure_nfs_client: True
    configure_smb_client: True
  hosts:
    <ip1/hostname1>:
      ansible_user: <username>
      ansible_ssh_pass: <password>
```

## Minimal hosts.yml file for Windows
```
all:
  vars:
    install_avira: True
    avira_package_path: /home/avira/NBAntiMalwareClient_2.4.zip
    scan_user: scanuser
    scan_group: scangroup
    scan_user_password: scanUserPassw0rd

windowsScanHosts:
  vars:
    ansible_connection:  winrm
    ansible_winrm_port:  5985
    ansible_winrm_transport: ntlm
    ansible_winrm_server_cert_validation: validate

    configure_nfs: True
    install_vc_runtime: True
    override_openssh: False
    openssh_download_url: "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip"
    user_uid: 1000
  hosts:
    <ip1/hostname1>:
      ansible_user: <username>
      ansible_ssh_pass: <password>

```

## Terminologies
### Common For ALL Platforms (inventory/hosts.yml)
| Param Name          | Default Value (If Applicable)           | Descripton |
| --------------------|-----------------------------------------|---------|
| install_avira       | True                                    | Installs NetBackup_Malware_Scanner if set to True|
| avira_package_path  | /home/avira/NBAntiMalwareClient_2.4.zip | Local absolute path of the NetBackup_Malware_Scanner package|
| scan_user           | scanuser                                | The user will be created if it does not exist on the requested hosts and NetBackup_Malware_Scanner will be configured using the same user|
| scan_group          | scangroup                               | This group would be created on the requested host if it does not exist and `scan_user` will be added in the same group |
| scan_user_password  | scanUserPassw0rd                        | This would be the password for `scan_user`, if not provided then <b> password won't be set </b> |

### Linux
| Param Name              | Default Value (If Applicable) | Descripton                                                                                                 |
|-------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------|
| add_entry_in_sshd_config | True                         | The scan_user's entry would be added in the `sshd_config` file if the value is `True`                     |
| configure_nfs_client      |  True                          | Installs `nfs-utils` package using `yum` if the value is `True`                                           |
| configure_smb_client      |  True                        | Installs `cifs-utils` package using `yum` if the value is `True`                                           |                                                                 |

### Windows
| Param Name                        | Default Value (If Applicable) | Descripton                                                                                                       |
|-----------------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------------|
| configure_nfs                    |  True                        | Enables `NFS-Client` feature if the value is `True`                                                              |
| install_vc_runtime               | True                         | Installs `vc-runtime` if the value is `True`. Please note that this would take much long time                   |
| override_openssh                 | False                         | Overrides openssh configuration if the value is `True`                                                           |
| openssh_download_url             | [OPENSSH](https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip) | Default URL from which the OPENSSH package would be installed |
| user_uid                         | 1000                          | User uid to be used for mapping to the windows non administrator user                                           |
| ansible_connection               | winrm                         | Connection is used for connecting                                                                 |
| ansible_winrm_port               | 5985                          | Port used for connecting                                                                         |
| ansible_winrm_transport          | ntlm                          | Transport used for connecting                                                                       |
| ansible_winrm_server_cert_validation |   validate             | Default cert validation would happen before connecting, if set to `ignore` then the cert validation wouldn't happen |

### Configuration Terms (ansible.cfg)
| Param Name              | Default Value (If Applicable) | Descripton                                                                                                 |
|-------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------|
| host_key_checking       | True                          | If `False` host key checking won't happen
| inventory           | `inventory/hosts.yml`         | Default inventory path to be used.|
| log_path            | ansible_log.rb                | Default location for storing logs when the script runs.|
| always              | False                          | Logs the changed part when the task runs.|

### Additional Details
1. To Disable host key checking (Not recommended)
    1. For Linux scan-hosts: set `host_key_checking` to `False` in `ansible.cfg`.
    2. For Windows scan-hosts: set `ansible_winrm_server_cert_validation` to `ignore` in `inventory/hosts.yml`

### md5sum hashes (find  . -type f -exec md5sum {} \;)
```
1bf11b06343e4d3d66bb05ed5acd4971  ./ReadMe.md
9251ac846ec4ea87fe47e1dac99a5685  ./ansible.cfg
141f360f70c64718575700de1b8e3849  ./inventory/hosts.yml
4797bb6e70248f94ae09e38c7761fe1a  ./linux/avira/fresh_install_linux.yml
d0a97a451320adb71d239320054c12eb  ./linux/avira/main.yml
6a09207a37df9050b4202b91970ae2ba  ./linux/avira/update_install_linux.yml
a4c2ce33ef8a1cceffd59614e9d07d85  ./linux/main.yml
23c6b4a49705962ed6711cd007321cd0  ./linux/utils/create_non_root_user.yml
9004de32953b489679c6b3e9b65b06af  ./linux/utils/prerequisites_linux.yml
ac1ecaf874c302f277f91de519ea525e  ./playbook.yml
4459dffb1aa7a560e129038e243fcdbd  ./windows/avira/fresh_install_windows.yml
256044057026a789063fe230d0e85af8  ./windows/avira/main.yml
f36034ad665f1fc47fa108dd1c058a19  ./windows/avira/update_install_windows.yml
9cc7278c5e1a962a33e57648fb230df3  ./windows/main.yml
711ef637fb62f2e108c3f49cb0cb5cd0  ./windows/openssh/install_openssh.yml
5551062d841442f9a4603bfc594f276a  ./windows/utils/create_non_administrator_user.yml
c2f116ed5142b87e3dc8377582f0a183  ./windows/utils/prerequisites_windows.yml
7d04d6250e37b20a8b86e777b69a99a2  ./windows/utils/configure_nfs.yml
4b8e312539895b1325837d290b4aa69d  ./LICENSE
038b8c8d8a771b6ec2ab2fa47d013ec5  ./install_ansible.sh
```

## Legal Notice
Legal Notice
Copyright © 2024 Veritas Technologies LLC. All rights reserved.
Veritas, the Veritas Logo, and NetBackup are trademarks or registered trademarks of Veritas Technologies LLC or its affiliates in the U.S. and other countries. Other names may be trademarks of their respective owners.
This product may contain third-party software for which Veritas is required to provide attribution to the third party ("Third-party Programs"). Some of the Third-party Programs are available under open-source or free software licenses. The License Agreement accompanying the Software does not alter any rights or obligations you may have under those open-source or free software licenses. Refer to the Third-party Legal Notices document accompanying this Veritas product or available at: https://www.veritas.com/about/legal/license-agreements
The product described in this document is distributed under licenses restricting its use, copying, distribution, and decompilation/reverse engineering. No part of this document may be reproduced in any form by any means without prior written authorization of Veritas Technologies LLC and its licensors, if any.
THE DOCUMENTATION IS PROVIDED "AS IS" AND ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID. VERITAS TECHNOLOGIES LLC SHALL NOT BE LIABLE FOR INCIDENTAL OR CONSEQUENTIAL DAMAGES IN
CONNECTION WITH THE FURNISHING, PERFORMANCE, OR USE OF THIS
DOCUMENTATION. THE INFORMATION CONTAINED IN THIS DOCUMENTATION IS SUBJECT TO CHANGE WITHOUT NOTICE.

The Licensed Software and Documentation are deemed to be commercial computer software as defined in FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and DFARS 227.7202, et seq. "Commercial Computer Software and Commercial Computer Software Documentation," as applicable, and any successor regulations, whether delivered by Veritas as on-premises or hosted services. Any use, modification, reproduction release, performance, display or disclosure
of the Licensed Software and Documentation by the U.S. Government shall be solely by the terms of this Agreement.
Veritas Technologies LLC
2625 Augustine Drive
Santa Clara, CA 95054
http://www.veritas.com

## Third-Party Legal Notices
This Veritas product may contain third-party software for which Veritas is required to provide attribution ("Third Party Programs"). Some of the Third Party Programs are available under open-source or free software licenses. The License Agreement accompanying the Licensed Software does not alter any rights or obligations you may have under those open-source or free software licenses. This document or appendix contains proprietary notices for the Third Party Programs and the licenses for the Third Party Programs, where applicable.
The following copyright statements and licenses apply to various open-source software components (or portions thereof) that are distributed with the Licensed Software.