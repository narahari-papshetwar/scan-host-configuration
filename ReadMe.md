#
# $Copyright: Copyright (c) 2024 Veritas Technologies LLC. All rights reserved VT25-0977-2658-84-51-3 $
#

# Scan Host Configuration Using Ansible
    Version: 1.0

## Prerequistes to be present on the controller node
    - RHEL Version = 8.x, 9.x
    - ansible      = 2.16.x
    - python       = 3.11.x
    - sshpass      = 1.x
    - pywinrm      = 0.4.x
    - requests     = 2.31.x (optional)

## How to use this project
    1. Clone the repository from GitHub and move to your Ansible Control Host:
		git clone https://github.com/scan-host-configuration-using-ansible.git
	2. Run the following command to run the playbook
		#ansible-playbook playbook.yml -i inventory/hosts.yml
		Note: Provide hostnames/ip list in the `inventory/hosts.yml` file

## Following would be installed by the script on the scan hosts
| OS      | Installed Prerequisites                                      |
|---------|---------------------------------------------------|
| Linux   | Non root user, libnsl, Configure Avira using non root user             |
| Windows | Non Administrator User, OpenSSH (9.4), NFS-Client, VC Runtime, Configure Avira using non Administrator user   |


## Minimal hosts.yml file for Linux
```
all:
  vars:
    install_avira: True
    avira_package_path: <avira_pkg_path>
    scan_user: scanuser
    scan_group: scangroup
    scan_user_password: <non_root_user_password>

linuxScanHosts:
  vars:
    add_entry_in_sshd_config: True
    install_cifs_utils: False
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
    avira_package_path: <avira_pkg_path>
    scan_user: scanuser
    scan_group: scangroup
    scan_user_password: <non_root_user_password>

windowsScanHosts:
  vars:
    ansible_connection:  winrm
    ansible_winrm_port:  5985
    ansible_winrm_transport: ntlm
    ansible_winrm_server_cert_validation: validate

    configure_nfs: False
    install_vc_runtime: False
    override_openssh: False
    openssh_download_url: "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip"
    user_uid: 1000
  hosts:
    <ip1/hostname1>:
      ansible_user: <username>
      ansible_ssh_pass: <password>
```

## Terminologies
### Common For ALL Platforms
| Param Name          | Default Value (If Applicable) | Descripton |
| --------------------|-------------------------------|---------|
| ansible_user        |                               | This would be used for connecting to the specified host |
| ansible_ssh_pass    |                               | This would be the password of the ansible_user used for connecting to the specified host |
| install_avira       | True                          | Installs avira if set to True|
| avira_package_path  |                               | Local absolute path of the AVIRA package |
| scan_user           | scanuser                      | This would be the user which would be created if not exists on the requested hosts and avira would be configured using this user|
| scan_group          | scangroup                     | This would be created on the requested host if not exists and scan_user would be added in this group |
| scan_user_password  |                               | This would be set as the password for scan_user created on the requested host, if not provided then password won't be set |
| inventory           | `inventory/`                     | Default inventory path to be used |
| log_path            | ansible_log.rb                | used for storing logs when the script runs |
| always              | True                          | Logs the changed part when the task runs |


### Linux
| Param Name              | Default Value (If Applicable) | Descripton                                                                                                 |
|-------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------|
| add_entry_in_sshd_config | True                          | The scan_user's entry would be added in the `sshd_config` file if the value is `True`                     |
| install_cifs_utils      |  False                        | Installs `cifs-utils` package using `yum` if the value is `True`                                           |
| host_key_checking       | True                          | If `False` host key checking won't happen                                                                  |


### Windows
| Param Name                        | Default Value (If Applicable) | Descripton                                                                                                       |
|-----------------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------------|
| configure_nfs                    |  False                        | Enables `NFS-Client` feature if the value is `True`                                                              |
| install_vc_runtime               | False                         | Installs `vc-runtime` if the value is `True`. Please note that this would take much long time                   |
| override_openssh                 | False                         | Overrides openssh configuration if the value is `True`                                                           |
| openssh_download_url             | [Link](https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip) | Default URL from which the OPENSSH package would be installed |
| ansible_winrm_server_cert_validation | True                       | Does the cert validation, defaults to True                                                                      |
| user_uid                         | 1000                          | User uid to be used for mapping to the windows non administrator user                                           |
| ansible_connection               | winrm                         | Connection is used for connecting                                                                 |
| ansible_winrm_port               | 5985                          | Port used for connecting                                                                         |
| ansible_winrm_transport          | ntlm                          | Transport used for connecting                                                                       |
| ansible_winrm_server_cert_validation |   validate             | Default cert validation would happen before connecting, if set to `ignore` then the cert validation wouldn't happen |

### md5sum hashes (find  . -type f -exec md5sum {} \;)
```
09d8abd01c4de21fc5ec715af0ecaa1a  ./ansible.cfg
b9b14652f547359b326bb8a15f090bd4  ./inventory/hosts.yml
4797bb6e70248f94ae09e38c7761fe1a  ./linux/avira/fresh_install_linux.yml
d829c4554479b7221fe1046e92700fd0  ./linux/avira/main.yml
b5b592923448a3f7dbc53db58ac27fcb  ./linux/avira/update_install_linux.yml
a4c2ce33ef8a1cceffd59614e9d07d85  ./linux/main.yml
23c6b4a49705962ed6711cd007321cd0  ./linux/utils/create_non_root_user.yml
9e553493e46323fe26e8fcfa82e21677  ./linux/utils/prerequisites_linux.yml
105be3471f3bcf907e8b54deb2b876ed  ./playbook.yml
4459dffb1aa7a560e129038e243fcdbd  ./windows/avira/fresh_install_windows.yml
bfcc597b0f202e2ba17548d6e74f9777  ./windows/avira/main.yml
f36034ad665f1fc47fa108dd1c058a19  ./windows/avira/update_install_windows.yml
9cc7278c5e1a962a33e57648fb230df3  ./windows/main.yml
711ef637fb62f2e108c3f49cb0cb5cd0  ./windows/openssh/install_openssh.yml
5551062d841442f9a4603bfc594f276a  ./windows/utils/create_non_administrator_user.yml
fb50fa577ec1677eb65b0639009026f4  ./windows/utils/prerequisites_windows.yml
0dc8ac86bd8f38fd073a3917ac429652  ./windows/utils/configure_nfs.yml
```
