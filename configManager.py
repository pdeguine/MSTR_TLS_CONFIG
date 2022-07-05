import os
import socket
import subprocess
import winreg
import xml.etree.ElementTree
from xml.etree import ElementTree as eT
import json
import shutil
import datetime
import win32crypt
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class ConfigManager:
    def __init__(self, config, ssl_toggle):
        self.ssl_toggle = ssl_toggle
        self.config = config
        self.fqdn = socket.getfqdn().upper()

    def apply(self):
        for component, value in self.config.items():
            if self.config[component]["installed"]:
                print(f"\n>> Configuring {component} ...\n")
                if component == "Intelligence Server":
                    self.configure_intelligence_server(value)

                else:
                    self.configure_service(value)

    def restart(self):
        for component in self.config:
            if self.config[component]["service_name"]:
                if not (component == "Web" or component == "Library"):
                    print(f"\n>> Restarting {component} ...\n")
                    self.restart_service(self.config[component]["service_name"])
                    time.sleep(1)

    def configure_service(self, config_dict):
        for configuration_file, value in config_dict["parameters"].items():
            if self.backup_file(configuration_file):
                self.update_config_file(configuration_file, value)
            elif config_dict["service_name"] is None:
                self.update_config_file(configuration_file, value)

    def configure_intelligence_server(self, config_dict):
        print(f"[-] {'Enabling' if self.ssl_toggle else 'Disabling'} TLS on I-Server.")
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
            with winreg.OpenKeyEx(reg, config_dict["parameters"]["registry_config"]["registry_key"],
                                  0, winreg.KEY_ALL_ACCESS) as reg_key:
                print(f'    [+] Updating registry key {config_dict["parameters"]["registry_config"]["registry_key"]}')
                for key, value in config_dict["parameters"]["registry_config"]["registry_parameters"].items():
                    print(f"    [+] Setting {key} to {value}")
                    if key != "SSLPort":
                        winreg.SetValueEx(reg_key, key, 0, winreg.REG_SZ, value)
                    else:
                        winreg.SetValueEx(reg_key, key, 0, winreg.REG_DWORD, int(hex(value), 16))

        print(f"[-] {'Enabling' if self.ssl_toggle else 'Disabling'} TLS for REST API port")
        # Get iserver cert fingerprint
        with open(config_dict["parameters"]['rest_api_config']['CertificatePath'], 'rb') as cert:
            certificate = x509.load_pem_x509_certificate(cert.read(), default_backend())
            fingerprint = str(certificate.fingerprint(hashes.SHA1()).hex())

        i_server_pfx_path = config_dict["parameters"]['rest_api_config']['i_server_pfx']
        if self.ssl_toggle:
            os.system('certutil -f -p "' + config_dict["parameters"]["rest_api_config"][
            "i_server_pfx_pw"] + '" -importpfx "' + i_server_pfx_path + '"')
        os.system("netsh http delete ssl ipport=0.0.0.0:34962")
        if self.ssl_toggle:
            os.system('netsh http add sslcert ipport=0.0.0.0:34962 certstorename=My certhash=' + fingerprint +
                  ' appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" ')

    @staticmethod
    def install_ca_cert(root_certificate):
        # From https://stackoverflow.com/questions/61888404/how-do-i-install-a-certificate-
        # to-trusted-root-certificates-using-python
        CERT_STORE_PROV_SYSTEM = 0x0000000A
        CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
        CRYPT_STRING_BASE64HEADER = 0x00000000
        CERT_SYSTEM_STORE_CURRENT_USER_ACCOUNT = 1 << 16
        X509_ASN_ENCODING = 0x00000001
        CERT_STORE_ADD_REPLACE_EXISTING = 3
        CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001

        # replace with your certificate file path
        crt_path = root_certificate

        with open(crt_path, 'r') as f:
            cert_str = f.read()

        cert_byte = win32crypt.CryptStringToBinary(cert_str, CRYPT_STRING_BASE64HEADER)[0]
        store = win32crypt.CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, None,
                                         CERT_SYSTEM_STORE_CURRENT_USER_ACCOUNT | CERT_STORE_OPEN_EXISTING_FLAG, "ROOT")

        try:
            store.CertAddEncodedCertificateToStore(X509_ASN_ENCODING, cert_byte, CERT_STORE_ADD_REPLACE_EXISTING)
        except:
            print("WARNING: Installation of root certificate failed. To manually install the root certificate \n"
                  f"on this machine, install {root_certificate} with right-click > Install Certificate.")
        finally:
            store.CertCloseStore(CERT_CLOSE_STORE_FORCE_FLAG)

    @staticmethod
    def backup_file(filepath):
        try:
            shutil.copyfile(filepath,
                            filepath + '_sslconfig_backup_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        except IOError:
            print(f"ERROR: Unable to locate {filepath}")
            return False
        else:
            print(f'\n[+] Backing up {filepath}')
            return True

    @staticmethod
    def update_config_file(filepath, property_values):

        # If file path points to .properties or .conf file
        if filepath.endswith('.properties') or filepath.endswith('.conf'):
            if os.path.exists(filepath):
                with open(filepath, 'r+') as file:
                    lines = file.readlines()
                    for key, value in property_values.items():
                        if any(key in default_property for default_property in lines):
                            for i in range(len(lines)):
                                if lines[i].startswith(key):
                                    if value != "":
                                        print(f"[-] Setting {key} to {value}")
                                        lines[i] = f"{key}={value}\n"
                                    else:
                                        print(f"[-] Removing {key}")
                                        lines[i] = ""
                        else:
                            if value != "":
                                print(f"[-] Setting {key} to {value}")
                                lines.append(f"{key}={value}\n")
                            else:
                                print(f"[-] Removing {key}")
                        file.truncate(0)
                        file.seek(0)
                        for default_property in lines:
                            file.write(default_property)
            else:
                with open(filepath, 'w') as file:
                    for key, value in property_values.items():
                        if value != "":
                            print(f"[-] Setting {key} to {value}")
                            file.write(f"{key}={value}\n")
                        else:
                            print(f"[-] Removing {key}")

        # if file is an .xml file
        elif filepath.endswith('.xml'):
            file = eT.parse(filepath)
            root = file.getroot()
            for key, value in property_values.items():
                xml_tag = root.find(key)
                if xml_tag is not None:
                    for sub_key, sub_value in value.items():
                        print(f"[-] Setting {sub_key} to {sub_value}")
                        xml_tag.set(sub_key, sub_value)
                else:
                    if '/' in key:
                        path = key.rpartition('/')[0]
                        parent = root.find(path)
                        tag = key.rpartition('/')[2].rpartition('[')[0]
                    else:
                        parent = root
                        tag = key.rpartition('[')[0]
                    eT.SubElement(parent, tag, value)

            xml.etree.ElementTree.indent(root)
            file.write(filepath)

        # If file is a .json file
        elif filepath.endswith('.json'):
            with open(filepath, 'r+') as file:
                data = json.load(file)
                for key, value in property_values.items():
                    if value != "":
                        print(f"[-] Setting {key} to {value}")
                        data[key] = value
                    else:
                        print(f"[-] Removing {key}")
                        try:
                            del data[key]
                        except KeyError:
                            pass
                file.truncate(0)
                file.seek(0)
                file.write(json.dumps(data, indent=3))

    @staticmethod
    def restart_service(service_name):
        if os.system(f'sc query "{service_name}" | find "RUNNING" >nul') == 0:
            os.system(f'net stop "{service_name}" && net start "{service_name}"')
        else:
            os.system(f'net start "{service_name}"')

    @staticmethod
    def copy_truststore(source, destination):
        try:
            shutil.copyfile(source,
                            destination)
        except IOError:
            return False
        else:
            return True
