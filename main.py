import os
import ctypes
import socket
import sys
import subprocess
import os
import socket
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

PATH_EXE = os.path.dirname(sys.executable)
KEYSTORE_PW = 'm$tr!23'
KEYSTORE = 'TSkeystore.pfx'
CERTIFICATE = "iserver_cert.pem"
KEY = "iserver_key.pem"
# AES encrypted password, retrieved from the registry of a SSL enabled I-Server with password m$tr!23
KEY_PASSWORD = "000000014ff340a763b7ac26c04176a958867b16069e1c44753d49" \
               "5452d04e9ac9373ea6c5cc2e25c70cd0babe01729dd7cd80fa9ffb"
TRUSTSTORE = "trusted.jks"
TRUSTSTORE_PW = "m$tr!23"
TRUSTSTORE_PEM = "MSTRTSRootCA.pem"
ROOT_CERTIFICATE = "MSTRTSRootCA.crt"
I_SERVER_PFX = "iserver.pfx"
SSL_PORT = 39321
NO_SSL_PORT = 34952
FQDN = socket.getfqdn().upper()
VERSION = "1.1"
REST_PORT = 34962
ssl_toggle = False
ssl_artifact_path = {
    KEYSTORE: f"{PATH_EXE}\\{KEYSTORE}",
    CERTIFICATE: f"{PATH_EXE}\\{CERTIFICATE}",
    KEY: f"{PATH_EXE}\\{KEY}",
    TRUSTSTORE: f"{PATH_EXE}\\{TRUSTSTORE}",
    ROOT_CERTIFICATE: f"{PATH_EXE}\\{ROOT_CERTIFICATE}",
    TRUSTSTORE_PEM: f"{PATH_EXE}\\{TRUSTSTORE_PEM}",
    I_SERVER_PFX: f"{PATH_EXE}\\{I_SERVER_PFX}"
}

component_path_service_names = {
    "Intelligence Server": {
        "service_name": "MicroStrategy Intelligence Server",
        "path": "C:\\Program Files (x86)\\MicroStrategy\\Intelligence Server",
        "installed": False
    },
    "Tomcat": {
        "service_name": "tomcat9",
        "path": "",
        "installed": False
    },
    "Web": {
        "service_name": None,
        "path": "",
        "installed": False
    },
    "Library": {
        "service_name": None,
        "path": "",
        "installed": False
    },
    "Collaboration Server": {
        "service_name": "MSTR_collaboration",
        "path": "C:\\Program Files (x86)\\MicroStrategy\\Collaboration Server",
        "installed": False
    },
    "Modeling Service": {
        "service_name": "MSTR_ModelingService",
        "path": "C:\\Program Files (x86)\\MicroStrategy\\ModelingService",
        "installed": False
    }
}


def check_ssl_artifacts_exist(artifact_dict):
    # Verify all ssl artifacts are available on their physical location
    for ssl_artifact, path in artifact_dict.items():
        if not os.path.exists(path):
            print(
                f"WARNING: {ssl_artifact} not found. Make sure it exists in same directory as the executable.\n\n")
            input("Press ENTER to exit.")
            exit()
        else:
            return True


def build_config(ssl_enabled, installed_components):
    new_config = {
        "Intelligence Server": {
            "installed": installed_components["Intelligence Server"]["installed"],
            "path": installed_components["Intelligence Server"]["path"],
            "service_name": installed_components["Intelligence Server"]["service_name"],
            "parameters": {
                "registry_config": {
                    "registry_key": r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                    "registry_parameters": {
                        "CertificatePath": ssl_artifact_path[CERTIFICATE],
                        "KeyPath": ssl_artifact_path[KEY],
                        "CertificateKeyPassword": KEY_PASSWORD,
                        "SSLPort": SSL_PORT if ssl_enabled else 4294967295
                    }
                },
                "rest_api_config": {
                    "i_server_pfx": ssl_artifact_path[I_SERVER_PFX].replace('/', '\\') if ssl_enabled else "",
                    "i_server_pfx_pw": KEYSTORE_PW,
                    "CertificatePath": ssl_artifact_path[CERTIFICATE],
                    "REST_PORT": REST_PORT
                }
            }

        },
        "Tomcat": {
            "installed": installed_components["Tomcat"]["installed"],
            "path": installed_components["Tomcat"]["path"],
            "service_name": installed_components["Tomcat"]["service_name"],
            "parameters": {
                installed_components["Tomcat"]["path"] + "\\conf\\server.xml": {
                    'Service/Connector[@port="8443"]': {
                        'keystoreFile': ssl_artifact_path[KEYSTORE].replace('/', '\\') if ssl_enabled else "",
                        'keystorePass': KEYSTORE_PW if ssl_enabled else ""
                    }
                }
            }
        },
        "Web": {
            "installed": installed_components["Web"]["installed"],
            "path": installed_components["Web"]["path"],
            "service_name": installed_components["Web"]["service_name"],
            "parameters": {
                installed_components["Web"]["path"] + "\\WEB-INF\\xml\\adminServers.xml": {
                    f'server[@name="{FQDN}"]': {
                        "name": FQDN,
                        "conn": "false"
                    }

                },
                installed_components["Web"]["path"] + "\\WEB-INF\\microstrategy.xml": {
                    'global/parameter[@name="sslTruststore"]': {
                        "value": str("WEB-INF" + '/' + TRUSTSTORE)
                    },
                    'global/parameter[@name="sslTruststorePwd"]': {
                        "value": TRUSTSTORE_PW
                    }
                },
                installed_components["Web"]["path"] + "\\WEB-INF\\xml\\sys_defaults.properties": {
                    "useEncryption": "2" if ssl_enabled else "0"
                },
                installed_components["Web"]["path"] + f"\\WEB-INF\\xml\\sys_defaults_{FQDN}.properties": {
                    "connectmode": "auto",
                    "port": SSL_PORT if ssl_enabled else NO_SSL_PORT
                }
            }
        },
        "Library": {
            "installed": installed_components["Library"]["installed"],
            "path": installed_components["Library"]["path"],
            "service_name": installed_components["Library"]["service_name"],
            "parameters": {
                installed_components["Library"]["path"] + "\\WEB-INF\\classes\\config\\configOverride.properties":
                    {
                        "trustStore.path": "file:" + ssl_artifact_path[TRUSTSTORE].replace('\\',
                                                                                           '/') if ssl_enabled else "",
                        "trustStore.passphrase": TRUSTSTORE_PW if ssl_enabled else "",
                        "iserver.default.hostname": FQDN,
                        "iserver.default.port": SSL_PORT if ssl_enabled else NO_SSL_PORT,
                        "iserver.tlsEnabled": "true" if ssl_enabled else "false"
                    }
            }
        },
        "Collaboration Server": {
            "installed": installed_components["Collaboration Server"]["installed"],
            "path": installed_components["Collaboration Server"]["path"],
            "service_name": installed_components["Collaboration Server"]["service_name"],
            "parameters": {
                installed_components["Collaboration Server"]["path"] + "\\config.json": {
                    "enableTls": "true" if ssl_enabled else "",
                    "keystoreFile": ssl_artifact_path[KEYSTORE].replace('\\', '/') if ssl_enabled else "",
                    "passphrase": KEYSTORE_PW if ssl_enabled else "",
                    "trustedCerts": [ssl_artifact_path[TRUSTSTORE_PEM].replace('\\', '/')] if ssl_enabled else [],
                    "authorizationServerUrl": f"https://{FQDN.lower()}:8443/MicroStrategyLibrary/api" if ssl_enabled
                    else f"http://{FQDN.lower()}:8080/MicroStrategyLibrary/api"
                }
            }
        },
        "Modeling Service": {
            "installed": installed_components["Modeling Service"]["installed"],
            "path": installed_components["Modeling Service"]["path"],
            "service_name": installed_components["Modeling Service"]["service_name"],
            "parameters": {
                installed_components["Modeling Service"]["path"] + "\\admin\\application.conf": {
                    "https.port": "10443" if ssl_enabled else "",
                    "play.server.https.keyStore.path": '"' + ssl_artifact_path[KEYSTORE].replace("\\",
                                                                                                 "/") + '"' if ssl_enabled else "",
                    "play.server.https.keyStore.type": "JKS" if ssl_enabled else "",
                    "play.server.https.keyStore.password": '"' + KEYSTORE_PW + '"' if ssl_enabled else ""
                },
                installed_components["Modeling Service"]["path"] + "\\admin\\modelservice.conf": {
                    "modelservice.iserver.tlsEnabled": "true" if ssl_enabled else "false",
                    "modelservice.trustStore.path": ssl_artifact_path[TRUSTSTORE].replace('\\',
                                                                                          '/') if ssl_enabled else "",
                    "modelservice.trustStore.passphrase": TRUSTSTORE_PW if ssl_enabled else ""
                },
                installed_components["Library"]["path"] + "\\WEB-INF\\classes\\config\\configOverride.properties": {
                    "services.MicroStrategy-Modeling-Service.tlsEnabled": "true" if ssl_enabled else "false",
                    "services.MicroStrategy-Modeling-Service.baseURL": f"https://{FQDN.lower()}:10443" if ssl_enabled else ""
                }
            }
        }
    }
    for component in list(new_config.keys()):
        if not new_config[component]["installed"]:
            del new_config[component]
    return new_config


def check_installed_components(services):
    # Check which of the above components are installed.
    installed_components = services

    for component, value in services.items():
        if services[component]["service_name"]:
            try:
                subprocess.check_output('sc qc "' + services[component]["service_name"] + '"')
            except subprocess.CalledProcessError:
                installed_components[component]["installed"] = False
            else:
                installed_components[component]["installed"] = True

        if installed_components["Tomcat"]["installed"]:
            installed_components["Tomcat"]["path"] = get_tomcat_home()
            installed_components["Web"]["installed"] = os.path.exists(
                installed_components["Tomcat"]["path"] + "\\webapps\\MicroStrategy")
            installed_components["Library"]["installed"] = os.path.exists(
                installed_components["Tomcat"]["path"] + "\\webapps\\MicroStrategyLibrary")

        if installed_components["Web"]["installed"]:
            installed_components["Web"]["path"] = installed_components["Tomcat"]["path"] + "\\webapps\\MicroStrategy"

        if installed_components["Library"]["installed"]:
            installed_components["Library"]["path"] = installed_components["Tomcat"][
                                                          "path"] + "\\webapps\\MicroStrategyLibrary"

    print("\n>> Checking installed components ...")
    for component, value in installed_components.items():
        if installed_components[component]["installed"]:
            print(f"[+] {component} ... installed")
        else:
            print(f"[-] {component} ... not found")

    return installed_components


def get_tomcat_home():
    try:
        output = subprocess.check_output('sc qc "tomcat9"', universal_newlines=True)
    except subprocess.CalledProcessError:
        return ""
    else:
        for line in output.split('\n'):
            if line.strip().startswith("BINARY_PATH_NAME"):
                path = str(line.split(': ')[1].split(' //')[0].strip('"').split(r'\bin')[0])
                if os.path.exists(path):
                    return path
                else:
                    return ""


def restart_components(config_dict):
    for component in config_dict:
        if config[component]["service_name"]:
            print(f"\n>> Restarting {component} ...\n")
            service_name = config[component]["service_name"]
            if os.system(f'sc query "{service_name}" | find "RUNNING" >nul') == 0:
                os.system(f'net stop "{service_name}" && net start "{service_name}"')
            else:
                os.system(f'net start "{service_name}"')
            time.sleep(1)


def configure_service(config_dict):
    for configuration_file, value in config_dict["parameters"].items():
        if backup_file(configuration_file):
            update_config_file(configuration_file, value)
        elif config_dict["service_name"] is None:
            update_config_file(configuration_file, value)


def configure_intelligence_server(config_dict):
    print(f"\n[+] {'Enabling' if ssl_toggle else 'Disabling'} TLS on I-Server")
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
        with winreg.OpenKeyEx(reg, config_dict["parameters"]["registry_config"]["registry_key"],
                              0, winreg.KEY_ALL_ACCESS) as reg_key:
            print(f'[+] Updating registry key {config_dict["parameters"]["registry_config"]["registry_key"]}')
            for key, value in config_dict["parameters"]["registry_config"]["registry_parameters"].items():
                print(f"[-] Setting {key} to {value}")
                if key != "SSLPort":
                    winreg.SetValueEx(reg_key, key, 0, winreg.REG_SZ, value)
                else:
                    winreg.SetValueEx(reg_key, key, 0, winreg.REG_DWORD, int(hex(value), 16))

    print(f"[+] {'Enabling' if ssl_toggle else 'Disabling'} TLS for REST API port {REST_PORT}")
    # Get iserver cert fingerprint
    with open(config_dict["parameters"]['rest_api_config']['CertificatePath'], 'rb') as cert:
        certificate = x509.load_pem_x509_certificate(cert.read(), default_backend())
        fingerprint = str(certificate.fingerprint(hashes.SHA1()).hex())

    i_server_pfx_path = config_dict["parameters"]['rest_api_config']['i_server_pfx']
    if ssl_toggle:
        os.system('certutil -f -p "' + config_dict["parameters"]["rest_api_config"][
            "i_server_pfx_pw"] + '" -importpfx "' + i_server_pfx_path + '"')
    os.system("netsh http delete ssl ipport=0.0.0.0:34962")
    if ssl_toggle:
        os.system('netsh http add sslcert ipport=0.0.0.0:34962 certstorename=My certhash=' + fingerprint +
                  ' appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" ')


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
        if os.path.exists(filepath):
            file = eT.parse(filepath)
        else:
            root_element = eT.Element("servers", version="1.0")
            file = eT.ElementTree(root_element)
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


def copy_truststore(source, destination):
    try:
        shutil.copyfile(source,
                        destination)
    except IOError:
        return False
    else:
        return True


# Execution
print("-----------------------------------------------------------------")
print(f"--- Configure MSTR environment with TLS/SSL certificates v{VERSION} ---")
print("-----------------------------------------------------------------\n\n")

if not ctypes.windll.shell32.IsUserAnAdmin():
    print("WARNING: This tool must be run as administrator. "
          "Right-click the executable and select 'Run As Administrator'\n\n")
    input("Press ENTER to exit.")
    exit()
else:
    mode = input("Enable or disable TLS on this machine? Type 1 for enable or type 2 for disable: ")
    if mode == "1":
        ssl_toggle = True
        check_ssl_artifacts_exist(ssl_artifact_path)
    elif mode == "2":
        ssl_toggle = False
    else:
        print("No valid input detected, try again. 1 or 2, ok?")
        input("\n\nPress ENTER to exit")
        exit()

config = build_config(ssl_toggle, check_installed_components(component_path_service_names))

if input(f"\nCONFIRM: MicroStrategy services will be restarted automatically if required. "
         f"Confirm you want to {'enable TLS' if ssl_toggle else 'disable TLS'} "
         f"on the components listed above. (Y/N) ").lower() == 'y':
    print("\n")

    for component, value in config.items():
        print(f"\n>> Configuring {component} ...")
        if component == "Intelligence Server":
            configure_intelligence_server(value)
        elif component == "Web":
            configure_service(value)
            copy_truststore(ssl_artifact_path[TRUSTSTORE], config["Web"]["path"] + "\\WEB-INF\\" + TRUSTSTORE)
        else:
            configure_service(value)
    if ssl_toggle:
        print("\n>> Installing root certificate into Windows Certificate Store. "
              "Confirm the installation on the pop-up window.\n")
        install_ca_cert(ssl_artifact_path[ROOT_CERTIFICATE])
    restart_components(config)
else:
    print("Ok :( Maybe next time then...")
    input("\n\nPress ENTER to exit")
    exit()

print(f">> Configuration complete. TLS has been {'enabled' if ssl_toggle else 'disabled'}.\n\n")

if ssl_toggle:
    print("----------------------------------------------------\n")
    print("Please read:\n")
    print(f"[-] Use the fully qualified domain name ({FQDN.lower()}) to connect to Tomcat.\n"
          f"    E.g. https://{FQDN.lower()}:8443/MicroStrategyLibrary for Library\n"
          f"    Without the FQDN, the browser will throw a certificate warning.\n\n"
          f"[-] The root CA certificate has already been installed into the Windows certificate store on\n"
          f"    this machine. If not, install it manually. To connect to this Tomcat server \n"
          f"    from a remote machine, install first the root certificate ({ROOT_CERTIFICATE})\n"
          f"    on the remote machine to avoid browser security warnings.\n"
          f"    To do so, copy the root certificate file onto the remote machine,\n"
          f"    and select 'Install Certificate'. Follow the on-screen directions.\n\n"
          f"[-] If MicroStrategy Web has been configured for SSL, it requires every Intelligence Server\n"
          f"    that is added to the Web Administration page to be SSL enabled. To connect to non-SSL\n"
          f"    enabled Intelligence Server, go to the Web Administration page > Security and select\n"
          f"    'No encryption'.")

input("\n\nPress ENTER to exit")
exit()
