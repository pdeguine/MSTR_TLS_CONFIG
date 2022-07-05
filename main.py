import os
import ctypes
import configManager
import socket
import sys
import subprocess

PATH_EXE = "c:\\ssl"
# PATH_EXE = os.path.dirname(sys.executable)
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


def build_config(ssl_toggle):
    # Verify all ssl artifacts are available on their physical location
    if ssl_toggle:
        required_ssl_artifacts = [f"{PATH_EXE}\\{KEYSTORE}",
                                  f"{PATH_EXE}\\{CERTIFICATE}",
                                  f"{PATH_EXE}\\{KEY}",
                                  f"{PATH_EXE}\\{TRUSTSTORE}",
                                  f"{PATH_EXE}\\{ROOT_CERTIFICATE}",
                                  f"{PATH_EXE}\\{TRUSTSTORE_PEM}",
                                  f"{PATH_EXE}\\{I_SERVER_PFX}"]

        for ssl_artifact in required_ssl_artifacts:
            if not os.path.exists(ssl_artifact):
                print(
                    f"WARNING: {ssl_artifact} not found. Make sure it exists in same directory as the executable.\n\n")
                input("Press ENTER to exit.")
                exit()

    config = {
        "Intelligence Server": {
            "installed": False,
            "path": "",
            "service_name": "MicroStrategy Intelligence Server",
            "parameters": {
                "registry_config": {
                    "registry_key": r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                    "registry_parameters": {
                        "CertificatePath": f"{PATH_EXE}\\{CERTIFICATE}",
                        "KeyPath": f"{PATH_EXE}\\{KEY}",
                        "CertificateKeyPassword": KEY_PASSWORD,
                        "SSLPort": SSL_PORT if ssl_toggle else 4294967295
                    }
                },
                "rest_api_config": {
                    "i_server_pfx": str(PATH_EXE + '/' + KEYSTORE).replace('/', '\\') if ssl_toggle else "",
                    "i_server_pfx_pw": KEYSTORE_PW,
                    "CertificatePath": f"{PATH_EXE}\\{CERTIFICATE}",
                    "REST_PORT": 34962
                }
            }

        },
        "Tomcat": {
            "installed": False,
            "path": get_tomcat_home() + "\\conf",
            "service_name": "tomcat9",
            "parameters": {
                "\\server.xml": {
                    'Service/Connector[@port="8443"]': {
                        'keystoreFile': str(PATH_EXE + '/' + KEYSTORE).replace('/', '\\') if ssl_toggle else "",
                        'keystorePass': KEYSTORE_PW if ssl_toggle else ""
                    }
                }
            }
        },
        "Web": {
            "installed": False,
            "path": get_tomcat_home() + "\\webapps\\MicroStrategy",
            "service_name": None,
            "parameters": {
                "\\WEB-INF\\xml\\adminServers.xml": {
                    f'server[@name="{FQDN}"]': {
                        "name": FQDN,
                        "conn": "false"
                    }

                },
                "\\WEB-INF\\microstrategy.xml": {
                    'global/parameter[@name="sslTruststore"]': {
                        "value": str("WEB-INF" + '/' + TRUSTSTORE).replace('\\', '/')
                    },
                    'global/parameter[@name="sslTruststorePwd"]': {
                        "value": TRUSTSTORE_PW
                    }
                },
                "\\WEB-INF\\xml\\sys_defaults.properties": {
                    "useEncryption": "2" if ssl_toggle else "0"
                },
                f"\\WEB-INF\\xml\\sys_defaults_{FQDN}.properties": {
                    "connectmode": "auto"
                }
            }
        },
        "Library": {
            "installed": False,
            "path": get_tomcat_home() + "\\webapps\\MicroStrategyLibrary",
            "service_name": None,
            "parameters": {
                "\\WEB-INF\\classes\\config\\configOverride.properties":
                    {
                        "trustStore.path": "file:" + str(PATH_EXE + '/' + TRUSTSTORE).replace('\\',
                                                                                              '/') if ssl_toggle else "",
                        "trustStore.passphrase": TRUSTSTORE_PW if ssl_toggle else "",
                        "iserver.default.hostname": FQDN,
                        "iserver.default.port": SSL_PORT if ssl_toggle else NO_SSL_PORT,
                        "iserver.tlsEnabled": "true" if ssl_toggle else "false"
                    }
            }
        },
        "Collaboration Server": {
            "installed": False,
            "path": "C:\\Program Files (x86)\\MicroStrategy\\Collaboration Server",
            "service_name": "MSTR_collaboration",
            "parameters": {
                "\\config.json": {
                    "enableTls": "true" if ssl_toggle else "false",
                    "keystoreFile": str(PATH_EXE + '/' + KEYSTORE).replace('\\', '/') if ssl_toggle else "",
                    "passphrase": KEYSTORE_PW if ssl_toggle else "",
                    "trustedCerts": [str(PATH_EXE + '/' + TRUSTSTORE_PEM).replace('\\', '/')] if ssl_toggle else [],
                    "authorizationServerUrl": f"https://{FQDN.lower()}:8443/MicroStrategyLibrary/api"
                }
            }
        },
        "Modeling Service": {
            "installed": False,
            "path": "C:\\Program Files (x86)\\MicroStrategy\\ModelingService\\admin",
            "service_name": "MSTR_ModelingService",
            "parameters": {
                "\\application.conf": {
                    "https.port": "10443" if ssl_toggle else "",
                    "play.server.https.keyStore.path": '"' + PATH_EXE.replace("\\",
                                                                              "/") + '/' + KEYSTORE + '"' if ssl_toggle else "",
                    "play.server.https.keyStore.type": "JKS" if ssl_toggle else "",
                    "play.server.https.keyStore.password": '"' + KEYSTORE_PW + '"' if ssl_toggle else ""
                },
                "\\modelservice.conf": {
                    "modelservice.iserver.tlsEnabled": "true" if ssl_toggle else "false",
                    "modelservice.trustStore.path": str(PATH_EXE + '/' + TRUSTSTORE).replace('\\',
                                                                                             '/') if ssl_toggle else "",
                    "modelservice.trustStore.passphrase": TRUSTSTORE_PW if ssl_toggle else ""
                },
                "\\WEB-INF\\classes\\config\\configOverride.properties": {
                    "services.MicroStrategy-Modeling-Service.tlsEnabled": "true" if ssl_toggle else "false",
                    "services.MicroStrategy-Modeling-Service.baseURL": f"https://{FQDN.lower()}:10443" if ssl_toggle else ""
                }
            }
        }
    }

    # Check which of the above components are installed.
    for component, value in config.items():
        if config[component]["service_name"]:
            try:
                subprocess.check_output('sc qc "' + config[component]["service_name"] + '"')
            except subprocess.CalledProcessError:
                config[component]["installed"] = False
            else:
                config[component]["installed"] = True
        else:
            if os.path.exists(config[component]["path"]):
                config[component]["installed"] = True
            else:
                config[component]["installed"] = False

    for component, value in list(config.items()):
        if component == "Modeling Service":
            for parameter, value in list(config[component]["parameters"].items()):
                if parameter == "\\WEB-INF\\classes\\config\\configOverride.properties":
                    config[component]["parameters"][config["Library"]["path"] + parameter] = value
                    del config[component]["parameters"][parameter]
                else:
                    config[component]["parameters"][config[component]["path"] + parameter] = value
                    del config[component]["parameters"][parameter]
        elif component == "Intelligence Server":
            pass
        else:
            for parameter, value in list(config[component]["parameters"].items()):
                config[component]["parameters"][config[component]["path"] + parameter] = value
                del config[component]["parameters"][parameter]

    return config


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


# Execution
print("-----------------------------------------------------------------")
print(f"--- Configure MSTR environment with TLS/SSL certificates {VERSION} ---")
print("-----------------------------------------------------------------\n\n")
ssl_toggle = False
if not ctypes.windll.shell32.IsUserAnAdmin():
    print("WARNING: This tool must be run as administrator. "
          "Right-click the executable and select 'Run As Administrator'\n\n")
    input("Press ENTER to exit.")
else:
    mode = input("Enable or disable TLS on this machine? Type 1 for enable or type 2 for disable: ")
    if mode == "1":
        ssl_toggle = True
    elif mode == "2":
        ssl_toggle = False
    else:
        print("No valid input detected, try again. 1 or 2, ok?")
        input("\n\nPress ENTER to exit")
        exit()

config = build_config(ssl_toggle)
configManager = configManager.ConfigManager(config, ssl_toggle)

if input("CONFIRM: MicroStrategy services will be restarted automatically if required. "
         "Confirm you want to proceed. (Y/N) ").lower() == 'y':
    print("\n")
configManager.apply()
configManager.copy_truststore(f"{PATH_EXE}\\{TRUSTSTORE}", config["Web"]["path"] + "\\WEB-INF\\" + TRUSTSTORE)
configManager.restart()

print("\n[-] Installing root certificate into Windows Certificate Store.\n")
configManager.install_ca_cert(f"{PATH_EXE}\\{ROOT_CERTIFICATE}")
print("[-] Configuration complete.\n\n")
print("----------------------------------------------------\n")
print("Please read:\n")
print(f"[-] Use the fully qualified domain name ({configManager.fqdn.lower()}) to connect to Tomcat.\n"
      f"    E.g. https://{configManager.fqdn.lower()}:8443/MicroStrategyLibrary for Library\n"
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
