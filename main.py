import os
import ctypes
import configManager

# PATH_EXE = os.path.dirname(sys.executable)
PATH_EXE = 'c:\\ssl (1)'
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


def build_config(ssl_toggle):
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
            "keystore_pw": KEYSTORE_PW,
            "keystore_path": f"{PATH_EXE}\\{KEYSTORE}",
            "certificate_path": f"{PATH_EXE}\\{CERTIFICATE}",
            "key_path": f"{PATH_EXE}\\{KEY}",
            "key_password": KEY_PASSWORD,
            "truststore_path": f"{PATH_EXE}\\{TRUSTSTORE}",
            "truststore_pw": TRUSTSTORE_PW,
            "truststore_pem": f"{PATH_EXE}\\{TRUSTSTORE_PEM}",
            "root_certificate": f"{PATH_EXE}\\{ROOT_CERTIFICATE}",
            "i_server_pfx": f"{PATH_EXE}\\{I_SERVER_PFX}",
            "ssl_port": SSL_PORT
        }
    else:
        config = {
            "keystore_pw": "",
            "keystore_path": "",
            "certificate_path": "",
            "key_path": "",
            "key_password": "",
            "truststore_path": "",
            "truststore_pw": "",
            "truststore_pem": "",
            "root_certificate": "",
            "i_server_pfx": "",
            "ssl_port": 4294967295
        }
    return config



# Execution
print("-----------------------------------------------------------------")
print("--- Configure MSTR environment with TLS/SSL certificates v1.1 ---")
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

configManager = configManager.ConfigManager(build_config(ssl_toggle), ssl_toggle)
print("Note: Current release only supports default MicroStrategy and Library deployment names\n\n")
if input("CONFIRM: MicroStrategy services will be restarted automatically if required. "
         "Confirm you want to proceed. (Y/N) ").lower() == 'y':
    print("\n")
configManager.apply()
configManager.restart()

print("[-] Installing root certificate into Windows Certificate Store.\n")
configManager.install_ca_cert()
print("[-] Configuration complete.\n\n")
print("----------------------------------------------------\n")
print("Please read:\n")
print(f"[-] Use the fully qualified domain name ({configManager.fqdn.lower()}) to connect to Tomcat.\n"
      f"    E.g. https://{configManager.fqdn.lower()}:8443/MicroStrategyLibrary for Library\n"
      f"    Without the FQDN, the browser will throw a certificate warning.\n\n"
      f"[-] The root CA certificate has already been installed into the Windows certificate store on\n"
      f"    this machine. If not, install it manually. To connect to this Tomcat server \n"
      f"    from a remote machine, install first the root certificate ({configManager.root_certificate})\n"
      f"    on the remote machine to avoid browser security warnings.\n"
      f"    To do so, copy the root certificate file onto the remote machine,\n"
      f"    and select 'Install Certificate'. Follow the on-screen directions.\n\n"
      f"[-] If MicroStrategy Web has been configured for SSL, it requires every Intelligence Server\n"
      f"    that is added to the Web Administration page to be SSL enabled. To connect to non-SSL\n"
      f"    enabled Intelligence Server, go to the Web Administration page > Security and select\n"
      f"    'No encryption'.")
input("\n\nPress ENTER to exit")
