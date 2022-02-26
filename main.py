import os
import socket
import subprocess
import winreg
import xml.etree.ElementTree
from xml.etree import ElementTree as eT
import json
import shutil
import datetime
import ctypes
import sys

path_exe = os.path.dirname(sys.executable)
mstr_classpath = os.getenv('MSTR_CLASSPATH')
keystore_pw = 'm$tr!23'
keystore_path = path_exe + '\\TSkeystore.pfx'
certificate_path = path_exe + "\\iserver_cert.pem"
key_path = path_exe + "\\iserver_key.pem"
# AES encrypted password, retrieved from the registry of a SSL enabled I-Server with password m$tr!23
key_password = "000000014ff340a763b7ac26c04176a958867b16069e1c44753d49" \
               "5452d04e9ac9373ea6c5cc2e25c70cd0babe01729dd7cd80fa9ffb"
truststore_path = path_exe + "\\trusted.jks"
truststore_pw = "m$tr!23"
truststore_pem = path_exe + "\\MSTRTSRootCA.pem"
root_certificate = path_exe + "MSTRTSRootCA.crt"
ssl_port = 39321
fqdn = socket.getfqdn().upper()


def check_installed_components():
    components = {
        "Intelligence Server": {"installed": False, "path": "", "func": i_server_enable_ssl},
        "Tomcat": {"installed": False, "path": "", "func": tomcat_enable_ssl},
        "Web": {"installed": False, "path": "", "func": configure_web},
        "Library": {"installed": False, "path": "", "func": configure_library},
        "Collaboration Server": {"installed": False, "path": "", "func": configure_collab}
    }

    # Intelligence Server
    try:
        subprocess.check_output('sc qc "MicroStrategy Intelligence Server"')
    except subprocess.CalledProcessError:
        components["Intelligence Server"]["installed"] = False
    else:
        components["Intelligence Server"]["installed"] = True

    # Tomcat
    try:
        output = subprocess.check_output('sc qc "tomcat9"', universal_newlines=True)
    except subprocess.CalledProcessError:
        components["Tomcat"]["installed"] = False
    else:
        components["Tomcat"]["installed"] = True
        for line in output.split('\n'):
            if line.strip().startswith("BINARY_PATH_NAME"):
                path = str(line.split(': ')[1].split(' //')[0].strip('"').split(r'\bin')[0])
                if os.path.exists(path):
                    components["Tomcat"]["path"] = path
                else:
                    components["Tomcat"]["path"] = ""

    # Web
    if components["Tomcat"]["installed"]:
        if os.path.exists(components["Tomcat"]["path"] + "\\webapps\\MicroStrategy"):
            components["Web"]["installed"] = True
            components["Web"]["path"] = components["Tomcat"]["path"] + "\\webapps\\MicroStrategy"

    # Library
    if components["Tomcat"]["installed"]:
        if os.path.exists(components["Tomcat"]["path"] + "\\webapps\\MicroStrategyLibrary"):
            components["Library"]["installed"] = True
            components["Library"]["path"] = components["Tomcat"]["path"] + "\\webapps\\MicroStrategyLibrary"

    # Collaboration Server
    if os.path.exists(r'C:\Program Files (x86)\MicroStrategy\Collaboration Server\config.json'):
        components["Collaboration Server"]["installed"] = True
        components["Collaboration Server"]["path"] = 'C:\\Program Files (x86)\\MicroStrategy\\' \
                                                     'Collaboration Server\\config.json'

    return components


def i_server_enable_ssl():
    print("[-] Configuring SSL for Intelligence Server.")
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
        with winreg.OpenKeyEx(reg, r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                              0, winreg.KEY_ALL_ACCESS) as reg_key:
            winreg.SetValueEx(reg_key, "CertificatePath", 0, winreg.REG_SZ, certificate_path)
            winreg.SetValueEx(reg_key, "KeyPath", 0, winreg.REG_SZ, key_path)
            winreg.SetValueEx(reg_key, "CertificateKeyPassword", 0, winreg.REG_SZ, key_password)
            winreg.SetValueEx(reg_key, "SSLPort", 0, winreg.REG_DWORD, int(hex(ssl_port), 16))
    print("[-] Restarting Intelligence Server.")
    if os.system('sc query "MicroStrategy Intelligence Server" | find "RUNNING" >nul') == 0:
        os.system('net stop "MicroStrategy Intelligence Server" && net start "MicroStrategy Intelligence Server"')
    else:
        os.system('net start "MicroStrategy Intelligence Server"')
    print(f"[-] Intelligence Server is configured for SSL on port {ssl_port}.")


def tomcat_enable_ssl():
    server_xml_path = installed_components["Tomcat"]["path"] + "\\conf\\server.xml"
    try:
        shutil.copyfile(server_xml_path,
                        server_xml_path + '_sslconfig_backup_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
    except IOError:
        print(f"ERROR: Unable to locate server.xml under {server_xml_path}")
    else:
        print('[-] Backing up server.xml')
        print(f'[-] Modifying SSL connector on port 8443\nSetting keystoreFile to {keystore_path}\n'
              f'Setting keystorePass to {keystore_pw}')
        server_xml = eT.parse(server_xml_path)
        root = server_xml.getroot()
        ssl_connector = root.find('Service/Connector[@port="8443"]')
        ssl_connector.set('keystoreFile', keystore_path)
        ssl_connector.set('keystorePass', keystore_pw)
        server_xml.write(server_xml_path)
        print('[-] Tomcat has been configured for SSL on port 8443.')


def restart_tomcat():
    if os.system('sc query "tomcat9" | find "RUNNING" >nul') == 0:
        os.system('net stop "tomcat9" && net start "tomcat9"')
    else:
        os.system('net start "tomcat9"')


def configure_collab():
    config_json_path = installed_components["Collaboration Server"]["path"]
    try:
        shutil.copyfile(config_json_path,
                        config_json_path + '_sslconfig_backup_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
    except IOError:
        print(f"ERROR: Collaboration Server config.json not found under {config_json_path}.")
    else:
        print("[-] Backing up config.json")
        print(f"[-] Setting:\nenableTls to true\nkeystoreFile to {keystore_path}\npassphrase to {keystore_pw}\n"
              f"trustedCerts to {truststore_pem}\n")
        with open(config_json_path, 'r+') as config_json:
            data = json.load(config_json)
            data['enableTls'] = "true"
            data['keystoreFile'] = keystore_path.replace('\\', '/')
            data['passphrase'] = keystore_pw
            data["trustedCerts"] = [truststore_pem.replace('\\', '/')]
            data["authorizationServerUrl"] = f"https://{fqdn.lower()}:8443/MicroStrategyLibrary/api"
            config_json.seek(0)
            config_json.write(json.dumps(data, indent=3))
    print(f"[-] Collaboration Server has been configured. It can be accessed under https://{fqdn.lower()}:3000")


def restart_collab():
    if os.system('sc query "MSTR_collaboration" | find "RUNNING" >nul') == 0:
        os.system('net stop "MSTR_collaboration" && net start "MSTR_collaboration"')
    else:
        os.system('net start "MSTR_collaboration"')


def configure_web():
    # Backup and update microstrategy.xml with truststore
    microstrategy_xml_path = installed_components["Web"]["path"] + "\\WEB-INF\\microstrategy.xml"
    print(microstrategy_xml_path)
    try:
        shutil.copyfile(microstrategy_xml_path,
                        microstrategy_xml_path + '_sslconfig_backup_' + datetime.datetime.now().strftime(
                            '%Y%m%d_%H%M%S'))
    except IOError:
        print(f"ERROR: Unable to locate microstrategy.xml under {microstrategy_xml_path}")
    else:
        print("[-] Backing up microstrategy.xml.")
        microstrategy_xml = eT.parse(microstrategy_xml_path)
        root = microstrategy_xml.getroot()
        print(f"[-] Setting sslTruststore (trusted.jks) and sslTruststorePwd ({truststore_pw}) parameters.")
        ts_path = root.find('global/parameter[@name="sslTruststore"]')
        ts_path.set('value', "trusted.jks")
        ts_pw = root.find('global/parameter[@name="sslTruststorePwd"]')
        ts_pw.set('value', truststore_pw)
        microstrategy_xml.write(microstrategy_xml_path)

        # Copy truststore into Web deployment folder
        print("[-] Copying truststore to " + installed_components["Web"]["path"] + "\\WEB-INF\\trusted.jks")
        shutil.copyfile(truststore_path,
                        installed_components["Web"]["path"] + "\\WEB-INF\\trusted.jks")

        # Ensure I-Server is added using FQDN
        print(f"[-] Adding Intelligence Server to the Web Administration page using {fqdn} "
              f"and setting port to {ssl_port}")
        admin_server_xml_path = installed_components["Web"]["path"] + "\\WEB-INF\\xml\\AdminServers.xml"
        print(admin_server_xml_path)
        try:
            shutil.copyfile(admin_server_xml_path,
                            admin_server_xml_path + '_sslconfig_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        except IOError:
            print("ERROR: Unable to locate AdminServers.xml")
        else:
            admin_server_xml = eT.parse(admin_server_xml_path)
            root = admin_server_xml.getroot()
            i_server_entries = root.findall('.//server')

            if i_server_entries:
                for entry in i_server_entries:
                    print(entry.get('name'))
                    print(socket.gethostname())
                    if entry.get('name').lower() == 'localhost' or entry.get('name').lower() == socket.gethostname():
                        entry.set('name', fqdn)
            else:
                eT.SubElement(root, "server", conn="false", name=fqdn)
                xml.etree.ElementTree.indent(root)
            admin_server_xml.write(admin_server_xml_path)

            # Enable SSL for I-Server on port 39321
            i_server_properties_file = installed_components["Web"]["path"] + "\\WEB-INF\\xml\\sys_defaults_" + \
                                       fqdn + ".properties"
            if os.path.exists(i_server_properties_file):
                with open(i_server_properties_file, 'r+') as i_server_properties:
                    properties = i_server_properties.readlines()
                    print(properties)
                    if any("connectmode" in i_server_property for i_server_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("connectmode"):
                                properties[i] = "connectmode=auto\n"
                    else:
                        properties.append("connectmode=auto\n")
                    if any("port" in i_server_property for i_server_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("port"):
                                properties[i] = f"port={ssl_port}\n"
                    else:
                        properties.append(f"port={ssl_port}\n")
                    i_server_properties.seek(0)
                    for i_server_property in properties:
                        i_server_properties.write(i_server_property)
            else:
                with open(i_server_properties_file, 'w') as i_server_properties:
                    i_server_properties.write(f"connmode=auto\nport={ssl_port}")

            # Enable TLS for connection to I-Server
            properties_file = installed_components["Web"]["path"] + "\\WEB-INF\\xml\\sys_defaults.properties"
            print("[-] Enabling TLS/SSL encryption for this MicroStrategy Web deployment.")
            if os.path.exists(properties_file):
                with open(properties_file, 'r+') as default_properties:
                    properties = default_properties.readlines()
                    if any("useEncryption" in default_property for default_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("useEncryption"):
                                properties[i] = "useEncryption=2\n"
                    else:
                        properties.append("useEncryption=2\n")
                    default_properties.seek(0)
                    for default_property in properties:
                        default_properties.write(default_property)
            else:
                with open(properties_file, 'w') as default_properties:
                    default_properties.write("useEncryption=2\n")

        print("[-] MicroStrategy Web configuration completed.")


def configure_library():
    # Backup configOverride.properties
    configoverride_path = installed_components["Library"][
                              "path"] + "\\WEB-INF\\classes\\config\\configOverride.properties"
    try:
        shutil.copyfile(configoverride_path,
                        configoverride_path + '_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
    except IOError:
        print("Can't find configOverride.properties")
    else:
        # update configOverride.properties with truststore
        print("[-] Backing up configOverride.properties.")
        print(f"[-] Setting:\ntrustStore.path to {truststore_path}\ntrustStore.passphrase to {truststore_pw}\n"
              f"iserver.default.port to {ssl_port}\niserver.default.hostname to {fqdn}\niserver.tlsEnabled to true\n")
        with open(configoverride_path, 'r+') as configoverride:
            properties = configoverride.readlines()
            if any("trustStore.path" in config_property for config_property in properties):
                for i in range(len(properties)):
                    if properties[i].startswith("trustStore.path"):
                        properties[i] = "trustStore.path=file:" + truststore_path.replace('\\', '/') + "\n"
            else:
                properties.append("trustStore.path=file:" + truststore_path.replace('\\', '/') + "\n")

            if any("trustStore.passphrase" in config_property for config_property in properties):
                for i in range(len(properties)):
                    if properties[i].startswith("trustStore.passphrase"):
                        properties[i] = "trustStore.passphrase=" + truststore_pw + "\n"
            else:
                properties.append("trustStore.passphrase=" + truststore_pw + "\n")

            if any("iserver.default.port" in config_property for config_property in properties):
                for i in range(len(properties)):
                    if properties[i].startswith("iserver.default.port"):
                        properties[i] = "iserver.default.port=" + str(ssl_port) + "\n"
            else:
                properties.append("iserver.default.port=" + str(ssl_port) + "\n")

            if any("iserver.default.hostname" in config_property for config_property in properties):
                for i in range(len(properties)):
                    if properties[i].startswith("iserver.default.hostname"):
                        properties[i] = "iserver.default.hostname=" + fqdn + "\n"
            else:
                properties.append("iserver.default.hostname=" + fqdn + "\n")

            if any("iserver.tlsEnabled" in config_property for config_property in properties):
                for i in range(len(properties)):
                    if properties[i].startswith("iserver.tlsEnabled"):
                        properties[i] = "iserver.tlsEnabled=true\n"
            else:
                properties.append("iserver.tlsEnabled=true\n")

            configoverride.seek(0)
            for config_property in properties:
                configoverride.write(config_property)
            print("MicroStrategy Library has been configured.")


# Execution
print("------------------------------------------------------------\n")
print("--- Configure MSTR environment with TLS/SSL certificates ---")
print("------------------------------------------------------------\n")
if not ctypes.windll.shell32.IsUserAnAdmin():
    print("WARNING: This tool must be run as administrator. "
          "Right-click the executable and select 'Run As Administrator'")
    input("Press ENTER to exit.")
else:
    if not os.path.exists(keystore_path):
        print("WARNING: SSL artifact files not found in same directory as the executable.")
        input("Press ENTER to exit.")
    else:
        print("[-] Checking Installed Components ...\n")
        installed_components = check_installed_components()
        for component in installed_components:
            print("[+] " + component + " ... " + str(installed_components[component]["installed"]))

        print("\n")
        if input("MSTR services will be restarted automatically if required. "
                 "Confirm you want to proceed. (Y/N) ").lower() == 'y':
            print("\n")
            for component in installed_components:
                if installed_components[component]["installed"]:
                    print(f"Configuring {component} ...")
                    installed_components[component]["func"]()
                    print("\n")
            if installed_components["Tomcat"]["installed"]:
                print("[-] Restarting Tomcat. It may take a couple of minutes before it has initialized.\n")
                restart_tomcat()
            if installed_components["Collaboration Server"]["installed"]:
                print("[-] Restarting Collaboration Server.")
                restart_collab()
            print("----------------------------------------------------\n")
            print(f"Configuration complete.\nUse the fully qualified domain name ({fqdn}) to connect to Tomcat.\n"
                  f"E.g. https://{fqdn}:8443/MicroStrategyLibrary for Library\n"
                  f"The root CA certificate has already been installed into the Windows certificate store on"
                  f"this machine. To connect to this Tomcat server from a remote machine, install first "
                  f"the root certificate ({root_certificate}) on the remote machine to avoid browser security warnings. "
                  f"To do so, copy the root certificate file onto the remote machine,"
                  f"double-click to open and select install certificate. Follow the on-screen directions.")
            input("Press ENTER to exit")
