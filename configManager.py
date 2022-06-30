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
        self.mstr_classpath = os.getenv('MSTR_CLASSPATH')
        self.keystore_pw = config["keystore_pw"]
        self.keystore_path = config["keystore_path"]
        self.certificate_path = config["certificate_path"]
        self.key_path = config["key_path"]
        self.key_password = config["key_password"]
        self.truststore_path = config["truststore_path"]
        self.truststore_pw = config["truststore_pw"]
        self.truststore_pem = config["truststore_pem"]
        self.root_certificate = config["root_certificate"]
        self.i_server_pfx = config["i_server_pfx"]
        self.ssl_port = config["ssl_port"]
        self.fqdn = socket.getfqdn().upper()
        self.components = self.check_installed_components()

    def check_installed_components(self):
        components = {
            "Intelligence Server": {"installed": False, "path": "", "func": self.i_server_configure,
                                    "restart_func": self.restart_intelligence_server},
            "Tomcat": {"installed": False, "path": "", "func": self.tomcat_configure,
                       "restart_func": self.restart_tomcat},
            "Web": {"installed": False, "path": "", "func": self.configure_web},
            "Library": {"installed": False, "path": "", "func": self.configure_library},
            "Collaboration Server": {"installed": False, "path": "", "func": self.configure_collab,
                                     "restart_func": self.restart_collab},
            "Modeling Service": {"installed": False, "path": "", "func": self.configure_modeling,
                                     "restart_func": self.restart_modeling}
        }

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

        # Modeling Service
        try:
            output = subprocess.check_output('sc qc "MSTR_ModelingService"', universal_newlines=True)
        except subprocess.CalledProcessError:
            components["Modeling Service"]["installed"] = False
        else:
            components["Modeling Service"]["installed"] = True
            for line in output.split('\n'):
                if line.strip().startswith("BINARY_PATH_NAME"):
                    path = str(line.split(': ')[1].split(' //')[0].strip('"').split(r'\ModelingService.exe')[0])
                    if os.path.exists(path):
                        components["Modeling Service"]["path"] = path
                    else:
                        components["Modeling Service"]["path"] = ""

        print("[-] Checking installed components ...\n")
        for component in components:
            print("     [+] " + component + " ... " +
                  "Found" if components[component]["installed"] else "Not found")
        return components

    def apply(self):
        for component in self.components:
            if self.components[component]["installed"]:
                print(f">> Configuring {component} ...\n")
                self.components[component]["func"]()
                time.sleep(1)

    def restart(self):
        for component in self.components:
            if self.components[component]["installed"]:
                if not (component == "Web" or component == "Library"):
                    print(f">> Restarting {component} ...\n")
                    self.components[component]["restart_func"]()
                    time.sleep(1)

    def i_server_configure(self):

        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
            with winreg.OpenKeyEx(reg, r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                                  0, winreg.KEY_ALL_ACCESS) as reg_key:
                winreg.SetValueEx(reg_key, "CertificatePath", 0, winreg.REG_SZ, self.certificate_path)
                winreg.SetValueEx(reg_key, "KeyPath", 0, winreg.REG_SZ, self.key_path)
                winreg.SetValueEx(reg_key, "CertificateKeyPassword", 0, winreg.REG_SZ, self.key_password)
                winreg.SetValueEx(reg_key, "SSLPort", 0, winreg.REG_DWORD, int(hex(self.ssl_port), 16))

        if self.ssl_toggle:
            print("[-] Configuring SSL for Intelligence Server.")
            print(f"    [+] Setting certificate {self.certificate_path}")
            print(f"    [+] Setting key {self.key_path}")
            print(f"    [+] Setting key password {self.keystore_pw}")
            print(f"    [+] Setting SSL port {self.ssl_port}")
            print(f"    [+] Enabling SSL for REST API port")
            # Get iserver cert fingerprint
            with open(self.certificate_path, 'rb') as cert:
                certificate = x509.load_pem_x509_certificate(cert.read(), default_backend())
                fingerprint = str(certificate.fingerprint(hashes.SHA1()).hex())

            i_server_pfx_path = self.i_server_pfx.replace("/", '\\')
            os.system(f'certutil -f -p "{self.keystore_pw}" -importpfx "{i_server_pfx_path}"')
            os.system("netsh http delete ssl ipport=0.0.0.0:34962")
            os.system('netsh http add sslcert ipport=0.0.0.0:34962 certstorename=My certhash=' + fingerprint +
                      ' appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" ')
            print(
                f"[-] SUCCESS: Intelligence Server has been configured for SSL connections on port {self.ssl_port}.\n\n")
        else:
            os.system("netsh http delete ssl ipport=0.0.0.0:34962")
            print(
                f"[-] SUCCESS: TLS configuration of Intelligence Server has been disabled.\n\n")

    def restart_intelligence_server(self):
        if os.system('sc query "MicroStrategy Intelligence Server" | find "RUNNING" >nul') == 0:
            os.system('net stop "MicroStrategy Intelligence Server" && net start "MicroStrategy Intelligence Server"')
        else:
            os.system('net start "MicroStrategy Intelligence Server"')

    def tomcat_configure(self):
        server_xml_path = self.components["Tomcat"]["path"] + "\\conf\\server.xml"
        try:
            shutil.copyfile(server_xml_path,
                            server_xml_path + '_sslconfig_backup_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        except IOError:
            print(f"ERROR: Unable to locate server.xml under {server_xml_path}")
        else:
            print('[-] Backing up server.xml')

            server_xml = eT.parse(server_xml_path)
            root = server_xml.getroot()
            ssl_connector = root.find('Service/Connector[@port="8443"]')
            ssl_connector.set('keystoreFile', self.keystore_path)
            ssl_connector.set('keystorePass', self.keystore_pw)
            server_xml.write(server_xml_path)
            if self.ssl_toggle:
                print(f'    [+] Setting keystoreFile to {self.keystore_path}')
                print(f'    [+] Setting keystorePass to {self.keystore_pw}')
                print('[-] SUCCESS: Tomcat has been configured for SSL on port 8443.\n\n')
            else:
                print('[-] SUCCESS: Tomcat TLS configuration has been disabled.\n\n')

    def restart_tomcat(self):
        if os.system('sc query "tomcat9" | find "RUNNING" >nul') == 0:
            os.system('net stop "tomcat9" && net start "tomcat9"')
        else:
            os.system('net start "tomcat9"')

    def configure_collab(self):
        config_json_path = self.components["Collaboration Server"]["path"]
        try:
            shutil.copyfile(config_json_path,
                            config_json_path + '_sslconfig_backup_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        except IOError:
            print(f"ERROR: Collaboration Server config.json not found under {config_json_path}.")
        else:
            print("[-] Backing up config.json")
            if self.ssl_toggle:
                print(f"    [+] Setting enableTls to 'true'")
                print(f"    [+] Setting keystoreFile to {self.keystore_path}")
                print(f"    [+] Setting passphrase to {self.keystore_pw}")
                print(f"    [+] Setting trustedCerts to {self.truststore_pem}")
                with open(config_json_path, 'r+') as config_json:
                    data = json.load(config_json)
                    data['enableTls'] = "true"
                    data['keystoreFile'] = self.keystore_path.replace('\\', '/')
                    data['passphrase'] = self.keystore_pw
                    data["trustedCerts"] = [self.truststore_pem.replace('\\', '/')]
                    data["authorizationServerUrl"] = f"https://{self.fqdn.lower()}:8443/MicroStrategyLibrary/api"
                    config_json.truncate(0)
                    config_json.seek(0)
                    config_json.write(json.dumps(data, indent=3))
                print(f"[-] SUCCESS: Collaboration Server has been configured. "
                      f"It can be accessed under https://{self.fqdn.lower()}:3000\n\n")

            else:
                with open(config_json_path, 'r+') as config_json:
                    data = json.load(config_json)

                    try:
                        del data['enableTls']
                    except KeyError:
                        pass

                    try:
                        del data['keystoreFile']
                    except KeyError:
                        pass

                    try:
                        del data['passphrase']
                    except KeyError:
                        pass

                    try:
                        del data["trustedCerts"]
                    except KeyError:
                        pass

                    data["authorizationServerUrl"] = f"http://{self.fqdn.lower()}:8080/MicroStrategyLibrary/api"
                    config_json.truncate(0)
                    config_json.seek(0)
                    config_json.write(json.dumps(data, indent=3))
                print(f"[-] SUCCESS: Collaboration Server has been configured. "
                      f"It can be accessed under http://{self.fqdn.lower()}:3000\n\n")

    def restart_collab(self):
        if os.system('sc query "MSTR_collaboration" | find "RUNNING" >nul') == 0:
            os.system('net stop "MSTR_collaboration" && net start "MSTR_collaboration"')
        else:
            os.system('net start "MSTR_collaboration"')

    def configure_web(self):
        # Backup and update microstrategy.xml with truststore
        microstrategy_xml_path = self.components["Web"]["path"] + "\\WEB-INF\\microstrategy.xml"
        print(microstrategy_xml_path)
        try:
            shutil.copyfile(microstrategy_xml_path,
                            microstrategy_xml_path + '_sslconfig_backup_' + datetime.datetime.now().strftime(
                                '%Y%m%d_%H%M%S'))
        except IOError:
            print(f"ERROR: Unable to locate microstrategy.xml under {microstrategy_xml_path}")
        else:
            print("[-] Backing up microstrategy.xml.")
            if self.ssl_toggle:
                microstrategy_xml = eT.parse(microstrategy_xml_path)
                root = microstrategy_xml.getroot()
                print("[-] Configuring trust store in microstrategy.xml")
                print(f"    [+] Setting sslTruststore to '/WEB-INF/trusted.jks'")
                print(f"    [+] Setting sslTruststorePwd to {self.truststore_pw}")
                ts_path = root.find('global/parameter[@name="sslTruststore"]')
                ts_path.set('value', "/WEB-INF/trusted.jks")
                ts_pw = root.find('global/parameter[@name="sslTruststorePwd"]')
                ts_pw.set('value', self.truststore_pw)
                microstrategy_xml.write(microstrategy_xml_path)

                # Copy truststore into Web deployment folder

                print("[-] Copying truststore to " + self.components["Web"]["path"] + "\\WEB-INF\\trusted.jks")
                shutil.copyfile(self.truststore_path,
                                self.components["Web"]["path"] + "\\WEB-INF\\trusted.jks")

                # Ensure I-Server is added using FQDN
                print(f"[-] Adding Intelligence Server to the Web Administration page using {self.fqdn} "
                      f"and setting port to {self.ssl_port}")
                print(f"    [+] Backing up AdminServers.xml")
                admin_server_xml_path = self.components["Web"]["path"] + "\\WEB-INF\\xml\\AdminServers.xml"
                try:
                    shutil.copyfile(admin_server_xml_path,
                                    admin_server_xml_path + '_sslconfig_' + datetime.datetime.now().strftime(
                                        '%Y%m%d_%H%M%S'))
                except IOError:
                    print("ERROR: Unable to locate AdminServers.xml")
                else:
                    admin_server_xml = eT.parse(admin_server_xml_path)
                    root = admin_server_xml.getroot()
                    i_server_entries = root.findall('.//server')

                    if i_server_entries:
                        entry_exists = False
                        for entry in i_server_entries:
                            if entry.get('name').lower() == 'localhost' or entry.get(
                                    'name').lower() == socket.gethostname() \
                                    or entry.get('name') == socket.gethostbyname(socket.gethostname()):
                                entry.set('name', self.fqdn)
                                entry_exists = True
                        if not entry_exists:
                            eT.SubElement(root, "server", conn="false", name=self.fqdn)
                            xml.etree.ElementTree.indent(root)
                    else:
                        eT.SubElement(root, "server", conn="false", name=self.fqdn)
                        xml.etree.ElementTree.indent(root)
                    print(f"    [+] Adding Intelligence Server using {self.fqdn}")
                    admin_server_xml.write(admin_server_xml_path)

                # Enable SSL for I-Server on port 39321
                i_server_properties_file = self.components["Web"]["path"] + "\\WEB-INF\\xml\\sys_defaults_" + \
                                           self.fqdn + ".properties"
                if os.path.exists(i_server_properties_file):
                    with open(i_server_properties_file, 'r+') as i_server_properties:
                        properties = i_server_properties.readlines()
                        if any("connectmode" in i_server_property for i_server_property in properties):
                            for i in range(len(properties)):
                                if properties[i].startswith("connectmode"):
                                    properties[i] = "connectmode=auto\n"
                        else:
                            properties.append("connectmode=auto\n")
                        if any("port" in i_server_property for i_server_property in properties):
                            for i in range(len(properties)):
                                if properties[i].startswith("port"):
                                    properties[i] = f"port={self.ssl_port}\n"
                        else:
                            properties.append(f"port={self.ssl_port}\n")
                        i_server_properties.truncate(0)
                        i_server_properties.seek(0)
                        for i_server_property in properties:
                            i_server_properties.write(i_server_property)
                else:
                    with open(i_server_properties_file, 'w') as i_server_properties:
                        i_server_properties.write(f"connmode=auto\nport={self.ssl_port}")
                print(f"    [+] Setting port to {self.ssl_port}")

                # Enable TLS for connection to I-Server
                properties_file = self.components["Web"]["path"] + "\\WEB-INF\\xml\\sys_defaults.properties"
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
                        default_properties.truncate(0)
                        default_properties.seek(0)
                        for default_property in properties:
                            default_properties.write(default_property)
                else:
                    with open(properties_file, 'w') as default_properties:
                        default_properties.write("useEncryption=2\n")
                print("     [+] Enabling SSL encryption.")
            else:
                i_server_properties_file = self.components["Web"]["path"] + "\\WEB-INF\\xml\\sys_defaults_" + \
                                           self.fqdn + ".properties"
                if os.path.exists(i_server_properties_file):
                    with open(i_server_properties_file, 'r+') as i_server_properties:
                        properties = i_server_properties.readlines()
                        if any("connectmode" in i_server_property for i_server_property in properties):
                            for i in range(len(properties)):
                                if properties[i].startswith("connectmode"):
                                    properties[i] = "connectmode=auto\n"
                        else:
                            properties.append("connectmode=auto\n")
                        if any("port" in i_server_property for i_server_property in properties):
                            for i in range(len(properties)):
                                if properties[i].startswith("port"):
                                    properties[i] = f"port=34952\n"
                        else:
                            properties.append(f"port=34952\n")
                        i_server_properties.truncate(0)
                        i_server_properties.seek(0)
                        for i_server_property in properties:
                            i_server_properties.write(i_server_property)
                else:
                    with open(i_server_properties_file, 'w') as i_server_properties:
                        i_server_properties.write(f"connmode=auto\nport=34952")
                print(f"    [+] Setting port to 34952")

                # Enable TLS for connection to I-Server
                properties_file = self.components["Web"]["path"] + "\\WEB-INF\\xml\\sys_defaults.properties"
                print("[-] Enabling TLS/SSL encryption for this MicroStrategy Web deployment.")
                if os.path.exists(properties_file):
                    with open(properties_file, 'r+') as default_properties:
                        properties = default_properties.readlines()
                        if any("useEncryption" in default_property for default_property in properties):
                            for i in range(len(properties)):
                                if properties[i].startswith("useEncryption"):
                                    properties[i] = "useEncryption=0\n"
                        else:
                            properties.append("useEncryption=0\n")
                        default_properties.truncate(0)
                        default_properties.seek(0)
                        for default_property in properties:
                            default_properties.write(default_property)
                else:
                    with open(properties_file, 'w') as default_properties:
                        default_properties.write("useEncryption=0\n")
                print("     [+] Disabling SSL encryption.")
            print("[-] MicroStrategy Web configuration completed.\n\n")

    def configure_library(self):
        # Backup configOverride.properties
        configoverride_path = self.components["Library"][
                                  "path"] + "\\WEB-INF\\classes\\config\\configOverride.properties"
        try:
            shutil.copyfile(configoverride_path,
                            configoverride_path + '_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        except IOError:
            print("ERROR: Can't find configOverride.properties")
        else:
            # update configOverride.properties with truststore
            print("[-] Backing up configOverride.properties.")
            # Enabling TLS on Library
            if self.ssl_toggle:
                print(f"    [+] Setting trustStore.path to {self.truststore_path}\n"
                      f"    [+] Setting trustStore.passphrase to {self.truststore_pw}\n"
                      f"    [+] Setting iserver.default.port to {self.ssl_port}\n"
                      f"    [+] Setting iserver.default.hostname to {self.fqdn}\n"
                      f"    [+] Setting iserver.tlsEnabled to true\n")
                with open(configoverride_path, 'r+') as configoverride:
                    properties = configoverride.readlines()
                    if any("trustStore.path" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("trustStore.path"):
                                properties[i] = "trustStore.path=file:" + self.truststore_path.replace('\\', '/') + "\n"
                    else:
                        properties.append("trustStore.path=file:" + self.truststore_path.replace('\\', '/') + "\n")

                    if any("trustStore.passphrase" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("trustStore.passphrase"):
                                properties[i] = "trustStore.passphrase=" + self.truststore_pw + "\n"
                    else:
                        properties.append("trustStore.passphrase=" + self.truststore_pw + "\n")

                    if any("iserver.default.port" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("iserver.default.port"):
                                properties[i] = "iserver.default.port=" + str(self.ssl_port) + "\n"
                    else:
                        properties.append("iserver.default.port=" + str(self.ssl_port) + "\n")

                    if any("iserver.default.hostname" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("iserver.default.hostname"):
                                properties[i] = "iserver.default.hostname=" + self.fqdn + "\n"
                    else:
                        properties.append("iserver.default.hostname=" + self.fqdn + "\n")

                    if any("iserver.tlsEnabled" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("iserver.tlsEnabled"):
                                properties[i] = "iserver.tlsEnabled=true\n"
                    else:
                        properties.append("iserver.tlsEnabled=true\n")

                    configoverride.truncate(0)
                    configoverride.seek(0)
                    for config_property in properties:
                        configoverride.write(config_property)
                    print("[-] SUCCESS: MicroStrategy Library has been configured.\n\n")
            # Disabling TLS on Library
            else:
                with open(configoverride_path, 'r+') as configoverride:
                    properties = configoverride.readlines()
                    if any("iserver.default.port" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("iserver.default.port"):
                                properties[i] = "iserver.default.port=" + str(34952) + "\n"
                    else:
                        properties.append("iserver.default.port=" + str(34952) + "\n")

                    if any("iserver.default.hostname" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("iserver.default.hostname"):
                                properties[i] = "iserver.default.hostname=" + self.fqdn + "\n"
                    else:
                        properties.append("iserver.default.hostname=" + self.fqdn + "\n")

                    if any("iserver.tlsEnabled" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if properties[i].startswith("iserver.tlsEnabled"):
                                properties[i] = "iserver.tlsEnabled=false\n"
                    else:
                        properties.append("iserver.tlsEnabled=false\n")
                    configoverride.truncate(0)
                    configoverride.seek(0)
                    for config_property in properties:
                        configoverride.write(config_property)
                    print("[-] SUCCESS: MicroStrategy Library has been configured.\n\n")

    def configure_modeling(self):
        # Backup application.conf
        application_conf_path = self.components["Modeling Service"][
                                  "path"] + "\\admin\\application.conf"
        try:
            shutil.copyfile(application_conf_path,
                            application_conf_path + '_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        except IOError:
            print("ERROR: Can't find application.conf")
        else:
            # update application.conf with truststore
            print("[-] Backing up application.conf.")
            # Enabling TLS on Modeling Service
            if self.ssl_toggle:
                print(f"    [+] Enabling https.port on 10443\n"
                      f"    [+] Setting play.server.https.keyStore.path to {self.keystore_path}\n"
                      f"    [+] Setting play.server.https.keyStore.type to JKS\n"
                      f"    [+] Setting play.server.https.keyStore.password to {self.keystore_pw}\n")
                with open(application_conf_path, 'r+') as application_conf:
                    properties = application_conf.readlines()
                    if any("https.port" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "https.port" in properties[i]:
                                properties[i] = "https.port = 10443\n"
                    else:
                        properties.append("https.port = 10443\n")

                    if any("play.server.https.keyStore.path" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "play.server.https.keyStore.path" in properties[i]:
                                properties[i] = 'play.server.https.keyStore.path = "' + self.keystore_path.replace('\\', '/') + '"\n'
                    else:
                        properties.append('play.server.https.keyStore.path = "' + self.keystore_path.replace('\\', '/') + '"\n')

                    if any("play.server.https.keyStore.type" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "play.server.https.keyStore.type" in properties[i]:
                                properties[i] = "play.server.https.keyStore.type = JKS\n"
                    else:
                        properties.append("play.server.https.keyStore.type = JKS\n")

                    if any("play.server.https.keyStore.password" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "play.server.https.keyStore.password" in properties[i]:
                                properties[i] = 'play.server.https.keyStore.password = "' + self.keystore_pw + '"\n'
                    else:
                        properties.append('play.server.https.keyStore.password = "' + self.keystore_pw + '"\n')

                    application_conf.truncate(0)
                    application_conf.seek(0)
                    for config_property in properties:
                        application_conf.write(config_property)

                    print("[-] SUCCESS: MicroStrategy Modeling Service application.conf has been configured for TLS access on port 10443.\n\n")

            # Disabling TLS on Modeling Service
            else:
                with open(application_conf_path, 'r+') as application_conf:
                    properties = application_conf.readlines()
                    if any("https.port" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "https.port" in properties[i]:
                                properties[i] = "# https.port = 10443\n"
                    else:
                        properties.append("# https.port = 10443\n")

                    if any("play.server.https.keyStore.path" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "play.server.https.keyStore.path" in properties[i]:
                                properties[i] = '# play.server.https.keyStore.path = "' + self.keystore_path.replace('\\',
                                                                                                                   '/') + '"\n'
                    else:
                        properties.append(
                            '# play.server.https.keyStore.path = "' + self.keystore_path.replace('\\', '/') + '"\n')

                    if any("play.server.https.keyStore.type" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "play.server.https.keyStore.type" in properties[i]:
                                properties[i] = "# play.server.https.keyStore.type = JKS\n"
                    else:
                        properties.append("# play.server.https.keyStore.type = JKS\n")

                    if any("play.server.https.keyStore.password" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "play.server.https.keyStore.password" in properties[i]:
                                properties[i] = '# play.server.https.keyStore.password = "' + self.keystore_pw + '"\n'
                    else:
                        properties.append('# play.server.https.keyStore.password = "' + self.keystore_pw + '"\n')

                    application_conf.truncate(0)
                    application_conf.seek(0)
                    for config_property in properties:
                        application_conf.write(config_property)
                    print("[-] SUCCESS: MicroStrategy Modeling Service application.conf has been configured without TLS.\n\n")

        # Backup modelservice.conf
        modelservice_conf_path = self.components["Modeling Service"][
                                    "path"] + "\\admin\\modelservice.conf"
        try:
            shutil.copyfile(modelservice_conf_path,
                            modelservice_conf_path + '_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        except IOError:
            print("ERROR: Can't find modelservice.conf")
        else:
            # update modelservice.conf with truststore
            print("[-] Backing up modelservice.conf.")
            # Enabling TLS on Modeling Service modelservice.conf
            if self.ssl_toggle:
                print(f"    [+] Setting modelservice.iserver.tlsEnabled to true\n"
                      f"    [+] Setting modelservice.trustStore.path to {self.truststore_path}\n"
                      f"    [+] Setting modelservice.trustStore.passphrase to {self.truststore_pw}\n")
                with open(modelservice_conf_path, 'r+') as modelservice_conf:
                    properties = modelservice_conf.readlines()
                    if any("modelservice.iserver.tlsEnabled" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "modelservice.iserver.tlsEnabled" in properties[i]:
                                properties[i] = "modelservice.iserver.tlsEnabled = true\n"
                    else:
                        properties.append("modelservice.iserver.tlsEnabled = true\n")

                    if any("modelservice.trustStore.path" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "modelservice.trustStore.path" in properties[i]:
                                properties[i] = 'modelservice.trustStore.path = ' + self.truststore_path.replace(
                                    '\\', '/') + '\n'
                    else:
                        properties.append(
                            'modelservice.trustStore.path = ' + self.truststore_path.replace('\\', '/') + '\n')

                    if any("modelservice.trustStore.passphrase" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "modelservice.trustStore.passphrase" in properties[i]:
                                properties[i] = f"modelservice.trustStore.passphrase = {self.truststore_pw}\n"
                    else:
                        properties.append(f"modelservice.trustStore.passphrase = {self.truststore_pw}\n")

                    modelservice_conf.truncate(0)
                    modelservice_conf.seek(0)
                    for config_property in properties:
                        modelservice_conf.write(config_property)

                    print(
                        "[-] SUCCESS: MicroStrategy Modeling Service modelservice.conf has been configured.\n\n")

            # Disabling TLS on Modeling Service modelservice.conf
            else:
                with open(modelservice_conf_path, 'r+') as modelservice_conf:
                    properties = modelservice_conf.readlines()
                    if any("modelservice.iserver.tlsEnabled" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "modelservice.iserver.tlsEnabled" in properties[i]:
                                properties[i] = "modelservice.iserver.tlsEnabled = false\n"
                    else:
                        properties.append("modelservice.iserver.tlsEnabled = false\n")

                    if any("modelservice.trustStore.path" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "modelservice.trustStore.path" in properties[i]:
                                properties[i] = '# modelservice.trustStore.path = "' + self.truststore_path.replace(
                                    '\\', '/') + '"\n'
                    else:
                        properties.append(
                            '# modelservice.trustStore.path = "' + self.truststore_path.replace('\\', '/') + '"\n')

                    if any("modelservice.trustStore.passphrase" in config_property for config_property in properties):
                        for i in range(len(properties)):
                            if "modelservice.trustStore.passphrase" in properties[i]:
                                properties[i] = f"# modelservice.trustStore.passphrase = {self.truststore_pw}\n"
                    else:
                        properties.append(f"# modelservice.trustStore.passphrase = {self.truststore_pw}\n")

                    modelservice_conf.truncate(0)
                    modelservice_conf.seek(0)
                    for config_property in properties:
                        modelservice_conf.write(config_property)

                    print(
                        "[-] SUCCESS: MicroStrategy Modeling Service modelservice.conf has been configured.\n\n")

        # Setup Library for Modeling Service using TLS
        configoverride_path = self.components["Library"][
                                  "path"] + "\\WEB-INF\\classes\\config\\configOverride.properties"
        if self.ssl_toggle:
            print(f"    [+] Setting services.MicroStrategy-Modeling-Service.tlsEnabled to true\n"
                  f"    [+] Setting services.MicroStrategy-Modeling-Service.baseURL to https://{self.fqdn.lower()}:10443\n")
            with open(configoverride_path, 'r+') as configoverride:
                properties = configoverride.readlines()
                if any("services.MicroStrategy-Modeling-Service.tlsEnabled" in config_property for config_property in properties):
                    for i in range(len(properties)):
                        if properties[i].startswith("services.MicroStrategy-Modeling-Service.tlsEnabled"):
                            properties[i] = "services.MicroStrategy-Modeling-Service.tlsEnabled = true\n"
                else:
                    properties.append("services.MicroStrategy-Modeling-Service.tlsEnabled = true\n")

                if any("services.MicroStrategy-Modeling-Service.baseURL" in config_property for config_property in properties):
                    for i in range(len(properties)):
                        if properties[i].startswith("services.MicroStrategy-Modeling-Service.baseURL"):
                            properties[i] = f"services.MicroStrategy-Modeling-Service.baseURL = https://{self.fqdn.lower()}:10443\n"
                else:
                    properties.append(f"services.MicroStrategy-Modeling-Service.baseURL = https://{self.fqdn.lower()}:10443\n")

                configoverride.truncate(0)
                configoverride.seek(0)
                for config_property in properties:
                    configoverride.write(config_property)
                print("[-] SUCCESS: MicroStrategy Library has been configured.\n\n")
        # Disabling TLS for Modeling Service on Library
        else:
            with open(configoverride_path, 'r+') as configoverride:
                properties = configoverride.readlines()
                if any("services.MicroStrategy-Modeling-Service.tlsEnabled" in config_property for config_property in
                       properties):
                    for i in range(len(properties)):
                        if properties[i].startswith("services.MicroStrategy-Modeling-Service.tlsEnabled"):
                            properties[i] = "services.MicroStrategy-Modeling-Service.tlsEnabled = false\n"
                else:
                    properties.append("services.MicroStrategy-Modeling-Service.tlsEnabled = false\n")

                if any("services.MicroStrategy-Modeling-Service.baseURL" in config_property for config_property in
                       properties):
                    for i in range(len(properties)):
                        if properties[i].startswith("services.MicroStrategy-Modeling-Service.baseURL"):
                            properties[
                                i] = f"services.MicroStrategy-Modeling-Service.baseURL = \n"
                else:
                    properties.append(
                        f"services.MicroStrategy-Modeling-Service.baseURL = \n")

                configoverride.truncate(0)
                configoverride.seek(0)
                for config_property in properties:
                    configoverride.write(config_property)
                print("[-] SUCCESS: MicroStrategy Library has been configured.\n\n")

    def restart_modeling(self):
        if os.system('sc query "MSTR_ModelingService" | find "RUNNING" >nul') == 0:
            os.system('net stop "MSTR_ModelingService" && net start "MSTR_ModelingService"')
        else:
            os.system('net start "MSTR_ModelingService"')

    def install_ca_cert(self):
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
        crt_path = self.root_certificate

        with open(crt_path, 'r') as f:
            cert_str = f.read()

        cert_byte = win32crypt.CryptStringToBinary(cert_str, CRYPT_STRING_BASE64HEADER)[0]
        store = win32crypt.CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, None,
                                         CERT_SYSTEM_STORE_CURRENT_USER_ACCOUNT | CERT_STORE_OPEN_EXISTING_FLAG, "ROOT")

        try:
            store.CertAddEncodedCertificateToStore(X509_ASN_ENCODING, cert_byte, CERT_STORE_ADD_REPLACE_EXISTING)
        except:
            print("WARNING: Installation of root certificate failed. To manually install the root certificate \n"
                  f"on this machine, install {self.root_certificate} with right-click > Install Certificate.")
        finally:
            store.CertCloseStore(CERT_CLOSE_STORE_FORCE_FLAG)
