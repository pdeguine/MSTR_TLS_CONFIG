import os
import subprocess
import winreg
from xml.etree import ElementTree as eT


class Machine:
    def __init__(self):
        self.i_server_exists = self.check_iserver()
        self.tomcat_home = ""
        self.web_home = ""
        self.library_home = ""
        self.tomcat_exists = self.check_tomcat()
        self.web_exists = self.check_web()
        self.library_exists = self.check_library()

    def check_iserver(self):
        try:
            output = subprocess.check_output('sc qc "MicroStrategy Intelligence Server"')
        except subprocess.CalledProcessError:
            print("Intelligence Server Service not found.")
            return False
        else:
            return True

    def check_tomcat(self):
        try:
            output = subprocess.check_output('sc qc "tomcat9"', universal_newlines=True)
        except subprocess.CalledProcessError:
            print("Tomcat Service not found.")
            return False
        else:
            for line in output.split('\n'):
                if line.strip().startswith("BINARY_PATH_NAME"):
                    path = str(line.split(': ')[1].split(' //')[0].strip('"').split(r'\bin')[0])
                    if os.path.exists(path):
                        self.tomcat_home = path
                        return True
                    else:
                        return False

    def check_web(self):
        if os.path.exists(self.tomcat_home + "\\webapps\\MicroStrategy"):
            self.web_home = self.tomcat_home + "\\webapps\\MicroStrategy"
            return True
        else:
            return False

    def check_library(self):
        if os.path.exists(self.tomcat_home + "\\webapps\\MicroStrategyLibrary"):
            self.library_home = self.tomcat_home + "\\webapps\\MicroStrategyLibrary"
            return True
        else:
            return False

    def i_server_enable_ssl(self, cert_path, key_path, key_password, ssl_port):
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
            with winreg.OpenKeyEx(reg, r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                                  0, winreg.KEY_ALL_ACCESS) as reg_key:
                winreg.SetValueEx(reg_key, "CertificatePath", 0, winreg.REG_SZ, cert_path)
                winreg.SetValueEx(reg_key, "KeyPath", 0, winreg.REG_SZ, key_path)
                winreg.SetValueEx(reg_key, "CertificateKeyPassword", 0, winreg.REG_SZ, key_password)
                winreg.SetValueEx(reg_key, "SSLPort", 0, winreg.REG_DWORD, int(hex(ssl_port), 16))

    def i_server_disable_ssl(self):
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
            with winreg.OpenKeyEx(reg, r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                                  0, winreg.KEY_ALL_ACCESS) as reg_key:
                winreg.SetValueEx(reg_key, "CertificatePath", 0, winreg.REG_SZ, "")
                winreg.SetValueEx(reg_key, "KeyPath", 0, winreg.REG_SZ, "")
                winreg.SetValueEx(reg_key, "CertificateKeyPassword", 0, winreg.REG_SZ, "")
                winreg.SetValueEx(reg_key, "SSLPort", 0, winreg.REG_DWORD, int(hex(4294967295), 16))

    def i_server_restart(self):
        if os.system('sc query "MicroStrategy Intelligence Server" | find "RUNNING" >nul') == 0:
            os.system('net stop "MicroStrategy Intelligence Server" && net start "MicroStrategy Intelligence Server"')
        else:
            os.system('net start "MicroStrategy Intelligence Server"')

    # Tomcat Configuration
    def tomcat_enable_ssl(self, keystore_path, keystore_pw):
        path = self.tomcat_home
        server_xml = eT.parse(path + "\\conf\\server.xml")
        root = server_xml.getroot()
        ssl_connector = root.find('Service/Connector[@port="8443"]')
        ssl_connector.set('keystoreFile', keystore_path)
        ssl_connector.set('keystorePass', keystore_pw)
        server_xml.write(self.tomcat_home + '\\conf\\server.xml')

    def tomcat_disable_ssl(self):
        path = self.tomcat_home
        server_xml = eT.parse(path + '\\conf\\server.xml')
        root = server_xml.getroot()
        ssl_connector = root.find('Service/Connector[@port="8443"]')
        ssl_connector.set('keystoreFile', '${user.home}/.keystore')
        ssl_connector.set('keystorePass', 'changeit')
        server_xml.write(self.tomcat_home + '\\conf\\server.xml')

    def tomcat_restart(self):
        if os.system('sc query "tomcat9" | find "RUNNING" >nul') == 0:
            os.system('net stop "tomcat9" && net start "tomcat9"')
        else:
            os.system('net start "tomcat9"')
        # Check if Tomcat is running
        # every 5 seconds check service status run request to see if Tomcat responds





