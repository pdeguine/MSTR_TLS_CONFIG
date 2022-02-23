import os
import glob
import winreg
from xml.etree import ElementTree as eT

mstr_classpath = os.getenv('MSTR_CLASSPATH')
private_key_pw = 'm$tr!23'
keystore_path = 'c:\\ssl\\TSkeystore.pfx'
reg_certificate_path = "C:\\ssl\\iserver_cert.pem"
reg_key_path = "C:\\ssl\\iserver_key.pem"
# AES encrypted password, retrieved from the registry of a SSL enabled I-Server with password m$tr!23
reg_key_password = "000000014ff340a763b7ac26c04176a958867b16069e1c44753d49" \
                   "5452d04e9ac9373ea6c5cc2e25c70cd0babe01729dd7cd80fa9ffb"
reg_ssl_port = 39321


# Make the machine with components a class
def check_installed_components():
    tomcat_home = glob.glob(pathname=mstr_classpath + "\\Tomcat\\apache*")[0]
    if tomcat_home:
        #TODO: Check latest Tomcat version
        print(f"TOMCAT_HOME: {tomcat_home}")
    else:
        print(f"TOMCAT_HOME: No installation found.")

    # Library
    if tomcat_home:
        library_root = glob.glob(pathname=tomcat_home + "\\webapps\\MicroStrategyLibrary")[0]
        web_root = glob.glob(pathname=tomcat_home + "\\webapps\\MicroStrategy")[0]

        if library_root:
            print(f"LIBRARY_ROOT: {library_root}")
        else:
            print(f"LIBRARY_ROOT: No Library deployment found.")

        if web_root:
            print(f"WEB_ROOT: {web_root}")
        else:
            print(f"WEB_ROOT: No Web deployment found.")


# Configure I-Server
def i_server_enable_ssl():
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
        with winreg.OpenKeyEx(reg, r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                              0, winreg.KEY_ALL_ACCESS) as reg_key:
            winreg.SetValueEx(reg_key, "CertificatePath", 0, winreg.REG_SZ, reg_certificate_path)
            winreg.SetValueEx(reg_key, "KeyPath", 0, winreg.REG_SZ, reg_key_path)
            winreg.SetValueEx(reg_key, "CertificateKeyPassword", 0, winreg.REG_SZ, reg_key_password)
            winreg.SetValueEx(reg_key, "SSLPort", 0, winreg.REG_DWORD, int(hex(reg_ssl_port), 16))


def i_server_disable_ssl():
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
        with winreg.OpenKeyEx(reg, r'SOFTWARE\WOW6432Node\MicroStrategy\Data Sources\CastorServer',
                              0, winreg.KEY_ALL_ACCESS) as reg_key:
            winreg.SetValueEx(reg_key, "CertificatePath", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(reg_key, "KeyPath", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(reg_key, "CertificateKeyPassword", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(reg_key, "SSLPort", 0, winreg.REG_DWORD, int(hex(4294967295), 16))


def i_server_restart():
    if os.system('sc query "MicroStrategy Intelligence Server" | find "RUNNING" >nul') == 0:
        os.system('net stop "MicroStrategy Intelligence Server" && net start "MicroStrategy Intelligence Server"')
    else:
        os.system('net start "MicroStrategy Intelligence Server"')


# Tomcat Configuration
def tomcat_enable_ssl():
    path = glob.glob(pathname=mstr_classpath + "\\Tomcat\\apache*")[0]
    server_xml = eT.parse(path + "\\conf\\server.xml")
    root = server_xml.getroot()
    ssl_connector = root.find('Service/Connector[@port="8443"]')
    ssl_connector.set('keystoreFile', keystore_path)
    ssl_connector.set('keystorePass', private_key_pw)
    server_xml.write('server.xml')


def tomcat_disable_ssl():
    path = glob.glob(pathname=mstr_classpath + "\\Tomcat\\apache*")[0]
    server_xml = eT.parse(path + "\\conf\\server.xml")
    root = server_xml.getroot()
    ssl_connector = root.find('Service/Connector[@port="8443"]')
    ssl_connector.set('keystoreFile', '${user.home}/.keystore')
    ssl_connector.set('keystorePass', 'changeit')
    server_xml.write('server.xml')


def tomcat_restart():
    if os.system('sc query "tomcat9" | find "RUNNING" >nul') == 0:
        os.system('net stop "tomcat9" && net start "tomcat9"')
    else:
        os.system('net start "tomcat9"')
    # Check if Tomcat is running
    # every 5 seconds check service status run request to see if Tomcat responds


# MSTR applications

# Execution
print("Configure MSTR environment with TLS/SSL certificates")
print("----------------------------------------------------")
print("Environment Details:")
check_installed_components()
# print("Restarting Intelligence Server")
# i_server_restart()
# print("Restarting Tomcat")
# tomcat_restart()
# tomcat_enable_ssl()
# tomcat_disable_ssl()
# i_server_enable_ssl()
# i_server_disable_ssl()