import os
import glob
import winreg
from xml.etree import ElementTree as eT
from machine import Machine

mstr_classpath = os.getenv('MSTR_CLASSPATH')
keystore_pw = 'm$tr!23'
keystore_path = 'c:\\ssl\\TSkeystore.pfx'
certificate_path = "C:\\ssl\\iserver_cert.pem"
key_path = "C:\\ssl\\iserver_key.pem"
# AES encrypted password, retrieved from the registry of a SSL enabled I-Server with password m$tr!23
key_password = "000000014ff340a763b7ac26c04176a958867b16069e1c44753d49" \
                   "5452d04e9ac9373ea6c5cc2e25c70cd0babe01729dd7cd80fa9ffb"
ssl_port = 39321

# Configure I-Server


# Execution
machine = Machine()
print("Configure MSTR environment with TLS/SSL certificates")
print("----------------------------------------------------")
print("Environment Details:")
print("[+] Intelligence Server {}".format("is installed." if machine.i_server_exists else "is not installed."))
print("[+] Tomcat {}".format("is installed." if machine.tomcat_exists else "not installed."))
print("  [-] Tomcat root directory: " + machine.tomcat_home if machine.tomcat_exists else "Not found")
print("[+] MicroStrategy Web {}".format("is deployed." if machine.web_exists
                                        else "is not deployed under the default name 'MicroStrategy'."))
print("  [-] MicroStrategy Web root directory: " + machine.web_home if machine.web_exists else "Not found")
print("[+] MicroStrategy Library {}".format("is deployed." if machine.library_exists
                                            else "is not deployed under the default name 'MicroStrategyLibrary'."))
print("  [-] MicroStrategy Library root directory: " + machine.library_home if machine.library_exists else "Not found")

action = input("Continue to configure all components? (Y/N) ")
if action == "Y":
    print("[+] Configuring Intelligence Server with SSL certificates.")
    machine.i_server_enable_ssl(certificate_path, key_path, key_password, ssl_port)
    print("  [-] Done.")
    print("[+] Restarting Intelligence Server.")
    machine.i_server_restart()
    print("  [-] Done.")
    print("[+] Configuring Tomcat with SSL keystore.")
    machine.tomcat_enable_ssl(keystore_path, keystore_pw)
    print("  [-] Done.")
    print("[+] Restarting Tomcat Service.")
    machine.tomcat_restart()
    print("  [-] Done. Tomcat may take a few minutes to become responsive.")
    print("\nConfiguration successful. The end.")

else:
    exit()
