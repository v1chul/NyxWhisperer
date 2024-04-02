import os
from sys import argv
import subprocess
import signal
import sys


def handler(sig, frame):

    sys.exit(0)


# Instalar el controlador de señales

signal.signal(signal.SIGINT, handler)

def run_cmd(cmd):
    try:
        process = subprocess.Popen(['/bin/bash', '-c', cmd])
        process.wait()
    except KeyboardInterrupt:
        print('\nInterrupción del usuario detectada, terminando el proceso...')
        process.terminate()  # o process.kill() si terminate() no funciona
        try:
            process.wait(timeout=5)  # Esperar un poco para que el proceso termine
        except subprocess.TimeoutExpired:
            process.kill()  # Forzar la terminación si aún no se detiene
        sys.exit(0)
# Colors
red = '\033[1;31m'
cyan = '\033[2;36m'
green = '\033[1;32m'
reset = '\033[0m'

print(green + "Scanner" + reset)
print(cyan + "Version: 0.1" + reset)

print(red + "DIRECTORY STRUCTURE" + reset)
print(cyan + "Writing directory structure" + reset)
# Create directories where the information will be stored
if not os.path.exists("masscan"):
    os.mkdir("masscan")
if not os.path.exists("vulns"):
    os.mkdir("vulns")
if not os.path.exists("loot"):
    os.mkdir("loot")
if not os.path.exists("relay"):
    os.mkdir("relay")
if not os.path.exists("users"):
    os.mkdir("users")


print(red + "Discovery" + reset)

if __name__ == "__main__":

    
    input_file = argv[1] if len(argv) > 1 else None
    exclude_file = argv[2] if len(argv) > 2 else None
    if not input_file or not os.path.isfile(input_file):
        print('Error: El archivo de rangos a examinar no se ha proporcionado o no existe.')
        sys.exit(1)

# Common Windows services
    if exclude_file:
        print(cyan + "SMB" + reset)
        cmd = f"sudo masscan -iL {input_file} -p445 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/smb"
        run_cmd(cmd)
        print(green + "SMB:" + reset, len([x for x in open('masscan/smb')]))

        print(cyan + "RDP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p3389 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/rdp"
        run_cmd(cmd)
        print(green + "RDP:" + reset, len([x for x in open('masscan/rdp')]))

        print(cyan + "WinRM" + reset)
        cmd = f"sudo masscan -iL {input_file} -p5985,5986 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/winrm"
        run_cmd(cmd)
        print(green + "WinRM:" + reset, len([x for x in open('masscan/winrm')]))

        print(cyan + "RPC" + reset)
        cmd = f"sudo masscan -iL {input_file} -p139 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/rpc"
        run_cmd(cmd)
        print(green + "RPC:" + reset, len([x for x in open('masscan/rpc')]))

        print(cyan + "LDAP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p389 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/ldap"
        run_cmd(cmd)
        print(green + "LDAP:" + reset, len([x for x in open('masscan/ldap')]))

        print(cyan + "LDAPS" + reset)
        cmd = f"sudo masscan -iL {input_file} -p636 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/ldap_ssl"
        run_cmd(cmd)
        print(green + "LDAPS:" + reset, len([x for x in open('masscan/ldap_ssl')]))

        print(cyan + "Kerberos" + reset)
        cmd = f"sudo masscan -iL {input_file} -p88 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/kerberos"
        run_cmd(cmd)
        print(green + "Kerberos:" + reset, len([x for x in open('masscan/kerberos')]))

        # Common Linux Server Services
        print(cyan + "FTP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p21 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/ftp"
        run_cmd(cmd)
        print(green + "FTP:" + reset, len([x for x in open('masscan/ftp')]))

        print(cyan + "SSH" + reset)
        cmd = f"sudo masscan -iL {input_file} -p22 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/ssh"
        run_cmd(cmd)
        print(green + "SSH:" + reset, len([x for x in open('masscan/ssh')]))

        print(cyan + "VNC" + reset)
        cmd = f"sudo masscan -iL {input_file} -p5900 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/vnc"
        run_cmd(cmd)
        print(green + "VNC:" + reset, len([x for x in open('masscan/vnc')]))

        # Database Server Services
        print(cyan + "MSSQL" + reset)
        cmd = f"sudo masscan -iL {input_file} -p1433 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/MSSQL"
        run_cmd(cmd)
        print(green + "MSSQL:" + reset, len([x for x in open('masscan/MSSQL')]))

        print(cyan + "MySQL" + reset)
        cmd = f"sudo masscan -iL {input_file} -p3306 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/MySQL"
        run_cmd(cmd)
        print(green + "MySQL:" + reset, len([x for x in open('masscan/MySQL')]))

        print(cyan + "OracleDB" + reset)
        cmd = f"sudo masscan -iL {input_file} -p1521 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/oracledb"
        run_cmd(cmd)
        print(green + "Oracle DB:" + reset, len([x for x in open('masscan/oracledb')]))

        print(cyan + "SMTP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p25 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/smtp"
        run_cmd(cmd)
        print(green + "SMTP:" + reset, len([x for x in open('masscan/smtp')]))

        print(cyan + "RSYNC" + reset)
        cmd = f"sudo masscan -iL {input_file} -p873 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/rsync"
        run_cmd(cmd)
        print(green + "RSYNC:" + reset, len([x for x in open('masscan/rsync')]))

        # Web Services
        print(cyan + "HTTP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p80 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/http"
        run_cmd(cmd)
        print(green + "HTTP:" + reset, len([x for x in open('masscan/http')]))

        print(cyan + "HTTPS" + reset)
        cmd = f"sudo masscan -iL {input_file} -p443 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/https"
        run_cmd(cmd)
        print(green + "HTTPS:" + reset, len([x for x in open('masscan/https')]))

        print(cyan + "ALTERNATIVE WEB PORTS" + reset)
        print(cyan + "8080" + reset)
        cmd = f"sudo masscan -iL {input_file} -pU:623 --rate 10000 --excludefile {exclude_file} | awk {{'printf \"%s:8080\\n\", $6'}} >> masscan/web_altport"
        run_cmd(cmd)
        print(cyan + "8081" + reset)
        cmd = f"sudo masscan -iL {input_file} -p8081 --rate 10000 --excludefile {exclude_file} | awk '{{printf \"%s:8081\\n\", $6}}' >> masscan/web_altport"
        run_cmd(cmd)
        print(cyan + "8443" + reset)
        cmd = f"sudo masscan -iL {input_file} -p8443 --rate 10000 --excludefile {exclude_file} | awk '{{printf \"%s:8443\\n\", $6}}' >> masscan/web_altport"
        run_cmd(cmd)
        print(green + "Alternative ports web:" + reset, len([x for x in open('masscan/web_altport')]))

        # Miscellaneous Services
        print(cyan + "RSH" + reset)
        cmd = f"sudo masscan -iL {input_file} -p514 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/rsh"
        run_cmd(cmd)
        print(green + "RSH:" + reset, len([x for x in open('masscan/rsh')]))

        print(cyan + "Telnet" + reset)
        cmd = f"sudo masscan -iL {input_file} -p23 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/telnet"
        run_cmd(cmd)
        print(green + "TELNET:" + reset, len([x for x in open('masscan/telnet')]))

        print(cyan + "Java RMI" + reset)
        cmd = f"sudo masscan -iL {input_file} -p1099 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/rmi"
        run_cmd(cmd)
        print(green + "JAVA RMI:" + reset, len([x for x in open('masscan/rmi')]))

        # UDP scan
        print(cyan + "IPMI" + reset)
        cmd = f"sudo masscan -iL {input_file} -pU:623 --rate 10000 --excludefile {exclude_file} | awk '{{print $6}}'  > masscan/ipmi"
        run_cmd(cmd)
        print(green + "IPMI:" + reset, len([x for x in open('masscan/ipmi')]))
    else:
        print(cyan + "SMB" + reset)
        cmd = f"sudo masscan -iL {input_file} -p445 --rate 10000  | awk '{{print $6}}'  > masscan/smb"
        run_cmd(cmd)
        print(green + "SMB:" + reset, len([x for x in open('masscan/smb')]))

        print(cyan + "RDP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p3389 --rate 10000  | awk '{{print $6}}'  > masscan/rdp"
        run_cmd(cmd)
        print(green + "RDP:" + reset, len([x for x in open('masscan/rdp')]))

        print(cyan + "WinRM" + reset)
        cmd = f"sudo masscan -iL {input_file} -p5985,5986 --rate 10000  | awk '{{print $6}}'  > masscan/winrm"
        run_cmd(cmd)
        print(green + "WinRM:" + reset, len([x for x in open('masscan/winrm')]))

        print(cyan + "RPC" + reset)
        cmd = f"sudo masscan -iL {input_file} -p139 --rate 10000  | awk '{{print $6}}'  > masscan/rpc"
        run_cmd(cmd)
        print(green + "RPC:" + reset, len([x for x in open('masscan/rpc')]))

        print(cyan + "LDAP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p389 --rate 10000  | awk '{{print $6}}'  > masscan/ldap"
        run_cmd(cmd)
        print(green + "LDAP:" + reset, len([x for x in open('masscan/ldap')]))

        print(cyan + "LDAPS" + reset)
        cmd = f"sudo masscan -iL {input_file} -p636 --rate 10000  | awk '{{print $6}}'  > masscan/ldap_ssl"
        run_cmd(cmd)
        print(green + "LDAPS:" + reset, len([x for x in open('masscan/ldap_ssl')]))

        print(cyan + "Kerberos" + reset)
        cmd = f"sudo masscan -iL {input_file} -p88 --rate 10000  | awk '{{print $6}}'  > masscan/kerberos"
        run_cmd(cmd)
        print(green + "Kerberos:" + reset, len([x for x in open('masscan/kerberos')]))

        # Common Linux Server Services
        print(cyan + "FTP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p21 --rate 10000  | awk '{{print $6}}'  > masscan/ftp"
        run_cmd(cmd)
        print(green + "FTP:" + reset, len([x for x in open('masscan/ftp')]))

        print(cyan + "SSH" + reset)
        cmd = f"sudo masscan -iL {input_file} -p22 --rate 10000  | awk '{{print $6}}'  > masscan/ssh"
        run_cmd(cmd)
        print(green + "SSH:" + reset, len([x for x in open('masscan/ssh')]))

        print(cyan + "VNC" + reset)
        cmd = f"sudo masscan -iL {input_file} -p5900 --rate 10000  | awk '{{print $6}}'  > masscan/vnc"
        run_cmd(cmd)
        print(green + "VNC:" + reset, len([x for x in open('masscan/vnc')]))

        # Database Server Services
        print(cyan + "MSSQL" + reset)
        cmd = f"sudo masscan -iL {input_file} -p1433 --rate 10000  | awk '{{print $6}}'  > masscan/MSSQL"
        run_cmd(cmd)
        print(green + "MSSQL:" + reset, len([x for x in open('masscan/MSSQL')]))

        print(cyan + "MySQL" + reset)
        cmd = f"sudo masscan -iL {input_file} -p3306 --rate 10000  | awk '{{print $6}}'  > masscan/MySQL"
        run_cmd(cmd)
        print(green + "MySQL:" + reset, len([x for x in open('masscan/MySQL')]))

        print(cyan + "OracleDB" + reset)
        cmd = f"sudo masscan -iL {input_file} -p1521 --rate 10000  | awk '{{print $6}}'  > masscan/oracledb"
        run_cmd(cmd)
        print(green + "Oracle DB:" + reset, len([x for x in open('masscan/oracledb')]))

        print(cyan + "SMTP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p25 --rate 10000  | awk '{{print $6}}'  > masscan/smtp"
        run_cmd(cmd)
        print(green + "SMTP:" + reset, len([x for x in open('masscan/smtp')]))

        print(cyan + "RSYNC" + reset)
        cmd = f"sudo masscan -iL {input_file} -p873 --rate 10000  | awk '{{print $6}}'  > masscan/rsync"
        run_cmd(cmd)
        print(green + "RSYNC:" + reset, len([x for x in open('masscan/rsync')]))

        # Web Services
        print(cyan + "HTTP" + reset)
        cmd = f"sudo masscan -iL {input_file} -p80 --rate 10000  | awk '{{print $6}}'  > masscan/http"
        run_cmd(cmd)
        print(green + "HTTP:" + reset, len([x for x in open('masscan/http')]))

        print(cyan + "HTTPS" + reset)
        cmd = f"sudo masscan -iL {input_file} -p443 --rate 10000  | awk '{{print $6}}'  > masscan/https"
        run_cmd(cmd)
        print(green + "HTTPS:" + reset, len([x for x in open('masscan/https')]))

        print(cyan + "ALTERNATIVE WEB PORTS" + reset)
        print(cyan + "8080" + reset)
        cmd = f"sudo masscan -iL {input_file} -pU:623 --rate 10000  | awk {{'printf \"%s:8080\\n\", $6'}} >> masscan/web_altport"
        run_cmd(cmd)
        print(cyan + "8081" + reset)
        cmd = f"sudo masscan -iL {input_file} -p8081 --rate 10000  | awk '{{printf \"%s:8081\\n\", $6}}' >> masscan/web_altport"
        run_cmd(cmd)
        print(cyan + "8443" + reset)
        cmd = f"sudo masscan -iL {input_file} -p8443 --rate 10000  | awk '{{printf \"%s:8443\\n\", $6}}' >> masscan/web_altport"
        run_cmd(cmd)
        print(green + "Alternative ports web:" + reset, len([x for x in open('masscan/web_altport')]))

        # Miscellaneous Services
        print(cyan + "RSH" + reset)
        cmd = f"sudo masscan -iL {input_file} -p514 --rate 10000  | awk '{{print $6}}'  > masscan/rsh"
        run_cmd(cmd)
        print(green + "RSH:" + reset, len([x for x in open('masscan/rsh')]))

        print(cyan + "Telnet" + reset)
        cmd = f"sudo masscan -iL {input_file} -p23 --rate 10000  | awk '{{print $6}}'  > masscan/telnet"
        run_cmd(cmd)
        print(green + "TELNET:" + reset, len([x for x in open('masscan/telnet')]))

        print(cyan + "Java RMI" + reset)
        cmd = f"sudo masscan -iL {input_file} -p1099 --rate 10000  | awk '{{print $6}}'  > masscan/rmi"
        run_cmd(cmd)
        print(green + "JAVA RMI:" + reset, len([x for x in open('masscan/rmi')]))

        # UDP scan
        print(cyan + "IPMI" + reset)
        cmd = f"sudo masscan -iL {input_file} -pU:623 --rate 10000  | awk '{{print $6}}'  > masscan/ipmi"
        run_cmd(cmd)
        print(green + "IPMI:" + reset, len([x for x in open('masscan/ipmi')]))
