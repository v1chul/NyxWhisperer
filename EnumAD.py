import subprocess
import sys
import re
import termios, tty

red = '\033[1;31m'
cyan = '\033[2;36m'
green = '\033[1;32m'
yellow = '\033[0;33m'
blue = '\033[0;34m'
purple = '\033[0;35m'   
reset = '\033[0m'

def flush_input():
    try:
        # Limpiar el buffer de entrada
        tty.setcbreak(sys.stdin.fileno())
        termios.tcflush(sys.stdin, termios.TCIOFLUSH)
    except Exception as e:
        # No se pudo limpiar el buffer de entrada, manejar el error según sea necesario
        print(f"No se pudo limpiar el buffer de entrada: {e}")

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

def clean_ansi_escape(output):
    # Función para limpiar los códigos ANSI.
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', output)

def run_smb_module():
    # Primer comando: CrackMapExec para obtener cuentas SMB con credenciales nulas
    cmd = "crackmapexec smb masscan/smb -u '' -p '' | grep + | tee loot/SMBnull.txt "
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        clean_output = clean_ansi_escape(output)
        with open('loot/SMBnull.txt', 'w') as f:
            f.write(clean_output)
        print(green + "SMB Null:" + reset)
        print(cyan + clean_output + reset)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando CrackMapExec para cuentas SMB nulas: {e}")
    
    # Segundo comando: Extraer las IPs y verificar los shares con permisos de lectura
    cmd = "awk '{print $2}' loot/SMBnull.txt > loot/SMBnullIPs.txt"
    subprocess.run(cmd, shell=True, check=True)
    cmd = "crackmapexec smb loot/SMBnullIPs.txt -u '' -p '' --shares | grep READ | tee loot/SMBnullShares.txt"
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        clean_output = clean_ansi_escape(output)
        with open('loot/SMBnullShares.txt', 'w') as f:
            f.write(clean_output)
        print(green + "SMB Null Shares:" + reset)
        print(cyan + clean_output + reset)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando CrackMapExec para shares SMB nulas: {e}")

    # Tercer comando: Identificar hosts que soportan SMBv1
    cmd = "crackmapexec smb masscan/smb | grep 'SMBv1:True'  | awk '{print $2}' | tee loot/SMBv1.txt"
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        smb_v1_output = result.stdout
        with open('loot/SMBv1.txt', 'w') as f:
            f.write(smb_v1_output)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar CrackMapExec para identificar SMBv1: {e}")

    # Cuarto comando: Usar Metasploit para comprobar la vulnerabilidad MS17-010 en hosts que soportan SMBv1
    cmd = "msfconsole -q -x 'use auxiliary/scanner/smb/smb_ms17_010; set rhosts file:loot/SMBv1.txt; run; exit' |tee loot/EternalBlue.txt"
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        eternalblue_output = result.stdout
        clean_output = clean_ansi_escape(eternalblue_output)
        with open('loot/EternalBlue.txt', 'w') as f:
            f.write(clean_output)
        print(green + "EternalBlue Positive:" + reset)
        print(cyan + clean_output + reset)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Metasploit para comprobar MS17-010 (EternalBlue): {e}")


def run_rdp_module():
        cmd = "msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set rhosts file:./masscan/rdp; run;exit' | tee loot/BlueKeep.txt"
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

            # Limpia la salida y guarda en un archivo
            clean_output = clean_ansi_escape(output)
            with open('loot/BlueKeep.txt', 'w') as f:
                f.write(clean_output)

            print(green + "Bluekeep Positive:" + reset)
            print(cyan + clean_output + reset)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")
            
def run_rpc_module():
    # Leer las IPs del archivo
    with open('masscan/rpc', 'r') as file:
        ips = file.readlines()

    # Eliminar los saltos de línea y espacios extra
    ips = [ip.strip() for ip in ips]

    for ip in ips:
        cmd = f"rpcclient -U '' {ip} -N -c 'enumdomusers' | tee loot/RPCnull.txt"
        try:
            #subprocess.run, espera a que se complete la salida antes de dar cualquier salida.
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

            # Procesar y guardar la salida según sea necesario
            # ...
            print(f"Resultados para {ip}:\n{output}")

        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar rpcclient para la IP {ip}: {e}")

def run_kerberos_module():
    # Indicar el nombre del dominio del archivo
    Dominio = input( yellow + "Introduce el nombre del dominio (por ejemplo, xyz.local): " + reset)
    ip = input(yellow + "Introduce la IP del DC (por ejemplo, 192.168.1.3): " + reset)
    threads = input(yellow + "Introduce el número de hilos (por defecto, 300): " + reset)
    
    # Proporciona un valor predeterminado para 'threads' si el usuario no introduce nada
    if not threads:
        threads = "300"

    # comando de kerbrute por defecto guardandolo en un archivo con su ip
    cmd = f"kerbrute userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -d {Dominio} --dc {ip} -t {threads} | tee loot/kerberosusers{ip}.txt"
    try:
        # subprocess.Popen, que te permite leer la salida del proceso en tiempo real.
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Lee la salida en tiempo real
        for output_line in iter(process.stdout.readline, ''):
            if '[+] VALID USERNAME:' in output_line:
                # Muestra o guarda los nombres de usuario válidos
                print(output_line.strip())

        # Espera a que el proceso termine y obtiene el estado final
        process.wait()

        if process.returncode != 0:
            # Manejo de errores si el proceso no termina correctamente
            print(f"Error al ejecutar kerbrute para la IP {ip}: Proceso terminó con código {process.returncode}")

    except Exception as e:
        # Manejo general de excepciones
        print(f"Error al ejecutar kerbrute para la IP {ip}: {e}")
        
def run_vnc_module():
        cmd = "msfconsole -q -x 'use auxiliary/scanner/vnc/vnc_none_auth; set rhosts file:./masscan/vnc; run;exit'  | tee loot/vncNoneAuth.txt"
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

            # Limpia la salida y guarda en un archivo
            clean_output = clean_ansi_escape(output)
            with open('loot/vncNoneAuth.txt', 'w') as f:
                f.write(clean_output)

            print(green + "VNC none auth:" + reset)
            print(cyan + clean_output + reset)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")
                    
def run_ldap_module():
    try:
        # Primero, ejecutamos el comando para LDAP sobre SSL
        cmd_ldaps = "msfconsole -q -x 'use auxiliary/gather/ldap_hashdump; set rhosts file:./masscan/ldap_ssl; run; exit'"
        result = subprocess.run(cmd_ldaps, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        # Limpia la salida y guarda en el archivo para LDAPS
        clean_output = clean_ansi_escape(output)
        with open('loot/NoneAuthLDAPS.txt', 'w') as f:
            f.write(clean_output)

        print(green + "LDAPs Hash dump:" + reset)
        print(cyan + clean_output + reset)

        # Luego, ejecutamos el comando para LDAP sin SSL
        cmd_ldap = "msfconsole -q -x 'use auxiliary/gather/ldap_hashdump; set rhosts file:./masscan/ldap; set rport 389; set ssl false; run; exit'"
        result = subprocess.run(cmd_ldap, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        # Limpia la salida y guarda en el archivo para LDAP
        clean_output = clean_ansi_escape(output)
        with open('loot/NoneAuthLDAP.txt', 'w') as f:
            f.write(clean_output)

        print(green + "LDAP Hash dump:" + reset)
        print(cyan + clean_output + reset)

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando: {e}")      
            
def run_ftp_module():
        cmd = "msfconsole -q -x 'use auxiliary/scanner/ftp/anonymous; set rhosts file:./masscan/ftp; run;exit' |tee loot/FTPanon.txt"

        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

            # Limpia la salida y guarda en un archivo
            clean_output = clean_ansi_escape(output)
            with open('loot/FTPanon.txt', 'w') as f:
                f.write(clean_output)

            print(green + "FTP anonymous:" + reset)
            print(cyan + clean_output + reset)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")            
 
def run_http_module():
    try:
        # Concatenar y formatear URLs para Eyewitness
        http_cmd = "awk '{printf \"http://%s/\\n\", $1}' masscan/http > loot/http_eyewitness"
        https_cmd = "awk '{printf \"https://%s/\\n\", $1}' masscan/https >> loot/http_eyewitness"
        
        # Ejecutar los comandos de preparación
        subprocess.run(http_cmd, shell=True, check=True)
        subprocess.run(https_cmd, shell=True, check=True)

        # Ejecutar Eyewitness
        eyewitness_cmd = "eyewitness -f loot/http_eyewitness -d loot/screenshots --no-prompt"
        result = subprocess.run(eyewitness_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Si todo va bien, imprime la salida estándar
        print(result.stdout)
        print(green + "Eyewitness Completado" + reset)

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando: {e}")
    except Exception as e:
        print(f"Error no esperado: {e}")   

def main():
    while True:
        try:
            print("Selecciona los módulos para ejecutar:")
            print("1. ALL")
            print("2. SMB")
            print("3. RDP")
            print("4. RPC")
            print("5. KERBEROS")
            print("6. FTP")
            print("7. HTTP(S)")
            print("8. VNC")
            print("9. LDAP(s)")
            print("0. Salir")
            choice_input = input("Introduce tu elección (por ejemplo, 1,2): ")

            if choice_input.strip() == "":
                print(red + "No se ha introducido ninguna opción. Por favor, intenta de nuevo." + reset)
                continue

            choices = choice_input.strip().split(',')
            valid_choices = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

            if all(choice in valid_choices for choice in choices):
                 if '1' in choices:
            # Reemplazar la elección 'ALL' por todas las opciones de módulo
                     run_module(['2', '3', '4', '5', '6', '7', '8', '9'])
 
                 else:
                     run_module(choices)
            else:
                print(red + "Opción no válida. Por favor, introduce números del 0 al 9, separados por comas." + reset)

        except EOFError:
            print(red + "\nEOFError capturado: entrada no válida. Saliendo del programa." + reset)
            sys.exit(1)
        except Exception as e:
            print(red + f"\nError inesperado: {e}. Saliendo del programa." + reset)
            sys.exit(1)

        
def run_module(choice):
    if '0' in choice:
        # Llamar al módulo SMB anon y null con cme
        exit()
    if '2' in choice:
        # Llamar al módulo SMB anon y null con cme
        print( red + "2. SMB" + reset)
        run_smb_module()
    if '3' in choice:
        # Llamar al módulo RDP  
        print( red + "3. RDP" + reset)
        run_rdp_module()   
    if '4' in choice:
        # Llamar al módulo RPC null 
        print( red + "4. RPC" + reset)
        run_rpc_module()
    if '5' in choice:
        # enumeración por kerberos
        print( red + "5. KERBEROS" + reset)
        run_kerberos_module()
    if '6' in choice:
        # Llamar al módulo ftp anon msfconsole
        print( red + "6. FTP" + reset)
        run_ftp_module()
    if '7' in choice:
        # Llamar al módulo EYEwitness
        print( red + "7. HTTP(s)" + reset)
        run_http_module()
    if '8' in choice:
        #Llamar al módulo RPC
        print( red + "8. VNC" + reset)
        run_vnc_module()
    if '9' in choice:
        # Llamar al módulo LDAP
        print(red + "9. LDAP" + reset)
        run_ldap_module()
    
if __name__ == "__main__":
    print(purple + """
 _   _           __        ___     _                              
| \ | |_   ___  _\ \      / / |__ (_)___ _ __   ___ _ __ ___ _ __ 
|  \| | | | \ \/ /\ \ /\ / /| '_ \| / __| '_ \ / _ \ '__/ _ \ '__|
| |\  | |_| |>  <  \ V  V / | | | | \__ \ |_) |  __/ | |  __/ |   
|_| \_|\__, /_/\_\  \_/\_/  |_| |_|_|___/ .__/ \___|_|  \___|_|   
       |___/                            |_|                       
                                                                """ + reset)
    print(green + """                                                               by V1chul""" + reset)
    main()
