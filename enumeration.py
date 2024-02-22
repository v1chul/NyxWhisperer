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
        cmd = "crackmapexec smb masscan/smb -u '' -p '' | grep + | tee loot/SMBnull.txt"
        
        sys.stdin.close()
        sys.stdin = open('/dev/tty', 'r')
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

            # Limpia la salida y guarda en un archivo
            clean_output = clean_ansi_escape(output)
            with open('loot/SMBnull.txt', 'w') as f:
                f.write(clean_output)

            print(green + "SMB Null:" + reset)
            print(cyan + clean_output + reset)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")
        
        cmd = "awk '{print $2}' loot/SMBnull.txt > loot/SMBnullIPs.txt & crackmapexec smb loot/SMBnullIPs.txt  -u '' -p '' --shares | tee loot/SMBnullShares.txt"
        sys.stdin.close()
        sys.stdin = open('/dev/tty', 'r')
        
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

            # Limpia la salida y guarda en un archivo
            clean_output = clean_ansi_escape(output)
            with open('loot/SMBnullShares.txt', 'w') as f:
                f.write(clean_output)

            print(green + "SMB Null Shares:" + reset)
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

def main_menu():
    while True:
        try:
            print("Selecciona los módulos para ejecutar:")
            print("1. ALL")
            print("2. SMB")
            print("3. RPC")
            print("4. KERBEROS")
            print("5. FTP")
            print("6. HTTP(S)")
            print("0. Salir")
            choice_input = input("Introduce tu elección (por ejemplo, 1,2): ")

            if choice_input.strip() == "":
                print(red + "No se ha introducido ninguna opción. Por favor, intenta de nuevo." + reset)
                continue

            choices = choice_input.strip().split(',')
            valid_choices = ['0', '1', '2', '3', '4', '5', '6']

            if all(choice in valid_choices for choice in choices):
                return choices
            else:
                print(red + "Opción no válida. Por favor, introduce números del 0 al 6, separados por comas." + reset)

        except EOFError:
            print(red + "\nEOFError capturado: entrada no válida. Saliendo del programa." + reset)
            sys.exit(1)
        except Exception as e:
            print(red + f"\nError inesperado: {e}. Saliendo del programa." + reset)
            sys.exit(1)

        
def run_module(choice):
    if '1' in choice:
        # Llamar a todos los modulos
        print("1. ALL")
    if '2' in choice:
        # Llamar al módulo SMB anon y null con cme
        print( red + "2. SMB" + reset)
        run_smb_module()
       
    if '3' in choice:
        # Llamar al módulo RPC null 
        print( red + "3. RPC" + reset)
        run_rpc_module()
    if '4' in choice:
        # enumeración por kerberos
        print( red + "4. KERBEROS" + reset)
        run_kerberos_module()
    if '5' in choice:
        # Llamar al módulo ftp anon msfconsole
        print("5. FTP")
    if '6' in choice:
        # Llamar al módulo EYEwitness
        print("6. HTTP")
    #if '7' in choice:
        # Llamar al módulo RPC
        #print("")
def main():
    while True:
        user_choice = main_menu()
        if user_choice == '0':
            break
        run_module(user_choice)

if __name__ == "__main__":
    main()
