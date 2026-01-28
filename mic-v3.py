
import hmac,hashlib
from pbkdf2 import PBKDF2
import binascii
import os
import sys


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
    print(f"#     {WHITE}@@@@@@@@@@@@@@@/      \\@@@/   @{RESET}        {WHITE}[{VIVID_RED}+{WHITE}]{RESET} Cyber-Weapon:............. WPA2-PSK Cracker    #")
    print(f"#    {WHITE}@@@@@@@@@@@@@@@@\\  {VIVID_RED}O{WHITE}   @@  @ {VIVID_RED}O{WHITE} @{RESET}        {WHITE}[{VIVID_RED}+{WHITE}]{RESET} Version:.................. 4.0                 #")
    print(f"#    {WHITE}@@@@@@@@@@@@@ @@@@@@@@@@  | \\@@@@@{RESET}      {WHITE}[{VIVID_RED}+{WHITE}]{RESET} Author:................... Fz3r0               #")
    print(f"#    {WHITE}@@@@@@@@@@@@@ @@@@@@@@@\\__@_/@@@@@{RESET}      {WHITE}[{VIVID_RED}+{WHITE}]{RESET} Github:................... github.com/Fz3r0    #")
    print(f"#     {WHITE}@@@@@@@@@@@@@@@/,/,/./'/_|.\\'\\,\\{RESET}       {WHITE}[{VIVID_RED}+{WHITE}]{RESET} Twitter:.................. @Fz3r0_OPs          #")
    print(f"#       {WHITE}@@@@@@@@@@@@@|  | | | | | | | |{RESET}      {WHITE}[{VIVID_RED}+{WHITE}]{RESET} Youtube:.................. @Fz3r0_OPs          #")
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
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} The tool is developed exclusively for educational purposes.")   
    print(f"{WHITE}[{RED}!{WHITE}]{RESET} The author assume no responsibility for any misuse of this tool!!!")
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

# Function: Clear Screen for Windows or Linux
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
    # Recommended: store both bytes + hex (easy for crypto + easy for printing)
    pmk_bytes = b''
    PMK = ''   # hex string
    ptk_bytes = b''
    PTK = ''   # hex string



## CLASS: Variables para erl tipo de ataque (esto ayuda para que las fucniones sepan que tan "deep" ir)
class switches:
    attack_type = 0
    pass_given = 0
  
#######################################################################################
#
# FORMULARIO DE VARIABLES
#

## Instrucciones con banner antes del formulario
def input_data_how():

    ## Instructions
    clear_screen()
    banner()

    viewdata()    
    print(f"{BOLD}{WHITE}###{RED} INSTRUCTIONS:{RESET} \n")
    print(f"{WHITE}[{NEON_YELLOW}1{WHITE}]{RESET} Capture a 802.11 Wi-Fi WPA2-PSK Authentication/Assocation/RSA process: \n")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} M1 & M2 EAPOL Frames MUST be captured during the 4-way-handshake. {RESET}")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} Use M1 & M2 information to fill the requested data. {RESET} \n")
    print(f"{WHITE}[{NEON_YELLOW}2{WHITE}]{RESET} String data like SSIDs or Passwords can be added manually or copy/paste, eg: \n")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} Fz3r0::CWAP {RESET} \n")
    print(f"{WHITE}[{NEON_YELLOW}3{WHITE}]{RESET} MAC Addresses MUST be entered in the following format: \n")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} F0:F1:F2:F3:F4:F5:F6 {WHITE}or{VIBRANT_CYAN} f0:f1:f2:f3:f4:f6:f6 {RESET} \n")
    print(f"{WHITE}[{NEON_YELLOW}4{WHITE}]{RESET} All Hexadecimal data MUST be extracted from the .pcap as HEX Stream, eg.: \n")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} f1b3a392f9a10693e031deb0edb996c27974f297c7963c005a5cd36116c80777 {RESET}")
    line()
    

## Formulario: Ingresar Valores de Variables en shell
def testdata():

    ## SSID   (Default: Fz3r0::CWAP)
    input_data_how()
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET}{BOLD} Paste the {VIVID_RED}SSID{RESET} of the {NEON_ORANGE}WLAN \n")
    print()
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default SSID:{VIVID_RED} Fz3r0::CWAP {RESET}\n") 
    WPA2Handshake.ssid        = input(f"{BOLD}{WHITE}->> {RESET}") or "Fz3r0::CWAP"

    ## AP     (Default: Telmex)
    input_data_how()
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET}{BOLD} Paste the {VIVID_RED}WLAN ADDRESS{RESET} of the {NEON_ORANGE}AP (BSSID) \n")
    print()    
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default AP WLAN ADDRESS (BSSID):{VIVID_RED} 50:4e:dc:90:2e:b8 {RESET}\n") 
    WPA2Handshake.macAP       = input(f"{BOLD}{WHITE}->> {RESET}") or "50:4e:dc:90:2e:b8"

    ## STA    (Default: Xiaomi Phone)
    input_data_how()
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET}{BOLD} Paste the {VIVID_RED}WLAN ADDRESS{RESET} of {NEON_ORANGE}client STA")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{BOLD} Hint: {RESET}{BRIGHT_AQUA}select {NEON_YELLOW} client STA WLAN ADDRESS {BRIGHT_AQUA}from any {NEON_YELLOW} Receiver Address (RA) {WHITE}/ {NEON_YELLOW}Transmitter Address (TA) frame corresponding to the {NEON_ORANGE}client STA \n")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default CLIENT STA WLAN ADDRESS:{VIVID_RED} 3c:13:5a:f2:46:88 {RESET}\n")     
    WPA2Handshake.macCli      = input(f"{BOLD}{WHITE}->> {RESET}") or "3c:13:5a:f2:46:88"

    ## Anonce (Default: M1 nonce (nonce from the AP/Authenticator)
    input_data_how()
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET}{BOLD} Paste the {VIVID_RED}ANONCE{RESET} - EAPOL M1 Nonce - AP/Authenticator Nonce {RESET}")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{BOLD} Hint: {RESET}{BRIGHT_AQUA}select {NEON_YELLOW}EAPOL M1 {WHITE}>> {VIVID_RED}Nonce {WHITE}<< {BRIGHT_AQUA}then {NEON_YELLOW}Right Click {WHITE}/ {NEON_YELLOW}Copy {WHITE}> {NEON_YELLOW}As HEX Stream \n")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default ANONCE:{VIVID_RED} f1b3a392f9a10693e031deb0edb996c27974f297c7963c005a5cd36116c80777 {RESET}\n")    
    WPA2Handshake.anonce      = input(f"{BOLD}{WHITE}->>{RESET}") or "f1b3a392f9a10693e031deb0edb996c27974f297c7963c005a5cd36116c80777"

    ## Snonce = M2 nonce (nonce from the STA/Supplicant)
    input_data_how()  
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET}{BOLD} Paste the {VIVID_RED}SNONCE{RESET} - EAPOL M2 HEX Nonce - STA/Supplicant Nonce {RESET}")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{BOLD} Hint: {RESET}{BRIGHT_AQUA}select {NEON_YELLOW}EAPOL M2 {WHITE}>> {VIVID_RED}Nonce {WHITE}<< {BRIGHT_AQUA}then {NEON_YELLOW}Right Click {WHITE}/ {NEON_YELLOW}Copy {WHITE}> {NEON_YELLOW}As HEX Stream \n")
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default SNONCE:{VIVID_RED} a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0 {RESET}\n")    
    WPA2Handshake.snonce      = input(f"{BOLD}{WHITE}->>{RESET}") or "a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0"

    ## MIC = M2 nonce (nonce from the STA/Supplicant)
    input_data_how() 
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET}{BOLD} Paste the {VIVID_RED}MIC{RESET} - EAPOL M2 HEX MIC {RESET}")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{BOLD} Hint: {RESET}{BRIGHT_AQUA}select {NEON_YELLOW}EAPOL M2 {WHITE}>> {VIVID_RED}MIC {WHITE}<< {BRIGHT_AQUA}then {NEON_YELLOW}Right Click {WHITE}/ {NEON_YELLOW}Copy {WHITE}> {NEON_YELLOW}As HEX Stream \n")    
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default MIC:{VIVID_RED} 07d2e88db2254f675d349996ef95ad93 {RESET}\n")    
    WPA2Handshake.mic         = input(f"{BOLD}{WHITE}->>{RESET}") or "07d2e88db2254f675d349996ef95ad93"

    # EAPOL 2 Frame > Only Payload (No Headers or FCS)
    input_data_how()
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET}{BOLD} Paste the {VIVID_RED}EAPOL M2 - PAYLOAD{RESET} - payload only! (excuding MAC Header, LLC and FCS) {RESET}")    
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{BOLD} Hint: {RESET}{BRIGHT_AQUA}select {NEON_YELLOW}EAPOL M2 {WHITE}>> {VIVID_RED}PAYLOAD (you should select ONLY the 802.1X Information Element of the M2 (the last 'directory' of the frame), you should NOT copy the entire 802.11 frame.) {WHITE}<< {BRIGHT_AQUA}then {NEON_YELLOW}Right Click {WHITE}/ {NEON_YELLOW}Copy {WHITE}> {NEON_YELLOW}As HEX Stream \n")    
    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default MIC:{VIVID_RED} 0103007b02010a00000000000000000001a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0000000000000000000000000000000000000000000000000000000000000000007d2e88db2254f675d349996ef95ad93001c301a0100000fac040100000fac040100000fac0280400000000fac06 {RESET}\n") 
    WPA2Handshake.Eapol2frame = input(f"{BOLD}{WHITE}->>{RESET}") or "0103007b02010a00000000000000000001a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc0000000000000000000000000000000000000000000000000000000000000000007d2e88db2254f675d349996ef95ad93001c301a0100000fac040100000fac040100000fac0280400000000fac06"

#######################################################################################
#
# FORMULARIO DE PASSWORD MANUAL Y MOSTRARLO
#

## Function: Ingresar Valores de Variables en shell
def testpassword():
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{NEON_YELLOW} The WPA2-PSK Passphrase is also known as the 'password' of the Wi-Fi network.{RESET}\n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} Input the password you wish to audit or press Enter to use the default (Hunter2006).")    
    WPA2Handshake.passw = input(f"{BOLD}{WHITE}->>{RESET}") or "Hunter2006"  

## Function: Ingresar Valores de Variables en shell

def password_selection():

    testpassword()   
    clear_screen()
    banner()
    viewdata()






#######################################################################################
#
# VER VARIABLES EN SHELL
#
 
# Visualize Variables in Shell
def viewdata():
    
    line()        
    print(f"{BOLD}{WHITE}###{RED} EAPOL M1 & M2 data:{RESET}\n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {NEON_YELLOW}4-Way-Handshake (EAPOL M1 & M2) data needed for MIC validation & cracking:{RESET}\n")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} SSID:............................. ", f"{PURPLE}{WPA2Handshake.ssid}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} MAC Address (AP):................. ", f"{TEAL}{str(WPA2Handshake.macAP)}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} MAC Address (STA):................ ", f"{ORANGE}{str(WPA2Handshake.macCli)}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} Anonce (AP):...................... ", f"{TEAL}{WPA2Handshake.anonce}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} Snonce (STA):..................... ", f"{ORANGE}{WPA2Handshake.snonce}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} MIC (EAPOL M2):................... ", f"{MAGENTA}{WPA2Handshake.mic}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} EAPOL M2 Payload:................. ", f"{CYAN}{WPA2Handshake.Eapol2frame}{RESET}")
    print()
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} Passphrase (Wi-Fi password):...... ", f"{CYAN}{WPA2Handshake.passw}{RESET}")
    print()
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} PMK (Pairwaise Master Key):....... ", f"{CYAN}{WPA2Handshake.PMK}{RESET}")    
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} PTK (Pairwaise Transient Key):.... ", f"{CYAN}{WPA2Handshake.PTK}{RESET}")    
    line()
 
# ==========================
# USER VARIABLES (SAME NAMES YOU ALREADY USE)
# ==========================
passphrase = ""
ssid = ""
iterations = 4096
dklen = 32
show_u = 3


####################################################################################################################
#
# Press ENTER to continue...

def pause(msg: str = "Press ENTER to continue...") -> None:
    """
    Pausa simple.
    Muestra el mensaje, espera ENTER,
    y luego borra SOLO la línea del mensaje.
    """
    try:
        # Imprime el prompt en su propia línea
        sys.stdout.write(f"{msg}")
        sys.stdout.flush()

        # Espera ENTER
        input()

        # Al dar ENTER, el cursor baja a la siguiente línea.
        # Subimos 1 línea, volvemos al inicio y limpiamos esa línea.
        sys.stdout.write("\033[1A\r\033[K")
        sys.stdout.flush()

    except KeyboardInterrupt:
        print()
        raise


# ==========================
# HEX DISPLAY (ALIGNED, CLEAR)
# ==========================
def show_blob(title: str, data: bytes) -> None:
    """
    Compact + aligned output (fixed columns, colored per byte):
      - raw bytes (python repr)
      - utf-8/ascii row (each byte colored)
      - decimal row (each byte colored, aligned under ascii)
      - hex stream (no spaces)
      - hex row (spaced, each byte colored, aligned)
    """

    COLOR_PALETTE = [
        NEON_GREEN, NEON_YELLOW, VIVID_BLUE, HOT_PINK,
        BRIGHT_ORANGE, VIBRANT_CYAN, NEON_PURPLE, BRIGHT_LIME,
        ELECTRIC_BLUE, SUNSHINE_YELLOW, NEON_ORANGE, BRIGHT_MAGENTA
    ]

    COL_W = 4

    def cell_ascii(b: int) -> str:
        if 32 <= b <= 126:
            return chr(b)
        return "."

    def cell_hex(b: int) -> str:
        return f"{b:02x}"

    def color_for(i: int) -> str:
        return COLOR_PALETTE[i % len(COLOR_PALETTE)]

    ascii_cells = []
    dec_cells = []
    hex_cells = []

    for i, b in enumerate(data):
        c = color_for(i)
        ascii_cells.append(f"{c}{cell_ascii(b):^{COL_W}}{RESET}")
        dec_cells.append(f"{c}{b:^{COL_W}}{RESET}")
        hex_cells.append(f"{c}{cell_hex(b):^{COL_W}}{RESET}")

    ascii_row = "".join(ascii_cells)
    dec_row = "".join(dec_cells)
    hex_row = "".join(hex_cells)

    hex_stream = data.hex()
    raw_repr = repr(data)

    print(f"\n{WHITE}=================>>  {VIVID_RED} {title} {RESET}{WHITE}{RESET}\n")
    print(f"{WHITE}Raw Bytes{VIVID_RED}:{NEON_YELLOW}      {raw_repr}")
    print(f"{WHITE}Lenght{VIVID_RED}:{NEON_YELLOW}         {len(data)} bytes\n")
    print(f"{WHITE}URF-8/ASCII{VIVID_RED}:{RESET}   {ascii_row}")
    print(f"{WHITE}decimal:       {dec_row}")
    print(f"{WHITE}HEX:           {hex_row}\n")
    print(f"{WHITE}HEX steream: {hex_stream}")


# ==========================
# CRYPTO PRIMITIVES
# ==========================
def prf_hmac_sha1(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha1).digest()

def int_32_be(i: int) -> bytes:
    return i.to_bytes(4, "big")


# ==========================
# YOUR BLOCK: PMK CALCULATION
# ==========================
def calculate_pmk(passphrase: str, ssid: str) -> bytes:
    """
    This replaces:
        PMK = PBKDF2(passphrase, ssid, 4096).read(32)

    But prints every skeleton step (compact, aligned),
    with strong visual explanation.
    """

    pause()

    print(f"""
{NEON_GREEN}Real Formula (Dynamic, using real variables){RESET}

{WHITE}PMK = first 32 bytes of:{RESET}

    {CYAN}T1 || T2{RESET}


{NEON_YELLOW}Where:{RESET}

{WHITE}T1 = U1 XOR U2 XOR U3 XOR ... XOR U4096   (using i = 1){RESET}
{WHITE}T2 = U1 XOR U2 XOR U3 XOR ... XOR U4096   (using i = 2){RESET}


{NEON_YELLOW}And for each block i:{RESET}

{WHITE}U1 = HMAC_SHA1( Passphrase , SSID || INT(i) ){RESET}
{WHITE}U2 = HMAC_SHA1( Passphrase , U1 ){RESET}
{WHITE}U3 = HMAC_SHA1( Passphrase , U2 ){RESET}
{WHITE}...{RESET}
{WHITE}U4096 = HMAC_SHA1( Passphrase , U4095 ){RESET}


{NEON_ORANGE}So each block is built as:{RESET}

{CYAN}Ti = U1 ⊕ U2 ⊕ U3 ⊕ ... ⊕ U4096{RESET}


{NEON_PINK}Then the final key is:{RESET}

{NEON_GREEN}About how the Passphrase really enters PBKDF2{RESET}

{WHITE}The passphrase is used as the HMAC secret key.{RESET}
{WHITE}It is NOT concatenated with the SSID or with any data.{RESET}

{CYAN}U = HMAC_SHA1( key = Passphrase , message = Data ){RESET}

{WHITE}So the password never appears in the data stream.{RESET}
{WHITE}It enters the algorithm as the cryptographic key that controls the hash.{RESET}

{WHITE}Changing the passphrase changes all U values, all T blocks,{RESET}
{WHITE}and therefore the final PMK.{RESET}

{WHITE}HMAC mixes the key into SHA1 internally (definition):{RESET}

{CYAN}HMAC(K, M) = SHA1( (K ⊕ opad) || SHA1( (K ⊕ ipad) || M ) ){RESET}

{WHITE}K = Passphrase{RESET}
{WHITE}M = Message (SSID || INT(i) or previous U value){RESET}

{NEON_YELLOW}Password enters here: as the HMAC secret key (K).{RESET}
""")

    pause()

    print(f"""
{NEON_GREEN}========================================================
STEP 1 - INPUT NORMALIZATION
--------------------------------------------------------
The human readable values are converted into raw bytes.
These are the real cryptographic inputs.

- Passphrase -> HMAC KEY
- SSID       -> SALT
========================================================{RESET}
""")

    # Strings -> Bytes (REAL data used by crypto)
    P = passphrase.encode("utf-8")
    S = ssid.encode("utf-8")

    show_blob("Passphrase bytes (P)  [HMAC KEY]", P)
    show_blob("SSID bytes (S)  [SALT]", S)

    pause()

    print(f"""
{NEON_ORANGE}========================================================
STEP 2 - PBKDF2 BLOCK GENERATION
--------------------------------------------------------
PBKDF2 with HMAC-SHA1 generates 20 bytes per block.
PMK needs 32 bytes → 2 blocks are required:

BLOCK 1 → T1 (20 bytes)
BLOCK 2 → T2 (20 bytes)

PMK = first 32 bytes of (T1 || T2)
========================================================{RESET}
""")

    hlen = 20
    blocks_needed = (dklen + hlen - 1) // hlen
    dk = b""
    T_blocks = []

    for block_index in range(1, blocks_needed + 1):

        pause()

        print(f"""
{BRIGHT_MAGENTA}########################################################
BLOCK {block_index}
--------------------------------------------------------
Each block starts from:
  SALT = SSID
  COUNTER = {block_index}

PBKDF2 uses:
  S || INT(i)

Where INT(i) is a 4-byte big-endian integer:
  {block_index}  ->  {int_32_be(block_index).hex()}
########################################################{RESET}
""")

        salt_block = S + int_32_be(block_index)
        show_blob("S || INT(i)  [SALT + COUNTER]", salt_block)

        print(f"""
{NEON_YELLOW}>> FIRST HMAC (U1)
--------------------------------------------------------
U1 = HMAC(KEY = Passphrase, DATA = S || INT(i))
--------------------------------------------------------{RESET}
""")

        U = prf_hmac_sha1(P, salt_block)
        T = bytearray(U)
        show_blob("U1 = HMAC(P, S||INT(i))", U)

        print(f"""
{NEON_ORANGE}>> ITERATIVE HMAC CHAIN
--------------------------------------------------------
U2 = HMAC(P, U1)
U3 = HMAC(P, U2)
...
U4096 = HMAC(P, U4095)
--------------------------------------------------------{RESET}
""")

        for j in range(2, iterations + 1):
            U = prf_hmac_sha1(P, U)

            for k in range(hlen):
                T[k] ^= U[k]

            if j <= show_u:
                show_blob(f"U{j} = HMAC(P, U{j-1})", U)
            elif j == show_u + 1:
                print(f"... skipping U{show_u+1} to U{iterations} ...")

        block_bytes = bytes(T)
        show_blob(f"T{block_index} = U1 XOR ... XOR U{iterations}", block_bytes)

        T_blocks.append(block_bytes)
        dk += block_bytes

    pause()

    print(f"""
{NEON_PINK}========================================================
STEP 3 - PMK CONSTRUCTION (VISUAL)
--------------------------------------------------------
We now join the blocks:

T1 || T2  =  40 bytes total

But PMK only needs 32 bytes, so we take:

PMK = T1 (20 bytes) +
      first 12 bytes of T2

Visually:

T1 = [####################] 20 bytes
T2 = [############........] only 12 bytes used

PMK = [################################]
========================================================{RESET}
""")

    T1 = T_blocks[0]
    T2 = T_blocks[1]

    print(f"{NEON_GREEN}T1 (20 bytes, used completely):{RESET}")
    print(T1.hex())

    print(f"\n{NEON_ORANGE}T2 (20 bytes, only first 12 bytes used):{RESET}")
    print(T2.hex())

    print(f"{RED}Used part of T2:{RESET}")
    print(T2[:12].hex())

    PMK = (T1 + T2)[:dklen]

    print(f"""
{VIVID_RED}PMK composition:
PMK = T1 || T2[0:12]

PMK = {T1.hex()} || {T2[:12].hex()}

PMK = {T1.hex()}{T2[:12].hex()}
""")

    # ✅ Save globally for other defs to reuse
    WPA2Handshake.pmk_bytes = PMK
    WPA2Handshake.PMK = PMK.hex()

    show_blob("PMK (final output)", PMK)

    


    print(f"{BOLD}{WHITE}###{RED} PMK  Result:\n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{NEON_YELLOW} Derivated from the WPA2-PSK Passphrase & SSID using PBKDF2 algorythm{RESET}\n")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} PMK (Pairwise Master Key):......... {WHITE}{BOLD}" + str(PMK.hex()))

    return PMK


# Muestra info de como mostrar el PMK por si el usuario pide mas info
def info_pmk():

    print(f"{BOLD}{WHITE}###{RED} PMK (Pairwise Master Key) DERIVATION || PBKDF2 KDF (Key Derivation Function): \n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK = 32 bytes (256-bit) Key derived from PSK Passphrase & SSID using PBKDF2.{RESET}")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK provides the foundation for RSNA keys in WPA2 authentication.{RESET} \n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK is derived by the AP & client STA; both PMKs should match to unlock ecrypted data.{RESET} \n")
    print(f"{WHITE}[{NEON_YELLOW}-{WHITE}]{RESET} {YELLOW}The PMK derives:{RESET} \n")
    print(f"   {WHITE}[{NEON_YELLOW}1{WHITE}]{RESET} {YELLOW}PTK (Pairwise Transient Key) - which divides into -> {RESET} \n")
    print(f"      {WHITE}[{NEON_YELLOW}1.1{WHITE}]{RESET} {YELLOW}KEK (Key Encryption Key):..... For EAPOL message encryption. {RESET}")
    print(f"      {WHITE}[{NEON_YELLOW}1.2{WHITE}]{RESET} {YELLOW}TK  (Temporal Key):........... For DATA encryption (MSDU Data Tx/Rx).{RESET}")
    print(f"      {WHITE}[{NEON_YELLOW}1.3{WHITE}]{RESET} {YELLOW}KCK (Key Confirmation Key):... for MIC integrity. {RESET}")
    print(f"      {WHITE}[{NEON_YELLOW}1.4{WHITE}]{RESET} {YELLOW}MICs: For DATA integrity.{RESET}")

    line2()

    print(f"{BOLD}{WHITE}PMK Formula    -->{RESET} {BOLD} {GREEN}PBKDF2 {WHITE}= {WHITE}({RED}Passphrase {WHITE}+ {PURPLE}SSID{WHITE}) * {CYAN}4096 iterations \n")
    print(f"{BOLD}{WHITE}PMK Derivation -->{RESET} {BOLD} {GREEN}PBKDF2 {WHITE}= {WHITE}({RED}{WPA2Handshake.passw} {WHITE}+ {PURPLE}{WPA2Handshake.ssid}{WHITE}) * {CYAN}4096 iterations \n")
    print(f"{BOLD}{WHITE}               -->{PINK}  READ{WHITE}: {PINK}HEX Stream {WHITE}(64 characters{WHITE}) {WHITE}= {PINK}32 byte {WHITE}/ {PINK}256 bit{RESET}")
    line()



####################################################################################################################
#
# Press ENTER to continue...


def pause(msg: str = "Press ENTER to continue...") -> None:
    """
    Pausa simple.
    Muestra el mensaje, espera ENTER,
    y luego borra SOLO la línea del mensaje.
    """
    try:
        # Imprime el prompt en su propia línea
        sys.stdout.write(f"{msg}")
        sys.stdout.flush()

        # Espera ENTER
        input()

        # Al dar ENTER, el cursor baja a la siguiente línea.
        # Subimos 1 línea, volvemos al inicio y limpiamos esa línea.
        sys.stdout.write("\033[1A\r\033[K")

        # (Opcional) también limpia la línea actual por si quedó algo raro
        # sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    except KeyboardInterrupt:
        print()
        raise

####################################################################################################################
#
# PTK DERIVATION :: PRF512 ALGORYTHM



def ptk_info():

    clear_screen()
    banner()
    viewdata()


    print(f"{BOLD}{WHITE}### {RED}PTK (Pairwise Transient Key) DERIVATION || PRF512 ALGORITHM:{RESET}\n")
    
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}] {YELLOW}PTK = 512-bit Key derived from PMK, MAC addresses, and nonces using PRF512 (Pseudo-Random Function).{RESET}")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}] {YELLOW}This key is used to secure WPA2 communications by providing encryption and integrity for data frames.{RESET}\n")
    
    print(f"{BOLD}{WHITE}General Formula:{RESET}")
    print(f"{WHITE}PTK = PRF512(PMK, 'Pairwise key expansion', Key Data){RESET}\n")
    
    print(f"{BOLD}{WHITE}Where:{RESET}")
    print(f"  - {CYAN}PMK{WHITE}: Pairwise Master Key derived from passphrase and SSID using PBKDF2.")
    print(f"  - {CYAN}Key Data{WHITE}: Concatenation of MAC addresses (AP & Client) and nonces (Anonce & Snonce).")
    print(f"  - {CYAN}PRF512{WHITE}: Pseudo-Random Function using HMAC-SHA1 to generate a fixed 512-bit output.\n")
    
    print(f"{BOLD}{WHITE}Key Data Composition:{RESET}")
    print(f"  {NEON_GREEN}- {WHITE}Key Data = Min(MAC_AP, MAC_Client) + Max(MAC_AP, MAC_Client) + Min(Anonce, Snonce) + Max(Anonce, Snonce){RESET}\n")
    
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}] {RESET}PRF512 iteratively applies HMAC-SHA1 to generate a 512-bit key by processing:")
    print(f"    {CYAN}Input:{WHITE} 'Pairwise key expansion' + Key Data + Counter")
    print(f"    {CYAN}Key:{WHITE} PMK")
    print(f"  Counter ensures uniqueness across iterations, producing 20-byte blocks that are concatenated until 64 bytes (512 bits) are reached.{RESET}\n")
    
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}] {RESET}{YELLOW}This function is essential in the WPA2 handshake for establishing secure communications.{RESET}\n")


    pause()


## PRF512

# Function: Algoritmo PRF512 (Para obtener PTK)
def customPRF512(pmk, text, key_data):

    ## Explicación general:

        # Esta función realiza la operación de Pseudo-Random Function (PRF) utilizando el algoritmo HMAC-SHA1 para generar una salida de longitud fija (512 bits) 

        # a partir de una clave (pmk), un texto (text), y datos adicionales (key_data). 

        # Este tipo de función es fundamental en el proceso de creación de la Pairwise Transient Key (PTK) en el protocolo WPA2, el cual se usa para cifrar las comunicaciones entre un dispositivo y el punto de acceso Wi-Fi.

    # Inicializamos el contador c, que se utilizará para iterar y modificar la entrada del HMAC-SHA1
    c = 0
    
    # Definimos el tamaño del bloque de salida que queremos obtener, 64 bytes (512 bits)
    block = 64
    
    # Creamos un objeto vacío de tipo bytes donde se acumularán los resultados del HMAC
    result = bytes()
    
    # Ejecutamos el ciclo mientras c se    print(f"    {NEON_PURPLE}-{VIBRANT_CYAN} or Press Enter to use default MIC:{VIVID_RED} 0103007b02010a00000000000000000001a3911874480ff4e4b772c016d107ace5e0fb5fd972e5deeae1f662edeb8b4fc00000000000000000000000000000000000000000000000000000000000000000a menor o igual al número de iteraciones necesarias para generar los 512 bits.
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

def generate_ptk(PMK):

    #Función para calcular el Pairwise Temporal Key (PTK) a partir del PMK.

    line()

    print(f"{BOLD}{WHITE}###{RED} PTK DERIVATION:{RESET} \n")


    ptk_info()


    print(f"{BOLD}{WHITE}###{RED} PTK DERIVATION wawa:{RESET} \n")



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

    pause()    
    
    return PTK




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
        print(f"{WHITE}[{BRIGHT_BLUE}9{WHITE}]{RESET} - Cancel / Back to Main Menu \n")
            
        # el try lo uso para poder loopear las instrcciones de manera limpia
        try:
            
            # Prompt the user to select an option
            opt = int(input(f"{BOLD}{WHITE}->>{RESET} "))
            line()

            # @ Main
            if opt == 9:
                print(f"Returning to main menu...\n")  
                clear_screen()

                main()  
            
            # @ BruteForce
            elif opt == 1:
                switches.attack_type = 1
                print(f"Initiating Bruteforce attack...\n")
                clear_screen()
                banner()
                viewdata()

                checkPasswdWordlist()  
            
            # @ Manual
            elif opt == 0:
                switches.attack_type = 0
                print(f"Initiating Manual attack...\n") 
                clear_screen()
                banner()
                viewdata()

                # << MANUAL CHECKING MAIN >>
                # 1- 
                password_selection()  
                # 2-                 
                info_pmk()
                # 3-                 
                checkPasswd() 

            # 
            else:
                print("Invalid selection. Please enter 0 to launch the MIC Cracker or 9 to exit.")

        except ValueError:
            print("Error: Invalid input. Please enter a valid number (0 or 9).")



     


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
  

    KCK = ptk[0:16]

    # para imprimir el binario raw de raws solo usar "print(KCK)"
    # para imprimirlo tipo Hex Strear usar "  print(str(KCK.hex()))"   
    print("[*] KCK: " + str(KCK.hex()))



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

    macAP = ''
    macCli = ''
    anonce = ''
    snonce = ''
    mic = ''
    passw = ''
    Eapol2frame = ''

## CLASS: Variables para erl tipo de ataque (esto ayuda para que las fucniones sepan que tan "deep" ir)
class switches:
    attack_type = 0
    pass_given = 0
    








                


#######################################################################################
#
# VER VARIABLES EN SHELL
#
 
# Visualize Variables in Shell
def viewdata():
          
    print(f"{BOLD}{WHITE}###{RED} EAPOL M1 & M2 data:{RESET}\n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {NEON_YELLOW}4-Way-Handshake (EAPOL M1 & M2) data needed for MIC validation & cracking:{RESET}\n")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} SSID:............................. ", f"{PURPLE}{WPA2Handshake.ssid}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} MAC Address (AP):................. ", f"{TEAL}{str(WPA2Handshake.macAP)}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} MAC Address (STA):................ ", f"{ORANGE}{str(WPA2Handshake.macCli)}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} Anonce (AP):...................... ", f"{TEAL}{WPA2Handshake.anonce}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} Snonce (STA):..................... ", f"{ORANGE}{WPA2Handshake.snonce}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} MIC (EAPOL M2):................... ", f"{MAGENTA}{WPA2Handshake.mic}{RESET}")
    print(f"{WHITE}[{NEON_ORANGE}+{WHITE}]{RESET} EAPOL M2 Payload:................. ", f"{CYAN}{WPA2Handshake.Eapol2frame}{RESET}")
    line()


####################################################################################################################
#
# PMK DERIVATION :: PBKDF2 ALGORYTHM

# Muestra info de como mostrar el PMK por si el usuario pide mas info
def info_pmk():

    print(f"{BOLD}{WHITE}###{RED} PMK (Pairwise Master Key) DERIVATION || PBKDF2 KDF (Key Derivation Function): \n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK = 32 bytes (256-bit) Key derived from PSK Passphrase & SSID using PBKDF2.{RESET}")    
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK provides the foundation for RSNA keys in WPA2 authentication.{RESET} \n")  
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET} {YELLOW}PMK is derived by the AP & client STA; both PMKs should match to unlock ecrypted data.{RESET} \n")      
    print(f"{WHITE}[{NEON_YELLOW}-{WHITE}]{RESET} {YELLOW}The PMK derives:{RESET} \n")    
    print(f"   {WHITE}[{NEON_YELLOW}1{WHITE}]{RESET} {YELLOW}PTK (Pairwise Transient Key) - which divides into -> {RESET} \n")     
    print(f"      {WHITE}[{NEON_YELLOW}1.1{WHITE}]{RESET} {YELLOW}KEK (Key Encryption Key):..... For EAPOL message encryption. {RESET}")  
    print(f"      {WHITE}[{NEON_YELLOW}1.2{WHITE}]{RESET} {YELLOW}TK  (Temporal Key):........... For DATA encryption (MSDU Data Tx/Rx).{RESET}")  
    print(f"      {WHITE}[{NEON_YELLOW}1.3{WHITE}]{RESET} {YELLOW}KCK (Key Confirmation Key):... for MIC integrity. {RESET}")  
    print(f"      {WHITE}[{NEON_YELLOW}1.4{WHITE}]{RESET} {YELLOW}MICs: For DATA integrity.{RESET}")  

    line2()

    print(f"{BOLD}{WHITE}PMK Formula    -->{RESET} {BOLD} {GREEN}PBKDF2 {WHITE}= {WHITE}({RED}Passphrase {WHITE}+ {PURPLE}SSID{WHITE}) * {CYAN}4096 iterations \n")
    print(f"{BOLD}{WHITE}PMK Derivation -->{RESET} {BOLD} {GREEN}PBKDF2 {WHITE}= {WHITE}({RED}{WPA2Handshake.passw} {WHITE}+ {PURPLE}{WPA2Handshake.ssid}{WHITE}) * {CYAN}4096 iterations \n")
    print(f"{BOLD}{WHITE}               -->{PINK}  READ{WHITE}: {PINK}HEX Stream {WHITE}(64 characters{WHITE}) {WHITE}= {PINK}32 byte {WHITE}/ {PINK}256 bit{RESET}")
    line()















# Función para calcular el Pairwise Master Key (PMK) a partir de la passphrase y el SSID.
def calculate_pmk(passphrase, ssid):

    # Formula para PMK:
    PMK = PBKDF2(passphrase, ssid, 4096).read(32)

    # Imprimir PMK:
    print(f"{BOLD}{WHITE}###{RED} PMK  Result:\n")
    print(f"{WHITE}[{NEON_YELLOW}?{WHITE}]{RESET}{NEON_YELLOW} Derivated from the WPA2-PSK Passphrase & SSID using PBKDF2 algorythm{RESET}\n")
    print(f"{WHITE}[{NEON_GREEN}+{WHITE}]{RESET} PMK (Pairwise Master Key):......... {WHITE}{BOLD}" + str(PMK.hex()))
    return PMK
    line()






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
  

    KCK = ptk[0:16]

    # para imprimir el binario raw de raws solo usar "print(KCK)"
    # para imprimirlo tipo Hex Strear usar "  print(str(KCK.hex()))"   
    print("[*] KCK: " + str(KCK.hex()))



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
