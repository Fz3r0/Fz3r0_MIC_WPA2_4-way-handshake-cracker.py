# Fz3r0_MIC_WPA2_4-way-handshake-cracker.py
A 4-way-handshake audit tool for cracking 

<img width="806" height="554" alt="image" src="https://github.com/user-attachments/assets/aeb25b7b-1ba8-4322-8bf8-24b06b1a4d85" />

<img width="875" height="728" alt="image" src="https://github.com/user-attachments/assets/2fe7599d-b3ed-4c7a-9747-b300d9be2649" />

<img width="505" height="524" alt="image" src="https://github.com/user-attachments/assets/a246bcc2-8c4a-40e6-9a7e-aa2187d60a53" />

<img width="474" height="432" alt="image" src="https://github.com/user-attachments/assets/37d43b89-c58c-473c-b228-fb15e826eaf3" />


# Algoritmo PRF512 (Para obtener PTK)

## Fórmula general

\[
\text{PRF}_{512}(\text{PMK}, \text{text}, \text{key\_data}) = \text{Truncate}_{512}\left(\bigoplus_{c=0}^{N-1} \text{HMAC-SHA1}(\text{PMK}, \text{text} || \text{key\_data} || \text{chr}(c))\right)
\]

![Fórmula PRF512](https://latex.codecogs.com/svg.image?\text{PRF}_{512}(\text{PMK},\text{text},\text{key\_data})=\text{Truncate}_{512}\left(\bigoplus_{c=0}^{N-1}\text{HMAC-SHA1}(\text{PMK},\text{text}\|\|\text{key\_data}\|\|\text{chr}(c))\right))

![image](https://github.com/user-attachments/assets/620b6686-db18-44e7-9800-7fea9edc3adf)



## Desglose de la fórmula

1. **PMK**: Es la clave derivada de la contraseña Wi-Fi (**Pairwise Master Key**). Es el secreto base.
2. **text**: Una cadena fija que indica el propósito de la clave derivada (ejemplo: `"Pairwise key expansion"` en WPA2).
3. **key_data**: Datos adicionales que incluyen las direcciones MAC del cliente y del punto de acceso, además del Nonce (aleatorio) de ambos.
4. **chr(c)**: El contador \( c \), que asegura que cada iteración genere una salida única.
5. **HMAC-SHA1**: Es una función hash basada en el algoritmo **SHA-1** y el uso de **PMK** como clave.
6. **\(\bigoplus_{c=0}^{N-1}\)** : La concatenación de los resultados **HMAC-SHA1** generados en cada iteración.
7. **N**: El número de iteraciones necesarias para generar suficientes bits para obtener 512 bits. Esto depende de que cada iteración genera **160 bits** (\(20 \, \text{bytes}\)):

\[
N = \left\lceil \frac{512}{160} \right\rceil = 4
\]

![caca](https://latex.codecogs.com/png.image?\dpi{200}\text{PRF}_{512}(\text{PMK},\text{text},\text{key\_data})=\text{Truncate}_{512}\left(\bigoplus_{c=0}^{N-1}\text{HMAC-SHA1}(\text{PMK},\text{text}||\text{key\_data}||\text{chr}(c))\right))

![Fórmula PRF512](https://latex.codecogs.com/png.image?\dpi{200}\text{PRF}_{512}(\text{PMK},\text{text},\text{key\_data})=\text{Truncate}_{512}\left(\bigoplus_{c=0}^{N-1}\text{HMAC-SHA1}(\text{PMK},\text{text}||\text{key\_data}||\text{chr}(c))\right))


![image](https://github.com/user-attachments/assets/14e65019-2398-4154-a361-031a0df438ee)

Por lo tanto, se necesitan 4 iteraciones para cubrir 512 bits.

8. **\(\text{Truncate}_{512}\)**: Una operación que toma únicamente los primeros **512 bits** (**64 bytes**) de la concatenación de los bloques generados.

## Pasos del algoritmo

1. Para cada iteración \( c \) (desde \( c = 0 \) hasta \( c = N-1 \)):
   - Generar:
     \[
     \text{HMAC-SHA1}(\text{PMK}, \text{text} || \text{key\_data} || \text{chr}(c))
     \]
2. Concatenar todos los bloques generados.
3. Tomar los primeros **512 bits** del resultado concatenado.

## Descripción del propósito

Este algoritmo se utiliza en el proceso de creación de la **Pairwise Transient Key (PTK)** en el protocolo **WPA2**, el cual es fundamental para cifrar las comunicaciones entre un dispositivo y el punto de acceso Wi-Fi.

## 4 way handshake 

<img width="1288" height="1131" alt="image" src="https://github.com/user-attachments/assets/dd7e24a9-87c7-403e-85b5-d0eb4a6e5f4b" />

