# Fz3r0_MIC_WPA2_4-way-handshake-cracker.py
A 4-way-handshake audit tool for cracking 

![image](https://github.com/user-attachments/assets/b968f745-e8aa-4504-9cc8-d808ba5b6836)

# Algoritmo PRF512 (Para obtener PTK)

## Fórmula general

\[
\text{PRF}_{512}(\text{PMK}, \text{text}, \text{key\_data}) = \text{Truncate}_{512}\left(\bigoplus_{c=0}^{N-1} \text{HMAC-SHA1}(\text{PMK}, \text{text} || \text{key\_data} || \text{chr}(c))\right)
\]

![Fórmula PRF512](https://latex.codecogs.com/png.latex?\text{PRF}_{512}(\text{PMK},\text{text},\text{key\_data})=\text{Truncate}_{512}\left(\bigoplus_{c=0}^{N-1}\text{HMAC-SHA1}(\text{PMK},\text{text}\|\|\text{key\_data}\|\|\text{chr}(c))\right))


![image](https://github.com/user-attachments/assets/620b6686-db18-44e7-9800-7fea9edc3adf)


## Desglose de la fórmula

1. **PMK**: Es la clave derivada de la contraseña Wi-Fi (**Pairwise Master Key**). Es el secreto base.
2. **text**: Una cadena fija que indica el propósito de la clave derivada (ejemplo: `"Pairwise key expansion"` en WPA2).
3. **key_data**: Datos adicionales que incluyen las direcciones MAC del cliente y del punto de acceso, además del Nonce (aleatorio) de ambos.
4. **chr(c)**: El contador \( c \), que asegura que cada iteración genere una salida única.
5. **HMAC-SHA1**: Es una función hash basada en el algoritmo **SHA-1** y el uso de **PMK** como clave.
6. **\(\bigoplus_{c=0}^{N-1}\)**: La concatenación de los resultados **HMAC-SHA1** generados en cada iteración.
7. **N**: El número de iteraciones necesarias para generar suficientes bits para obtener 512 bits. Esto depende de que cada iteración genera **160 bits** (\(20 \, \text{bytes}\)):

   \[
   N = \left\lceil \frac{512}{160} \right\rceil = 4
   \]

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
