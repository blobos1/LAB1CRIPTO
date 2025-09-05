from scapy.all import sniff, ICMP, Raw
from collections import Counter
import string

# Define las frecuencias de letras en español (aproximadas) para la comparación
frecuencias_espanol = {
    'e': 16.78, 'a': 11.96, 'o': 8.69, 'l': 8.37, 's': 7.88,
    'n': 7.01, 'd': 6.87, 'r': 5.58, 'u': 4.79, 'i': 4.15,
    't': 3.31, 'c': 2.92, 'p': 2.89, 'm': 2.37, 'y': 1.54,
    'q': 1.11, 'b': 0.92, 'h': 0.89, 'g': 0.73, 'f': 0.61,
    'v': 0.52, 'j': 0.49, 'ñ': 0.47, 'z': 0.45, 'x': 0.14, 'k': 0.11, 'w': 0.04
}

# -----------------
# Funciones de apoyo
# -----------------

def descifrar_cesar(texto, desplazamiento):
    """Descifra un texto usando el cifrado César con un desplazamiento dado."""
    resultado = ""
    for char in texto:
        if 'a' <= char.lower() <= 'z' or char.lower() == 'ñ':
            if char.lower() == 'ñ':
                # Manejo simple de la 'ñ'
                pos = 'abcdefghijklmnñopqrstuvwxyz'.find(char.lower())
                if pos != -1:
                    nueva_pos = (pos - desplazamiento + 27) % 27
                    caracter_descifrado = 'abcdefghijklmnñopqrstuvwxyz'[nueva_pos]
                else:
                    caracter_descifrado = char
            else:
                inicio = ord('a')
                codificado = (ord(char.lower()) - inicio - desplazamiento + 26) % 26
                caracter_descifrado = chr(codificado + inicio)

            if char.isupper():
                caracter_descifrado = caracter_descifrado.upper()
            resultado += caracter_descifrado
        else:
            resultado += char
    return resultado

def analizar_frecuencia(texto):
    """Calcula las frecuencias de letras en un texto."""
    letras = [char.lower() for char in texto if char.isalpha()]
    total_letras = len(letras)
    if total_letras == 0:
        return {}
    
    contador = Counter(letras)
    frecuencias = {
        letra: (contador.get(letra, 0) / total_letras) * 100
        for letra in string.ascii_lowercase + 'ñ'
    }
    return frecuencias

def comparar_frecuencias(frecuencias_texto, frecuencias_ref):
    """Compara las frecuencias de un texto con las de referencia para hallar la similitud."""
    similitud = 0
    for letra in frecuencias_ref:
        diff = frecuencias_texto.get(letra, 0) - frecuencias_ref.get(letra, 0)
        similitud += diff ** 2
    return similitud

# -----------------
# Lógica principal de captura y descifrado
# -----------------

def procesar_paquetes(paquete):
    """Función de callback para procesar cada paquete capturado."""
    global mensaje_cifrado
    
    if paquete.haslayer(ICMP) and paquete[ICMP].type == 8 and paquete.haslayer(Raw):
        caracter = paquete[Raw].load.decode('utf-8', errors='ignore')
        if caracter.isprintable() and len(caracter) == 1:
            mensaje_cifrado += caracter
            print(f"Paquete ICMP capturado. Caracter: '{caracter}'")
            print(f"Mensaje parcial: {mensaje_cifrado}")
            if len(mensaje_cifrado) >= 20:
                print("\nAnalizando posibles descifrados...")
                descifrar_mensaje_completo()

def descifrar_mensaje_completo():
    """Descifra el mensaje capturado y encuentra la opción más probable."""
    posibles_descifrados = []
    
    for desplazamiento in range(26):
        texto_descifrado = descifrar_cesar(mensaje_cifrado, desplazamiento)
        frecuencias_texto = analizar_frecuencia(texto_descifrado)
        similitud = comparar_frecuencias(frecuencias_texto, frecuencias_espanol)
        posibles_descifrados.append((similitud, texto_descifrado, desplazamiento))
    
    posibles_descifrados.sort(key=lambda x: x[0])
    
    print("\n--- Posibles Combinaciones de Descifrado ---")
    
    for i, (similitud, texto, desplazamiento) in enumerate(posibles_descifrados):
        if i == 0:
            print(f"✅ Descifrado más probable (desplazamiento {desplazamiento}):")
            print(f"   -> Mensaje: '{texto}'")
            print(f"   -> Similitud con frecuencias en español: {similitud:.2f}\n")
        else:
            print(f"   - Desplazamiento {desplazamiento}: '{texto}'")

# Inicializamos la variable global que acumulará el mensaje
mensaje_cifrado = ""

# Empezar a escuchar los paquetes ICMP
print("Escuchando paquetes ICMP. Asegúrate de ejecutar el script del emisor...")
sniff(filter="icmp", prn=procesar_paquetes, store=0, timeout=60)