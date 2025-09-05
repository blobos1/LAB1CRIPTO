import sys

def cifrar_cesar(texto, desplazamiento):
    """
    Cifra un texto utilizando el algoritmo de cifrado César.
    """
    resultado = ""

    # Itera sobre cada carácter del texto de entrada
    for char in texto:
        # Verifica si el carácter es una letra
        if 'a' <= char <= 'z':
            # Cifra letras minúsculas
            resultado += chr((ord(char) - ord('a') + desplazamiento) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            # Cifra letras mayúsculas
            resultado += chr((ord(char) - ord('A') + desplazamiento) % 26 + ord('A'))
        else:
            # Añade caracteres que no son letras sin cambios
            resultado += char

    return resultado

if __name__ == "__main__":
    # Verifica que el usuario haya proporcionado la cadena y el desplazamiento
    if len(sys.argv) < 3:
        print("Uso: python3 cesar.py \"<string a cifrar>\" <desplazamiento>")
        sys.exit(1)

    # Lee los argumentos de la línea de comandos
    string_a_cifrar = sys.argv[1]
    desplazamiento = int(sys.argv[2])

    # Cifra el string y muestra el resultado
    string_cifrado = cifrar_cesar(string_a_cifrar, desplazamiento)
    print(string_cifrado)       