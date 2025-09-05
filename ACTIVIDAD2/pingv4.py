from scapy.all import IP, ICMP, Raw, send

# Define el mensaje que quieres enviar y la dirección IP de destino
mensaje = "larycxpajorj h bnpdarmjm nw anmnb"
# Sustituye '127.0.0.1' por la dirección IP de la máquina a la que quieres enviar el mensaje
target_ip = "192.168.1.1"  

print(f"Enviando mensaje oculto a través de paquetes ICMP a {target_ip}...\n")

# Bucle a través de cada carácter del mensaje
for char in mensaje:
    # Construir el paquete: capa IP + capa ICMP + carga útil (payload) con el carácter
    packet = IP(dst=target_ip) / ICMP() / Raw(load=char.encode('utf-8'))
    
    # Enviar el paquete
    send(packet, verbose=0)
    
    print(f"Carácter '{char}' enviado en un paquete ICMP.")

print("\nMensaje enviado por completo.")