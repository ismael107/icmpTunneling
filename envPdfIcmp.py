from scapy.all import *
import os
import re

def copy_and_modify_binary_data(pdf_path, txt_path):
    # Leer el archivo PDF en modo binario
    with open(pdf_path, 'rb') as pdf_file:
        binary_data = pdf_file.read()
    
    # Convertir los datos binarios a una cadena de texto con representación hexadecimal
    hex_data = binary_data.hex()
    
    # Crear una lista para almacenar los bloques modificados
    modified_data = []
    
    # Agregar la marca inicial
    modified_data.append('[-> INI]')
    
    # Dividir los datos en bloques de 15 caracteres y agregar el número de bloque
    block_size = 15
    total_blocks = len(hex_data) // block_size
    for i in range(total_blocks):
        block = hex_data[i * block_size:(i + 1) * block_size]
        modified_data.append(f'[-> {i}] {block} [<- F]')
    
    # Añadir cualquier restante del bloque final si no es múltiplo de 15
    if len(hex_data) % block_size != 0:
        remaining_block = hex_data[total_blocks * block_size:]
        modified_data.append(f'[-> {total_blocks}] {remaining_block} [<- F]')
        total_blocks += 1
# Agregar la marca final
    modified_data.append(f'[-> {total_blocks} FIN]')
    
    # Unir todos los bloques en una sola cadena con saltos de línea
    modified_text = '\n'.join(modified_data)
    
    # Escribir el texto modificado en el archivo TXT
    with open(txt_path, 'w', encoding='utf-8') as txt_file:
        txt_file.write(modified_text)

def read_file_in_blocks(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"El archivo {file_path} no se encuentra.")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Dividir el contenido en bloques respetando las marcas
    blocks = re.split(r'(\[-> \d+\] .+? \[<- F\])', content)
    
    # Filtrar bloques vacíos y devolver bloques junto con sus marcas
    blocks = [block for block in blocks if block.strip()]
    
    return blocks

def send_icmp_packets(ip_address, data_blocks):
    for block in data_blocks:
        # Crear paquete ICMP Echo Request
        packet = IP(dst=ip_address)/ICMP()/Raw(load=block)
        print(f"Enviando paquete con datos: {block}")
        send(packet)

def packet_callback(packet):
    if packet.haslayer(ICMP):
        # Extraer el contenido del paquete ICMP recibido
        icmp_data = packet[Raw].load.decode(errors='ignore')
        print(f"Paquete ICMP recibido: {icmp_data}")

def main():
    # Obtener la ruta actual del script
    current_directory = os.path.dirname(os.path.abspath(__file__))
    
    # Definir las rutas de los archivos PDF, TXT y de salida
    pdf_path = os.path.join(current_directory, 'ejemplo.pdf')
    txt_path = os.path.join(current_directory, 'salida.txt')
    output_pdf_path = os.path.join(current_directory, 'salida.pdf')
# Crear y modificar el archivo salida.txt
    copy_and_modify_binary_data(pdf_path, txt_path)
    
    # Leer el archivo y dividir en bloques respetando las marcas
    try:
        data_blocks = read_file_in_blocks(txt_path)
    except FileNotFoundError as e:
        print(e)
        return
    
    # Definir la dirección IP del destinatario
    ip_address = '192.168.1.130'
    
    # Enviar los paquetes ICMP
    send_icmp_packets(ip_address, data_blocks)
    
    print("Envío de paquetes ICMP completado.")
    
    # Escuchar las respuestas ICMP
    print("Esperando respuestas ICMP...")
    sniff(filter="icmp", prn=packet_callback, timeout=30)

if __name__ == "__main__":
    main()
