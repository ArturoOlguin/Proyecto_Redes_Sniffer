# Si no se tiene instalado Scapy, ejecutar el siguiente comando para instalarlo:
# pip install scapy 

from scapy.all import sniff, PcapReader, wrpcap 
# - sniff: para capturar paquetes en una interfaz de red.
# - PcapReader: para leer paquetes desde un archivo .pcap.
# - wrpcap: para exportar paquetes capturados a un archivo .pcap.

class Sniffer:
    # Clase para implementar un sniffer de red.
    # Implemtacion de metodos para capturar, leer, filtrar, mostrar y exportar paquetes de red.

    def __init__(self):
        self.captura_paquetes = []
        # Inicializa una lista vacía para almacenar los paquetes capturados.

    def iniciar_captura(self, interface="eth0", filter=""):
        # Método para iniciar la captura de paquetes en una interfaz de red específica.
        # interface: Nombre de la interfaz de red (por defecto "eth0"). (Cambiar deacuerdo a la interfaz utilizada)
        # filter: Filtros para capturar solo ciertos tipos de tráfico.

        print("Captura iniciada. Presionar CTRL+C para detener la captura.")
        try:
            # Inicia la captura utilizando la función sniff.
            # - iface: Interfaz de red donde se realizará la captura.
            # - filter: Filtro en formato BPF (por ejemplo, "tcp" para capturar solo paquetes TCP).
            # - prn: Define una función lambda para imprimir un resumen de cada paquete capturado.
            # - store: Guarda los paquetes capturados en la lista `self.captura_paquetes`.
            self.captura_paquetes = sniff(iface=interface, filter=filter, prn=lambda x: x.summary(), store=True)
        
        except KeyboardInterrupt:
            print(f"Captura finalizada. Se capturaron {len(self.captura_paquetes)} paquetes.")

    def leer_paquetes(self, pcapfile):
        # pcapfile: Nombre del archivo .pcap a leer.

        try:
            # Utiliza PcapReader para leer los paquetes del archivo especificado.
            self.captura_paquetes = [pkt for pkt in PcapReader(pcapfile)]
            print(f"Lectura del archivo {pcapfile} correcta.")
            # Muestra un mensaje de éxito si el archivo se leyó correctamente.
        
        except Exception as e:
            # Captura y muestra cualquier error que ocurra al leer el archivo.
            print(f"Error al leer el archivo {pcapfile}: {e}")

    def filtro_por_protocolo(self, protocol):

        filtrado_de_paquetes = [pkt for pkt in self.captura_paquetes if pkt.haslayer(protocol)]
        # Utiliza una lista por comprensión para seleccionar solo los paquetes que contienen la capa del protocolo especificado.
        return filtrado_de_paquetes
        # Devuelve la lista de paquetes filtrados.

    def imprimir_paquetes(self, packets=None):
        # packets: Lista de paquetes a mostrar (si no se proporciona, se usa `self.captura_paquetes`).

        if packets is None:
            # Si no se especifican paquetes, utiliza los paquetes capturados en la instancia.
            packets = self.captura_paquetes
        
        for packet in packets:
            # Itera sobre cada paquete en la lista.
            packet.show()
            # Muestra el contenido detallado del paquete.
            print("---" * 20)

    def exportar(self, packets, filename="captura.pcap"):
        # packets: Lista de paquetes a exportar.
        # filename: Nombre del archivo de salida (por defecto "captura.pcap").

        wrpcap(filename, packets)
        # Utiliza la función wrpcap para guardar los paquetes en el archivo especificado.
        print("Paquetes guardados con éxito.")
        # Mensaje de confirmación de que los paquetes se guardaron correctamente.
