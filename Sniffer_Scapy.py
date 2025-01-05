# Si no se tiene instalado scapy ejecutar #
## pip install scapy 

from scapy.all import sniff, PcapReader, wrpcap

class Sniffer: # Clase para el sniffer en donde se colocan todas las funciones que ejecuta #

    def __init__(self):
        self.captura_paquetes = [] # Inicia la captura con una lista vacia para almacenar los paquetes#

    def iniciar_captura (self, interface="eth0", filter=""):
        
        print ("Captura iniciada. Presionar CTRL+C para detener la captura")

        try:
            self.captura_paquetes = sniff(iface=interface, filter=filter, prn=lambda x:x.summary(),store=True)

        except KeyboardInterrupt:
            print(f"Captura finalizada. Se capturaron {len(self.captura_paquetes)}")

    def leer_paquetes (self, pcapfile):
        try:
            self.captura_paquetes = [pkt for pkt in PcapReader(pcapfile)]
            print(f"Lectura del archivo {pcapfile} correcta")

        except Exception as e:
            print(f"Error al leer el archivo {pcapfile}: {e}")


    def filtro_por_protocolo (self, protocol):
        filtrado_de_paquetes = [pkt for pkt in self.captura_paquetes if pkt.haslayer(protocol)]
        return filtrado_de_paquetes
    
    def imprimir_paquetes (self, packets = None):
        if packets is None:
            packets = self.captura_paquetes
        for packet in packets:
            packet.show()
            print("---" * 20)

    def exportar (self, packets, filename = "captura.pcap"):
        wrpcap(filename, packets)
        print("Paquetetes guardados con exito")