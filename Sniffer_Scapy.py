# Si no se tiene instalado scapy ejecutar #
## pip install scapy 

from scapy.all import sniff, PcapReader, wrpcap, IP, TCP, UDP

class Sniffer:

    def __init__(self):
        self.captura_paquetes = []

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
    
    def imprimir_paquetes(self, packets=None):
        if packets is None:
            packets = self.captura_paquetes

        print("Resumen de paquetes:")
        for i, packet in enumerate(packets, 1):
            # Verificar si el paquete tiene capa IP
            if IP in packet:
                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Otro"
                print(f"{i}: Time: {packet.time:.6f} | Source: {packet[IP].src} | "
                    f"Destination: {packet[IP].dst} | Protocol: {protocol} | Length: {len(packet)}")
            else:
                print(f"{i}: Paquete sin capa IP.")
        print("Fin del resumen.")
    
    def exportar (self, packets, filename = "captura.pcap"):
        wrpcap(filename, packets)
        print("Paquetetes guardados con exito")