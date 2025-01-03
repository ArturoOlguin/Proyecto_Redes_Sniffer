from scapy.all import sniff, PcapReader, wrpcap

class Sniffer:

    def __init__(self):
        self.captura_paquetes = []

    def iniciar_captura (self, interface="eth0", filter=""):

        print ("Captura iniciada. Presionar CTRL+C para detener la captura")

        try:
            self.captura_paquetes = sniff(iface=interface, filter=filter, prn=lambda x:x.summary(),store=True)

        except KeyboardInterrupt:
            print(f"Captura finalizada. Se capturaron {len(self.captura_paquetes)}")

