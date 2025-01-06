from Sniffer_Scapy import Sniffer

def main():

    sniffer = Sniffer()

    print("Iniciando la captura")
    sniffer.iniciar_captura(interface = "Wi-Fi", filter="tcp or udp")

    paquetes_tcp = sniffer.filtro_por_protocolo ("TCP")
    paquetes_upd = sniffer.filtro_por_protocolo("UDP")

    total_de_paquetes = paquetes_tcp + paquetes_upd



    if total_de_paquetes:
        print("Detalles de los paquetes:")
        sniffer.imprimir_paquetes(total_de_paquetes)
    else:
        print("No se capturaron paquetes UDP ni TCP")


    sniffer.exportar (total_de_paquetes, filename="Captura_TCP_&_UDP.pcap")
    print("Paquetes exportados a 'Captura_TCP_&_UDP.pcap'.")
    
    print(f"Total paquetes: {len(total_de_paquetes)}")
    print(f"Total paquetes TCP: {len(paquetes_tcp)}")
    print(f"Total paquetes UDP: {len(paquetes_upd)}")


if __name__ == "__main__":
    main()
