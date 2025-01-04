#import pyshark
from scapy.all import rdpcap
import datetime

class pcap_parser:
    def __init__(self,pcap_file):
        self.pcap_file=pcap_file
        self.packets=None
        self.stats=defaultdict(int)

    def read_pcap(self):
        try:
            print(f"PCAP analyzing in progress: {self.pcap_file}") #TODO: update with progress bar
            self.packets=rdpcap(self.pcap_file)
            return True
        except Exception as e:
            print(f"PCAP failed to process: {str(e)}")
            return False

    def basic_stats(self):
        if not self.packets:
            return None
        stats={
                'total_packets':len(self.packets),
                'start_time':datetime.datetime.fromtimestamp(float(self.packets[0].time)),
            'end_time':datetime.datetime.fromtimestamp(float(self.packets[-1].time)),
            'protocols':defaultdict(int)
        }

        for packet in self.packets:
            if packet.haslayer('IP'):
                stats['protocols'][packet['IP'].proto]+=1
            if packet.haslayer('Ether'):
                stats['protocols'][packet]['Ether'].type]+=1
        return stats # TODO: option to print out packet that either has IP-based protocols or Ether-based protocol, layer 4 would be the best option here

    def packet_summary(self,packet_index):
        if not self.packets or packet_index >= len(self.packets):
            return None
            
        packet = self.packets[packet_index]
        summary = {
            'time': datetime.datetime.fromtimestamp(float(packet.time)),
            'length': len(packet),
            'layers': []
        }

        while packet:
            summary['layers'].append(packet.name)
            packet = packet.payload if packet.payload else None
            
        return summary


def main():
    parser=pcap_parser("test.pcap")
    if parser.read_pcap():
        stats=parser.basic_stats()
        if stats:
            print("\nBasic Statistics:")
            print(f"Total Packets: {stats['total_packets']}")
            print(f"Capture Start: {stats['start_time']}")
            print(f"Capture End: {stats['end_time']}")
            print("\nProtocol Distribution:")
            for proto, count in stats['protocols'].items():
                print(f"Protocol {proto}: {count} packets")

            for i in range(len(packet)) {
                    packets=parser.packet_summary(i):
                    print("\nFirst Packet Summary:")
                    print(f"Time: {first_packet['time']}")
                    print(f"Length: {first_packet['length']} bytes")
                    print(f"Layers: {' -> '.join(first_packet['layers'])}")

