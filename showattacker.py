import os
from scapy.layers.l2 import ARP, Ether, sniff

DB ={}
def scarpwatch_callback(ptk):
    if ARP in ptk:
        ip,mac =ptk[ARP].psrc, ptk[ARP].hwsrc
        if mac !=DB[ip]:
            if Ether in ptk:
                target = ptk[Ether].dst
            else:
                 target = "%s?" % ptk[ARP].pdst
            return "poisoning attack: target=%s victim=%s attacker=%s" % (target, ip, mac)
        else:
            DB[ip]=mac
            return "oh !!!! gathering info from router %s=%s" % (mac, ip)

        sniff(store=0, prn=scarpwatch_callback)