#include <iostream>
#include <tins/tins.h>
#include <string>
#include <vector>

using namespace Tins;
using namespace std;
class STs_{
    string bssid;
    //EAPoL packet_data;
};
class APs_{
    string bssid_;
    string essid_;
    struct STs_ station_;
};

static vector<RadioTap> vpkt;
static PacketWriter write("./test.pcap", PacketWriter::RADIOTAP);
bool eapSniffer(PDU &pdu){
    RadioTap &pkt = pdu.rfind_pdu<RadioTap>();

    //if(pkt.rfind_pdu<RSNEAPOL>().length()){ >> cannot capture EAPoL 4th
    RadioTap radio = RadioTap() / pkt.rfind_pdu<Dot11Data>() / pkt.rfind_pdu<SNAP>() / pkt.rfind_pdu<RSNEAPOL>();
    vpkt.push_back(radio);
    write.write(vpkt.begin(), vpkt.end());
    return true;
}

void EAPoL_tracer(string inf){
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    //config.set_filter("type mgt subtype beacon");
    Sniffer sniffer(inf, config);
    sniffer.sniff_loop(eapSniffer);
}

enum {
    CMD,INF
};

int main(int argc, char *argv[])
{
    if(argc < 2){
        cout << "Useage: EAPoL_Collector <interface>\n" <<endl;
    }
    EAPoL_tracer(argv[INF]);

}
