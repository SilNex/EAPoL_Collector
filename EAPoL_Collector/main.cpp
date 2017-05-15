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

static vector<RadioTap> vradioTap;
static PacketWriter write("./test.pcap", PacketWriter::RADIOTAP);
bool eapSniffer(PDU &pdu){
    const RadioTap &radioTap = pdu.rfind_pdu<RadioTap>();

    RSNEAPOL rsneapol = radioTap.rfind_pdu<RSNEAPOL>();
    cout << (int)rsneapol.packet_type()<< endl;
    RadioTap pkt = RadioTap() / Dot11Data() / SNAP() / rsneapol;

    vradioTap.push_back(pkt);
    write.write(vradioTap.begin(), vradioTap.end());

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
