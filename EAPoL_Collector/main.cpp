#include <iostream>
#include <tins/tins.h>
#include <string>
#include <vector>
#include <map>

using namespace Tins;
using namespace std;


//static vector<RadioTap> vpkt;
//static PacketWriter write("./test.pcap", PacketWriter::RADIOTAP);
//bool eapSniffer(PDU &pdu){
//    RadioTap &pkt = pdu.rfind_pdu<RadioTap>();

//    //if(pkt.rfind_pdu<RSNEAPOL>().length()){ >> cannot capture EAPoL 4th
//    if(pkt.rfind_pdu<RSNEAPOL>().length()){
//        cout << "Collected EAPoL pakcet!" << endl;
//    }
//    RadioTap radio = RadioTap() / pkt.rfind_pdu<Dot11Data>() / pkt.rfind_pdu<SNAP>() / pkt.rfind_pdu<RSNEAPOL>();
//    vpkt.push_back(radio);
//    write.write(vpkt.begin(), vpkt.end());
//    return true;
//}

//void EAPoL_tracer(string inf){
//    SnifferConfiguration config;
//    config.set_promisc_mode(true);
//    //config.set_filter("type mgt subtype beacon");
//    Sniffer sniffer(inf, config);
//    sniffer.sniff_loop(eapSniffer);
//}

//class PacketWriter_ : PacketWriter{

//};

enum {
    CMD,INF
};

class Station{
public:
    string MACaddr;
};

class AccessPoint{
public:
    string eSSID;
    string bSSID;
    vector<RadioTap> vpkt;
    pcap_t* handle_;
    //EAPoL PACKETs
    Station st;
};



void Packetwrite(PDU* pdu, map<string, AccessPoint>& APs, map<string, PacketWriter>& write_packet);
bool exists_file(string fname);
void get_info(PDU * pdu, map<string, AccessPoint>& APs);
string get_bssid(Dot11Beacon packet);

int main(int argc, char *argv[]){
    if(argc < 2){
        cout << "Useage: EAPoL_Collector <interface>\n" <<endl;
    }
    //EAPoL_tracer(argv[INF]);
    map<string, AccessPoint> packet;
    map<string, PacketWriter> write_packet;
    Sniffer sniffer(static_cast<string>(argv[INF]));
    PDU * pdu = sniffer.next_packet();
    while(1){
        get_info(pdu, packet);
        Packetwrite(pdu, packet, write_packet);
        pdu = sniffer.next_packet();
    }
}

void Packetwrite(PDU* pdu, map<string, AccessPoint>& APs, map<string, PacketWriter>& write_packet){
    try{
        AccessPoint& ap = APs[get_bssid(pdu->rfind_pdu<Dot11Beacon>())];
        try{
            if(!exists_file(ap.eSSID+".pcap")){
                static PacketWriter write(ap.eSSID+".pcap", PacketWriter::RADIOTAP);
                ap.handle_ = write.handle_;
                cout << "make file" << ap.eSSID << endl;
                write.write(ap.vpkt.begin(), ap.vpkt.end());
            } else {
                write.handle_ = ap.handle_;
                write.write(ap.vpkt.begin(), ap.vpkt.end());
            }
        } catch (pcap_error){
            return;
        }
    } catch(pdu_not_found) {
        return;
    }
}

void get_info(PDU *pdu, map<string, AccessPoint> &APs){
    Dot11 const & dot11 = pdu->rfind_pdu<Dot11>();
    auto const type = dot11.type(); // small_uint<2>
    try{
        Dot11Beacon& beacon = pdu->rfind_pdu<Dot11Beacon>();
        string bssid=get_bssid(beacon);
        AccessPoint& ap = APs[bssid];
        ap.bSSID = bssid;
        ap.eSSID = beacon.ssid();
        ap.vpkt.push_back(pdu->rfind_pdu<RadioTap>());
    }
    catch(pdu_not_found){
        if(Dot11::DATA == type){
            Dot11Data data = dot11.rfind_pdu<Dot11Data>();
            if(Dot11::BROADCAST == data.addr1() || Dot11::BROADCAST == data.addr2())
                return;
            string const ap_bssid = data.addr1().to_string();
            string const station = data.addr2().to_string();
            AccessPoint& ap = APs[ap_bssid];
            ap.st.MACaddr = station;
            ap.vpkt.push_back(pdu->rfind_pdu<RadioTap>());
        }
        else if(Dot11::MANAGEMENT == type ){
            auto const subtype = dot11.subtype();

            if(Dot11::PROBE_REQ == subtype){
                Dot11ProbeRequest probe_req = dot11.rfind_pdu<Dot11ProbeRequest>();
                string const ap_bssid = probe_req.addr1().to_string();
                string const station = probe_req.addr2().to_string();
                AccessPoint& ap = APs[ap_bssid];
                ap.st.MACaddr = station;
                ap.vpkt.push_back(pdu->rfind_pdu<RadioTap>());
            }
            else if(Dot11::PROBE_RESP == subtype){
                Dot11ProbeResponse probe_res = dot11.rfind_pdu<Dot11ProbeResponse>();
                string const ap_bssid = probe_res.addr2().to_string();
                string const station = probe_res.addr1().to_string();
                AccessPoint& ap = APs[ap_bssid];
                ap.st.MACaddr = station;
                ap.vpkt.push_back(pdu->rfind_pdu<RadioTap>());
            }
        }
        return;
    }
}

string get_bssid(Dot11Beacon packet){
    return packet.addr2().to_string();
}

bool exists_file(string fname){
    if (FILE *file = fopen(fname.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }
}
