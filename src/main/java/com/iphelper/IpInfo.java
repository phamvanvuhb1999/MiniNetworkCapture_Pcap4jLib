package com.iphelper;

import javax.sound.sampled.Port;
import javax.swing.text.AbstractDocument.LeafElement;

import com.github.phamvanvuhb1999.App;

import org.pcap4j.packet.namednumber.IpVersion;

public class IpInfo {
    private
        int version;
        String macsource;
        String macdes;
    public String timestamp;

    public IpHelper helper;
    public IpInfo(IpHelper iphelper, String timestamp){
        this.helper = iphelper;
        this.version = iphelper.getIpVersion();
        String[] ips = iphelper.getIpv4mcapInfo();
        this.macsource = ips[0];
        this.macdes = ips[1];
        this.timestamp = timestamp;
    }

    public boolean isIpv4Packet(){
        return this.helper.ipv4Helper != null;
    }

    public int getVersion(){
        return this.version;
    }

    public String getSourceAddress(){
        return this.macsource;
    }

    public String getDesAddress(){
        return this.macdes;
    }

    public String getTimestamp(){
        return this.timestamp;
    }

    public String getProtocol(){
        if(getVersion() == 4){
            if(this.helper.isArpPacket()){
                return App.protoString.get(this.helper.arpHelper.getProtocolCode());
            }
            return App.protoString.get(this.helper.ipv4Helper.getProtocolCode());
        }else {
            return App.protoString.get(this.helper.ipv6Helper.getProtocolCode());
        }
    }

    public int getPacketLength(){
        return this.helper.getPacketLength();
    }

    public String getInfo(){
        try{
            if(this.helper.isTcpPacket()){
                boolean isIpv4 = isIpv4Packet();
                int[] Ports;
                if(isIpv4){
                    Ports = getPort(isIpv4, this.helper.ipv4Helper.tcpHelper,true);
                }else {
                    Ports = getPort(false, this.helper.ipv6Helper.tcpHelper, true);
                }
                if(Ports[0] == 80 || Ports[1] == 80){
                    if(isIpv4 && this.helper.ipv4Helper != null){
                        return this.helper.ipv4Helper.tcpHelper.getHttpInfo(true);
                    }else if(!isIpv4 && this.helper.ipv6Helper != null){
                        return this.helper.ipv6Helper.tcpHelper.getHttpInfo(false);
                    }
                }else {
                    if(isIpv4 && this.helper.ipv4Helper != null){
                        return this.helper.ipv4Helper.tcpHelper.getTcpInfo();
                    }else {
                        return this.helper.ipv6Helper.tcpHelper.getTcpInfo();
                    }
                }
            }else if(this.helper.isIcmpPacket()){
                boolean isIpv4 = isIpv4Packet();
                if(isIpv4){
                    return this.helper.ipv4Helper.icmpHelper.getIcmpInfo();
                }else {
                    return this.helper.ipv6Helper.icmpHelper.getIcmpInfo();
                }
            }else if(this.helper.isUdpPacket()){
                boolean isIpv4 = isIpv4Packet();
                if(isIpv4){
                    int[] Ports = getPort(isIpv4Packet(), this.helper.ipv4Helper.udpHelper, false);
                    String temp = "";
                    if(Ports[0] == 137 && Ports[1] == 137){
                        temp += " NBNS ";
                    }
                    temp += "Length: " + getPacketLength();
                    return temp;
                }else {
                    int[] Ports = getPort(isIpv4Packet(), this.helper.ipv6Helper.udpHelper, false);
                    String temp = "";
                    if(Ports[0] == 137 && Ports[1] == 137){
                        temp += " NBNS ";
                    }
                    temp += "Length: " + getPacketLength();
                    return temp;
                }
            }else if(this.helper.isArpPacket()){
                return this.helper.arpHelper.getArpInfo();
            }
        }catch(Exception e){
            e.printStackTrace();
        }
        return "info";
    }

    public int[] getPort(boolean isVersion4, ProtocolHelper helper, boolean istcp){
        UdpHelper udpHelper1;
        TcpHelper tcpHelper1;
        int[] result = new int[2];
        if(istcp){
            tcpHelper1 = (TcpHelper)helper;
            if(isVersion4){
                result[0] = tcpHelper1.getSourcePort();
                result[1] = tcpHelper1.getDestinationPort();
            }else {
                result[0] = tcpHelper1.getSourcePort();
                result[1] = tcpHelper1.getDestinationPort();
            }  
        }else {
            udpHelper1 = (UdpHelper)helper;
            if(isVersion4){
                result[0] = udpHelper1.getSourcePort();
                result[1] = udpHelper1.getDestinationPort();
            }else {
                result[0] = udpHelper1.getSourcePort();
                result[1] = udpHelper1.getDestinationPort();
            }  
        }
        return result;
    }

    public String toString(){
        String result = "\n";
        result += "Time: " + this.timestamp + "\n";
        result += "EthernetII: \n";
        result += "\tDestination MAC: " + this.getDesAddress() + "\n";
        result += "\tSource MAC: " + this.getSourceAddress() + "\n";
        
        if(this.version == 4){
            if(this.helper.isArpPacket()){
                result += "Internet Protocol Version 4: \n";
                result += this.helper.arpHelper.toString();
            }else {
                result += "Internet Protocol Version 4: \n";
                result += this.helper.ipv4Helper.toString();
            }
        }else if(this.version == 6){
            result += "Internet Protocol Version 6: \n";
            result += this.helper.ipv6Helper.toString();
        }
        return result;
    }
}
