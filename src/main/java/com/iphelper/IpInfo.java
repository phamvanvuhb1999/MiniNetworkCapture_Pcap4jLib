package com.iphelper;

import com.github.phamvanvuhb1999.App;

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
