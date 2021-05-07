package com.iphelper;
import org.pcap4j.util.ByteArrays;

public class Ipv4Helper {
    int START_MCAPINFO = 0;
    int START_IP_INFO = 14;
    int IP_INFO_LENGTH = 20;
    byte[] data;
    TcpHelper tcpHelper;
    UdpHelper udpHelper;
    IcmpHelper icmpHelper;
    int protocolCode;

    public Ipv4Helper(byte[] rawData){
        this.data = new byte[rawData.length];
        this.data = rawData;
        int protocol = this.getProtocol();
        this.protocolCode = protocol;
        if(protocol == 6){
            this.tcpHelper = new TcpHelper(this.data, this.START_IP_INFO + this.IP_INFO_LENGTH);
        }else if(protocol == 17){
            this.udpHelper = new UdpHelper(this.data, this.START_IP_INFO + this.IP_INFO_LENGTH);
        }else if(protocol == 1){
            this.icmpHelper = new IcmpHelper(this.data, this.START_IP_INFO + this.IP_INFO_LENGTH);
        }
    }

    public int getProtocolCode(){
        return this.protocolCode;
    }

    public boolean isIcmpPacket(){
        return this.icmpHelper != null;
    } 

    public boolean isUdpPacket(){
        return this.udpHelper != null;
    }

    public boolean isTcpPacket(){
        return this.tcpHelper != null;
    }

    public int getHeaderLength(){
        byte bversion = this.data[this.START_IP_INFO];
        int version = bversion & 0x0F;
        return version;
    }

    public int getTotalLength(){
        byte[] btotallength = new byte[2];
        System.arraycopy(this.data, this.START_IP_INFO+2, btotallength, 0, btotallength.length);
        int totalLength = 0;
        totalLength += (btotallength[0] & 0xFF)*Math.pow(2, 8);
        totalLength += (btotallength[1] & 0xFF);

        return totalLength;
    }

    public String getIndentification(int offsetInIpinfo){
        //2 for ipversion, 2 for total len
        int offset = offsetInIpinfo > 0 ? offsetInIpinfo : 4;
        byte[] bindentifi = new byte[2];
        System.arraycopy(this.data, this.START_IP_INFO + offset, bindentifi, 0, bindentifi.length);
        return "0x"+ByteArrays.toHexString(bindentifi, "");
    }

    public String GetFlag(){
        byte bindentifi = this.data[this.START_IP_INFO+5];
        return "0x"+ByteArrays.toHexString(bindentifi, "");
    }

    public int getIntValue(int offset, int bytelength){
        if(bytelength == 1){
            byte byt = this.data[offset];
            return (byt & 0xFF);
        }
        else return 0;
    }

    public String getHexString(int offset, int bytelength){
        if(bytelength <= 0){
            return "";
        }
        byte[] byt = new byte[bytelength];
        System.arraycopy(this.data, offset , byt, 0, bytelength);
        return "0x" + ByteArrays.toHexString(byt, "");
    }

    public String getFragmentOfset(){
        return getIndentification(6);
    }

    public int getTimeToLive(){
        return getIntValue(this.START_IP_INFO + 8, 1);
    }

    public int getProtocol(){
        return getIntValue(this.START_IP_INFO + 9,1);
    }

    public String getCheckSum(){
        return getHexString(this.START_IP_INFO + 10, 2);
    }

    public String getIpv4AddressFromHex(int offset){
        int bytelength = 4;
        if(offset + bytelength > this.data.length){
            throw new IndexOutOfBoundsException("In getipv4AddressFromHex");
        }
        byte[] byt = new byte[bytelength];
        System.arraycopy(this.data, offset , byt, 0, bytelength);
        String result = "";
        for(int i = 0; i < bytelength; i ++){
            if(i != bytelength - 1){
                result += (byt[i] & 0xFF) + ".";
            }else {
                result += (byt[i] & 0xFF) + "";
            }
        }

        return result;
    }

    public String getIpv4SourceAddress(){
        return getIpv4AddressFromHex(this.START_IP_INFO + 12);
    }

    public String getIpv4DestinationAddress(){
        return getIpv4AddressFromHex(this.START_IP_INFO + 16);
    }

    public String getTcpData(){
        byte[] data = new byte[getTotalLength()-34];
        System.arraycopy(this.data, this.START_IP_INFO+20, data, 0, data.length);
        return new TcpHelper(data,this.START_IP_INFO+this.IP_INFO_LENGTH).test();
    }

    public String toString(){
        String result = "";
        result += "\tHeader Length: 20 bytes(" + this.getHeaderLength()+")\n";
        result += "\tTotal Length: " + this.getTotalLength() + "\n";
        result += "\tIdentification: " + this.getIndentification(0) + "\n";
        result += "\tFlags: " + this.GetFlag() + "\n";
        result += "\tFragmentOffset: " + this.getIndentification(4) + "\n";
        result += "\tProtocol: " + this.getProtocol() + "\n";
        result += "\tHeader Checksum: " + this.getCheckSum() +"\n";
        result += "\tSource Address: " + this.getIpv4SourceAddress() + "\n";
        result += "\tDestination Address: " + this.getIpv4DestinationAddress() + "\n";

        switch(this.getProtocol()){
            case 6:
                result += this.tcpHelper.toString();
                break;
            case 17:
                result += this.udpHelper.toString();
            case 1:
                if(this.icmpHelper != null){
                    result += this.icmpHelper.toString();
                }
            default:
                break;
        }
        return result;
    }

}
