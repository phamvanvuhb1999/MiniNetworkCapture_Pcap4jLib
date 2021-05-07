package com.iphelper;


import org.pcap4j.util.ByteArrays;


public class IpHelper {
    int MCAPINFO_LENGTH = 14;
    byte[] data;
    public Ipv4Helper ipv4Helper;
    public Ipv6Helper ipv6Helper;
    public ArpHelper arpHelper;

    public IpHelper(byte[] rawData){
        this.data = new byte[rawData.length];
        this.data = rawData;
        int ipversion = this.getIpVersion();
        //System.out.println("Ipversion: " + ipversion);
        if(ipversion == 4){
            if(isArpPacket()){
                arpHelper = new ArpHelper(this.data);
            }else {
                ipv4Helper = new Ipv4Helper(this.data);
            }
        }else if(ipversion == 6){
            ipv6Helper = new Ipv6Helper(this.data);
        }
    }

    public int getPacketLength(){
        return this.data.length; //-8
    }

    public boolean isIcmpPacket(){
        if(getIpVersion() == 4){
            if(isArpPacket()){
                return false;
            }
            return this.ipv4Helper.isIcmpPacket() || false;
        }else if(getIpVersion() == 6){
            return this.ipv6Helper.isIcmpPacket() || false;
        }else {
            return false;
        }
    } 

    public boolean isUdpPacket(){
        if(getIpVersion() == 4){
            if(isArpPacket()){
                return false;
            }
            return this.ipv4Helper.isUdpPacket() || false;
        }else if(getIpVersion() == 6){
            return this.ipv6Helper.isUdpPacket() || false;
        }else {
            return false;
        }
    }

    public boolean isTcpPacket(){
        if(getIpVersion() == 4){
            if(isArpPacket()){
                return false;
            }
            return this.ipv4Helper.isTcpPacket() || false;
        }else if(getIpVersion() == 6){
            return this.ipv6Helper.isTcpPacket() || false;
        }else {
            return false;
        }
    }
    public String[] getIpv4mcapInfo(){
        byte[] bsourceAddress = new byte[6];
        byte[] bdesAddress = new byte[6];

        System.arraycopy(this.data, 0, bdesAddress, 0, bdesAddress.length);
        System.arraycopy(this.data, 0 + 6, bsourceAddress, 0, bsourceAddress.length);

        String sourceAddress = ByteArrays.toHexString(bsourceAddress, ":");
        String destinationAddress = ByteArrays.toHexString(bdesAddress, ":");
        
        String[] address = new String[2];
        address[0] = sourceAddress;
        address[1] = destinationAddress;
        return address;
    }

    public int getIpVersion(){
        byte[] btype = new byte[2];
        System.arraycopy(this.data, 0 + 12, btype, 0, btype.length);
        //System.out.println(ByteArrays.toHexString(btype, ""));
        if(btype[0] == 0x08 && (btype[1] == 0x00 || btype[1] == 0x06)){
            return 4;
        }
        // if(btype[0] == 0x86 && btype[1] == 0xdd){
        //     return 6;
        // }
        // return -1;
        else {
            return 6;
        }
    }

    public boolean isArpPacket(){
        byte[] btype = new byte[2];
        System.arraycopy(this.data, 0 + 12, btype, 0, btype.length);
        if(btype[0] == 0x08 && btype[1] == 0x06){
            return true;
        }
        return false;
    }


    public String getIpSourceAddress(){
        if(getIpVersion() == 4){
            if(isArpPacket()){
                return this.arpHelper.getSourceAddress();
            }else {
                return this.ipv4Helper.getIpv4SourceAddress();
            }
        }else{
            return this.ipv6Helper.getSourceAddress();
        }
    }

    public String getIpDestinationAddress(){
        if(getIpVersion() == 4){
            if(isArpPacket()){
                return this.arpHelper.getDestinationAddress();
            }
            return this.ipv4Helper.getIpv4DestinationAddress();
        }
        else{
            return this.ipv6Helper.getDestinationAddress();
        }
    }
}