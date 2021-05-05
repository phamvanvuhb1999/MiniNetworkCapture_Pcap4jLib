package com.iphelper;


import org.pcap4j.util.ByteArrays;


public class IpHelper {
    int MCAPINFO_LENGTH = 14;
    byte[] data;
    public Ipv4Helper ipv4Helper;
    public Ipv6Helper ipv6Helper;

    public IpHelper(byte[] rawData){
        this.data = new byte[rawData.length];
        this.data = rawData;
        int ipversion = this.getIpVersion();
        if(ipversion == 4){
            ipv4Helper = new Ipv4Helper(this.data);
        }else if(ipversion == 6){
            ipv6Helper = new Ipv6Helper(this.data);
        }
    }

    public int getPacketLength(){
        return this.data.length - 8;
    }

    public boolean isIcmpPacket(){
        return this.ipv4Helper.isIcmpPacket() || false;
    } 

    public boolean isUdpPacket(){
        return this.ipv4Helper.isUdpPacket() || false;
    }

    public boolean isTcpPacket(){
        return this.ipv4Helper.isTcpPacket() || false;
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
        int result = (btype[0] == 0x08 && btype[1] == 0X00) ? 4 : 6;
        return result;
    }
}