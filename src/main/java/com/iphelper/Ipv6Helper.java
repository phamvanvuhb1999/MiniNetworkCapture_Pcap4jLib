package com.iphelper;
import com.github.phamvanvuhb1999.App;

import org.pcap4j.util.ByteArrays;

public class Ipv6Helper {
    int START_MCAPINFO = 0;
    int START_IP_INFO = 14;
    int trafficLabelLength = 4; //values property
    int bPayloadLength = 2;
    int bNextHeaderLength = 1;
    int bHopLimitLength = 1;
    int bSourceAddressLength = 16;
    int bDestinationAddressLength = 16;
    int IP_INFO_LENGTH = 40;

    byte[] data;
    TcpHelper tcpHelper;
    public UdpHelper udpHelper;
    IcmpHelper icmpHelper;
    int protocolCode;

    public Ipv6Helper(byte[] rawData){
        this.data = new byte[rawData.length];
        System.arraycopy(rawData, 0, this.data, 0, rawData.length);
        int protocol = this.getProtocol();
        this.protocolCode = protocol;
        if(protocol == 6){
            this.tcpHelper = new TcpHelper(this.data, this.START_IP_INFO + this.IP_INFO_LENGTH);
        }else if(protocol == 17){
            this.udpHelper = new UdpHelper(this.data, this.START_IP_INFO + this.IP_INFO_LENGTH);
        }else if(protocol == 58){
            this.icmpHelper = new IcmpHelper(this.data, this.START_IP_INFO + this.IP_INFO_LENGTH);
        }
    }

    public int getProtocolCode(){
        return this.protocolCode;
    }

    public int getIntValue(int offset, int bytelength){
        int result = 0;
        byte[] arrTemp = new byte[bytelength];
        System.arraycopy(this.data, offset, arrTemp, 0, arrTemp.length);
        for(int i = 0; i < bytelength; i ++){
            int temp = (int)((arrTemp[bytelength - i - 1] & 0xFF)*Math.pow(2, 4*i));
            result += temp;
        }
        return result;
    }

    public String getHexString(int offset, int bytelength){
        if(bytelength <= 0){
            return "";
        }
        byte[] byt = new byte[bytelength];
        System.arraycopy(this.data, offset , byt, 0, bytelength);
        return "0x" + ByteArrays.toHexString(byt, "");
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

    public String getIpv6AddressFromHex(int offset){
        int bytelength = 16;
        //log("Offset: " + offset + " Length: " + this.data.length);
        if(offset + bytelength > this.data.length){
            throw new IndexOutOfBoundsException("In getipv6AddressFromHex");
        }
        byte[] byt = new byte[bytelength];
        System.arraycopy(this.data, offset , byt, 0, bytelength);
        String result = "";
        for(int i = 0; i < bytelength; i ++){
            if(i != bytelength - 1){
                if(i%2 != 0){
                    result += ByteArrays.toHexString(byt[i], "") + ":";
                }else {
                    result += ByteArrays.toHexString(byt[i], "");
                }
            }else {
                result += ByteArrays.toHexString(byt[i],"");
            }
        }

        return result;
    }

    public String intToHexAddress(int input){
        if(input <= 15){
            return "0" + Integer.toHexString(input);
        }else {
            return Integer.toHexString(input);
        }
    }

    //.... 0000 0000 .... offset for
    public String getTrafficClass(int offset){
        byte[] temp = new byte[2];
        System.arraycopy(this.data, this.START_IP_INFO, temp, 0, temp.length);
        int result = 0;
        result += (temp[1] >> offset) & 0x0F;
        result +=  (temp[0] & 0xFF)*Math.pow(2, 4);
        return "0x"+ByteArrays.toHexString(((Integer)result).byteValue(), "");
    }
    //.... 0000 00.. .... offset for
    public String getDifferentiatedCodePoint(){
        return getTrafficClass(6);
    }

    public String getFlowLabel(){
        byte[] byt = new byte[3];
        System.arraycopy(this.data, this.START_IP_INFO + 1 , byt, 0, 3);
        byt[0] = (byte)(byt[0] & 0x0F);
        return "0x" + ByteArrays.toHexString(byt, "");
    }

    public int getExplicitCongestion(){
        byte temp = this.data[this.START_IP_INFO + 2];
        return (temp >> 2) & 0x03;
    }

    public int getPayloadLength(){
        return getIntValue(this.START_IP_INFO + this.trafficLabelLength, this.bPayloadLength);
    }

    public int getProtocol(){
        return getIntValue(this.START_IP_INFO + this.trafficLabelLength 
            + this.bPayloadLength, bNextHeaderLength);
    }

    public int getHopLimit(){
        return getIntValue(this.START_IP_INFO + this.trafficLabelLength 
            + this.bPayloadLength + this.bNextHeaderLength, this.bHopLimitLength);
    }

    public String getSourceAddress(){
        return getIpv6AddressFromHex(this.START_IP_INFO + this.trafficLabelLength 
            + this.bPayloadLength + this.bNextHeaderLength 
            + this.bHopLimitLength);
    }

    public String getDestinationAddress(){
        return getIpv6AddressFromHex(this.START_IP_INFO + this.trafficLabelLength 
            + this.bPayloadLength + this.bNextHeaderLength 
            + this.bHopLimitLength + this.bSourceAddressLength);
    }

    public String toString(){
        String result = "";
        int proCode = this.getProtocol();
        result += "Protocol Code: " + proCode + "\n";
        try{
            String type = App.protoString.get(proCode);
            if(type != null){
                result += "\tTraffic Class: " + this.getTrafficClass(4) + "\n";
                result += "\t\tDifferented Sevices Code: " + this.getDifferentiatedCodePoint() + "\n";
                result += "\t\tExplicit Congestion: " + this.getExplicitCongestion() + "\n";
                result += "\tFlow Label: " + this.getFlowLabel() + "\n";
                result += "\tPayload Length: " + this.getPayloadLength() + "\n";
                result += "\tNext Header: " + this.getProName(proCode)+ " ("+proCode+") " + "\n";
                result += "\tHop Limit: " + this.getHopLimit() + "\n";
                result += "\tSource Address: " + this.getSourceAddress() + "\n"; 
                result += "\tDestination Address: " + this.getDestinationAddress() + "\n";

                switch(this.getProtocol()){
                    case 6:
                        result += this.tcpHelper.toString();
                        break;
                    case 17:
                        result += this.udpHelper.toString();
                        break;
                    case 58:
                        result += this.icmpHelper.toString();
                        break;
                    default:
                        break;
                }
                return result;
            }
            return "";
        }catch(Exception e){
            e.printStackTrace();
            return "";
        }
    }

    private String getProName(int code){
        switch(code){
            case 1:
                return "ICMP";
            case 6:
                return "TCP";
            case 17:
                return "UDP";
            default:
                return "ARP";
        }
    }

    public static void log(String log){
        System.out.println(log);
    }

}
