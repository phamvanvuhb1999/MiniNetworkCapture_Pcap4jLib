package com.iphelper;

import org.pcap4j.util.ByteArrays;

public class ArpHelper{
    byte[] data;
    int START_IP_INFO = 14;
    int bhardwareType = 2;
    int bprotocolType = 2;
    int bhardwareSize = 1;
    int bprotocolSize = 1;
    int bopCode = 2;
    int bsenderMacAddress = 6;
    int bsenderIpAddress = 4;
    int btargetMacAddress = 6;
    int btargetIpAddress = 4;

    public ArpHelper(byte[] rawdata){
        this.data = new byte[rawdata.length];
        System.arraycopy(rawdata, 0, this.data, 0, rawdata.length);
    }

    public String getHardwareType(){
        int result = getIntFromBytes(this.START_IP_INFO, bhardwareType);
        return "Ethenet (" + result + ")";
    }

    public String getProtoType(){
        byte[] array = new byte[bprotocolType];
        System.arraycopy(this.data, this.START_IP_INFO + bhardwareType, array, 0, bprotocolType);
        String name = "" + getNameIpversion(array);
        String hexString = "0x" + getHexStringfromBytes(this.START_IP_INFO + bhardwareType, bprotocolType, "");
        return name + " (" + hexString +")";
    }

    public int getHardwareSize(){
        return getIntFromBytes(this.START_IP_INFO + bhardwareType + bprotocolType, bhardwareSize);
    }

    public int getProtocolSize(){
        return getIntFromBytes(this.START_IP_INFO + bhardwareType + bprotocolType + bhardwareSize, bprotocolSize);
    }

    public String getOpCode(){
        int code = getIntFromBytes(this.START_IP_INFO + bhardwareType + bprotocolType + bhardwareSize + bprotocolSize, bopCode);
        String type = code == 1 ? "Request " : "Response ";
        return type + "(" + code + ")";
    }

    public String getSenderMac(int off){
        return getHexStringfromBytes(this.START_IP_INFO + bhardwareType + bprotocolType + bhardwareSize + bprotocolSize + bopCode + off, bsenderMacAddress, ":");
    }

    public String getSenderIp(int off){
        int offset = this.START_IP_INFO + bhardwareType + bprotocolType + bhardwareSize + bprotocolSize + bopCode + bsenderMacAddress + off;
        String result = "";
        for(int i = 0; i < bsenderIpAddress; i ++){
            result += getIntFromBytes(offset, 1);
            if(i != bsenderIpAddress - 1){
                result += ".";
            }
        } 
        return result;
    }

    public String getTargetMac(){
        return getSenderMac(10);
    }

    public String getTargetIp(){
        return getSenderIp(10);
    }

    private String getNameIpversion(byte[] array){
        try{
            if(array[0] == 0x08 && array[1] == 0x00){
                return "IPv4";
            }else {
                return "IPv6";
            }
        }catch(Exception e){
            e.printStackTrace();
            return "IPv4";
        }
    }

    public int getIpversionCode(){
        byte[] array = new byte[bprotocolType];
        System.arraycopy(this.data, this.START_IP_INFO + bhardwareType, array, 0, bprotocolType);
        if(array[0] == 0x08 && array[1] == 0x00){
            return 4;
        }else {
            return 6;
        }
    }

    private String getHexStringfromBytes(int offset, int length, String seperator){
        try{
            byte[] baddress = new byte[length];
            System.arraycopy(this.data, offset, baddress, 0, length);
            return ByteArrays.toHexString(baddress, seperator);
        }catch(Exception e){
            e.printStackTrace();
            return "";
        }
    }

    private int getIntFromBytes(int offset, int length){
        try{
            if(length == 1){
                return this.data[offset] & 0xff;
            }
            byte[] barray = new byte[length];
            System.arraycopy(this.data, offset, barray, 0, length);
            int result = 0;
            for(int i = length - 1; i >= 0; i --){
                int temp  = (barray[i] & 0xff);
                temp *= Math.pow(2, 4*(length - 1 - i));
                result += temp;
            }
            return result;
        }catch(Exception e){
            e.printStackTrace();
            return -1;
        }
    }
    
    public String getSourceAddress(){
        return getSenderIp(0);
    }

    public String getDestinationAddress(){
        return getTargetIp();
    }

    public int getProtocolCode(){
        return 100;
    }

    public String getArpInfo(){
        String result = "";
        if(getOpCode() == "Request (1)"){
            result += "Who has " + getTargetIp() + " tell " + getSenderIp(0) +" ?";
        }else {
            result += getSenderIp(0) + " is at " + getSenderMac(0);
        }
        return result;
    }

    public String toString(){
        String result = "";
        result += "\tHardware type: " + this.getHardwareType() + "\n";
        result += "\tProtocol type: " + this.getProtoType() + "\n";
        result += "\tHardware size: " + this.getHardwareSize() + "\n";
        result += "\tProtocol size: " + this.getProtocolSize() + "\n";
        result += "\tOpcode: " + this.getOpCode() + "\n";
        result += "\tSender MAC address: " + this.getSenderMac(0) + "\n";
        result += "\tSender IP address: " + this.getSenderIp(0) + "\n";
        result += "\tTarget MAC address: " + this.getTargetMac() + "\n"; 
        result += "\tTarget IP address: " + this.getTargetIp() + "\n";
        return result;
    }
}