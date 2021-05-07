package com.iphelper;

import org.pcap4j.util.ByteArrays;

public class ProtocolHelper {
    byte[] data;
    public ProtocolHelper(byte[] data, int offset){
        this.data = new byte[data.length];
        System.arraycopy(data, offset, this.data, 0, data.length - offset);
    }
    protected int getIntFromByteArray(int offset, int length){
        try{
            if(offset < 0 || offset + length > 20){
                return -1;
            }else {
                byte[] temp = new byte[length];
                System.arraycopy(this.data, offset, temp, 0, length);
                int sum = 0;
                for(int i = length - 1; i >= 0; i --){
                    sum += (temp[i] & 0xFF)*Math.pow(2, 8*i);
                }
                return sum;
            }
        }catch(Exception e){
            e.printStackTrace();
            return -1;
        }
    }

    protected String getStringFromByteArray(int offset, int length, String Separator, int bitcut){
        try{
            int cut = 0;
            if(bitcut > cut){
                cut = bitcut;
            }
            if(offset < 0 || offset + length > 20){
                return "";
            }else {
                byte[] temp = new byte[length];
                System.arraycopy(this.data, offset, temp, 0, length);
                if(cut > 0 && cut <= 8){
                   int a = (temp[0] << cut);
                   temp[0] = ByteArrays.toByteArray(a, 1)[0];
                   return "0x"+ByteArrays.toHexString(temp, Separator);
                }else {
                    return "0x"+ByteArrays.toHexString(temp, Separator);
                }
            }
        }catch(Exception e){
            e.printStackTrace();
            return "";
        }
    }


    protected String getDataStringFromByteArray(int offset, int length, String Separator){
        try{
            if(offset < 0){
                return "Invalid offset || lenth.";
            }else {
                byte[] temp = new byte[length];
                System.arraycopy(this.data, offset, temp, 0, length);
                char[] result = new char[length];
                for(int i = 0; i < length; i++){
                    int code = (temp[i] & 0xFF);
                    if(code <= 255 && code >= 0){
                        result[i] = (char)code;
                    }else {
                        result[i] = (char)46;
                    }
                }
                return String.valueOf(result);
            }
        }catch(Exception e){
            e.printStackTrace();
            return "Exception in getdataString tcpHelper.";
        }
    }

    public String getReadableFromBytesData(byte[] data){
        String result = "";
        for(int i = 0; i < data.length; i ++){
            int temp = (data[i] & 0xff);
            if(temp >= 0 && temp <= 255){
                result += Character.toString((char)temp) + " ";
            }else {
                result += ".";
            }
            
            if((i + 1)%8 == 0){
                result += "\t";
            }
            if((i + 1)%16 == 0){
                result += "\n\t";
            }
        }
        return result;
    }

    public String getPrintPayload(String payload){
        if(payload.trim() == ""){
            return "";
        }else {
            String[] temp = payload.split(" ");
            String result = "";
            for(int i = 0 ; i < temp.length; i ++){
                result += temp[i] + " ";
                if((i + 1)%8 == 0){
                    result += "\t";
                }
                if((i + 1)%16 == 0){
                    result += "\n\t";
                }
            }
            return result.toString();
        }
    }
}
