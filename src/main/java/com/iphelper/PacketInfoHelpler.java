package com.iphelper;

public class PacketInfoHelpler extends ProtocolHelper{
    public PacketInfoHelpler(byte[] data, int offset){
        super(data, offset);
    }

    public String httpHeader(){
        String result = "";
        for(int i = 0; i < this.data.length - 1; i ++){
            if(this.data[i] != 0x0d || this.data[i + 1]  != 0x0a){
                String temp = (char)(this.data[i] & 0xFF) + "";
            }
        }

        return result;
    }
}
