package com.iphelper;

import org.pcap4j.util.ByteArrays;

public class UdpHelper extends ProtocolHelper{
    int bsourcePortLength = 2;
    int bdesPortLength = 2;
    int bLength = 2;
    int bcheckSumLength = 2;
    int btransactionIdLength = 2;
    int flagsUDPLength = 2;
    int questionLength = 2;
    int answerRRsLength = 2;
    int authorityRRsLength = 2;
    int additionalRRsLength = 2;


    public UdpHelper(byte[] data, int offset){
        super(data, offset);
    }

    public int getSourcePort(){
        return getIntFromByteArray(0, bsourcePortLength);
    }

    public int getDestinationPort(){
        return getIntFromByteArray(2, bdesPortLength);
    }

    public int getLength(){
        return getIntFromByteArray(4, bLength);
    }

    public String getCheckSum(){
        return getStringFromByteArray(6, bcheckSumLength, "", 0);
    }

    public String test(){
        return getDataStringFromByteArray(0, this.data.length, "");
    }

    public String getTransactionId(){
        return getStringFromByteArray(8, 2, "", 0);
    }

    public String getUDPPayload(){
        return ByteArrays.toHexString(this.getPayloadData(), " ");
    }

    public byte[] getPayloadData(){
        byte[] result = new byte[this.data.length - 8];
        System.arraycopy(this.data, 8, result, 0, result.length);
        return result;
    }

    public String toString(){
        String result = "";
        result += "\tSource Port: " + this.getSourcePort()+"\n";
        result += "\tDestination Port : " + this.getDestinationPort() + "\n";
        result += "\tLength: " + this.getLength() + "\n";
        result += "\tChecksum: " + this.getCheckSum() +"\n";
        result += "UDP Payload: \n";
        result += "\t" + this.getPrintPayload(this.getUDPPayload())+ "\n\n";
        result += "\t" + this.getReadableFromBytesData(this.getPayloadData()) + "\n";
        return result;
    }
}