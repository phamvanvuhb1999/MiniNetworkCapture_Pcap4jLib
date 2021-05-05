package com.iphelper;

import org.pcap4j.util.ByteArrays;

public class TcpHelper extends ProtocolHelper{
    int bsourcePortLength = 2;
    int bdesPortLength = 2;
    int bsequenceNumberLength = 4;
    int backnowledgmentNumberLength = 4;
    int bflagLength = 2;
    int bwindowLenth = 2;
    int bcheckSumLength = 2;
    int burgentPointerLength = 2;

    public TcpHelper(byte[] data, int offset){
        super(data, offset);
    }

    public int getSourcePort(){
        return getIntFromByteArray(0, bsourcePortLength);
    }

    public int getDestinationPort(){
        return getIntFromByteArray(2, bdesPortLength);
    }

    public int getSequenceNumber(){
        return getIntFromByteArray(4, bsequenceNumberLength);
    }

    public int getAcknowledgmentNumber(){
        return getIntFromByteArray(8, backnowledgmentNumberLength);
    }

    public String getFlags(){
        return getStringFromByteArray(12, bflagLength, "", 4);
    }

    public int getWindowSize(){
        return getIntFromByteArray(14, bwindowLenth);
    }

    public String getCheckSum(){
        return getStringFromByteArray(16, bcheckSumLength, "", 0);
    }

    public String gerUrgentPoiter(){
        return getStringFromByteArray(18, burgentPointerLength, "", 0);
    }

    public String test(){
        return getDataStringFromByteArray(0, this.data.length, "");
    }

    public byte[] getPayloadData(){
        byte[] result = new byte[this.data.length - 20];
        System.arraycopy(this.data, 20, result, 0, result.length);
        return result;
    }
    
    public String getTCPPayload(){
        return ByteArrays.toHexString(this.getPayloadData(), " ");
    }

    public String toString(){
        String result = "";
        result += "\tSource Port: " + this.getSourcePort()+"\n";
        result += "\tDestination Port : " + this.getDestinationPort() + "\n";
        result += "\tTCP Segment Len: " + "\n";
        result += "\tSequence Numer: " + this.getSequenceNumber() + "\n";
        result += "\tAcknowledment Number: " + this.getAcknowledgmentNumber() + "\n";
        result += "\tFlag: " + this.getFlags() + "\n";
        result += "\tWindow: " + this.getWindowSize() +"\n";
        result += "\tChecksum: " + this.getCheckSum() +"\n";
        result += "\tUrgent Poiter: " + this.gerUrgentPoiter() + "\n";
        result += "TCP Payload: \n";
        result += "\t" + this.getPrintPayload(this.getTCPPayload()) + "\n\n";
        result += "\t" + this.getReadableFromBytesData(this.getPayloadData()) + "\n";
        return result;
    }
}
 