package com.iphelper;
import org.pcap4j.util.ByteArrays;

public class IcmpHelper extends ProtocolHelper{
    int bTypeLength = 1;
    int bCodeLength = 1;
    int bCheckSumLength = 2;
    int bIdentifierBE = 2;
    int bIdentifierLE = 2;
    int bSequenceNumberBE = 2;
    int bSequenceNumberLE = 2;


    public IcmpHelper(byte[] data, int offset){
        super(data, offset);
    }

    public int getType(){
        return getIntFromByteArray(0, bTypeLength);
    }

    public int getCode(){
        return getIntFromByteArray(1, bCodeLength);
    }

    public String getCheckSum(){
        return getStringFromByteArray(2, bCheckSumLength, "", 0);
    }

    public String getIdentifierBE(){
        return getStringFromByteArray(4, bIdentifierBE, "", 0);
    }
    public String getIdentifierLE(){
        return getStringFromByteArray(6, bIdentifierLE, "", 0);
    }

    public String getSequenceNumberBE(){
        return getStringFromByteArray(8, bIdentifierBE, "", 0);
    }
    public String getSequenceNumberLE(){
        return getStringFromByteArray(10, bIdentifierLE, "", 0);
    }
    

    public String getIcmpPayload(){
        byte[] temp = this.getPayloadData();
        String result = "Data (" +temp.length+") \n";
        result += "\t\t" + "Data:" + ByteArrays.toHexString(temp, "");
        return result;
    }

    public byte[] getPayloadData(){
        byte[] result = new byte[this.data.length - 12];
        System.arraycopy(this.data, 12, result, 0, result.length);
        return result;
    }

    public String toString(){
        String result = "";
        result += "\tType: " + this.getType() + "\n";
        result += "\tCode: " + this.getCode() + "\n";
        result += "\tChecksum: " + this.getCheckSum() + "\n";
        result += "\tIdentifier(BE): " + this.getIdentifierBE() +"\n";
        result += "\tIdentifier(LE): " + this.getIdentifierLE() + "\n";
        result += "\tSequence Number(BE): " + this.getSequenceNumberBE() + "\n";
        result += "\tSequence Number(LE): " + this.getSequenceNumberLE() +"\n";
        result += "ICMP Payload: \n";
        result += "\t" + this.getPrintPayload(this.getIcmpPayload()) + "\n\n";
        result += "\t" + this.getReadableFromBytesData(this.getPayloadData()) + "\n";
        return result;
    }
}