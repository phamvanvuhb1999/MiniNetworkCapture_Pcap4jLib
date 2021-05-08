package com.github.phamvanvuhb1999;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
//import org.pcap4j.util.NifSelector;
import java.io.IOException;
//import java.time.temporal.ValueRange;
import java.util.List;

//import javax.lang.model.element.Element;

import org.pcap4j.core.Pcaps;
//import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
//import org.pcap4j.packet.namednumber.IpVersion;

import com.iphelper.*;
import java.awt.EventQueue;
import java.util.*;

import java.util.ArrayList;
import java.util.Hashtable;
import com.controller.Controller;
import com.gui.*;

/**
 *
 */

public class App 
{
    public static Hashtable<String, Integer> protoCode = new Hashtable<String, Integer>();
    public static Hashtable<Integer, String> protoString = new Hashtable<Integer, String>();
    public static List<PcapNetworkInterface> allNetInterface;
    public GUI gui;
    public Controller controller;

    static String ipVersion = "...";
    static String protocol = "...";
    static boolean flagChange = false;

    public static ArrayList<IpInfo> listInfoPacket = new ArrayList<IpInfo>();
    public static boolean isRunning = false;
    public static boolean Saved = false;
    public static boolean offlineMode = false;
    public static String offlinePath = "";

    static int snapshotLength = 65536;
    static int readIimeout = 1000;
    static int maxPackets = 10;

    private Provider provider;
    public Worker worker;

    
    public static List<PcapNetworkInterface> getNetworkDevice() {
        List<PcapNetworkInterface> allDevs = null;
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        
        if(allDevs == null || allDevs.isEmpty()){
            System.out.print("No NIF to capture.");
        }

        return allDevs;
    }


    public synchronized void changeState(boolean newState){
        isRunning = newState;
    }

    public boolean getState(){
        return isRunning;
    }

    public void tryCreateWorker(PcapNetworkInterface net){
        try{
            if(this.worker == null){
                this.worker = new Worker();
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public ArrayList<IpInfo> getInfoListWithFilter(){
        ArrayList<IpInfo> result = new ArrayList<IpInfo>();
        System.out.println("List IpInfo.size: " + listInfoPacket.size());
        if(listInfoPacket.size() > 0){
            try{
                if(protocol == "..." && ipVersion == "..."){
                    result = listInfoPacket;
                }else {
                    for(int i = 0 ; i < listInfoPacket.size(); i ++){
                        IpInfo temp = listInfoPacket.get(i);
                        if(filterIpInfo(temp)){
                            result.add(temp);
                        }
                    }
                }
            }catch(Exception e){
                e.printStackTrace();
            }
        }
        return result;
    }

    public synchronized void updateFilter(String ipver, String proto) throws Exception{
        if(flagChange){
            throw new Exception("Already switching filter.");
        }else if(proto == protocol && ipver == ipVersion){
            changeFilter(false);
        }else {
            if(checkValidProtocol(proto) || proto == "..."){
                protocol = proto;
            }
            if(checkValidIpversion(ipver) || ipver == "..."){
                ipVersion = ipver;
            }
            changeFilter(true);
        }
    }


    private synchronized void changeFilter(boolean flag){
        flagChange = flag;
    }

    private boolean filterIpInfo(IpInfo packetInfo){
        boolean ipcheck = false;
        boolean ver4 = packetInfo.isIpv4Packet();
        if(ipVersion == "..."){
            if(protocol == "..."){
                return true;
            }else {
                ipcheck = true;
                if(ipcheck){
                    return checkProtocol(packetInfo);
                }else{
                    return false;
                }
            }
        }else {
            if((ver4 && ipVersion == "IPv4") || (!ver4 && ipVersion == "IPv6")){
                ipcheck = true;
            }
            if(ipcheck){
                return checkProtocol(packetInfo);
            }else{
                return false;
            }
        }
    }

    public boolean checkProtocol(IpInfo packetInfo){
        if(protocol == "..." 
            || (protocol == "TCP" && packetInfo.helper.isTcpPacket()) 
            || (protocol == "UDP" && packetInfo.helper.isUdpPacket()) 
            || (protocol == "ICMP" && packetInfo.helper.isIcmpPacket())){
            return true;
        }else {
            return false;
        }
    }

    public void Stop(){
        try{
            this.worker.stop();
            this.provider.stop();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public App(){
        final App that = this;
        this.gui = new GUI();
        try{
            allNetInterface = getNetworkDevice();
            this.provider = new Provider();
            this.worker = new Worker();
            this.provider.start();
            this.worker.start();
        }catch(Exception e){
            e.printStackTrace();
        }
        
        EventQueue.invokeLater(new Thread() {
			public void run() {
                this.setPriority(MAX_PRIORITY);
				try {
					that.gui.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
    }

    public static void main(String[] args) throws IOException{
        App app = new App();
        Controller controller = new Controller(app.gui, app);
        app.controller = controller;
        defineProtocol();
        while(true){
            try{
                Thread.sleep(1000);
                if(!isRunning){
                    if(offlineMode){
                        app.worker.openOffline(App.offlinePath);
                    }
                }
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }

    public void setFilter(String version, String protoco ){
        ipVersion = version == null ? null : version;
        protocol = protoco == null ? null : protoco;
    }


    public static void setOffline(String filepath){
        offlineMode = true;
        offlinePath = filepath;
    }


    public static void defineProtocol(){
        int[] code = {1,17,6,58,100};
        String[] type = {"ICMP","UDP","TCP","Ipv6 ICMP", "ARP IPV4"};
        for(int i = 0 ; i < code.length; i ++){
            protoCode.put(type[i], code[i]);
            protoString.put(code[i], type[i]);
        }
    }

    private boolean checkValidProtocol(String protocol){
        try{
            int code = -1;
            Object temp =  protoCode.get(protocol);
            if(temp != null){
                code = (int)temp;
            }
            if(code >= 0){
                return true;
            }else {
                return false;
            }
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
    }

    private boolean checkValidIpversion(String Ipversion){
        return Ipversion == "IPv4" || Ipversion == "IPv6";
    }

    private synchronized void addListIpInfo(IpInfo newpac){
        try{
            listInfoPacket.add(newpac);
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void closeDumper(){
        try{
            this.worker.dumper.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    class Provider extends Thread{
        @Override
        public void run() {
            this.setPriority(MAX_PRIORITY - 1);
            super.run();
            while(true){
                try{
                    Thread.sleep(1000);
                }catch(Exception e){
                    e.printStackTrace();
                }
                if(flagChange){
                    ArrayList<IpInfo> result = getInfoListWithFilter();
                    System.out.print("Result size: " + result.size());
                    gui.updateTabel(result);
                    changeFilter(false);
                }
            }
        }
    }

    class Worker extends Thread{
        PcapNetworkInterface networkInt;
        boolean legal = true;
        PacketListener listener;
        PcapHandle handle;

        public boolean inited = false;
        public PcapDumper dumper;
        public Worker(){}

        private void init(){
            try{
                this.networkInt = Controller.getInterface(GUI.getCurrentInterface());
                if(this.networkInt == null){
                    return;
                }
                this.inited = true; 
                handle = networkInt.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readIimeout);
                dumper = null;
                dumper = handle.dumpOpen("src/main/java/com/dump/"+getRandomFilename());
                listener = new PacketListener(){
                    @Override
                    public void gotPacket(Packet packet){
                        byte[] rawData = packet.getRawData();
                        try{
                            dumper.dump(packet, handle.getTimestamp());
                            if(rawData.length > 0){//filter ARP packet/ handle later.
                                IpInfo info = new IpInfo(new IpHelper(rawData), handle.getTimestamp().toString());
                                if(info.helper.getIpVersion() > 0){
                                    addListIpInfo(info);
                                    if(filterIpInfo(info)){
                                        gui.updateTabel(info);
                                    }
                                }
                            }
                        }catch(Exception e){
                            e.printStackTrace(); 
                        }  
                    }
                };
            }catch(Exception e){
                legal = false;
                e.printStackTrace();
            }
        }

        public void openOffline(String filename){
            try{
                this.handle = Pcaps.openOffline(filename);
                while(true){
                    handle.getNextPacket();
                }
            }catch(Exception e){
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            super.run();
            this.setPriority(MAX_PRIORITY - 1);
            try {
                while(true){
                    Thread.sleep(100);
                    if(!this.inited && isRunning){
                        this.init();
                    }
                    else if(this.inited && isRunning){
                        handle.loop(maxPackets, listener);
                    }else {
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    public static void ClearPackets(){
        App.listInfoPacket = new ArrayList<IpInfo>();
    }


    public static void setSaved(boolean flag){
        App.Saved = flag;
    }

    public static String getRandomFilename(){
        String filename = new Date().toString() + ".pcap";
        filename = filename.replaceAll(" ", "_");
        filename = filename.replaceAll(":", ".");
        return filename;
    }
}


// List<PcapNetworkInterface> devices = getNetworkDevice();
        // for(int i = 0 ; i < devices.size(); i ++){
        //     System.out.print("\nDEVICE[" + i +"]: "+devices.get(i).toString() + '\n');
        // }

        // final PcapHandle handle;
        // try {

        //     handle = devices.get(5).openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readIimeout);
        //     // if(protocol != null){
        //     //     handle.setFilter("icmp", BpfCompileMode.OPTIMIZE);
        //     // }
        //     PacketListener listener = new PacketListener(){
        //         @Override
        //        public void gotPacket(Packet packet){
        //             //System.out.println(handle.getTimestamp());
        //             byte[] rawData = packet.getRawData();
        //             IpInfo info = new IpInfo(new IpHelper(rawData), handle.getTimestamp().toString());
        //             // System.out.println(ByteArrays.toHexString(packet.getRawData(), " "));
        //             // System.out.println(info.toString());
        //             try{
        //                 if(!info.isIpv4Packet()){
        //                     // if(info.helper.isTcpPacket()){
        //                     //     System.out.println(info.toString());
        //                     // }
        //                     System.out.println(info.toString());
        //                 }
        //             }catch(Exception e){
        //                 e.printStackTrace(); 
        //             }
                    
        //        }
        //     };
        //     int maxPackets = 100;
        //     while(true){
        //         // if(chanceFilter){
        //         //     handle.setFilter(protocol, BpfCompileMode.OPTIMIZE);
        //         // }
        //         handle.loop(maxPackets, listener); 
        //     }
        // } catch (Exception e) {
        //     e.printStackTrace();
        // }