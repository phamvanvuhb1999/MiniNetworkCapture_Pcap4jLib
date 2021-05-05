package com.github.phamvanvuhb1999;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
//import org.pcap4j.util.NifSelector;
import java.io.IOException;
import java.util.List;
import org.pcap4j.core.Pcaps;
//import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import com.iphelper.*;
import java.awt.EventQueue;

import java.util.ArrayList;
import java.util.Hashtable;
import com.controller.Controller;

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
    static ArrayList<IpInfo> listInfoPacket = new ArrayList<IpInfo>();
    static boolean isRunning = false;
    static int snapshotLength = 65536;
    static int readIimeout = 1000;
    static int maxPackets = 100;

    private Provider provider;
    private Worker worker;

    
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
        if(listInfoPacket.size() > 0){
            try{
                for(int i = 0 ; i < listInfoPacket.size(); i ++){
                    IpInfo temp = listInfoPacket.get(i);
                    if(filterIpInfo(temp, ipVersion, protocol)){
                        result.add(temp);
                    }
                }
            }catch(Exception e){
                e.printStackTrace();
            }
        }
        return result;
    }

    public void updateFilter(String ipver, String proto) throws Exception{
        
        if(flagChange){
            throw new Exception("Already switching filter.");
        }else {
            if(checkValidProtocol(proto)){
                protocol = proto;
            }
            if(checkValidIpversion(ipver)){
                ipVersion = ipver;
            }
            changeFilter(true);
        }
    }


    private synchronized void changeFilter(boolean flag){
        flagChange = flag;
    }

    private boolean filterIpInfo(IpInfo packetInfo, String ipversion, String protocol){
        boolean version4 = packetInfo.isIpv4Packet();
        if(version4 && ipversion != "IPv4"){
            return false;
        }
        if(!version4 && ipversion != "IPv6"){
            return false;
        }
        if(ipversion == "..." || (version4 && ipversion == "IPv4") || (!version4 && ipversion == "IPv6")){
            if(protocol == "..."){
                return true;
            }
            boolean isTcp = packetInfo.helper.isIcmpPacket();
            if(isTcp && (protocol != "TCP")){
                return false;
            }
            boolean isUdp = packetInfo.helper.isUdpPacket();
            if(isUdp && protocol != "UDP"){
                return false;
            }
            boolean isIcmp = packetInfo.helper.isIcmpPacket();
            if(isIcmp && protocol != "ICMP"){
                return false;
            }
        }

        return true;
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
                System.out.println("State: " + isRunning);
                if(isRunning){
                    
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


    public static void defineProtocol(){
        int[] code = {1,17,6,58};
        String[] type = {"ICMP","UDP","TCP","Ipv6 ICMP"};
        for(int i = 0 ; i < code.length; i ++){
            protoCode.put(type[i], code[i]);
            protoString.put(code[i], type[i]);
        }
    }

    private boolean checkValidProtocol(String protocol){
        try{
            int code = protoCode.get(protocol);
            if(code >= 0){
                return true;
            }
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
        return true;
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
                if(flagChange && isRunning){
                    changeFilter(false);
                    ArrayList<IpInfo> result = getInfoListWithFilter();
                    gui.updateTabel(result);
                }
            }
        }
    }

    class Worker extends Thread{
        PcapNetworkInterface networkInt;
        boolean legal = true;
        public boolean inited = false;
        PacketListener listener;
        PcapHandle handle;
        public Worker(){}

        private void init(){
            try{
                this.networkInt = Controller.getInterface(GUI.getCurrentInterface());
                if(this.networkInt == null){
                    return;
                }
                this.inited = true;
                handle = networkInt.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readIimeout);
                listener = new PacketListener(){
                    @Override
                    public void gotPacket(Packet packet){
                        byte[] rawData = packet.getRawData();
                        try{
                            IpInfo info = new IpInfo(new IpHelper(rawData), handle.getTimestamp().toString());
                            addListIpInfo(info);
                            gui.updateTabel(info);
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
        @Override
        public void run() {
            super.run();
            this.setPriority(MAX_PRIORITY - 1);
            try {
                while(true){
                    Thread.sleep(100);
                    if(!this.inited && isRunning){
                        System.out.println("Inited: " + this.inited + "  IsRunning: " + isRunning + " INIT.");
                        this.init();
                    }
                    else if(this.inited && isRunning){
                        System.out.println("Inited: " + this.inited + "  IsRunning: " + isRunning + " LOOP.");
                        handle.loop(maxPackets, listener);
                    }else {
                        System.out.println("Inited: " + this.inited + "  IsRunning: " + isRunning + " STOP.");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
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