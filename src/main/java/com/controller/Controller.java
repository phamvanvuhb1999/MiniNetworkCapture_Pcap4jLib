package com.controller;


import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JTable;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.awt.event.ActionEvent;

import com.github.phamvanvuhb1999.App;
import com.github.phamvanvuhb1999.GUI;

import org.pcap4j.core.PcapNetworkInterface;

public class Controller {
    GUI gui;
    App app;
    public Controller(GUI gui, App app){
        this.gui = gui;
        this.app = app;
        updateListInterfaceToCombobox();

        addEventListener();
    }

    private void updateListInterfaceToCombobox(){
        List<PcapNetworkInterface> listInterface = App.allNetInterface;
        
        getIpFromString(listInterface.get(5).getAddresses().toString());
        ArrayList<String> networkInfo = new ArrayList<String>();
        networkInfo.add("");
        for(int i = 0 ; i< listInterface.size(); i ++){
            PcapNetworkInterface temp = listInterface.get(i);
            String info = (i + 1) + " "+ temp.getDescription() + getIpFromString(temp.getAddresses().toString());
            networkInfo.add(info);
        }

        this.gui.setInterfaceCombobox(networkInfo);
    }

    private String getIpFromString(String string){
        String temp = string.replaceAll("[\\[\\]]", " ");
        String[] temp1 = temp.split(" ");
        return temp1[3];
    }

    private void addEventListener(){
        JButton btnRun = this.gui.run_btn;
        JButton btnFilter = this.gui.filter_btn;
        JButton btnSave = this.gui.save_btn;
        JTable table = this.gui.table;
        final JComboBox proto_type = this.gui.ProtocolTypeC;
        final JComboBox ip_version = this.gui.IpversionC;
        final JComboBox networkInterface = this.gui.networkInterface;

        btnRun.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
                if(GUI.getCurrentInterface().trim() != ""){
                    boolean state = app.getState();
                    app.changeState(!state);
                }
			}
		});

        btnSave.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){

            }
        });

        btnFilter.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                String ipver = ip_version.getSelectedItem().toString();
                String proto = proto_type.getSelectedItem().toString();
                try{
                    app.updateFilter(ipver, proto);
                }catch(Exception e1){
                    e1.printStackTrace();
                }
            }
        });
    }


    public static PcapNetworkInterface getInterface(String string){
        try {
            int index = Integer.parseInt((string.split(" ")[0]));
            return App.allNetInterface.get(index - 1);
        } catch (Exception e) {
            return null;
        }
    }

    private static void log(String message){
        System.out.println(message);
    }
}
