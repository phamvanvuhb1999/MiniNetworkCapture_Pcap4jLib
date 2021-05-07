package com.controller;


import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import java.awt.event.ActionListener;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.awt.event.ActionEvent;
import java.util.*;

import com.github.phamvanvuhb1999.App;
import com.gui.GUI;

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
        JButton btnOpenFile = this.gui.open_btn;
        final JComboBox proto_type = this.gui.ProtocolTypeC;
        final JComboBox ip_version = this.gui.IpversionC;
        final JComboBox networkInterface = this.gui.networkInterface;

        btnRun.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
                if(app.getState() == false){
                    App.ClearPackets();
                    App.setSaved(false);
                }
                if(GUI.getCurrentInterface().trim() != ""){
                    boolean state = app.getState();
                    app.changeState(!state);
                }
			}
		});

        btnSave.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                try{
                    if(App.isRunning || App.Saved || App.listInfoPacket.size() <= 0){
                        return;
                    }

                    String filename = new Date().toString() + ".txt";
                    app.closeDumper();

                    filename = filename.replaceAll(" ", "_");
                    filename = filename.replaceAll(":", ".");
                    String path = "src/main/java/com/log/";

                    JFileChooser fileChooser = new JFileChooser();
                    fileChooser.setCurrentDirectory(new File(path));
                    fileChooser.setSelectedFile(new File(filename));
                    int returnValue = fileChooser.showOpenDialog(null);
                    if (returnValue == JFileChooser.APPROVE_OPTION) 
                    {
                        File selectedFile = fileChooser.getSelectedFile();
                        String filePath = selectedFile.getAbsolutePath();
                        File file = new File(filePath);
                        OutputStream os = new BufferedOutputStream(new FileOutputStream(file));
                        for(int i = 0; i < App.listInfoPacket.size(); i ++){
                            String temp = App.listInfoPacket.get(i).toString();
                            os.write(temp.getBytes());
                            os.flush();
                        }
                        os.close();

                        App.setSaved(true);
                    }

                }catch(Exception e1){
                    e1.printStackTrace();
                }
            }
        });

        btnFilter.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                String ipver = ip_version.getSelectedItem().toString();
                String proto = proto_type.getSelectedItem().toString();
                System.out.println("\nFilter: " + ipver + " " + proto);
                try{
                    app.updateFilter(ipver, proto);
                }catch(Exception e1){
                    e1.printStackTrace();
                }
            }
        });

        btnOpenFile.addActionListener(new ActionListener(){
            private void ChooseButton1MouseClicked(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) 
                {
                File selectedFile = fileChooser.getSelectedFile();
                String fullpath = selectedFile.getAbsolutePath();
                App.setOffline(fullpath);
                }
            }
            public void actionPerformed(ActionEvent e){
                ChooseButton1MouseClicked(e);
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
