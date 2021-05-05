package com.github.phamvanvuhb1999;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.Image;
import java.util.ArrayList;
import java.util.Scanner;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JButton;
import javax.swing.JTable;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.table.DefaultTableModel;

import java.awt.event.ActionListener;
import java.io.File;
import java.awt.event.ActionEvent;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;


import com.iphelper.IpInfo;

import javax.swing.SwingConstants;
import javax.swing.ImageIcon;
import java.awt.Font;

public class GUI extends JFrame {

	private JPanel contentPane;
	
	public JTable table;
	public String path = "";
	public JButton run_btn;
	public JButton save_btn;
	public JButton filter_btn;
	public JComboBox ProtocolTypeC;
	public JComboBox IpversionC;
	public JTextArea info;
	public static JComboBox networkInterface;
	private ArrayList<IpInfo> currentFill = new ArrayList<IpInfo>();



	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GUI frame = new GUI();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public GUI() {
		try{
			File myObj = new File("env.txt");
      		Scanner myReader = new Scanner(myObj);
			if(myReader.hasNextLine()){
				this.path = myReader.nextLine();
				System.out.println(this.path);
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 984, 568);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		run_btn = new JButton("");
		//ImageIcon imageIcon = new ImageIcon("playIcon.jpg");
		//run_btn.setIcon(imageIcon);
		run_btn.setBounds(23, 11, 45, 25);
		run_btn.setIcon(new ImageIcon(new ImageIcon(path + "playIcon.jpg").getImage().getScaledInstance(45, 25, Image.SCALE_DEFAULT)));
		contentPane.add(run_btn);
		
		save_btn = new JButton("");
		save_btn.setBounds(93, 11, 45, 25);
		save_btn.setIcon(new ImageIcon(new ImageIcon(path + "Icon.png").getImage().getScaledInstance(45, 25, Image.SCALE_DEFAULT)));
		contentPane.add(save_btn);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(10, 50, 663, 470);
		contentPane.add(scrollPane);
		
		table = new JTable();
		table.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"No.", "Time", "Source Address", "Destination Address", "Protocol", "Length", "Infor"
			}
		));
		table.getColumnModel().getColumn(0).setPreferredWidth(51);
		table.getColumnModel().getColumn(1).setPreferredWidth(85);
		table.getColumnModel().getColumn(2).setPreferredWidth(152);
		table.getColumnModel().getColumn(3).setPreferredWidth(153);
		table.getColumnModel().getColumn(4).setPreferredWidth(60);
		table.getColumnModel().getColumn(5).setPreferredWidth(49);
		table.getColumnModel().getColumn(6).setPreferredWidth(201);
		scrollPane.setViewportView(table);
		
		IpversionC = new JComboBox();
		IpversionC.setModel(new DefaultComboBoxModel(new String[] {"...", "IPv4", "IPv6"}));
		IpversionC.setBounds(233, 14, 53, 22);
		contentPane.add(IpversionC);
		
		ProtocolTypeC = new JComboBox();
		ProtocolTypeC.setModel(new DefaultComboBoxModel(new String[] {"...", "ICMP", "TCP", "UDP"}));
		ProtocolTypeC.setBounds(377, 14, 60, 22);
		contentPane.add(ProtocolTypeC);
		
		JLabel lblNewLabel = new JLabel("VERSION");
		lblNewLabel.setBounds(174, 18, 55, 14);
		contentPane.add(lblNewLabel);
		
		JLabel lblNewLabel_1 = new JLabel("PROTOCOL");
		lblNewLabel_1.setBounds(306, 18, 70, 14);
		contentPane.add(lblNewLabel_1);
		
		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setBounds(673, 48, 297, 472);
		contentPane.add(scrollPane_1);
		
		info = new JTextArea();
		scrollPane_1.setViewportView(info);
		info.setEditable(false);
		
		JLabel lblMiniNetworkCapture = new JLabel("Mini Network Capture Tool");
		lblMiniNetworkCapture.setFont(new Font("Tahoma", Font.BOLD, 18));
		lblMiniNetworkCapture.setHorizontalAlignment(SwingConstants.CENTER);
		lblMiniNetworkCapture.setBounds(683, 0, 277, 47);
		contentPane.add(lblMiniNetworkCapture);
		
		filter_btn = new JButton("");
		filter_btn.setBounds(459, 14, 40, 25);
		filter_btn.setIcon(new ImageIcon(new ImageIcon(path + "filter.png").getImage().getScaledInstance(40, 23, Image.SCALE_DEFAULT)));
		contentPane.add(filter_btn);

		networkInterface = new JComboBox();
		networkInterface.setBounds(524, 14, 144, 22);
		contentPane.add(networkInterface);

		table.getSelectionModel().addListSelectionListener(new ListSelectionListener(){
			public void valueChanged(ListSelectionEvent event) {
				System.out.println(table.getValueAt(table.getSelectedRow(), 0).toString());
				int rowIndex = Integer.parseInt(table.getValueAt(table.getSelectedRow(), 0).toString());
				String string = currentFill.get(rowIndex + 1).toString();
				info.setText(string);
			}
		});
	}

	public synchronized void updateTabel(IpInfo newpac){
		currentFill.add(newpac);
		DefaultTableModel model = (DefaultTableModel) table.getModel();
		model.addRow(InInfoToListObject(newpac, model.getRowCount()));
	}

	public Object[] InInfoToListObject(IpInfo newpac, int currentIndex){
		Object[] result = new Object[7];
		result[0] = currentIndex + 1;
		result[1] = newpac.getTimestamp();
		result[2] = newpac.getSourceAddress();
		result[3] = newpac.getDesAddress();
		result[4] = newpac.getProtocol();
		result[5] = newpac.getPacketLength();
		result[6] = "info";
		return result;
	}

	public void updateTabel(ArrayList<IpInfo> result){
		if(result.size() == 1){
			updateTabel(result.get(0));
		}else if(result.size() > 1){

		}
	}

	public void setInterfaceCombobox(ArrayList<String> list){
		String[] temp = new String[list.size()];
		for(int i = 0 ; i < list.size(); i ++){
			temp[i] = list.get(i);
		}
		this.networkInterface.setModel(new DefaultComboBoxModel(temp));
	}

	public static String getCurrentInterface(){
		try{
			Object temp = networkInterface.getSelectedItem();
			if(temp == null){
				return "";
			}else {
				return temp.toString();
			}
		}catch(Exception e){
			e.printStackTrace();
			return "";
		}
	}
}
