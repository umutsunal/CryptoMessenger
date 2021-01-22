import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.io.*;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;
import javax.swing.JDesktopPane;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.midi.SysexMessage;
import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ScrollPaneConstants;

import java.awt.Font;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import java.awt.Color;
import java.awt.SystemColor;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.FlowLayout;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JDesktopPane;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import java.awt.Font;
import java.awt.LayoutManager;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import java.awt.Color;
import java.awt.SystemColor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

public class Client extends JFrame{
	
	public static String userName;
	public static int clientNumber;
	
	public static String AESKey;
	public static String DESKey;

	public static String AESInitVec;
	public static String DESInitVec;
	
	public static SecretKey AESKeyObject;
	public static SecretKey DESKeyObject;
	
	public static IvParameterSpec AESInitVecObject;
	public static IvParameterSpec DESInitVecObject;
	
	private static JPanel contentPane;
	private static JTextField textField;
	
	private static DataInputStream inStream;
	private static DataOutputStream outStream;
	
	private static JTextArea outputText;
	
	public static boolean isSent = false;
	public static String currentString;
	public static String sendString;
	
	public static boolean isEncrypted = false;
	
	
	public static String AESCBCEnc(String Base64Key, String Base64InitVec, String plainText) throws UnsupportedEncodingException {
		
		String resultString = "";
		
		
		try {
        	byte[] decodedKey = Base64.getDecoder().decode(Base64Key);
        	SecretKeySpec myAesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        	
        	
        	byte[] decodedInitVec = Base64.getDecoder().decode(Base64InitVec);
        	IvParameterSpec myInitVec = new IvParameterSpec(decodedInitVec);
 
        	
			Cipher AESCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			AESCipher.init(Cipher.ENCRYPT_MODE, myAesKey, myInitVec);
			
			byte[] text = plainText.getBytes();
           
            // Encrypt the text
            byte[] textEncrypted = AESCipher.doFinal(text);

            
            byte[] encodedBase64 = Base64.getEncoder().encode(textEncrypted);
            
            resultString = new String(encodedBase64);
            
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return resultString;
		
	}
	
	public static String AESOFBEnc(String Base64Key, String Base64InitVec, String plainText) throws UnsupportedEncodingException  {
		String resultString = "";

		
		try {
        	byte[] decodedKey = Base64.getDecoder().decode(Base64Key);

        	SecretKeySpec myAesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        	
        	byte[] decodedInitVec = Base64.getDecoder().decode(Base64InitVec);
        	IvParameterSpec myInitVec = new IvParameterSpec(decodedInitVec);
        	
			Cipher AESCipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
			AESCipher.init(Cipher.ENCRYPT_MODE, myAesKey, myInitVec);
			
			byte[] text = plainText.getBytes();
           
            // Encrypt the text
            byte[] textEncrypted = AESCipher.doFinal(text);
            
            byte[] encodedBase64 = Base64.getEncoder().encode(textEncrypted);
            
            resultString = new String(encodedBase64);
            
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return resultString;
	}	
	
	public static String DESCBCEnc(String Base64Key, String Base64InitVec, String plainText) throws UnsupportedEncodingException {
		String resultString = "";

		
		try {
        	byte[] decodedKey = Base64.getDecoder().decode(Base64Key);
        	SecretKeySpec myDesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
        	
        	
        	byte[] decodedInitVec = Base64.getDecoder().decode(Base64InitVec);
        	IvParameterSpec myInitVec = new IvParameterSpec(decodedInitVec);

        	
			Cipher DESCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			DESCipher.init(Cipher.ENCRYPT_MODE, myDesKey, myInitVec);
			
			byte[] text = plainText.getBytes();
           
            // Encrypt the text
            byte[] textEncrypted = DESCipher.doFinal(text);
            
            byte[] encodedBase64 = Base64.getEncoder().encode(textEncrypted);
            
            resultString = new String(encodedBase64);
            
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return resultString;
	}
	
	public static String DESOFBEnc(String Base64Key, String Base64InitVec, String plainText) throws UnsupportedEncodingException {
		String resultString = "";

		try {
        	byte[] decodedKey = Base64.getDecoder().decode(Base64Key);
        	SecretKeySpec myDesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
        	
        	
        	byte[] decodedInitVec = Base64.getDecoder().decode(Base64InitVec);
        	IvParameterSpec myInitVec = new IvParameterSpec(decodedInitVec);
 
        	
			Cipher DESCipher = Cipher.getInstance("DES/OFB/PKCS5Padding");
			DESCipher.init(Cipher.ENCRYPT_MODE, myDesKey, myInitVec);
			
			byte[] text = plainText.getBytes();
           
            // Encrypt the text
            byte[] textEncrypted = DESCipher.doFinal(text);

            
            byte[] encodedBase64 = Base64.getEncoder().encode(textEncrypted);
            
            resultString = new String(encodedBase64);
            
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return resultString;		
	}		

	public static void makeIsSentTrue() {
		isSent = true;
	}
	
	public static void initializeGUI(JFrame frame) {
		frame.setBackground(SystemColor.control);
		frame.setForeground(Color.BLUE);
		frame.setTitle("Crypto Messenger");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setBounds(100, 100, 750, 550);
		contentPane = new JPanel();
		contentPane.setBackground(SystemColor.control);
		contentPane.setForeground(Color.GREEN);
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		frame.setContentPane(contentPane);
		
		JPanel panel = new JPanel();
		panel.setBackground(SystemColor.control);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBackground(SystemColor.control);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBackground(SystemColor.control);
		
		JPanel panel_3 = new JPanel();
		GroupLayout gl_contentPane = new GroupLayout(contentPane);
		gl_contentPane.setHorizontalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addContainerGap()
							.addComponent(panel, GroupLayout.DEFAULT_SIZE, 716, Short.MAX_VALUE))
						.addComponent(panel_1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addContainerGap()
							.addComponent(panel_2, GroupLayout.DEFAULT_SIZE, 716, Short.MAX_VALUE))
						.addGroup(gl_contentPane.createSequentialGroup()
							.addContainerGap()
							.addComponent(panel_3, GroupLayout.PREFERRED_SIZE, 706, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap())
		);
		gl_contentPane.setVerticalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addComponent(panel, GroupLayout.PREFERRED_SIZE, 72, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(panel_1, GroupLayout.PREFERRED_SIZE, 205, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(panel_2, GroupLayout.DEFAULT_SIZE, 181, Short.MAX_VALUE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(panel_3, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
					.addGap(18))
		);
		//////////////////////////////////////////////////////////////////////////
		////////////////////CONNECTING DURUMU VE USER NAME BASTIRILACAK
		textField = new JTextField();
		textField.setBackground(SystemColor.control);
		textField.setColumns(10);
		textField.setEditable(false);
		
		///////////////////////////////////////////////////////////////
		GroupLayout gl_panel_3 = new GroupLayout(panel_3);
		gl_panel_3.setHorizontalGroup(
			gl_panel_3.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_3.createSequentialGroup()
					.addContainerGap()
					.addComponent(textField, GroupLayout.PREFERRED_SIZE, 267, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(429, Short.MAX_VALUE))
		);
		gl_panel_3.setVerticalGroup(
			gl_panel_3.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_3.createSequentialGroup()
					.addComponent(textField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
		);
		panel_3.setLayout(gl_panel_3);
		
		//===========================================================================================================================================
		//===========================================================================================================================================
		
		
		// USERNAME WINDOW
		JFrame userNameBox = new JFrame(); 
		
		String tempstring = JOptionPane.showInputDialog(userNameBox,"Enter Username (no username is not accepted)");
		
		
		try {
			if(tempstring.length()>0) {
				userName=tempstring;
			}
			else {
				System.exit(0);
			}
		}
		catch(NullPointerException e) {
			System.exit(0);
		}

		//WRITE USERNAME TO LEFT-BOTTOM SIDE
		textField.setText("Connected: " + userName);
		
		
		
		
		//----------------------------------------------------------
		// DISCONNECT BUTTON
		JButton disconnectButton = new JButton("Disconnect");
		disconnectButton.setFont(new Font("Tahoma", Font.BOLD, 10));
		
		disconnectButton.addActionListener( new ActionListener()
		{
		    @Override
		    public void actionPerformed(ActionEvent e)
		    {
		    	System.exit(0);
		    }
		});
		
		
		
		//----------------------------------------------------------
		//  AES RADIO BUTTON
		JRadioButton aesButton = new JRadioButton("AES");
		
		
		//----------------------------------------------------------
		//  DES RADIO BUTTON
		JRadioButton desButton = new JRadioButton("DES");
			
		
		ButtonGroup AESDESGroup = new ButtonGroup();
		AESDESGroup.add(aesButton);
		AESDESGroup.add(desButton);
		
		
		
		
		//----------------------------------------------------------
		//  CBC RADIO BUTTON
		JRadioButton cbcButton = new JRadioButton("CBC");
		
		
		
		//----------------------------------------------------------
		//  OFB RADIO BUTTON
		JRadioButton ofbButton = new JRadioButton("OFB");
		
		
		ButtonGroup CBCOFBGroup = new ButtonGroup();
		CBCOFBGroup.add(cbcButton);
		CBCOFBGroup.add(ofbButton);
		
		//===============================================================================================================================================
		
		JLabel lblNewLabel = new JLabel("Server");
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD | Font.ITALIC, 11));
		
		JLabel lblNewLabel_1 = new JLabel("Method");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.BOLD, 10));
		
		JLabel lblNewLabel_2 = new JLabel("Mode");
		lblNewLabel_2.setFont(new Font("Tahoma", Font.BOLD, 10));
		GroupLayout gl_panel = new GroupLayout(panel);
		gl_panel.setHorizontalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addComponent(lblNewLabel, GroupLayout.DEFAULT_SIZE, 706, Short.MAX_VALUE)
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(30)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(disconnectButton)
							.addGap(320)
							.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
								.addGroup(gl_panel.createSequentialGroup()
									.addComponent(aesButton)
									.addPreferredGap(ComponentPlacement.UNRELATED)
									.addComponent(desButton))
								.addComponent(lblNewLabel_1, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE))
							.addGap(53)
							.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
								.addGroup(gl_panel.createSequentialGroup()
									.addComponent(cbcButton)
									.addPreferredGap(ComponentPlacement.UNRELATED)
									.addComponent(ofbButton))
								.addComponent(lblNewLabel_2, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE))))
					.addContainerGap())
		);
		gl_panel.setVerticalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(Alignment.TRAILING, gl_panel.createSequentialGroup()
					.addComponent(lblNewLabel)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblNewLabel_1)
						.addComponent(lblNewLabel_2))
					.addPreferredGap(ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						//.addComponent(connectButton)
						.addComponent(disconnectButton)
						.addComponent(aesButton)
						.addComponent(cbcButton)
						.addComponent(desButton)
						.addComponent(ofbButton))
					.addGap(35))
		);
		panel.setLayout(gl_panel);
		
		
		/////////////////////////////////////////////////////////////////////////////////////
		
		// "TEXT" TEXT AREA
		JTextArea inputText = new JTextArea();
		inputText.setLineWrap(true);
		
		// "CRYPTED TEXT" TEXT AREA
		JTextArea cryptedText = new JTextArea();
		cryptedText.setEditable(false);
		cryptedText.setLineWrap(true);
		
		// ENCRYPT BUTTON
		JButton encryptButton = new JButton("Encrypt");
		encryptButton.setFont(new Font("Tahoma", Font.BOLD, 12));
		encryptButton.addActionListener( new ActionListener()
		{
		    @Override
		    public void actionPerformed(ActionEvent e)
		    {
		    	
		    	if(aesButton.isSelected() && cbcButton.isSelected() && inputText.getText().length() != 0) {
		    		try {
						cryptedText.setText(AESCBCEnc(AESKey, AESInitVec, inputText.getText()));					
						
					} catch (UnsupportedEncodingException e1) {
						
						e1.printStackTrace();
					}
		    	}
		    	else if(aesButton.isSelected() && ofbButton.isSelected() && inputText.getText().length() != 0) {
		    		try {
						cryptedText.setText(AESOFBEnc(AESKey, AESInitVec, inputText.getText()));
						
					} catch (UnsupportedEncodingException e1) {
						e1.printStackTrace();
					}
		    		
		    		
		    	}
		    	else if(desButton.isSelected() && cbcButton.isSelected() && inputText.getText().length() != 0) {
		    		try {
						cryptedText.setText(DESCBCEnc(DESKey, DESInitVec, inputText.getText()));
					
		    		} catch (UnsupportedEncodingException e1) {
						
						e1.printStackTrace();
					}
		    	}
		    	else if(desButton.isSelected() && ofbButton.isSelected() && inputText.getText().length() != 0) {
		    		try {
						cryptedText.setText(DESOFBEnc(DESKey, DESInitVec, inputText.getText()));
						
					} catch (UnsupportedEncodingException e1) {
					
						e1.printStackTrace();
					}
		    	}
		    
		    }
		});
		
		
		// SEND BUTTON
		JButton sendButton = new JButton("Send");
		sendButton.setFont(new Font("Tahoma", Font.BOLD, 12));
		
		sendButton.addActionListener( new ActionListener()
		{
		    @Override
		    public void actionPerformed(ActionEvent e)
		    {
		    	try {

		    		if(cryptedText.getText().length() != 0) {	//IF THE TEXT IS ENCRYPTED BEFORE. IF NOT, IT WILL NOT SEND ANYTHING.
		    			//SEND BASE64 ENCRYPTED TEXT TO THE SERVER
		    			outStream.writeUTF(cryptedText.getText());
		    		
		    			//SEND USERNAME TO THE SERVER
		    			outStream.writeUTF(userName);
		    			
		    			//SEND AES OR DES TO THE SERVER
		    			if(aesButton.isSelected()) outStream.writeUTF("AES");
		    			else outStream.writeUTF("DES");
		    			
		    			//SEND CBC OR OFB TO THE SERVER
		    			if(cbcButton.isSelected()) outStream.writeUTF("CBC");
		    			else outStream.writeUTF("OFB");
		    			
		    		}

		    		
				} 
		    	catch (IOException e1) {
					e1.printStackTrace();
				}
		    }
		});			
		
		

		
		
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		JLabel lblNewLabel_3 = new JLabel("Text");
		
		JLabel lblNewLabel_4 = new JLabel("Crypted Text");
		GroupLayout gl_panel_2 = new GroupLayout(panel_2);
		gl_panel_2.setHorizontalGroup(
			gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_2.createSequentialGroup()
					.addGap(21)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
						.addComponent(lblNewLabel_3, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
						.addComponent(inputText, GroupLayout.PREFERRED_SIZE, 253, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_2.createSequentialGroup()
							.addComponent(cryptedText, GroupLayout.PREFERRED_SIZE, 248, GroupLayout.PREFERRED_SIZE)
							.addGap(18)
							.addComponent(encryptButton)
							.addGap(10)
							.addComponent(sendButton))
						.addComponent(lblNewLabel_4, GroupLayout.PREFERRED_SIZE, 84, GroupLayout.PREFERRED_SIZE))
					.addContainerGap(14, Short.MAX_VALUE))
		);
		gl_panel_2.setVerticalGroup(
			gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(Alignment.TRAILING, gl_panel_2.createSequentialGroup()
					.addContainerGap(96, Short.MAX_VALUE)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
						.addComponent(encryptButton)
						.addComponent(sendButton))
					.addGap(82))
				.addGroup(gl_panel_2.createSequentialGroup()
					.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblNewLabel_3)
						.addComponent(lblNewLabel_4))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
						.addComponent(inputText, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE)
						.addComponent(cryptedText, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE))
					.addContainerGap(22, Short.MAX_VALUE))
		);
		panel_2.setLayout(gl_panel_2);
		
		
		///////////////////////////////////////////////////////////////
		
		// OUTPUT CONSOLE TEXT AREA
		outputText = new JTextArea();
		outputText.setEditable(false);
		
		outputText.setLineWrap(true);
		outputText.setWrapStyleWord(true);

	
		
		
		////////////////////////////////////////////////////////////
		GroupLayout gl_panel_1 = new GroupLayout(panel_1);
		gl_panel_1.setHorizontalGroup(
			gl_panel_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1.createSequentialGroup()
					.addContainerGap()
					.addComponent(outputText, GroupLayout.DEFAULT_SIZE, 706, Short.MAX_VALUE)
					.addContainerGap())
		);
		gl_panel_1.setVerticalGroup(
			gl_panel_1.createParallelGroup(Alignment.LEADING)
				.addComponent(outputText, GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE)
		);
		panel_1.setLayout(gl_panel_1);
		contentPane.setLayout(gl_contentPane);
	}
	
	public static void main(String[] args) throws Exception {
		try{
			Socket socket=new Socket("127.0.0.1",9999);
			
		    inStream=new DataInputStream(socket.getInputStream());
		    outStream=new DataOutputStream(socket.getOutputStream());
		    	
		    String keysAndInits = "";
		    keysAndInits = inStream.readUTF();
		    String[] keysAndInitsArray = keysAndInits.split("\\n");
		    
		    AESKey = keysAndInitsArray[0];
		    DESKey = keysAndInitsArray[1];
		    AESInitVec = keysAndInitsArray[2];
		    DESInitVec = keysAndInitsArray[3];		    
		    
		    
		    EventQueue.invokeLater(new Runnable() {
				public void run() {
					try {
						JFrame frame = new JFrame();
						frame.setVisible(true);
						initializeGUI(frame);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			});
		    
		    
		    
		    
		    while(true){	//CLIENT AÇIK OLDUÐU SÜRECE YAPILACAKLAR
		    		
		    		//BASE64 ENCRYPTED TEXT FROM SERVER
		    		String tempstring= inStream.readUTF();
		    		outputText.append(tempstring + "\n");
		    		

		    		
		    		//GET USERNAME FROM THE SERVER
		    		String tempusername = inStream.readUTF();
		    		
		    		//PRINT USERNAME TO THE CONSOLE
		    		outputText.append(tempusername + "> ");
		    		
		    		//GET DECRYPTED MESSAGE FROM THE SERVER
		    		String decrypted = inStream.readUTF();
		    		
		    		//PRINT DECRYPTED MESSAGE TO THE CONSOLE
		    		outputText.append(decrypted + "\n");
		    		
		    		
		    		//isSent=false;
		    	//}

		    	
		    	
		    }
		
		}
		catch(Exception e){
		}
	}

}