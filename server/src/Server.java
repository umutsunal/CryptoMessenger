import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Server {
	//Custom port
	private int port = 9999;	
	
	//Data Stream lists to communicate clients
    private List<DataOutputStream> clientStreams = new ArrayList<DataOutputStream>();		

    //Key and IV variables
	public static SecretKey AESKey;
	public static SecretKey DESKey;

	public static IvParameterSpec AESInitVec;
	public static IvParameterSpec DESInitVec;
	
	//FileWriter variable
	public static FileWriter logTxtWriter;
    
	public static SecretKey createAESKey() throws Exception {
		KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
		keygenerator.init(128);
        SecretKey myDesKey = keygenerator.generateKey();
        
        return myDesKey;
	}
	
	public static SecretKey createDESKey() throws Exception {
		KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
		keygenerator.init(56);
        SecretKey myDesKey = keygenerator.generateKey();
        
        return myDesKey;
	}
	
	public static IvParameterSpec createAESInitVec() throws Exception {
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[16];
		randomSecureRandom.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		
		
		return ivParams;
	}
	
	public static IvParameterSpec createDESInitVec() throws Exception {
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[8];
		randomSecureRandom.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		

		
		return ivParams;
	}
	
	public static void printKeysAndIVs(SecretKey AESKey, SecretKey DESKey, IvParameterSpec AESInitVec, IvParameterSpec DESInitVec, FileWriter writer) throws IOException {
        
        writer.write("AES Key: "+ Base64.getEncoder().encodeToString(AESKey.getEncoded())+"\n");
        writer.write("DES Key: "+ Base64.getEncoder().encodeToString(DESKey.getEncoded())+"\n");
        writer.write("AES IV: " + Base64.getEncoder().encodeToString(AESInitVec.getIV())+"\n");
        writer.write("DES IV: " + Base64.getEncoder().encodeToString(DESInitVec.getIV())+"\n");
        writer.flush();
	}
    

    
	
	
	//MAIN METHOD
    public static void main(String args[]) throws Exception {
       new Server().server();
    }
    
    private void server() throws Exception {
        ServerSocket serverSocket = null; 

        try {	
        	serverSocket = new ServerSocket(port);
	        
			//AES AND DES KEYS FOR THE WHOLE SERVER-CLIENTS
			AESKey = createAESKey();
			DESKey = createDESKey();
			
			//AES AND DES IV'S FOR THE WHOLE SERVER-CLIENTS
			AESInitVec = createAESInitVec();
			DESInitVec = createDESInitVec();

			//CREATE LOG.TXT FILE
			File logTxtObj = new File("log.txt");
		    logTxtWriter = new FileWriter(logTxtObj, true);
			
			//PRINTS THE KEYS AND IVS
			printKeysAndIVs(AESKey, DESKey, AESInitVec, DESInitVec, logTxtWriter);
			

			
        }
		catch(BindException bind) {	//If a server is already in use, close the new one.
			System.out.println("Server already in use.");
			System.exit(0);
		}
        catch (IOException e) {
            System.out.println(e.getMessage() + " failed to create server socket ");
            return;
        }
	
        while (true) {
           try {
        	   Socket socket = serverSocket.accept();
               DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());
	       
               DataInputStream inStream = new DataInputStream(socket.getInputStream());
   			   
               outStream.writeUTF(Base64.getEncoder().encodeToString(AESKey.getEncoded())+"\n"+Base64.getEncoder().encodeToString(DESKey.getEncoded())+"\n"+Base64.getEncoder().encodeToString(AESInitVec.getIV())+"\n"+Base64.getEncoder().encodeToString(DESInitVec.getIV()));
               outStream.flush();
	       
               clientStreams.add(outStream);
               new ClientThreads(socket, outStream, this, AESKey, DESKey, AESInitVec, DESInitVec, logTxtWriter).start();
	       
           } 
	   catch (IOException e) {

           } 
        }
    }
    
    synchronized List getClients() { 
    	return clientStreams; 
    }
    
    synchronized void removeClient(DataOutputStream remoteOut) {
    	clientStreams.remove(remoteOut);
    }
    
}




class ClientThreads extends Thread {
    private Socket clientSocket;
    private DataOutputStream outStream;
    private Server server;
    private DataInputStream inStream;
    
	private SecretKey AESKey;
	private SecretKey DESKey;

	private IvParameterSpec AESInitVec;
	private IvParameterSpec DESInitVec;
    
    private FileWriter fileWriter;

    ClientThreads(Socket socket, DataOutputStream outStream, Server server, SecretKey AESKey,SecretKey DESKey,IvParameterSpec AESInitVec,IvParameterSpec DESInitVec, FileWriter fileWriter) throws IOException {
        this.clientSocket = socket;
        this.outStream = outStream;
        this.server = server;
        
        this.AESKey = AESKey;
        this.DESKey = DESKey;
        this.AESInitVec = AESInitVec;
        this.DESInitVec = DESInitVec;
        
        this.fileWriter = fileWriter;
        
        inStream = new DataInputStream(socket.getInputStream());
    }

	public static String AESCBCDec(SecretKey AESKey, IvParameterSpec AESInitVec, String encryptedText){	  
		  
		  String decryptedText = null;
		
		  try {
			Cipher AEScipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			AEScipher.init(Cipher.DECRYPT_MODE, AESKey, AESInitVec);
			decryptedText = new String(AEScipher.doFinal(Base64.getDecoder().decode(encryptedText)));
			
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
		return decryptedText;

		
	  }
	
	public static String AESOFBDec(SecretKey AESKey, IvParameterSpec AESInitVec, String encryptedText){	  
		  
		  String decryptedText = null;
		
		  try {
			Cipher AEScipher = Cipher.getInstance("AES/OFB/PKCS5PADDING");
			AEScipher.init(Cipher.DECRYPT_MODE, AESKey, AESInitVec);
			decryptedText = new String(AEScipher.doFinal(Base64.getDecoder().decode(encryptedText)));
			
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
		return decryptedText;

		
	  }	
	
	public static String DESCBCDec(SecretKey DESKey, IvParameterSpec DESInitVec, String encryptedText){	  
		  
		  String decryptedText = null;
		
		  try {
			Cipher DEScipher = Cipher.getInstance("DES/CBC/PKCS5PADDING");
			DEScipher.init(Cipher.DECRYPT_MODE, DESKey, DESInitVec);
			decryptedText = new String(DEScipher.doFinal(Base64.getDecoder().decode(encryptedText)));
			
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
		return decryptedText;

		
	  }
	
	public static String DESOFBDec(SecretKey DESKey, IvParameterSpec DESInitVec, String encryptedText){	  
		  
		  String decryptedText = null;
		
		  try {
			Cipher DEScipher = Cipher.getInstance("DES/OFB/PKCS5PADDING");
			DEScipher.init(Cipher.DECRYPT_MODE, DESKey, DESInitVec);
			decryptedText = new String(DEScipher.doFinal(Base64.getDecoder().decode(encryptedText)));
			
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
		return decryptedText;

		
	  }
    
    public void run() {
        String Base64Encrypted, userNameOfClient, AESorDES, CBCorOFB;

        try {
            while (true) {          
            	//GET BASE64 ENCRYPTED TEXT FROM A CLIENT
            	Base64Encrypted = inStream.readUTF();
                
            	//SEND BASE64 ENCRYPTED TEXT TO ALL CLIENTS
            	broadcast(Base64Encrypted);
            	fileWriter.write(Base64Encrypted + "\n");
            	fileWriter.flush();
            	
            	//GET USERNAME OF USED CLIENT
            	userNameOfClient = inStream.readUTF();
                
                //SEND USERNAME TO ALL CLIENTS
                broadcast(userNameOfClient);
                fileWriter.write(userNameOfClient + "> ");
                fileWriter.flush();
                
                //GET MODE (AES OR DES)
                AESorDES = inStream.readUTF();
                
                //GET MODE (CBC OR OFB)
                CBCorOFB = inStream.readUTF();
                
                //SEND DECRYPTED TEXT TO ALL CLIENTS (SELECT MODES (AES OR DES AND CBC OR OFC))
                if(AESorDES.equals("AES")) {
                	if(CBCorOFB.equals("CBC")) {
                		broadcast(AESCBCDec(AESKey, AESInitVec, Base64Encrypted));
                		fileWriter.write(AESCBCDec(AESKey, AESInitVec, Base64Encrypted) + "\n");
                		fileWriter.flush();
                	}
                	else {
                		broadcast(AESOFBDec(AESKey, AESInitVec, Base64Encrypted));
                		fileWriter.write(AESOFBDec(AESKey, AESInitVec, Base64Encrypted) + "\n");
                		fileWriter.flush();
                	}
                }
                else {
                	if(CBCorOFB.contentEquals("CBC")) {
                		broadcast(DESCBCDec(DESKey, DESInitVec, Base64Encrypted));
                		fileWriter.write(DESCBCDec(DESKey, DESInitVec, Base64Encrypted) + "\n");
                		fileWriter.flush();
                	}
                	else {
                		broadcast(DESOFBDec(DESKey, DESInitVec, Base64Encrypted));
                		fileWriter.write(DESOFBDec(DESKey, DESInitVec, Base64Encrypted) + "\n");
                		fileWriter.flush();
                	}
                }
                
                
                
                
            }
        } 
        catch (IOException e) {
        	server.removeClient(outStream);
        } 
        finally {
            try { 
            	clean(); 
            } 
            catch (IOException x) { 
            	
            }
        }
    }
    
    //SEND THE MESSAGE TO ALL THE CLIENTS USING STREAM LIST
    private void broadcast(String s) {
    	List clientStreams = server.getClients();
    	DataOutputStream dataOut = null;
       
    	for (Iterator i = clientStreams.iterator(); i.hasNext(); ) {
    	dataOut = (DataOutputStream)(i.next());
	   
	   		try {
	   			dataOut.writeUTF(s); 
	   		} 
	   		catch (IOException x) 
	   		{
	   			server.removeClient(dataOut);
	   		}
    	}
    }
    
    private void clean() throws IOException {
       if (outStream != null) {
          server.removeClient(outStream);
          outStream.close();
       }

       if (inStream != null) {
    	   inStream.close();
       }

       if (clientSocket != null) {
    	   clientSocket.close();
       }
    }
}
