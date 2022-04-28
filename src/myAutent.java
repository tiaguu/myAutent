import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import org.apache.commons.codec.binary.Hex;



public class myAutent {

	
	private static String KEYSTORE_PATH = System.getProperty("user.dir")+"/bin/keystore/keystore.server";
	private static String KEY_ALIAS = "server";
	private static String KEYSTORE_PASSWORD = "server";
	private static byte[] pw_salt = { (byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52,
			(byte) 0x3e, (byte) 0xea, (byte) 0xf2 };
	
	public static void main(String[] args) {
		
		System.setProperty("javax.net.ssl.keyStore", KEYSTORE_PATH);
		System.setProperty("javax.net.ssl.keyStorePassword", KEYSTORE_PASSWORD);
		
		System.out.println("myAutent initialized...\n");
		myAutent server = new myAutent();
		server.startServer();
	}
	
	public void startServer (){
		ServerSocket sSoc = null;
		
		// create ssl server socket
		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			sSoc = ssf.createServerSocket(23456);

		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		Scanner sc = new Scanner(System.in); 
		File directory = new File(System.getProperty("user.dir")+"/bin/files/");
		File userFile = new File(System.getProperty("user.dir")+"/bin/files/users.txt");
		File macFile = new File(System.getProperty("user.dir")+"/bin/files/users.mac");
	    try {
	        if (!directory.exists()){
	            directory.mkdir();
	        }
	    	if (userFile.createNewFile()) {
				BufferedOutputStream outFile = new BufferedOutputStream(new FileOutputStream(userFile));
				
				System.out.println("Insert an admin password:");
				String adminpw = sc.nextLine();
				
				// Hash the admin password 
				MessageDigest md = MessageDigest.getInstance("SHA-512");
				
				md.update(adminpw.getBytes());
				md.update(pw_salt);
				
				byte[] hash = md.digest();
				
				outFile.write(("1;Administrador;"+Base64.getEncoder().encodeToString(hash)).getBytes());
				
				System.out.println("New users file created\n");
				String pathstr = System.getProperty("user.dir") + "/bin/files/1";
			    Path path = Paths.get(pathstr);
			    Files.createDirectory(path);
			    
			    try {
			    	
					this.generateKey("1", Base64.getEncoder().encodeToString(hash));
				
			    } catch (CertificateException | NoSuchProviderException | KeyStoreException | OperatorException e) {
				
			    	// TODO Auto-generated catch block
					e.printStackTrace();
				
			    }
				
			    outFile.close();
			}
	    	
	    	// checks if mac file already exists
			if (!macFile.exists()) {
				
				System.out.println("WARNING: There's no MAC protecting users file intergrity!");
				System.out.println("Do you wish to calculate it? (yes/no)");
				String rep = sc.nextLine();
				boolean writeMac = false;
				boolean ans = true;
				while (ans) {
					if (rep.equals("yes")) {
						writeMac = true;
						ans = false;
					} else if (rep.equals("no")) {
						ans = false;
					}
				}
				
				if (writeMac) {
					macFile.createNewFile();
					this.writeMacFile(macFile);
				}
				
			} else {
				this.verifyMacFile();
			}
			
			sc.close();
			
			while(true) {
				try {
					Socket inSoc = sSoc.accept();
					ServerThread newServerThread = new ServerThread(inSoc);
					newServerThread.start();
			    }
			    catch (IOException e) {
			        e.printStackTrace();
			    }
			}
			
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e1) {
			e1.printStackTrace();
			System.out.println("Error: creating users file");
		}
		
         
		
		
	}
	
	//Threads utilizadas para comunicacao com os clientes
	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
		}
 
		public void run(){
			try {
				ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
				
				String user = null;
				String passwd = null;

				try {
					user = (String)in.readObject();
					passwd = (String)in.readObject();
				} catch (ClassNotFoundException e) {
					System.out.println("Error: Listening to clients – " + e.getMessage());
				}
				
				try {
					verifyMacFile();
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
						| IllegalStateException | IOException e1) {
					System.out.println("Error: Verifying MAC file");
				}
				
				String line;
				boolean auth = false;
				BufferedReader reader = new BufferedReader(new FileReader(System.getProperty("user.dir")+"/bin/files/users.txt"));
			    while ((line = reader.readLine()) != null && auth != true)
			    {
			    	String[] userArray = line.split(";");
			    	
			    	MessageDigest md2 = MessageDigest.getInstance("SHA-512");
			    	
			    	md2.update(passwd.getBytes());
					md2.update(pw_salt);
			    	byte[] hashed_pw = md2.digest();
			    	
			    	if (user.equals(userArray[0]) && Base64.getEncoder().encodeToString(hashed_pw).equals(userArray[2]) ) {
						out.writeObject(true);
						auth = true;
						passwd = userArray[2];
					}
			    }
				
				if (auth) {
					try {
						String command = (String)in.readObject();
						
						switch (command) {
							case "-c":
								createUser(user, in, out);
								break;
							case "-l":
								listFiles(user, in, out);
								break;
							case "-e":
								sendFiles(user, passwd, in, out);
								break;
							case "-d":
								retrieveFiles(user, passwd, in, out);
								break;
							case "-s":
								sendHashedFiles(user, passwd, in, out);
								break;
							case "-v":
								verifySignatures(user, passwd, in, out);
								break;
						}
					} catch (ClassNotFoundException e) {
						System.out.println("Error: Listening to clients – " + e.getMessage());
					} catch (EOFException e) {
						System.out.println("Error: Listening to clients – No valid command was provided");
					}
				} else {
					out.writeObject(false);
				}
				
				out.close();
				in.close();
 			
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		private void createUser(String user, ObjectInputStream in, ObjectOutputStream out) {
			
			if (user.equals("1")) {
			
				try {
					verifyMacFile();
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
						| IllegalStateException | IOException e1) {
					System.out.println("Error: Verifying MAC file");
				}
				
				try {
					String userID = (String)in.readObject();
					String userName = (String)in.readObject();
					String userPw = (String)in.readObject();
					
					File userFile = new File(System.getProperty("user.dir")+"/bin/files/users.txt");
					Scanner myReader = new Scanner(userFile);
					boolean usedID = false;
					while (myReader.hasNextLine()) {
						String userLine = myReader.nextLine();
						String[] userArray = userLine.split(";");
						if (userID.equals(userArray[0])) {
							usedID = true;
							out.writeObject("Error: ID already in use");
						}
					}
					myReader.close();
					
					if (!usedID) {
						
							try {
								FileWriter myWriter = new FileWriter(System.getProperty("user.dir")+"/bin/files/users.txt", true);
								
								byte[] hash = null;
								try {
									// Hash the admin password 
									MessageDigest md = MessageDigest.getInstance("SHA-512");
									
									md.update(userPw.getBytes());
									md.update(pw_salt);
									
									hash = md.digest();
									
								} catch (NoSuchAlgorithmException e) {
									System.out.println("Error: generating users password hash");
								}
								
								myWriter.write("\n"+userID+";"+userName+";"+Base64.getEncoder().encodeToString(hash));
							    myWriter.close();
							    
							    String pathstr = System.getProperty("user.dir") + "/bin/files/" + userID;
							    Path path = Paths.get(pathstr);
							    Files.createDirectory(path);
							    
							    out.writeObject("New user created successfully");
							    System.out.println("New user "+userName+" with ID "+userID+" has been created");
							    
							    File macFile = new File(System.getProperty("user.dir")+"/bin/files/users.mac");
							    writeMacFile(macFile);
							    
							    generateKey(userID, Base64.getEncoder().encodeToString(hash));
							    
							} catch (NoSuchAlgorithmException | CertificateException | NoSuchProviderException
									 | KeyStoreException | OperatorException e) {
								System.out.print("Error: Creating user in server – "+ e.getMessage());
							}
						
					}
					
				} catch (ClassNotFoundException e) {
					System.out.print("Error: Creating user in server – "+ e.getMessage());
				} catch (IOException e) {
					System.out.print("Error: Creating user in server – "+ e.getMessage());
				}
			} else {
				try {
					out.writeObject("Error: Only the admin has the permission to create new users");
				} catch (IOException e) {
					System.out.print("Error: Creating user in server – "+ e.getMessage());
				}
			}
			
		}
		
		private void listFiles(String user, ObjectInputStream in, ObjectOutputStream out) {
			
			try {
				String pathstr = System.getProperty("user.dir") + "/bin/files/" + user;
				File f = new File(pathstr);
		        String[] pathnames = f.list();
		        
		        String[][] files_info = new String[0][0];
		        if (pathnames != null) {
		        	files_info = new String[pathnames.length][3];
		        	
		        	int count = 0;
			        for (String filename : pathnames) {
			        	File file = new File(pathstr + "/" + filename);
			    		
			        	Date lastModified = new Date(file.lastModified());
			        	
			        	DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy");  
			        	DateFormat timeFormat = new SimpleDateFormat("HH:mm");  
			        	String date = dateFormat.format(lastModified);  
			        	String time = timeFormat.format(lastModified);  
			        	
			        	String[] file_info = new String[] { 
			        			  date, time, file.getName()};
			    		files_info[count] = file_info;
			    		count++;
			        }
			        
			        
						out.writeObject(files_info);
					
				    System.out.println("User "+user+" has consulted its files");
		        } else {
		        	out.writeObject(files_info);
		        }
			} catch (IOException e) {
				System.out.print("Error: Listing files in server – "+ e.getMessage());
			}
			
		}
		
		private void sendFiles(String user, String password, ObjectInputStream in, ObjectOutputStream out) {
			
			try {
				String[] filenames = (String[])in.readObject();
				
				for (String file : filenames) {
				
					String FileOutDir = System.getProperty("user.dir") + "/bin/files/" + user + "/" + file;
					
					boolean create = false;
					
					File file_exists = new File(FileOutDir);
					if (file_exists.exists()) {
					    out.writeObject(true);
					    create = (boolean)in.readObject();
					} else {
						out.writeObject(false);
						create = true;
					}
					
					if (create) {
						
						try {
							
							// gets the user private key from the keystore
							PrivateKey userPrivateKey = getUserPrivateKey(user, password);
							
							// generates a random key to encrypt the file
						    KeyGenerator kg = KeyGenerator.getInstance("AES");
						    kg.init(128);
						    SecretKey key = kg.generateKey();
							
							Cipher c = Cipher.getInstance("AES");
						    c.init(Cipher.ENCRYPT_MODE, key);
							
							FileOutputStream outFileStream = new FileOutputStream(FileOutDir);
							BufferedOutputStream outFile = new BufferedOutputStream(outFileStream);
							CipherOutputStream outCipher = new CipherOutputStream(outFile, c);
							
							// initiates the signature with SHA256withRSA algorithm
							Signature s = Signature.getInstance("SHA256withRSA");
							s.initSign(userPrivateKey);
							
							MessageDigest md = MessageDigest.getInstance("SHA-256");
							
							int len = ((Long)in.readObject()).intValue();
							
							int count = 0;
							int bytesRead;
							while (count < len) {
								byte[] buffer = new byte[1024];
								bytesRead = in.read(buffer, 0, Math.min(len - count, 1024));
								
								// signs the buffer with the digital signature
								md.update(buffer);
								
								// writes the buffer to the stream
								outCipher.write(buffer);
								count += bytesRead;
							}
							
							s.update(md.digest());
							
							outCipher.close();
							outFile.close();
							outFileStream.close();
							
							try {
								String KeyFileOutDir = System.getProperty("user.dir") + "/bin/files/" + user + "/" + file + ".key";
								BufferedOutputStream kos = new BufferedOutputStream(new FileOutputStream(KeyFileOutDir));
								
								Certificate userCertificate = this.getUserCertificate(user, password);
								
								Cipher ca = Cipher.getInstance("RSA");
								
								ca.init(Cipher.WRAP_MODE, userCertificate);
							    byte[] keyEncoded = ca.wrap(key);
							
							    kos.write(keyEncoded);
							    kos.close();
							} catch (NoSuchPaddingException | IllegalBlockSizeException e) {
								System.out.print("Error: Encryption in server – "+ e.getMessage());
							}
						    
							
							
							byte[] signature = s.sign();
							
							// sends the signature to the client
							out.writeObject(signature);
							
							// saves the signature in the server's file system
							String SignatureFileOutDir = System.getProperty("user.dir") + "/bin/files/" + user + "/" + file + ".signed." + user;
							FileOutputStream outSignatureFileStream = new FileOutputStream(SignatureFileOutDir);
							BufferedOutputStream outSignatureFile = new BufferedOutputStream(outSignatureFileStream);
							
							outSignatureFile.write(signature);
							
							outSignatureFile.close();
							outSignatureFileStream.close();
							
							
							System.out.println("New file "+file+" stored in user "+user+" directory");
							out.writeObject(true);
							
							
						} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException
								| CertificateException | InvalidKeyException | SignatureException | NoSuchPaddingException e) {
							System.out.print("Error: Auth in server – "+ e.getMessage());
						}
						
					}
					
				}
				
			} catch (ClassNotFoundException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			} catch (IOException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			}
			
		}
		
		private void retrieveFiles(String user, String password, ObjectInputStream in, ObjectOutputStream out) {
			
			try {
				
				
				PublicKey userPublicKey = null;
				try {
					userPublicKey = (PublicKey) getUserPublicKey(user, password);
				} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException
						| CertificateException e2) {
					
					// TO DO 
					
				}
				
				String[] filenames = (String[])in.readObject();
				
				for (String file : filenames) {			
				
					String FileOutDir = System.getProperty("user.dir") + "/bin/files/" + user + "/" + file;
					
					boolean retrieve = false;
					
					File file_exists = new File(FileOutDir);
					if (file_exists.exists()) {
					    out.writeObject(true);
					    retrieve = true;
					} else {
						out.writeObject(false);
					}
					
					
					if (retrieve) {
						
						String KeyInDir = System.getProperty("user.dir") + "/bin/files/" + user + "/" + file + ".key";
						BufferedInputStream BufferKey = new BufferedInputStream(new FileInputStream(KeyInDir));
						
						//Dicas para decifrar
						byte[] KeyEncoded = new byte[256];
						BufferKey.read(KeyEncoded);
						
						PrivateKey userPrivateKey;
						Cipher c = null;
						try {
							userPrivateKey = this.getUserPrivateKey(user, password);
							
							Cipher ca = Cipher.getInstance("RSA");
						    ca.init(Cipher.UNWRAP_MODE, userPrivateKey);
						    
						    Key keyEncoded = ca.unwrap(KeyEncoded, "RSA", Cipher.SECRET_KEY);
							
						    SecretKeySpec KeySpec = new SecretKeySpec(keyEncoded.getEncoded(), "AES");
						    
						    c = Cipher.getInstance("AES");
							c.init(Cipher.DECRYPT_MODE, KeySpec);
						} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException
								| CertificateException | NoSuchPaddingException | InvalidKeyException e1) {
							System.out.print("Error: Encryption in server – "+ e1.getMessage());
						}
						
						//File myFile = new File(FileOutDir);
					    
					    //Long len = myFile.length();
					    //int len = c.getOutputSize((int) myFile.length());
					    //out.writeObject(len);
						
					    BufferedInputStream myFileB = new BufferedInputStream(new FileInputStream(FileOutDir));
					    BufferedInputStream cipherInputStream =  new BufferedInputStream(new CipherInputStream(myFileB, c));
					    
					    byte[] buffer = new byte[1026];
					    while (true) {
					      int r = cipherInputStream.read(buffer, 2, 1024);
					      if (r == -1) break;
					      buffer[0] = (byte) (r >> 8);
					      buffer[1] = (byte) r;
					      out.write(buffer, 0, r + 2);
					    }
					    buffer[0] = 0; buffer[1] = 0;
					    out.write(buffer, 0, 2);
					    out.flush();
					    
					    myFileB.close();
					    cipherInputStream.close();
					    
					    try {
							if ((boolean)in.readObject()) {
								System.out.println("File "+file+" sent to client correctly");
							} else {
								System.out.println("Error: Retrieving files from server");
							}
						} catch (ClassNotFoundException e) {
							System.out.print("Error: Retrieving files from server – "+ e.getMessage());
						}
					    
					    // sends the signature to the client
					    String inSignDir = System.getProperty("user.dir") + "/bin/files/" + user + "/" + file + ".signed." + user;
						BufferedInputStream inSignStream = new BufferedInputStream(new FileInputStream(inSignDir));
						byte[] signature = (byte[]) inSignStream.readAllBytes(); 
					    
						out.writeObject(signature);
						
						inSignStream.close();
						
						try {
							if ((boolean)in.readObject()) {
								System.out.println("This file's signature was also sent to the user correctly");
							} else {
								System.out.println("Error: Retrieving files from server");
							}
						} catch (ClassNotFoundException e) {
							System.out.print("Error: Retrieving files from server – "+ e.getMessage());
						}
						
					}
					
				}
				
			} catch (ClassNotFoundException e) {
				System.out.print("Error: Retrieving files from server – "+ e.getMessage());
			} catch (IOException e) {
				System.out.print("Error: Retrieving files from server – "+ e.getMessage());
			}
			
		}
		
		private void sendHashedFiles(String user, String password, ObjectInputStream in, ObjectOutputStream out) {
			
			try {
				String[] filenames = (String[])in.readObject();
				
				for (String file : filenames) {
				
					String FileOutDir = System.getProperty("user.dir") + "/bin/files/" + user + "/" + file;
						
					try {
						
						// gets the user private key from the keystore
						PrivateKey userPrivateKey = getUserPrivateKey(user, password);
						
						// initiates the signature with SHA256withRSA algorithm
						Signature s = Signature.getInstance("SHA256withRSA");
						s.initSign(userPrivateKey);
						
						byte[] hash = (byte[]) in.readObject();
						
						s.update(hash);
						
						byte[] signature = s.sign();
						
						// sends the signature to the client
						out.writeObject(signature);
						
					} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException
							| CertificateException | InvalidKeyException | SignatureException e) {
						System.out.print("Error: Auth in server – "+ e.getMessage());
					}
					
				}
				
			} catch (ClassNotFoundException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			} catch (IOException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			}
			
		}

		private void verifySignatures(String user, String password, ObjectInputStream in, ObjectOutputStream out) {
			
			try {
				
				
				PublicKey userPublicKey = null;
				try {
					userPublicKey = (PublicKey) getUserPublicKey(user, password);
				} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException
						| CertificateException e2) {
					System.out.print("Error: Verifying signatures in server – "+ e2.getMessage());
				}
				
				
				String[] filenames = (String[])in.readObject();
				
				for (String file : filenames) {			
					
					try {
						
						Signature s = Signature.getInstance("SHA256withRSA");
					    s.initVerify(userPublicKey);
						
					    byte[] hash = (byte[]) in.readObject();
						byte[] signature = (byte[])in.readObject();
						
						s.update(hash);
					    
						if (s.verify(signature)) {
							out.writeObject(true);
							System.out.println("Verified "+file+"'s signature correctly");
						} else {
							out.writeObject(false);
							System.out.println(file+"'s signature is not valid");
						}
						
					} catch (SignatureException e2) {
						out.writeObject(false);
						System.out.println(file+"'s signature is not valid");
					}
				}
				
			} catch (ClassNotFoundException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
				System.out.print("Error: Verifying signatures in server – "+ e.getMessage());
			} 
			
		}
		
		private PrivateKey getUserPrivateKey (String usernumber, String password) 
				throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
			
			String user_keystore_path = System.getProperty("user.dir")+"/bin/files/"+usernumber+"/"+usernumber+".keystore";
			FileInputStream kfile = new FileInputStream(user_keystore_path);  //keystore
	 	   	KeyStore kstore = KeyStore.getInstance("PKCS12");
	 	   	kstore.load(kfile, password.toCharArray());           //password
	 	   	PrivateKey userPrivateKey = (PrivateKey) kstore.getKey(usernumber, password.toCharArray());
	 	   	
	 	   	return userPrivateKey;
			
		}
		
		private PublicKey getUserPublicKey (String usernumber, String password) 
				throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
			
			String user_keystore_path = System.getProperty("user.dir")+"/bin/files/"+usernumber+"/"+usernumber+".keystore";
			FileInputStream kfile = new FileInputStream(user_keystore_path);  //keystore
	 	   	KeyStore kstore = KeyStore.getInstance("PKCS12");
	 	   	kstore.load(kfile, password.toCharArray());           //password
	 	   	
	 	   	Certificate cert = kstore.getCertificate(usernumber);
	 	   	PublicKey userPublicKey = cert.getPublicKey();
	 	   	
	 	   	return userPublicKey;
			
		}
		
		private Certificate getUserCertificate (String usernumber, String password) 
				throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
			
			String user_keystore_path = System.getProperty("user.dir")+"/bin/files/"+usernumber+"/"+usernumber+".keystore";
			FileInputStream kfile = new FileInputStream(user_keystore_path);  //keystore
	 	   	KeyStore kstore = KeyStore.getInstance("PKCS12");
	 	   	kstore.load(kfile, password.toCharArray());           //password
	 	   	
	 	   	Certificate cert = kstore.getCertificate(usernumber);
	 	   	
	 	   	return cert;
		}
		
	}
	
	private void generateKey(String userID, String userPw)
		      throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException, KeyStoreException, OperatorException {
		
			// gera chaves assimetricas RSA  
		    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		    keyPairGenerator.initialize(2048);
		    KeyPair keyPair = keyPairGenerator.generateKeyPair();
		    
		    // define informacao para o certificado
		    X500Name dnName = new X500Name("CN=" + userID);
		    BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());
		    Instant startDate = Instant.now();
		    Instant endDate = startDate.plus(2 * 365, ChronoUnit.DAYS);
		    
		    // classe que assina o certificado - certifcado auto assinado
		    String signatureAlgorithm = "SHA256WithRSA";
		    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
		    
		    // cria o certificado
		    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
		        dnName, certSerialNumber, Date.from(startDate), Date.from(endDate), dnName,
		        keyPair.getPublic());
		    Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build((ContentSigner)contentSigner));
		    
		    // guarda chave privada + certificado na keystore
		    String user_keystore_path = System.getProperty("user.dir")+"/bin/files/"+userID+"/"+userID+".keystore";
		    
		    KeyStore kstore = KeyStore.getInstance("JKS");
		    if ((new File(user_keystore_path)).exists()){  // **** file da keystore
				FileInputStream kfile1 = new FileInputStream(user_keystore_path); 
				kstore.load(kfile1, userPw.toCharArray()); // **** password da keystore
				kfile1.close();
		    } else {
				kstore.load(null, null); // **** caso em que o file da keystore ainda n�o existe
		    }
		    		
			Certificate chain [] = {certificate, certificate};
			
			// **** atencao ao alias do user e 'a password da chave privada
			kstore.setKeyEntry(userID, (Key)keyPair.getPrivate(), userPw.toCharArray(), chain);
			FileOutputStream kfile = new FileOutputStream(user_keystore_path); // keystore
			kstore.store(kfile, userPw.toCharArray());
					
	}
	
	private void writeMacFile(File macFile) throws IllegalStateException, IOException {
		BufferedOutputStream outMacFile = new BufferedOutputStream(new FileOutputStream(macFile));
		
		try {
			Mac mac = Mac.getInstance("HmacSHA512");
			
			BufferedReader reader = new BufferedReader(new FileReader(System.getProperty("user.dir")+"/bin/files/users.txt"));
			
			String userLine;
			while ((userLine = reader.readLine()) != null) {
				
				String[] userArray = userLine.split(";");
				if (userArray[0].equals("1")) {
					String password_admin = userArray[2];
					
					// Gerar a chave secreta baseando-se na password
				    PBEKeySpec keySpec = new PBEKeySpec(password_admin.toCharArray(), pw_salt, 65536, 256); 
				    SecretKeyFactory kf;
					kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
					
					SecretKey key = kf.generateSecret(keySpec);
					
					mac.init(key);
				}
				
				byte[] buf = userLine.getBytes();
				mac.update(buf);
			}
			reader.close();
		    
			byte[] generated_bytes = mac.doFinal();
			outMacFile.write(Base64.getEncoder().encodeToString(generated_bytes).getBytes());
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
			e.printStackTrace();
			System.out.println("Error: generating users password hash");
		}
		
		System.out.println("New MAC created\n");
		outMacFile.close();
	}
	
	private void verifyMacFile() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IllegalStateException, IOException {
		
		File mac_file = new File(System.getProperty("user.dir")+"/bin/files/users.mac");

		boolean exists = mac_file.exists();
		
		if (exists) {
			Mac mac = Mac.getInstance("HmacSHA512");
			
			mac.reset();
			
			BufferedReader reader = new BufferedReader(new FileReader(System.getProperty("user.dir")+"/bin/files/users.txt"));
			
			String userLine;
			while ((userLine = reader.readLine()) != null) {
				
				String[] userArray = userLine.split(";");
				if (userArray[0].equals("1")) {
					String password_admin = userArray[2];
					
					// Gerar a chave secreta baseando-se na password
				    PBEKeySpec keySpec = new PBEKeySpec(password_admin.toCharArray(), pw_salt, 65536, 256); 
				    SecretKeyFactory kf;
					kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
					
					SecretKey key = kf.generateSecret(keySpec);
					
					mac.init(key);
				}
				
				byte[] buf = userLine.getBytes();
				mac.update(buf);
			}
			
			byte[] toCompare = mac.doFinal();
			
			String inMacDir = System.getProperty("user.dir") + "/bin/files/users.mac";
			BufferedInputStream inSignStream = new BufferedInputStream(new FileInputStream(inMacDir));
			
			if (Base64.getEncoder().encodeToString(toCompare).equals(new String(inSignStream.readAllBytes(), StandardCharsets.UTF_8))) {
				System.out.println("MAC correctly verified.");
			} else {
				System.out.println("MAC is incorrect, users file has been corrupted, shuting down.");
				System.exit(-1);
			}
			
			reader.close();
		}
		
	}
	
}
