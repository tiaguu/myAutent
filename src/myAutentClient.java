import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class myAutentClient {

	private static String KEYSTORE_PATH = System.getProperty("user.dir")+"/bin/keystore/truststore.client";
    private static String KEY_ALIAS = "server";
    private static String KEYSTORE_PASSWORD = "server";
	
	public static void main(String[] args) {
		System.setProperty("javax.net.ssl.trustStore", KEYSTORE_PATH);
        System.setProperty("javax.net.ssl.trustStorePassword", KEYSTORE_PASSWORD);
		
		if (verifyCommand(args)) {
			System.out.println("myAutentClient initialized...");
			
			Scanner sc = new Scanner(System.in);
			String password = null;
			int commandArg = 4;
			
			if (args[4].equals("-p")) {
				commandArg = 6;
			} else {
				password = askPassword(sc);
			}
			
			String user = args[1];
			String server = args[3];
			
			if (password == null) {
				password = args[5];
			}
			
			try {
				String[] serverArray = server.split(":");
				
				String host = serverArray[0];
				int port = Integer.parseInt(serverArray[1]);
				
				try {
					// create ssl client socket
					SocketFactory sf = SSLSocketFactory.getDefault();
			        Socket socket = sf.createSocket(host, port);
					
					//Socket socket = new Socket(host, port);
					
					ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
					ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
					
					if (auth(user, password, in, out)) {
						
						System.out.println("Authentication succeeded\n");
						switch (args[commandArg]) {
							case "-c":
								createUser(args, in, out);
								break;
							case "-l":
								listFiles(args, in, out);
								break;
							case "-e":
								sendFiles(args, in, out, sc);
								break;
							case "-d":
								retrieveFiles(args, in, out);
								break;
							case "-s":
								sendHashedFiles(args, in, out);
								break;
							case "-v":
								verifySignatures(args, in, out);
								break;
						}
					} else {
						System.out.println("Error: Authentication in server failed, provide a correct username and password");
					}
					
					out.close();
					in.close();
					socket.close();
					sc.close();
					
				} catch (IOException e) {
					System.out.print("Error: Connecting to server – "+ e.getMessage());
				}
				
			} catch (ArrayIndexOutOfBoundsException e) {
				System.out.println("Error: Provide a valid host and port");
			}
			
			
				
		}
		
	}
	
	private static boolean verifyCommand(String[] args) {
		
		if (args.length >= 4) {
			if (args[0].equals("-u")) {
				try {
					Integer.parseInt(args[1]);
					if (args[2].equals("-a")) {
						if (args.length >= 5) {
							// se indicar a password, tem de ter pelo menos 7 argumentos
							if (args[4].equals("-p")) {
								if (args.length >= 7) {
									if (args[6].equals("-c") || args[6].equals("-l") || 
											args[6].equals("-e") || args[6].equals("-d") ||
											args[6].equals("-s") || args[6].equals("-v")) {
										return true;
									} else {
										System.out.println("Error: Not a valid command");
										return false;
									}
								} else {
									System.out.println("Error: Not a valid command");
									return false;
								}
							// se nao indicar a password, tem de ter pelo menos 5 argumentos
							} else if (args[4].equals("-c") || args[4].equals("-l") || 
									args[4].equals("-e") || args[4].equals("-d") ||
									args[4].equals("-s") || args[4].equals("-v")) {								
								return true;
							} else {
								System.out.println("Error: Not a valid command");
								return false;
							}
						} else {
							System.out.println("Error: Not a valid command");
							return false;
						}
					} else {
						System.out.println("Error: Must identify a server to initialize myAutentClient");
						return false;
					}
				} catch (NumberFormatException e) {
					System.out.println("Error: User field must be an integer");
					return false;
				}
			} else {
				System.out.println("Error: Must identify an user to initialize myAutentClient");
				return false;
			}
		} else {
			System.out.println("Error: Must identify an user and a server to initialize myAutentClient");
			return false;
		}
		
	}

	private static String askPassword(Scanner sc) {
		
		System.out.println("Insert your password:");
		String pw = sc.nextLine();
		
		return pw;
		
	}

	private static boolean auth(String user, String password, ObjectInputStream in, ObjectOutputStream out) {
		try {
			out.writeObject(user);
			out.writeObject(password);
			
			try {
				return (boolean)in.readObject();
			} catch (ClassNotFoundException e) {
				System.out.print("Error: Authentication in server failed – "+ e.getMessage());
				return false;
			}
			
		} catch (IOException e) {
			System.out.print("Error: Authentication in server failed – "+ e.getMessage());
			return false;
		}
	}
	
	private static void createUser(String[] command, ObjectInputStream in, ObjectOutputStream out) {
		
		String userID = null;
		String userName = null;
		String userPw = null;
		String c = null;
		if (command.length == 8) {
			c = command[4];
			userID = command[5];
			userName = command[6];
			userPw = command[7];
		} else if (command.length == 10) { 
			c = command[6];
			userID = command[7];
			userName = command[8];
			userPw = command[9];
		} else {
			System.out.print("Error: Not a valid create user command");
		}
		
		if (c != null) {
			try {
				out.writeObject(c);
				out.writeObject(userID);
				out.writeObject(userName);
				out.writeObject(userPw);
				
				try {
					System.out.println(in.readObject());
				} catch (ClassNotFoundException e) {
					System.out.print("Error: Creating user in server – "+ e.getMessage());
				}
				
			} catch (IOException e) {
				System.out.print("Error: Creating user in server – "+ e.getMessage());
			}
			
		}
		
	}
	
	private static void listFiles(String[] command, ObjectInputStream in, ObjectOutputStream out) {
		
		String c = null;
		if (command.length == 5) {
			c = command[4];
		} else if (command.length == 7) {
			c = command[6];
		} else {
			System.out.print("Error: Not a valid list files command");
		}
		
		if (c != null) {
			try {
				out.writeObject(c);
				
				try {
					String[][] files_info = (String[][])in.readObject();
					if (files_info.length > 0) {
						for (String[] file_info : files_info) {
							System.out.println(file_info[0]+"	"+file_info[1]+"	"+file_info[2]);
						}
					} else {
						System.out.println("There are no files stored in your server directory");
					}
					
				} catch (ClassNotFoundException e) {
					System.out.print("Error: Listing files in server – "+ e.getMessage());
				}
				
			} catch (IOException e) {
				System.out.print("Error: Listing files in server – "+ e.getMessage());
			}
		}
	}

	private static void sendFiles(String[] command, ObjectInputStream in, ObjectOutputStream out, Scanner sc) {
		
		String user = command[1];
		String c = null;
		String[] filenames = null;
		if (command.length >= 6 && command[4].equals("-e")) {
			c = command[4];
			filenames = Arrays.copyOfRange(command, 5, command.length);
		} else if (command.length >= 8 && command[6].equals("-e")) {
			c = command[6];
			filenames = Arrays.copyOfRange(command, 7, command.length);
		} else {
			System.out.print("Error: Not a valid send files command");
		}
		
		if (c != null) {
			try {
				out.writeObject(c);
				
				List<String> existingFileNames = new ArrayList<String>();
				for (String file : filenames) {
					String ExistsFileDir = System.getProperty("user.dir") + "/bin/files/" + file;
					File file_exists = new File(ExistsFileDir);
					if (file_exists.exists()) {
						existingFileNames.add(file);
					} else {
						System.out.println("Could not send file "+file+" because this file does not exist in your local machine.");
					}
				}
				
				String[] simpleFilesArray = new String[existingFileNames.size()];
				existingFileNames.toArray(simpleFilesArray);
				out.writeObject(simpleFilesArray);
				
				// ENVIAR OS FICHEIROS PARA O SERVIDOR
				for (String filename : existingFileNames) {
					
					String FileDir = System.getProperty("user.dir") + "/bin/files/" + filename;
				    
					boolean file_exists = (boolean)in.readObject();
					
					boolean create = true;
					if (file_exists) {
						boolean ans = true;
						while (ans) {
							System.out.println("\nThere's already a file with name "+filename+" stored in the server, do you wish to replace it? (yes or no)");
							String rep = sc.nextLine();
							if (rep.equals("yes")) {
								out.writeObject(true);
								ans = false;
							} else if (rep.equals("no")) {
								out.writeObject(false);
								create = false;
								ans = false;
							}
						}
					}
					
					if (create) {
					    
						File myFile = new File(FileDir);
						
					    Long len = myFile.length();
					    out.writeObject(len);
					    
					    BufferedInputStream myFileB = new BufferedInputStream(new FileInputStream(FileDir));
					    
					    byte[] buffer = new byte[1024];
					    int n;
					    while ((n = myFileB.read(buffer, 0, 1024)) > 0) {
					    	out.write(buffer, 0, n);
					    }
					    
					    out.flush();
					    myFileB.close();
					    
					    try {
					    	
					    	byte[] signature = (byte[]) in.readObject();
					    	
					    	// saves the signature in the user's file system
							String SignatureFileOutDir = System.getProperty("user.dir") + "/bin/files/" + filename + ".signed." + user;
							FileOutputStream outSignatureFileStream = new FileOutputStream(SignatureFileOutDir);
							BufferedOutputStream outSignatureFile = new BufferedOutputStream(outSignatureFileStream);
							
							outSignatureFile.write(signature);
							
							outSignatureFile.close();
							outSignatureFileStream.close();
					    	
							if ((boolean)in.readObject()) {
								System.out.println("File "+filename+" stored in server correctly");
							} else {
								System.out.println("Error: Sending files to server");
							}
						} catch (ClassNotFoundException e) {
							System.out.print("Error: Sending files to server – "+ e.getMessage());
						}
						
					}
				    
				}
				
			} catch (IOException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			} catch (ClassNotFoundException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			}
			
		}
		
	}
	
	private static void retrieveFiles(String[] command, ObjectInputStream in, ObjectOutputStream out) {
		
		String user = command[1];
		String c = null;
		String[] filenames = null;
		if (command.length >= 6 && command[4].equals("-d")) {
			c = command[4];
			filenames = Arrays.copyOfRange(command, 5, command.length);
		} else if (command.length >= 8 && command[6].equals("-d")) {
			c = command[6];
			filenames = Arrays.copyOfRange(command, 7, command.length);
		} else {
			System.out.print("Error: Not a valid retrieve files command");
		}
		
		if (c != null) {
			try {
				out.writeObject(c);
				out.writeObject(filenames);
				
				for (String file : filenames) {
					boolean exists = (boolean)in.readObject();
					// boolean authorized = (boolean)in.readObject();
					
					if (exists) {
						// if (authorized) {
							
							String FileOutDir = System.getProperty("user.dir") + "/bin/files/" + file;
							
							FileOutputStream outFileStream = new FileOutputStream(FileOutDir);
							BufferedOutputStream outFile = new BufferedOutputStream(outFileStream);
							
							int len = ((Long)in.readObject()).intValue();
							
							int count = 0;
							int bytesRead;
							
							while (count < len) {
								byte[] buffer = new byte[1024];
								bytesRead = in.read(buffer, 0, Math.min(len - count, 1024));
								outFile.write(buffer);
								count += bytesRead;
							}
							
							outFile.close();
							outFileStream.close();
							
							out.writeObject(true);
							System.out.println("File "+file+" was retrieved from the server successfully");
							
							byte[] signature = (byte[]) in.readObject();
					    	
					    	// saves the signature in the user's file system
							String SignatureFileOutDir = System.getProperty("user.dir") + "/bin/files/" + file + ".signed." + user;
							FileOutputStream outSignatureFileStream = new FileOutputStream(SignatureFileOutDir);
							BufferedOutputStream outSignatureFile = new BufferedOutputStream(outSignatureFileStream);
							
							outSignatureFile.write(signature);
							
							outSignatureFile.close();
							outSignatureFileStream.close();
							
							out.writeObject(true);
							System.out.println("File "+file+"'s signature was retrieved from the server successfully");
						
						//} else {
						//	System.out.println("You are not authorized to retrieve file "+file);
						//}
					} else {
						System.out.println("File "+file+" does not exist in server");
					}
				}
				
				
				
				
			} catch (IOException e) {
				System.out.print("Error: Listing files in server – "+ e.getMessage());
			} catch (ClassNotFoundException e) {
				System.out.print("Error: Listing files in server – "+ e.getMessage());
			}
		}
	}

	private static void sendHashedFiles(String[] command, ObjectInputStream in, ObjectOutputStream out) {
		
		String user = command[1];
		String c = null;
		String[] filenames = null;
		if (command.length >= 6 && command[4].equals("-s")) {
			c = command[4];
			filenames = Arrays.copyOfRange(command, 5, command.length);
		} else if (command.length >= 8 && command[6].equals("-s")) {
			c = command[6];
			filenames = Arrays.copyOfRange(command, 7, command.length);
		} else {
			System.out.print("Error: Not a valid send files command");
		}
		
		if (c != null) {
			try {
				out.writeObject(c);
				
				// checks which files exist in client's directory
				List<String> existingFileNames = new ArrayList<String>();
				for (String file : filenames) {
					String ExistsFileDir = System.getProperty("user.dir") + "/bin/files/" + file;
					File file_exists = new File(ExistsFileDir);
					if (file_exists.exists()) {
						existingFileNames.add(file);
					} else {
						System.out.println("Could not send hashed file "+file+" because this file does not exist in your local machine.");
					}
				}
				
				String[] simpleFilesArray = new String[existingFileNames.size()];
				existingFileNames.toArray(simpleFilesArray);
				out.writeObject(simpleFilesArray);
				
				// ENVIAR OS FICHEIROS PARA O SERVIDOR
				for (String filename : existingFileNames) {
					
					String FileDir = System.getProperty("user.dir") + "/bin/files/" + filename;
				        
					File myFile = new File(FileDir);
					
				    BufferedInputStream myFileB = new BufferedInputStream(new FileInputStream(FileDir));
				    
				    MessageDigest md = MessageDigest.getInstance("SHA");
				    
				    byte[] buffer = new byte[1024];
				    int n;
				    while ((n = myFileB.read(buffer, 0, 1024)) > 0) {
				    	// gera a sintese do ficheiro
				    	md.update(buffer);
				    }
				    
				    byte[] hash = md.digest();
				    out.writeObject(hash);
				    
				    /*
				    byte[] buffer2 = new byte[1024];
				    int n2;
				    while ((n2 = hash.read(buffer2, 0, 1024)) > 0) {
				    	// gera a sintese do ficheiro
				    	md.update(buffer);
				    }
				    out.write(hash, 0, hash.length);
				    
				    out.flush();
				    myFileB.close();
				    
				    // has finished sending the file
				    out.writeObject(true);
				    */
				    try {
				    	
				    	byte[] signature = (byte[]) in.readObject();
				    	
				    	// saves the signature in the user's file system
						String SignatureFileOutDir = System.getProperty("user.dir") + "/bin/files/" + filename + ".signed." + user;
						FileOutputStream outSignatureFileStream = new FileOutputStream(SignatureFileOutDir);
						BufferedOutputStream outSignatureFile = new BufferedOutputStream(outSignatureFileStream);
						
						outSignatureFile.write(signature);
						
						outSignatureFile.close();
						outSignatureFileStream.close();
				    	
						// ???? O SERVIDOR GUARDA AS ASSINATURAS E AS SINTESES ????
						/*
						if ((boolean)in.readObject()) {
							System.out.println("File "+filename+" stored in server correctly");
						} else {
							System.out.println("Error: Sending files to server");
						}
						*/
					} catch (ClassNotFoundException e) {
						System.out.print("Error: Sending files to server – "+ e.getMessage());
					}
					
				
				    
				}
				
			} catch (IOException | NoSuchAlgorithmException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			} 
				
			
		}
		
	}

	private static void verifySignatures(String[] command, ObjectInputStream in, ObjectOutputStream out) {
		
		String user = command[1];
		String c = null;
		String[] filenames = null;
		if (command.length >= 6 && command[4].equals("-v")) {
			c = command[4];
			filenames = Arrays.copyOfRange(command, 5, command.length);
		} else if (command.length >= 8 && command[6].equals("-v")) {
			c = command[6];
			filenames = Arrays.copyOfRange(command, 7, command.length);
		} else {
			System.out.print("Error: Not a valid send files command");
		}
		
		if (c != null) {
			try {
				out.writeObject(c);
				
				// checks which files exist in client's directory
				List<String> existingFileNames = new ArrayList<String>();
				for (String file : filenames) {
					String ExistsFileDir = System.getProperty("user.dir") + "/bin/files/" + file;
					File file_exists = new File(ExistsFileDir);
					
					String ExistsSigantureDir = System.getProperty("user.dir") + "/bin/files/" + file + ".signed." + user;
					File signature_exists = new File(ExistsSigantureDir);
					
					if (file_exists.exists()) {
						if (signature_exists.exists()) {
							existingFileNames.add(file);
						} else {
							System.out.println("Could not send file "+file+"'s digital signature because the signature does not exist in your local machine.");
						}
					} else {
						System.out.println("Could not send hashed file "+file+" because this file does not exist in your local machine.");
					}
					
					
				}
				
				String[] simpleFilesArray = new String[existingFileNames.size()];
				existingFileNames.toArray(simpleFilesArray);
				out.writeObject(simpleFilesArray);
				
				// ENVIAR OS FICHEIROS PARA O SERVIDOR
				for (String filename : existingFileNames) {
					
					String FileDir = System.getProperty("user.dir") + "/bin/files/" + filename;
					File myFile = new File(FileDir);
					
				    Long len = myFile.length();
				    out.writeObject(len);
				    
				    BufferedInputStream myFileB = new BufferedInputStream(new FileInputStream(FileDir));
				    
				    MessageDigest md = MessageDigest.getInstance("SHA");
				    
				    byte[] buffer = new byte[1024];
				    int n;
				    while ((n = myFileB.read(buffer, 0, 1024)) > 0) {
				    	// gera a sintese do ficheiro
				    	byte[] hash = md.digest(buffer);
				    	out.write(hash, 0, n);
				    }
				    
				    out.flush();
				    myFileB.close();
				    
				    // sends the signature to the server
				    String inSignDir = System.getProperty("user.dir") + "/bin/files/" + filename + ".signed." + user;
					BufferedInputStream inSignStream = new BufferedInputStream(new FileInputStream(inSignDir));
					byte[] signature = (byte[]) inSignStream.readAllBytes(); 
				    
					out.writeObject(signature);
					
					inSignStream.close();
					
					
					// POR COMPLETAR – RECEBE VERIFICAÇÃO DA ASSINATURA
					
					
				}
			} catch (IOException | NoSuchAlgorithmException e) {
				System.out.print("Error: Sending files to server – "+ e.getMessage());
			}
		}
		
	}

}
