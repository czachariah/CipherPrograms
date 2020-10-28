import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This is the scrypt class.
 * 
 * Will take a text-password in order to create a seed. The seed will be used in
 * order to generate pseudorandom stream of bytes that are used in order to
 * encrypt or decrypt the plaintext or cipher file given.
 * 
 * @author Chris Zachariah
 */
public class scrypt {
    public static void main(String[] args) {
        // make sure all the fileNames/pathToFiles are given
        if (args.length != 3) {
            System.out.println("usage: java scrypt password plaintextfile ciphertextfile");
            return;
        }

        // read in the password and create the seed out of it
        String password = getPassword(args[0]);
        long seed = getSeed(password);
        
        // in case an empty key is given
        if (password.length() == 0) {
            System.out.println("Empty password file.");
            return;
        } else {
            System.out.println("using seed=" + seed + " from password=\"" + args[0] + "\"");
        }
        
        

    } // ends the main() 

    /**
     * This method is used in order to read all the bytes from the passwordFile and store it as a String.
     * @param fileName is the passwordFile name or path
     * @return a String containing the contents of the passwordFile
     */
    public static String getPassword(String fileName) {
        String content = "";
        try {
            content = new String(Files.readAllBytes(Paths.get(fileName)));
        } catch (IOException ex) {
            System.out.println("Error obtaining the password.");
            ex.printStackTrace();
        }
        return content;
    } // ends the getPassword() method


    public static long getSeed(String pass) {
        long hash = 0;
        for(int i = 0 ; i < pass.length() ; ++i) {
            int c = pass.charAt(i);
            hash = c + (hash << 6) + (hash << 16) - hash;
        }
        return hash;
    } // ends the getSeed() method
    
} // ends the scrypt class
