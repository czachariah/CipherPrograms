import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This is the vencrypt class.
 * 
 * Usage:
 *  java vencrypt key message cipher
 * 
 * Obtains key data from the key.
 * Encrypts the message and writes it into the cipher.
 * 
 * @author Chris Zachariah (cvz2)
 */
public class vencrypt {
    public static void main(String[] args) {
        // make sure all the fileNames/pathToFiles are given
        if (args.length != 3) {
            System.out.println("Incorrect Number of Arguments. Please Try again.");
            return;
        }
        
        // read and store in the key
        String getKey = getAllBytes(args[0]);
        char[] key = getKey.toCharArray();

        // now read through the message, figure out the cypher using the key and print out to the cypher
        
        
        int a = 0x41;
        int b = 0x6e;
        int c = (a + b) % 256;
        System.out.println(String.format("0x%X", c));

        

    } // ends the main()

    /**
     * This method is used in order to read all the bytes from the keyFile and store it as a String.
     * @param fileName is the keyFile name or path to keyFile
     * @return a String containing the contents of the keyFile
     */
    public static String getAllBytes(String fileName) {
        String content = "";
        try {
            content = new String(Files.readAllBytes(Paths.get(fileName)));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return content;
    } // ends the getAllBytes() method
} // ends the vencrypt class