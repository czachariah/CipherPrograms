import java.io.*;
import java.util.*;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This is the vencrypt class.
 * 
 * Usage: java vencrypt key message cipher
 * 
 * Obtains key data from the key. Encrypts the message and writes it into the
 * cipher (in hex).
 * 
 * @author Chris Zachariah
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

        // in case an empty key is given
        if (getKey.length() == 0) {
            System.out.println("An empty key file was given. Cypher and message will be the same.");
            key = new char[1];
            key[0] = 0;
        } else {
            System.out.println("Key: '" + getKey + "' , Size: " + getKey.length());
        }

        // now read through the message, figure out the cypher using the key and print out to the cypher
        int placeInKey = 0;
        try {
            Scanner scanner = new Scanner(new File(args[1]));
            OutputStream writer = new FileOutputStream(args[2]);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                for (int i = 0 ; i < line.length() ; ++i) {
                    int messageChar = line.charAt(i);
                    int keyChar = key[placeInKey];
                    char cypherHex = (char) ((messageChar + keyChar) % 256);
                    writer.write(cypherHex);
                    ++placeInKey;
                    if (placeInKey >= key.length) { // wrap around the key once the pointer reaches the end 
                        placeInKey = 0;
                    }
                } // ends the for loop
            } // ends the while loop
            scanner.close();
            writer.close();
        } catch (FileNotFoundException ex) {
            System.out.println("Error opening the message to encrypt.");
            ex.printStackTrace();
        } catch (IOException ex) {
            System.out.println("Error opening the cypher file to write into.");
            ex.printStackTrace();
        }

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
            System.out.println("Error obtaining the key.");
            ex.printStackTrace();
        }
        return content;
    } // ends the getAllBytes() method

} // ends the vencrypt class