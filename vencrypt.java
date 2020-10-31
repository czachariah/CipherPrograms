import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This is the vencrypt class.
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
            System.out.println("usage: java vencrypt [keyfile] [plaintextfile] [ciphertextfile]");
            return;
        }

        // read and store in the key
        String getKey = getAllBytes(args[0]);
        char[] key = getKey.toCharArray();

        // in case an empty key is given
        if (getKey.length() == 0) {
            System.out.println("empty key file");
            return;
        } else {
            System.out.println("keyFile=" + args[0] + ", length=" + getKey.length());
        }

        // now read through the message, figure out the cypher using the key and print out to the cypher
        int placeInKey = 0;
        try {
            FileInputStream scanner = new FileInputStream(args[1]); // message
            OutputStream writer = new FileOutputStream(args[2]);    // cipher
            int numRead;
            byte readData[] = new byte[8]; // store the bytes being read
            do {
                numRead = scanner.read(readData);
                for (int i = 0; i < numRead; ++i){
                    int messageChar = (int)readData[i];
                    int keyChar = key[placeInKey];
                    char cypherHex = (char) ((messageChar + keyChar) % 256);
                    writer.write(cypherHex);
                    ++placeInKey;
                    if (placeInKey >= key.length) { // wrap around the key once the pointer reaches the end 
                        placeInKey = 0;
                    }
                }
            } while (numRead != -1);
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