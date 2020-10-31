import java.io.*;
import java.math.BigInteger;
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
            System.out.println("usage: java scrypt password plaintextfile/ciphertextfile ciphertextfile/plaintextfile");
            return;
        }

        // read in the password and create the seed out of it
        String password = getPassword(args[0]);
        long seed = getSeed(password);
        
        // in case an empty key is given
        if (password.length() == 0) {
            System.out.println("empty password file");
            return;
        } else {
            System.out.println("using seed=" + seed + " from password=\"" + args[0] + "\"");
        }

        // convert to Big Integer to work with unsigned numbers
        BigInteger seedToBigNum = new BigInteger(Long.toString(seed));
        BigInteger firstPsudoRandNum = getPsudoRandNum(seedToBigNum);
        BigInteger nextPsudoRandNum = firstPsudoRandNum;

        // now iterate through the message and XOR both the message byte and pseudorandom byte
        try {       
            FileInputStream scanner = new FileInputStream(args[1]); // cipher
            OutputStream writer = new FileOutputStream(args[2]);    // message
            int numRead;
            byte readData[] = new byte[8]; // store the bytes being read
            do {
                numRead = scanner.read(readData);
                for (int i = 0; i < numRead; ++i){
                    int messageChar = (int)readData[i];
                    String messageCharString = Integer.toString(messageChar);

                    BigInteger messageByte = new BigInteger(messageCharString);
                    BigInteger xorVal = messageByte.xor(nextPsudoRandNum);

                    char byteToWrite = (char)xorVal.intValue();
                    writer.write(byteToWrite);

                    nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                }
            } while (numRead != -1);
            scanner.close();
            writer.close();
        } catch (FileNotFoundException ex) {
            System.out.println("Error opening the cipher file.");
            ex.printStackTrace();
        } catch (IOException ex) {
            System.out.println("Error opening the message file to write into.");
            ex.printStackTrace();
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


    /**
     * This method is used in order to obtain the seed number using the password.
     * @param pass the password
     * @return the seed number
     */
    public static long getSeed(String pass) {
        long hash = 0;
        for(int i = 0 ; i < pass.length() ; ++i) {
            int c = pass.charAt(i);
            hash = c + (hash << 6) + (hash << 16) - hash;
        }
        return hash;
    } // ends the getSeed() method

    /**
     * This method will be used in order to calculate a pseudorandom number.
     * @param num the current pseudorandom number
     * @return the next pseudorandom number
     */
    public static BigInteger getPsudoRandNum(BigInteger numb) {
        BigInteger a = new BigInteger("1103515245");
        BigInteger c = new BigInteger("12345");
        BigInteger m = new BigInteger("256");
        return numb.multiply(a).add(c).mod(m);
    } // ends the getPsudoRandNum() method
    
} // ends the scrypt class