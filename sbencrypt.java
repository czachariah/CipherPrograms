import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This is the sbencrypt class.
 * 
 * Will take a password file, plaintext file and cipher file in order to encrypt
 * the plaintext into the cipher file. This will be done using cipher block
 * chaining and padding.
 * 
 * @author Chris Zachariah
 */
public class sbencrypt {
    public static void main(String[] args) {
        // make sure all the fileNames/pathToFiles are given
        if (args.length != 3) {
            System.out.println("usage: java sbencrypt password plaintextfile ciphertextfile");
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

        // make initilization vector (used just for the first block of the message)
        BigInteger[] iv = new BigInteger[16];
        BigInteger seedToBigNum = new BigInteger(Long.toString(seed));
        BigInteger firstPsudoRandNum = getPsudoRandNum(seedToBigNum);
        iv[0] = firstPsudoRandNum;
        BigInteger nextPsudoRandNum = getPsudoRandNum(firstPsudoRandNum);
        for(int i = 1 ; i < 16 ; ++i) {
            iv[i] = nextPsudoRandNum;
            nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
        }

        // now iterate through the message and XOR both the message byte and pseudorandom byte
        try {       
            FileInputStream scanner = new FileInputStream(args[1]); // cipher
            OutputStream writer = new FileOutputStream(args[2]);    // message
            int numBytesRead;
            int blocksChained = 0;
            boolean hasPad = false;
            byte lastBlock[] = new byte[16]; // the last block that was read
            byte curBlock[] = new byte[16];  // store the bytes being read
            do {
                numBytesRead = scanner.read(curBlock);
                if (blocksChained == 0) { // first block ; use iv
                    if (numBytesRead > 0 && numBytesRead < 16) { // needs padding at the end
                        int padNum = 16 - numBytesRead;
                        int padNumHex = 0x00 + padNum;
                        for (int i = numBytesRead ; i < 16 ; ++i) {
                            curBlock[i] = (byte)padNumHex;
                        }
                        writer.write(curBlock);
                        hasPad = true;
                    } else {
                        if (numBytesRead != -1) {
                          writer.write(curBlock);  
                        }
                    }
                    lastBlock = curBlock;
                    ++blocksChained;
                } else {
                    if (numBytesRead > 0 && numBytesRead < 16) { // needs padding at the end
                        int padNum = 16 - numBytesRead;
                        int padNumHex = 0x00 + padNum;
                        for (int i = numBytesRead ; i < 16 ; ++i) {
                            curBlock[i] = (byte)padNumHex;
                        }
                        writer.write(curBlock);
                        hasPad = true;
                    } else {
                        if (numBytesRead != -1) {
                            writer.write(curBlock);  
                        }
                    }
                    lastBlock = curBlock;
                    ++blocksChained;
                }

                // this condition is true if the number of message bytes is a multiple of 16
                // and needs a whole block at the end
                if (numBytesRead == -1) {
                    if (hasPad == false) {
                        int padNumHex = 0x00 + 16;
                        for (int i = 0 ; i < 16 ; ++i) {
                            lastBlock[i] = (byte)padNumHex;
                        }
                        writer.write(lastBlock);
                    }
                }

            } while (numBytesRead != -1);
            scanner.close();
            writer.close();
        } catch (FileNotFoundException ex) {
            System.out.println("Error opening the cipher file.");
            ex.printStackTrace();
        } catch (IOException ex) {
            System.out.println("Error opening the message file to write into.");
            ex.printStackTrace();
        }


    } // ends the main() method

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

} // ends the sbencrypt class

/*


for (int i = 0; i < numBytesRead; ++i){
                        int messageChar = (int)curBlock[i];
                        String messageCharString = Integer.toString(messageChar);
    
                        BigInteger messageByte = new BigInteger(messageCharString);
                        BigInteger xorVal = messageByte.xor(nextPsudoRandNum);
    
                        char byteToWrite = (char)xorVal.intValue();
                        writer.write(byteToWrite);
    
                        nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                    }

*/
