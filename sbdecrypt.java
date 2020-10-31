import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This is the sbdecrypt class.
 * 
 * Will take a password file, cipher file and plaintext file in order to decrypt
 * the cipher into the plaintext file.
 * 
 * @author Chris Zachariah
 */
public class sbdecrypt {
    public static void main(String[] args) {
        // make sure all the fileNames/pathToFiles are given
        if (args.length != 3) {
            System.out.println("usage: java sbdecrypt password ciphertextfile plaintextfile");
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

        // make initilization vector (used just for the first block of the message)
        BigInteger[] iv = new BigInteger[16];
        BigInteger[] iv2 = new BigInteger[16];
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
            FileInputStream nextScanner = new FileInputStream(args[1]); // cipher , will be used in order to figure out which is the last block 
            OutputStream writer = new FileOutputStream(args[2]);    // plaintext
            int numBytesRead;
            int numNextBytesRead;
            int blocksChained = 0;
            byte lastBlock[] = new byte[16]; // the last block that was read
            byte lastBlock2[] = new byte[16]; // the last block that was read
            byte curBlock[] = new byte[16];  // store the bytes being read
            byte nextBlock[] = new byte[16];  // store the next bytes that will be read

            numNextBytesRead = nextScanner.read(nextBlock); // read first block (garunteed that there will be at least padding of 16)
        
            do {
                numNextBytesRead = nextScanner.read(nextBlock);
                numBytesRead = scanner.read(curBlock);

                if (numBytesRead == -1) {
                    break;
                }
                if (numNextBytesRead == -1) { // means that the curBlock is the last block with padding
                    if (blocksChained == 0) { // there is only one block in the cipher
                        
                         // read next 16 bytes from keystream
                         for(int i = 0 ; i < 16 ; ++i) {
                            nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                            iv2[i] = nextPsudoRandNum;
                        }

                        // make the cipher text block by XORing the curBlock with the iv
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv2[i].byteValue()));
                        }

                        // shuffle the bytes based on the keystream data
                        for(int i = 15 ; i >= 0 ; --i) {
                            BigInteger first = new BigInteger(Integer.toString((iv2[i].intValue() >> 4) & (0xf)));
                            BigInteger second = new BigInteger(Integer.toString((iv2[i].intValue()) & (0xf)));
                            byte temp = curBlock[first.intValue()];
                            curBlock[first.intValue()] = curBlock[second.intValue()];
                            curBlock[second.intValue()] = temp;
                        }
                   
                        // apply CBC by XORing the curBlock with iv (only since this is the first block)
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                        }
                        
                        // write to the cipher file (excluding the padding)
                        for(int i = 0 ; i < 16 ; ++i) {
                            if(curBlock[i] != curBlock[15]) {
                                writer.write(curBlock[i]);
                            }
                        }
                        ++blocksChained;
                    } else {
                        // copy the contents of the curBlock to the lastBlock2 in order to use for later iterations
                        System.arraycopy(curBlock, 0, lastBlock2, 0, 16);

                         // read next 16 bytes from keystream
                         for(int i = 0 ; i < 16 ; ++i) {
                            nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                            iv2[i] = nextPsudoRandNum;
                        }

                        // make the cipher text block by XORing the curBlock with the iv
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv2[i].byteValue()));
                        }

                        // shuffle the bytes based on the keystream data
                        for(int i = 15 ; i >= 0 ; --i) {
                            BigInteger first = new BigInteger(Integer.toString((iv2[i].intValue() >> 4) & (0xf)));
                            BigInteger second = new BigInteger(Integer.toString((iv2[i].intValue()) & (0xf)));
                            byte temp = curBlock[first.intValue()];
                            curBlock[first.intValue()] = curBlock[second.intValue()];
                            curBlock[second.intValue()] = temp;
                        }
                   
                        // apply CBC by XORing the curBlock with lastBlock
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (lastBlock[i]));
                        }
                        
                        // write to the cipher file (excluding the padding)
                        for(int i = 0 ; i < 16 ; ++i) {
                            if(curBlock[i] != curBlock[15]) {
                                writer.write(curBlock[i]);
                            }
                        }
                        ++blocksChained;
                    }
                } else {
                    if (blocksChained == 0) { // this is the first full block

                        // copy the contents of the curBlock to the lastBlock in order to use in the next iteration
                        System.arraycopy(curBlock, 0, lastBlock2, 0, 16);

                         // read next 16 bytes from keystream
                         for(int i = 0 ; i < 16 ; ++i) {
                            nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                            iv2[i] = nextPsudoRandNum;
                        }

                        // make the cipher text block by XORing the curBlock with the iv
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv2[i].byteValue()));
                        }

                        // shuffle the bytes based on the keystream data
                        for(int i = 15 ; i >= 0 ; --i) {
                            BigInteger first = new BigInteger(Integer.toString((iv2[i].intValue() >> 4) & (0xf)));
                            BigInteger second = new BigInteger(Integer.toString((iv2[i].intValue()) & (0xf)));
                            byte temp = curBlock[first.intValue()];
                            curBlock[first.intValue()] = curBlock[second.intValue()];
                            curBlock[second.intValue()] = temp;
                        }
                   
                        // apply CBC by XORing the curBlock with iv (only since this is the first block)
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                        }

                        System.arraycopy(lastBlock2, 0, lastBlock, 0, 16);
                        
                        writer.write(curBlock);

                        ++blocksChained;
                    } else {
                        // copy the contents of the curBlock to the lastBlock in order to use in the next iteration
                        System.arraycopy(curBlock, 0, lastBlock2, 0, 16);

                        // read next 16 bytes from keystream
                        for(int i = 0 ; i < 16 ; ++i) {
                            nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                            iv2[i] = nextPsudoRandNum;
                        }

                        // make the cipher text block by XORing the curBlock with the iv
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv2[i].byteValue()));
                        }

                        // shuffle the bytes based on the keystream data
                        for(int i = 15 ; i >= 0 ; --i) {
                            BigInteger first = new BigInteger(Integer.toString((iv2[i].intValue() >> 4) & (0xf)));
                            BigInteger second = new BigInteger(Integer.toString((iv2[i].intValue()) & (0xf)));
                            byte temp = curBlock[first.intValue()];
                            curBlock[first.intValue()] = curBlock[second.intValue()];
                            curBlock[second.intValue()] = temp;
                        }
              
                        // apply CBC by XORing the curBlock with lastBlock
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (lastBlock[i]));
                        }

                        System.arraycopy(lastBlock2, 0, lastBlock, 0, 16);
                   
                        writer.write(curBlock);

                        ++blocksChained;
                    }
                }
            } while (numBytesRead != -1);
            nextScanner.close();
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

} // ends the sbdecrypt class