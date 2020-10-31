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
            System.out.println("empty password file");
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
            FileInputStream scanner = new FileInputStream(args[1]); // message
            OutputStream writer = new FileOutputStream(args[2]);    // cipher
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

                        // apply CBC by XORing the curBlock with iv (only since this is the first block)
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                        }

                        // read next 16 bytes from keystream
                        for(int i = 0 ; i < 16 ; ++i) {
                            nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                            iv[i] = nextPsudoRandNum;
                        }
                        
                        // shuffle the bytes based on the keystream data
                        for(int i = 0 ; i < 16 ; ++i) {
                            BigInteger first = new BigInteger(Integer.toString((iv[i].intValue()) & (0xf)));
                            BigInteger second = new BigInteger(Integer.toString((iv[i].intValue() >> 4) & (0xf)));
                            byte temp = curBlock[first.intValue()];
                            curBlock[first.intValue()] = curBlock[second.intValue()];
                            curBlock[second.intValue()] = temp;
                        }
                        
                        // make the cipher text block by XORing the curBlock with the iv
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                        }
                        // write to the cipher file
                        writer.write(curBlock);
                        // copy the contents of the curBlock to the lastBlock in order to use in the next iteration
                        System.arraycopy(curBlock, 0, lastBlock, 0, 16);
                        ++blocksChained;
                        hasPad = true;
                    } else {
                        if (numBytesRead != -1) {
                            // applyb CBC by XORing the curBlock with iv (only since this is the first block)
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                            }
                            // read next 16 bytes from keystream
                            for(int i = 0 ; i < 16 ; ++i) {
                                nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                                iv[i] = nextPsudoRandNum;
                            }
                            // shuffle the bytes based on the keystream data
                            for(int i = 0 ; i < 16 ; ++i) {
                                BigInteger first = new BigInteger(Integer.toString((iv[i].intValue()) & (0xf)));
                                BigInteger second = new BigInteger(Integer.toString((iv[i].intValue() >> 4) & (0xf)));
                                byte temp = curBlock[first.intValue()];
                                curBlock[first.intValue()] = curBlock[second.intValue()];
                                curBlock[second.intValue()] = temp;
                            }
                            // make the cipher text block by XORing the curBlock with the iv
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                            }
                            // write to the cipher file
                            writer.write(curBlock); 
                            // copy the contents of the curBlock to the lastBlock in order to use in the next iteration
                            System.arraycopy(curBlock, 0, lastBlock, 0, 16);
                            ++blocksChained; 
                        }
                    }
                } else {
                    if (numBytesRead > 0 && numBytesRead < 16) { // needs padding at the end ; here can use the lastBlock
                        int padNum = 16 - numBytesRead;
                        int padNumHex = 0x00 + padNum;
                        for (int i = numBytesRead ; i < 16 ; ++i) {
                            curBlock[i] = (byte)padNumHex;
                        }
                        // applyb CBC by XORing the curBlock with lastBlock (since this is NOT the first block)
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (lastBlock[i]));
                        }
                        // read next 16 bytes from keystream
                        for(int i = 0 ; i < 16 ; ++i) {
                            nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                            iv[i] = nextPsudoRandNum;
                        }
                        // shuffle the bytes based on the keystream data
                        for(int i = 0 ; i < 16 ; ++i) {
                            BigInteger first = new BigInteger(Integer.toString((iv[i].intValue()) & (0xf)));
                            BigInteger second = new BigInteger(Integer.toString((iv[i].intValue() >> 4) & (0xf)));
                            byte temp = curBlock[first.intValue()];
                            curBlock[first.intValue()] = curBlock[second.intValue()];
                            curBlock[second.intValue()] = temp;
                        }
                        // make the cipher text block by XORing the curBlock with the iv
                        for(int i = 0 ; i < 16 ; ++i) {
                            curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                        }
                        writer.write(curBlock);
                        System.arraycopy(curBlock, 0, lastBlock, 0, 16);
                        ++blocksChained;
                        hasPad = true;
                    } else {
                        if (numBytesRead != -1) {
                            // applyb CBC by XORing the curBlock with lastBlock (since this is NOT the first block)
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (lastBlock[i]));
                            }
                            // read next 16 bytes from keystream
                            for(int i = 0 ; i < 16 ; ++i) {
                                nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                                iv[i] = nextPsudoRandNum;
                            }
                            // shuffle the bytes based on the keystream data
                            for(int i = 0 ; i < 16 ; ++i) {
                                BigInteger first = new BigInteger(Integer.toString((iv[i].intValue()) & (0xf)));
                                BigInteger second = new BigInteger(Integer.toString((iv[i].intValue() >> 4) & (0xf)));
                                byte temp = curBlock[first.intValue()];
                                curBlock[first.intValue()] = curBlock[second.intValue()];
                                curBlock[second.intValue()] = temp;
                            }
                            // make the cipher text block by XORing the curBlock with the iv
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                            }
                            writer.write(curBlock);
                            System.arraycopy(curBlock, 0, lastBlock, 0, 16);
                            ++blocksChained;  
                        }
                    }
                }

                // this condition is true if the number of message bytes is a multiple of 16
                // and needs a whole block of padding at the end
                if (numBytesRead == -1) {
                    if (hasPad == false) {
                        if (blocksChained == 0) { // message was empty (use iv)
                            int padNumHex = 0x00 + 16;
                            for (int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte)padNumHex;
                            }
                            // applyb CBC by XORing the curBlock with iv (only since this is the first block)
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                            }
                            // read next 16 bytes from keystream
                            for(int i = 0 ; i < 16 ; ++i) {
                                nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                                iv[i] = nextPsudoRandNum;
                            }
                            // shuffle the bytes based on the keystream data
                            for(int i = 0 ; i < 16 ; ++i) {
                                BigInteger first = new BigInteger(Integer.toString((iv[i].intValue()) & (0xf)));
                                BigInteger second = new BigInteger(Integer.toString((iv[i].intValue() >> 4) & (0xf)));
                                byte temp = curBlock[first.intValue()];
                                curBlock[first.intValue()] = curBlock[second.intValue()];
                                curBlock[second.intValue()] = temp;
                            }
                            // make the cipher text block by XORing the curBlock with the iv
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                            }
                            // write to the cipher file
                            writer.write(curBlock);
                        } else { // message was an even multiple of 16, can use lastBlock
                            int padNumHex = 0x00 + 16;
                            for (int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte)padNumHex;
                            }
                            // applyb CBC by XORing the curBlock with lastBlock (since this is NOT the first block)
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (lastBlock[i]));
                            }
                            // read next 16 bytes from keystream
                            for(int i = 0 ; i < 16 ; ++i) {
                                nextPsudoRandNum = getPsudoRandNum(nextPsudoRandNum);
                                iv[i] = nextPsudoRandNum;
                            }
                            // shuffle the bytes based on the keystream data
                            for(int i = 0 ; i < 16 ; ++i) {
                                BigInteger first = new BigInteger(Integer.toString((iv[i].intValue()) & (0xf)));
                                BigInteger second = new BigInteger(Integer.toString((iv[i].intValue() >> 4) & (0xf)));
                                byte temp = curBlock[first.intValue()];
                                curBlock[first.intValue()] = curBlock[second.intValue()];
                                curBlock[second.intValue()] = temp;
                            }
                            // make the cipher text block by XORing the curBlock with the iv
                            for(int i = 0 ; i < 16 ; ++i) {
                                curBlock[i] = (byte) ((curBlock[i]) ^ (iv[i].byteValue()));
                            }
                            writer.write(curBlock);
                        }
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
