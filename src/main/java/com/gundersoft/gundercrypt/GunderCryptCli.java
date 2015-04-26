package com.gundersoft.gundercrypt;

/** 
 * GunderCryptCli
 * A basic command line interface for the GunderCrypt Class
 * Subject to latest GNU GPL License
 * I CANNOT, WILL NOT, and SHOULD NOT be held responsible for any damages, lost data, or
 * other inconvenience resulting from the use of this code.
 * 
 * Note: This software is intended for basic ciphering and is not a valid replacement for
 * actual encryption software.
 * Copyright 2012-2015
 * @author Christian D. Gunderman
 */
public class GunderCryptCli {
    public static final double version = 1.1;

    /**
     * The CLI entry point.
     * @param args An array passed by the system containing commandline
     * arguments.
     */
    public static void main(String[] args) {
        String password = null;
        if (args.length >= 2) {
            if (args.length == 3)
                password = args[2];
            if (args[0].equals("encode") || args[0].equals("e")) {
                if (password != null) {
                    String encoded = GunderCrypt
                        .encodeString(args[1], password);
                    if (encoded != null)
                        System.out.println(encoded);
                    else
                        System.out.println("error");
                    return;
                } else {
                    String encoded = GunderCrypt.obscure(args[1]);
                    if (encoded != null)
                        System.out.println(encoded);
                    else
                        System.out.println("error");
                    return;
                }
            }
            if (args[0].equals("decode") || args[0].equals("d")) {
                if (password != null) {
                    String encoded = GunderCrypt
                        .decodeString(args[1], password);
                    if (encoded != null)
                        System.out.println(encoded);
                    else
                        System.out.println("error");
                    return;
                } else {
                    String encoded = GunderCrypt
                        .illuminate(args[1]);
                    if (encoded != null)
                        System.out.println(encoded);
                    else
                        System.out.println("error");
                    return;
                }
            }
        }
        printUsageInfo();
    }

    /**
     * Parses arguments fed in on the command line.
     * 
     * @param args An array containing command line arguments.
     * @return Returns null if not successful conflict.
     */
    private static void printUsageInfo() {
        System.out.println("GunderCrypt CLI");
        System.out.println("Cipher Version: " + GunderCrypt.version);
        System.out.println("CLI Version: " + version);
        System.out.println("(C)2012 C. Gunderman");
        System.out.println();
        System.out.println("GunderCrypt is an Advanced text Ciphering tool and should be run as follows:");
        System.out.println("  GunderCrypt.jar [mode] [text] [password]");
        System.out.println();
        System.out.println("Modes:");
        System.out.println("  encode	Turns a string into an encoded message.");
        System.out.println("  e			Same as encode.");
        System.out.println("  decode	Decodes a coded message.");
        System.out.println("  d			Same as decode.");
        System.out.println();
        System.out.println("text:");
        System.out.println("  The text that will be encoded into the final message.");
        System.out.println();
        System.out.println("password:");
        System.out.println("  An optional parameter that will add an additional level of protection by password protecting the ciphered text"
                           + "MUST be all CAPITAL letters and spaces ONLY.");
        System.out.println();
        System.out.println("Return Value:");
        System.out.println("  Prints \"error\" if unsuccessful, or the decrypted/encrypted text if successful.");
        System.out.println("  Password MUST be upper case.");
    }
}
