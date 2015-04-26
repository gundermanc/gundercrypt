package com.gundersoft.gundercrypt;

import java.util.ArrayList;
import java.util.Random;

/** 
 * GunderCrypt
 * A basic text cipher class. Recommend using the encodeString and decodeString methods ONLY.
 * Subject to latest GNU GPL License
 * I CANNOT, WILL NOT, and SHOULD NOT be held responsible for any damages, lost data, or
 * other inconvenience resulting from the use of this code.
 * 
 * Note: This software is intended for basic ciphering and is not a valid replacement for
 * actual encryption software.
 * Copyright 2012:
 * @author Christian D. Gunderman
 */
public abstract class GunderCrypt {
    public static final double version = 1.1;

    /**
     * Gets the indexes of where words start and puts them into an array of
     * Integer class instances.
     * 
     * @param sourceStr
     *            The string to have the words counted
     * @return An ArrayList<Integer> containing the indexes of where words start
     */
    public static ArrayList<Integer> getWordIndexes(String sourceStr) {
        ArrayList<Integer> indexes = new ArrayList<Integer>();
        boolean inWord = false; // already inside of a word
        for (int i = 0; i < sourceStr.length(); i++) {
            // if not whitespace then...
            if (sourceStr.charAt(i) != ' ' && sourceStr.charAt(i) != '\n'
                && sourceStr.charAt(i) != '\r'
                && sourceStr.charAt(i) != '\t') {
                if (!inWord) {
                    // set inWord and increment word count.
                    inWord = true;
                    indexes.add(i);
                }
            } else
                inWord = false; // no longer inside of a word
        }
        return indexes;
    }

    /**
     * Shifts a sentence by the specified number per character. Essentially a
     * very basic cipher. This is not very secure and should only be used when
     * security is not an issue.
     * 
     * @param sourceStr
     *            is a String containing the text to be encoded
     * @param shift
     *            is an int representing the number to shift each char
     * @return The modified String containing the ciphered text
     */
    public static String shiftSentence(String sourceStr, int shift) {
        StringBuilder finalStringBuilder = new StringBuilder();
        if (shift > 25)
            return null;

        // handle negative numbers
        if (shift < 0)
            shift = 26 + shift;

        // shifts each character by the specified shift index
        for (int i = 0; i < sourceStr.length(); i++) {
            finalStringBuilder.append(shiftChar(sourceStr.charAt(i), shift));
        }
        return finalStringBuilder.toString();
    }

    /**
     * Shifts a char by the specified number. Can be used by other cryptographic
     * methods as a basis for the obscuring of text.
     * 
     * @param c
     *            The char to be modified.
     * @param shift
     *            The int value representing how many letters to shift c.
     * @return A char value containing the shifted int
     */
    public static char shiftChar(char c, int shift) {
        if (shift > 25)
            return 0;

        if (shift < 0) // handle negative numbers
            shift = 26 + shift;

        if ((Character.isUpperCase(c) && (c + shift) > 'Z')
            || (Character.isLowerCase(c) && (c + shift) > 'z'))
            shift -= 26;
        return (char) (c + (Character.isLetter(c) ? shift : 0));
    }

    /**
     * Encodes an integer value, 0-25 as a capital letter for use in the storage
     * of seeds inside of a ciphered string.
     * 
     * @param c
     *            An integer 1 through 25 that will be converted to a char.
     * @return A char value containing the encoded int
     */
    public static char encodeInt(int c) {
        if (c <= 25 && c > -1) {
            return (char) (c + 'A');
        }
        return 0;
    }

    /**
     * Decodes a char value into an integer 0-25 that represents its location in
     * the alphabet.
     * 
     * @param c
     *            The char value of the integer to be decoded
     * @return An int containing the decoded letter
     */
    public static int decodeInt(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        return -1;
    }

    /**
     * Encodes a string using a pseudo-random seed containing between 4-25
     * integer values that are used to perform shift operations on each letter.
     * The final seed is stored as a letter representation before the first
     * letter of each of the first 25 words in the sentence. This method of
     * encoding has the benefit of being incrackable should the cracker lose
     * part of the encoded string.
     * 
     * @param sourceStr
     * @return A String containing the encoded String value and pseudo random
     *         seed.
     */
    public static String obscure(String sourceStr) {
        // add header so decoder method recognizes encrypted string
        sourceStr = "BeS" + sourceStr + "EeS";

        ArrayList<Integer> keys = new ArrayList<Integer>();
        ArrayList<Integer> wordIndexes = getWordIndexes(sourceStr);
        Random generator = new Random();
        StringBuilder finalStringBuilder = new StringBuilder();
        int currentLetter = 0;
        int currentWord = 0;

        // generate per letter key
        for (int i = 0; i < wordIndexes.size() && keys.size() < 26; i++) {
            keys.add(generator.nextInt(25) + 1);
        }

        // encode letters
        for (int i = 0; i < sourceStr.length(); i++) {
            // if current char is NOT whitespace
            if (wordIndexes.contains(i)) {
                // if(currentWord < 26)
                finalStringBuilder.append(encodeInt(keys.get(currentWord)));
                if (currentWord > 24)
                    currentWord = 0;
                else
                    currentWord++;
            }

            // encode letters
            finalStringBuilder.append(shiftChar(sourceStr.charAt(i),
                                                keys.get(currentLetter)));
            if (currentLetter < (keys.size() - 1))
                currentLetter++;
            else
                currentLetter = 0;
        }
        return finalStringBuilder.toString();
    }

    /**
     * Deciphers a String encoded with illuminate. See illuminate function for
     * more details on the design of this method set.
     * 
     * @param sourceStr
     *            String containing the encrypted text to be deciphered
     * @return String containing the decoded text, or null if text does not
     *         contain the encryption header and footer (basically, it was not
     *         decoded successfully).
     */
    public static String illuminate(String sourceStr) {
        ArrayList<Integer> keys = new ArrayList<Integer>();
        ArrayList<Integer> wordIndexes = getWordIndexes(sourceStr);
        StringBuilder finalStringBuilder = new StringBuilder();
        int currentLetter = 0;
        int currentWord = 0;

        // get code keys
        for (int i = 0; i < sourceStr.length(); i++) {
            if (wordIndexes.contains(i) && currentWord < 26) {
                keys.add(decodeInt(sourceStr.charAt(i))); // adds the key to the
                // list
                currentWord++;
            }
        }

        currentWord = 0;
        for (int i = 0; i < sourceStr.length(); i++) {
            // encode letters
            if (!wordIndexes.contains(i)) {
                finalStringBuilder.append(shiftChar(sourceStr.charAt(i),
                                                    keys.get(currentLetter) * (-1)));
                if (currentLetter < (keys.size() - 1))
                    currentLetter++;
                else
                    currentLetter = 0;
                currentWord++;
            }
        }
        String finalString = finalStringBuilder.toString();
        if (finalString.startsWith("BeS") && finalString.endsWith("EeS"))
            return finalString.substring(3, finalString.length() - 3);
        else
            return null;
    }

    /**
     * Converts a String pass code to an ArrayList<Integer> containing the
     * numeric values of each letter. This method is useful for converting a
     * pass code to shift values for a cipher method. Note: This method ONLY
     * converts capital letters to numbers. Spaces are omitted from the array
     * and any non-letters or lower case letters will cause the method to return
     * null.
     * 
     * @param passCode
     *            A String containing ONLY capital letters and spaces
     *            representing a passcode.
     * @return An ArrayList<Integer> containing the pass code's numeric
     *         representation, or null if the passcode contains an illegal char.
     */
    private static ArrayList<Integer> passCodeToKeys(String passCode) {
        ArrayList<Integer> keys = new ArrayList<Integer>();
        for (int i = 0; i < passCode.length(); i++) {
            char c = passCode.charAt(i);
            if (Character.isLetter(c) && Character.isUpperCase(c))
                keys.add(decodeInt(c));
            else if (c != ' ')
                return null;
        }
        return keys;
    }

    /**
     * A cipher function similar to obscure(), only, allowing the user to
     * produce his/her own pass code to encode the text. This method is intended
     * as a LEVEL of encoding and is meant to be used on top of another sublevel
     * to secure text to the fullest. Use encodeString() instead of this method.
     * 
     * @param sourceStr
     *            String to be encoded
     * @param passCode
     *            String containing ONLY capital letters and spaces that will be
     *            used to encode the text.
     * @return Returns a String with the text shifted according to the numeric
     *         representation of passCode. Note: There is no error checking in
     *         this method, save the password. It will return the shuffled
     *         characters whether they were decoded correctly or not, unless the
     *         pass code contains illegal characters, then null will be
     *         returned.
     */
    public static String createCapsule(String sourceStr, String passCode) {
        ArrayList<Integer> keys = new ArrayList<Integer>();
        StringBuilder finalStringBuilder = new StringBuilder();
        int currentLetter = 0;

        // get the key values from the pass code
        if ((keys = passCodeToKeys(passCode)) == null)
            return null;

        // encode string
        for (int i = 0; i < sourceStr.length(); i++) {
            finalStringBuilder.append(shiftChar(sourceStr.charAt(i),
                                                keys.get(currentLetter)));
            if (currentLetter < keys.size() - 1)
                currentLetter++;
            else
                currentLetter = 0;
        }
        return finalStringBuilder.toString();
    }

    /**
     * A decipher function similar to illuminate(), only, allowing the user to
     * produce his/her own pass code to decode the text. This method is intended
     * as a LEVEL of encoding and is meant to be used on top of another sublevel
     * to secure text to the fullest. Use decodeString() instead of this method.
     * 
     * @param sourceStr
     *            String to be decoded
     * @param passCode
     *            String containing ONLY capital letters and spaces that will be
     *            used to decode the text.
     * @return Returns a String with the text shifted according to the numeric
     *         representation of passCode. Note: There is no error checking in
     *         this method, save the password. It will return the shuffled
     *         characters whether they were decoded correctly or not, unless the
     *         pass code contains illegal characters, then null will be
     *         returned.
     */
    public static String openCapsule(String sourceStr, String passCode) {
        ArrayList<Integer> keys = new ArrayList<Integer>();
        StringBuilder finalStringBuilder = new StringBuilder();
        int currentLetter = 0;

        // get the key values from the pass code
        if ((keys = passCodeToKeys(passCode)) == null)
            return null;

        // decode string
        for (int i = 0; i < sourceStr.length(); i++) {
            finalStringBuilder.append(shiftChar(sourceStr.charAt(i),
                                                -keys.get(currentLetter)));
            if (currentLetter < keys.size() - 1)
                currentLetter++;
            else
                currentLetter = 0;
        }
        return finalStringBuilder.toString();
    }

    /**
     * Convenience method that combines the best two levels of security into one
     * method that will allow for the encoding of text securely with a pass
     * code.
     * 
     * @param sourceStr
     *            The String to be encoded.
     * @param passCode
     *            The pass code to be used. Note: Must be all capital and no
     *            numbers or symbols other than space.
     * @return A String with the encoded text, or null if function fails.
     */
    public static String encodeString(String sourceStr, String passCode) {
        // bottom level: pseudo random seed and word padding algorithm
        sourceStr = obscure(sourceStr);

        // top level: password protection
        if (sourceStr != null)
            return createCapsule(sourceStr, passCode);
        else
            return null;
    }

    /**
     * Convenience method that combines the best two levels of security into one
     * method that will allow for the encoding of text securely with a pass
     * code.
     * 
     * @param sourceStr
     *            The String to be decoded.
     * @param passCode
     *            The pass code to be used. Note: Must be all capital and no
     *            numbers or symbols other than space.
     * @return A String with the decoded text, or null if function fails.
     */
    public static String decodeString(String sourceStr, String passCode) {
        // top level: password protection
        sourceStr = openCapsule(sourceStr, passCode);

        // bottom level: pseudo random seed and word padding algorithm
        // returns null if password was incorrect
        if (sourceStr != null)
            return illuminate(sourceStr);
        else
            return null;
    }
}
