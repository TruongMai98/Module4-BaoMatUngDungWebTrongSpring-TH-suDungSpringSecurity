package com.codegym;

import java.security.MessageDigest;
import java.util.Date;

public class HashedPassword {
    public static void main(String[] args) throws Exception {
        // Hash a password using the SHA-256 algorithm
        String password = "root";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedPassword = digest.digest(password.getBytes("UTF-8"));

        // Convert the hash to a hexadecimal string
        StringBuilder sb = new StringBuilder();
        for (byte b : hashedPassword) {
            sb.append(String.format("%02x", b));
        }
        String hashedPasswordHex = sb.toString();

        System.out.println("--- Hashed Password Hex --- (" + password + ") " + hashedPasswordHex + " " + new Date());
        //--- Hashed Password Hex --- (admin) 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 Thu Dec 29 00:09:05 ICT 2022
        //--- Hashed Password Hex --- (root) 4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2 Thu Dec 29 00:09:25 ICT 2022
    }
}
