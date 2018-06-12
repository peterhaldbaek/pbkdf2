package com.briskbee.pbkdf2;

import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertEquals;

public class PBKDF2Test {

    @Test
    public void testPBKDF2() throws NoSuchAlgorithmException, InvalidKeySpecException {
        assertEquals("edf738254821c55da61e6afa20efd0c657cb941c", PBKDF2.pbkdf2("password", "salt", 5000, 20));
    }
}
