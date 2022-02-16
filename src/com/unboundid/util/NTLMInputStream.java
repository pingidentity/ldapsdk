/*
 * Copyright 2007-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2022 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2007-2022 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util;

import java.io.InputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class NTLMInputStream extends InputStream {

    private final InputStream inputStream;
    private byte[] buffer = new byte[1024*64];
    private int start = 0;
    private int end = 0;
    private RC4 serverRC4;
    private byte[] serverSigningKey;

    public NTLMInputStream(byte[] ntlmKey, InputStream inputStream) {
        this.inputStream = inputStream;

        serverSigningKey = generateKey(ntlmKey, "session key to server-to-client signing key magic constant");
        byte[] serverSealingKey = generateKey(ntlmKey, "session key to server-to-client sealing key magic constant");
    
        serverRC4 = new RC4(serverSealingKey);
    
    }

    private byte[] concat(byte[] aby1, byte[] aby2) {
        byte[] aby = new byte[aby1.length+aby2.length];
        System.arraycopy(aby1, 0, aby, 0, aby1.length);
        System.arraycopy(aby2, 0, aby, aby1.length, aby2.length);
        return aby;
    }


    private byte[] generateKey(byte[] ntlmKey, String constant) {
        // concat the masterKey and the constant
        byte[] concatKey = concat(ntlmKey, constant.getBytes());
        concatKey = concat(concatKey, new byte[] {0});
  
        MessageDigest md5;
  
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
  
        byte[] key;
        key = md5.digest(concatKey);
  
        return key;
    }

    private static byte[] hmacMD5(byte[] data, byte[] key) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(
                    key,
                    "HmacMD5");
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(keySpec);
            byte[] rawHmac = mac.doFinal(data);
            return rawHmac;
        }
        catch (Exception e) {
            return null;
        }
    }

    public int read(byte[] b,
                    int off,
                    int len)
            throws IOException {

        try {
            while (available()==0) {
                Thread.sleep(100);
            }
        }
        catch (Exception e) {

        }

        if (inputStream.available()>0) {
            readNextMessage();
        }

        synchronized (buffer) {

            if (start==end) {
                return 0;
            }
            else {
                int readLen = Math.min(end-start, len);
                System.arraycopy(buffer, start, b, off, readLen);
                start+=readLen;
                System.arraycopy(buffer, start, buffer, 0, end-start);
                end = end-start;
                start = 0;
                return readLen;
            }
        }
    }

    private synchronized void readNextMessage() throws IOException {
        int messageLength = (inputStream.read()<<24) | (inputStream.read()<<16) | (inputStream.read()<<8) | (inputStream.read());

        byte[] version = new byte[4];
        inputStream.read(version);
        byte[] signature = new byte[8];
        inputStream.read(signature);
        byte[] sequence = new byte[4];
        inputStream.read(sequence);
        byte[] encrytedMessage = new byte[messageLength-16];
        int r = inputStream.read(encrytedMessage);
        while (r<encrytedMessage.length) {
            try {
                Thread.yield();
            }
            catch (Exception e) {
            }
            r+= inputStream.read(encrytedMessage, r, encrytedMessage.length-r);
        }

        // decrypt the message
        byte[] decryptedMessage = new byte[encrytedMessage.length];
        serverRC4.update(encrytedMessage, 0, encrytedMessage.length, decryptedMessage, 0);

        // verify the signature
        byte[] sequence_message = concat(sequence, decryptedMessage);
        // hmac-md5
        byte[] hmacSignature = hmacMD5(sequence_message, serverSigningKey);
        // encrypt the signature
        byte[] verifySignature = new byte[8];
        serverRC4.update(hmacSignature, 0, 8, verifySignature, 0);


        while (buffer.length<decryptedMessage.length+end) {
            // grow the buffer;
            byte[] newBuffer = new byte[buffer.length*2];
            System.arraycopy(buffer, 0, newBuffer, 0, buffer.length);
            buffer = newBuffer;
        }
        System.arraycopy(decryptedMessage, 0, buffer, end, decryptedMessage.length);
        end +=decryptedMessage.length;
    }

    public int read(byte[] b)
            throws IOException {
        return read(b, 0, b.length);
    }

    public int available()
            throws IOException {

        if (inputStream.available()>0) {
            readNextMessage();
        }

        return end-start;
    }

    public void close()
            throws IOException {
        inputStream.close();
    }

    public int read() throws IOException {      
        if (inputStream.available()>0) {
            readNextMessage();
        }

        try {
            while (start==end) {
                Thread.sleep(100);
            }
        }
        catch (Exception e) {
        }

        synchronized (buffer) {
            byte r = buffer[start];
            start++;
            return r;
        }
    }
}
