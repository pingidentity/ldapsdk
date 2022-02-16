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

import java.io.OutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class NTLMOutputStream extends OutputStream {

    private final byte[] clientSigningKey;
    private final RC4 clientRC4;

    private int sequenceNumber = 0;

    private OutputStream outputStream;

    public NTLMOutputStream(byte[] ntlmKey, OutputStream outputStream) {

        this.outputStream = outputStream;

        clientSigningKey = generateKey(ntlmKey, "session key to client-to-server signing key magic constant");
        byte[] clientSealingKey = generateKey(ntlmKey, "session key to client-to-server sealing key magic constant");
        clientRC4 = new RC4(clientSealingKey);
    
    }

    private byte[] concat(byte[] aby1, byte[] aby2, int off, int len) {
        byte[] aby = new byte[aby1.length+len];
        System.arraycopy(aby1, 0, aby, 0, aby1.length);
        System.arraycopy(aby2, off, aby, aby1.length, len);
        return aby;
    }  

    public void close()
            throws IOException {
        outputStream.close();
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

    public synchronized void write(byte[] message, int off, int len) throws IOException {

        int messageLength = len+16;
        byte[] length = {(byte)((messageLength>>24)&0xff),(byte)((messageLength>>16)&0xff),(byte)((messageLength>>8)&0xff),(byte)(messageLength&0xff)};
        byte[] version = {1,0,0,0};
        byte[] sequence = {(byte)((sequenceNumber>>0)&0xff),(byte)((sequenceNumber>>8)&0xff),(byte)((sequenceNumber>>16)&0xff),(byte)((sequenceNumber>>24)&0xff)};
        sequenceNumber++;

        // assemble the final message to send
        byte[] outputMessage = new byte[4+messageLength];
        System.arraycopy(length, 0, outputMessage, 0, 4);
        System.arraycopy(version, 0, outputMessage, 4, 4);
        System.arraycopy(sequence, 0, outputMessage, 16, 4);

        // encrypt the message
        clientRC4.update(message, off, len, outputMessage, 20);

        // produce the signature
        // concatenate the sequence number and the message
        byte[] sequence_message = concat(sequence, message, off, len);
        // md5-hmac
        byte[] hmacSignature = hmacMD5(sequence_message, clientSigningKey);
        // encrypt the signature
        clientRC4.update(hmacSignature, 0, 8, outputMessage, 8);

        outputStream.write(outputMessage);
        outputStream.flush();
    }

    public void flush()
            throws IOException {
        outputStream.flush();
    }

    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    public void write(int arg0) throws IOException {
        byte[] aby = {(byte)arg0};
        write(aby);
    }
}
