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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class NTLM implements Serializable {

    private static final int NTLMFLAG_NEGOTIATE_UNICODE = 1<<0;
    private static final int NTLMFLAG_NEGOTIATE_OEM = 1<<1;
    private static final int NTLMFLAG_REQUEST_TARGET = 1<<2;
    private static final int NTLMFLAG_NEGOTIATE_SIGN = 1<<4;
    private static final int NTLMFLAG_NEGOTIATE_SEAL = 1<<5;
    private static final int NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE = 1<<6;
    private static final int NTLMFLAG_NEGOTIATE_LM_KEY = 1<<7;
    private static final int NTLMFLAG_NEGOTIATE_NETWARE = 1<<8;
    private static final int NTLMFLAG_NEGOTIATE_NTLM_KEY = 1<<9;
    private static final int NTLMFLAG_NEGOTIATE_ANONYMOUS = 1<<11;
    private static final int NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED = 1<<12;
    private static final int NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED = 1<<13;
    private static final int NTLMFLAG_NEGOTIATE_LOCAL_CALL = 1<<14;
    private static final int NTLMFLAG_NEGOTIATE_ALWAYS_SIGN = 1<<15;
    private static final int NTLMFLAG_TARGET_TYPE_DOMAIN = 1<<16;
    private static final int NTLMFLAG_TARGET_TYPE_SERVER = 1<<17;
    private static final int NTLMFLAG_TARGET_TYPE_SHARE = 1<<18;
    private static final int NTLMFLAG_NEGOTIATE_NTLM2_KEY = 1<<19;
    private static final int NTLMFLAG_REQUEST_INIT_RESPONSE = 1<<20;
    private static final int NTLMFLAG_REQUEST_ACCEPT_RESPONSE = 1<<21;
    private static final int NTLMFLAG_REQUEST_NONNT_SESSION_KEY = 1<<22;
    private static final int NTLMFLAG_NEGOTIATE_TARGET_INFO = 1<<23;
    private static final int NTLMFLAG_NEGOTIATE_128 = 1<<29;
    private static final int NTLMFLAG_NEGOTIATE_KEY_EXCHANGE = 1<<30;
    private static final int NTLMFLAG_NEGOTIATE_56 = 0x80000000;

    private Cipher client_cipher;
    private Cipher server_cipher;
    private int client_seq = 0;
    private final int server_seq = 0;
    private byte[] client_sign_key = null;
    private byte[] client_seal_key = null;
    private byte[] server_sign_key = null;
    private byte[] server_seal_key = null;


    private int serverFlags;
    private String encoding;
    private int version;
    private byte[] serverChallenge;
    private String targetName;
    private byte[] targetInfo;
    private byte[] exported_session_key;
    private byte[] encrypted_session_key;

    private String  targetInfoNetBIOSComputerName;
    private String  targetInfoNetBIOSDomainName;
    private String  targetInfoDNSComputerName;
    public String  targetInfoDNSDomainName;
    private String  targetInfoDNSTreeName;


    public byte[] createType1Message(String workstation, String domain) throws IOException {
        int flags = NTLMFLAG_NEGOTIATE_OEM |
                NTLMFLAG_REQUEST_TARGET |
                NTLMFLAG_NEGOTIATE_SIGN |
                NTLMFLAG_NEGOTIATE_SEAL |
                NTLMFLAG_NEGOTIATE_128 |
                NTLMFLAG_NEGOTIATE_56 |
                NTLMFLAG_NEGOTIATE_KEY_EXCHANGE |
                NTLMFLAG_NEGOTIATE_NTLM_KEY |
                NTLMFLAG_NEGOTIATE_NTLM2_KEY |
                NTLMFLAG_NEGOTIATE_ALWAYS_SIGN |
                NTLMFLAG_NEGOTIATE_UNICODE;
        return createType1Message(workstation, domain, flags);
    }

    public byte[] createType1Message(String workstation, String domain, int flags) throws IOException {

        boolean domainProvided = (domain != null && domain.length()>0);
        boolean workstationProvided = (workstation != null && workstation.length()>0);

        int dataPos = 32;
        WriteBuffer message = new WriteBuffer();
        message.write("NTLMSSP".getBytes(StandardCharsets.US_ASCII));
        message.write(0);
        message.writeUInt32LE(1);


        if (domainProvided) {
            flags |= NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED;
        }
        else {
            flags &= (NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED ^ 0xffffffff);
        }

        if (workstationProvided) {
            flags |= NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED;
        }
        else {
            flags &= (NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED ^ 0xffffffff);
        }

        message.writeUInt32LE(flags);

        if (domainProvided) {
            message.writeUInt16LE(domain.length());
            message.writeUInt16LE(domain.length());
            message.writeUInt32LE(dataPos);
            dataPos += domain.length();
        }
        else {
            message.writeUInt16LE(0);
            message.writeUInt16LE(0);
            message.writeUInt32LE(0);
        }


        if (workstationProvided) {
            message.writeUInt16LE(workstation.length());
            message.writeUInt16LE(workstation.length());
            message.writeUInt32LE(dataPos);
            //dataPos += workstation.length();
        }
        else {
            message.writeUInt16LE(0);
            message.writeUInt16LE(0);
            message.writeUInt32LE(0);
        }

        if (domainProvided) {
            message.write(domain.toUpperCase().getBytes(StandardCharsets.US_ASCII));
        }

        if (workstationProvided) {
            message.write(workstation.toUpperCase().getBytes(StandardCharsets.US_ASCII));
        }

        message.write(0x06);
        message.write(0x01);
        message.write(0xb1);
        message.write(0x1d);
        message.write(0x00);
        message.write(0x00);
        message.write(0x00);
        message.write(0x0f);

        return message.toByteArray();
    }

    public void decodeType2Message(byte[] message) {

        serverFlags = ReadBuffer.dec_uint32le(message, 20);

        encoding = ((serverFlags & NTLMFLAG_NEGOTIATE_OEM) == NTLMFLAG_NEGOTIATE_OEM)? "ascii" :"UTF-16LE";

        version = ((serverFlags & NTLMFLAG_NEGOTIATE_NTLM2_KEY) == NTLMFLAG_NEGOTIATE_NTLM2_KEY)? 2 :1;

        serverChallenge = new byte[8];
        System.arraycopy(message, 24, serverChallenge, 0, 8);

        int targetLength = ReadBuffer.dec_uint16le(message, 12);
        int targetOffset = ReadBuffer.dec_uint32le(message, 16);

        byte[] targetBytes = new byte[targetLength];
        System.arraycopy(message, targetOffset, targetBytes, 0, targetLength);
        targetName = parseString(targetBytes,0, targetLength);

        if ((serverFlags & NTLMFLAG_NEGOTIATE_TARGET_INFO) == NTLMFLAG_NEGOTIATE_TARGET_INFO) {

            int targetInfoLength = ReadBuffer.dec_uint16le(message, 40);
            int targetInfoOffset = ReadBuffer.dec_uint32le(message, 44);

            targetInfo = new byte[targetInfoLength];
            System.arraycopy(message, targetInfoOffset, targetInfo, 0, targetInfoLength);

            parseTargetInfo();
        }
    }

    public String parseString(byte[] aby, int offset, int length) {
        try {
            return new String(aby, offset, length, StandardCharsets.UTF_16LE);
        }
        catch (Exception e) {
        }
        return "";
    }

    public void parseTargetInfo() {
        int pos = 0;
        while (targetInfo.length>pos) {
            int itemType = ReadBuffer.dec_uint16le(targetInfo, pos);
            int itemLength = ReadBuffer.dec_uint16le(targetInfo, pos+2);
            pos+=4;
            if (itemType == 0x1) {
                targetInfoNetBIOSComputerName = parseString(targetInfo, pos, itemLength);
            }
            if (itemType == 0x2) {
                targetInfoNetBIOSDomainName = parseString(targetInfo, pos, itemLength);
            }
            if (itemType == 0x3) {
                targetInfoDNSComputerName = parseString(targetInfo, pos, itemLength);
            }
            if (itemType == 0x4) {
                targetInfoDNSDomainName = parseString(targetInfo, pos, itemLength);
            }
            if (itemType == 0x5) {
                targetInfoDNSTreeName = parseString(targetInfo, pos, itemLength);
            }
            if (itemType == 0x7) {
                // timestamp
            }
            if (itemType == 0x0) {
                // end of list
                break;
            }
            pos += itemLength;
        }
    }

    public byte[] createNTLMHash(String password) throws IOException {
        try {
            MD4 crypt = new MD4();
            crypt.update(password.getBytes(StandardCharsets.UTF_16LE));
            return crypt.digest();
        }
        catch (Exception nsa) {
            throw new IOException(nsa.toString());
        }
    }

    public byte[] HMAC_MD5(byte[] key, byte[] aby) {
        try {
            Mac mac = Mac.getInstance("HMACMD5");
            mac.init(new SecretKeySpec(key, "ASCII"));
            mac.update(aby);
            return mac.doFinal();
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] createLMv2Response(String username, byte[] ntlmHash, byte[] nonce, String domain) throws IOException {

        byte[] ntlm2hash = createNTLMv2Hash(ntlmHash, username, domain);

        WriteBuffer data = new WriteBuffer();
        data.write(serverChallenge);

        data.write(nonce, 0, 8);

        byte[] hashedBuffer = HMAC_MD5(ntlm2hash, data.toByteArray());

        WriteBuffer data2 = new WriteBuffer();
        data2.write(hashedBuffer);
        data2.write(data.toByteArray(), 0,8);

        return data2.toByteArray();
    }

    public byte[] createNTLMv2Blob(byte[] nonce) throws IOException {

        WriteBuffer data = new WriteBuffer();

        // blob signature
        data.writeUInt32BE(0x01010000);

        // reserved
        data.writeUInt32LE(0);

        // 11644473600000 = diff between 1970 and 1601
        long timestamp = (System.currentTimeMillis()+11644473600000l)*10000;
        long timestampLow = timestamp & 0xffffffff;
        long timestampHigh = (timestamp >> 32) & 0xffffffff;
        data.writeUInt32LE((int)timestampLow);
        data.writeUInt32LE((int)timestampHigh);

        data.write(nonce, 0, 8);

        data.writeUInt32LE(0);

        data.write(targetInfo);

        data.writeUInt32LE(0);

        return data.toByteArray();
    }

    public byte[] createNTLMv2Hash(byte[] ntlmHash, String username, String domain) throws IOException {
        byte[] bytes = (username.toUpperCase()+domain).getBytes(StandardCharsets.UTF_16LE);
        return HMAC_MD5(ntlmHash, bytes);
    }

    public byte[] createNTProofStr(byte[] blob, byte[] ntlmv2_hash) throws IOException {
        WriteBuffer challengeBlob = new WriteBuffer();
        challengeBlob.write(serverChallenge);
        challengeBlob.write(blob);
        return HMAC_MD5(ntlmv2_hash, challengeBlob.toByteArray());
    }

    public byte[] createNTLMv2Response(byte[] nt_proof_str, byte[] blob) throws IOException {
        WriteBuffer data = new WriteBuffer();
        data.write(nt_proof_str);
        data.write(blob);
        return data.toByteArray();
    }

    private byte[] createUserSessionKey(byte[] ntlmv2_hash, byte[] nt_proof_str) {
        return HMAC_MD5(ntlmv2_hash, nt_proof_str);
    }

    public byte[] createType3Message(String username, String password, String workstation, String domain) throws IOException {

        int dataPos = 32;
        WriteBuffer message = new WriteBuffer();
        message.write("NTLMSSP".getBytes(StandardCharsets.US_ASCII));
        message.write(0);
        message.writeUInt32LE(3);

        if (username.contains("\\")) {
            if (domain == null || domain.length()==0) {
                domain = username.substring(0, username.indexOf("\\"));
            }
            username = username.substring(username.indexOf("\\")+1);
        }

        WriteBuffer messageTrailer = new WriteBuffer();

        if (version == 2) {
            dataPos = 64;

            byte[] ntlmHash = createNTLMHash(password);

            byte[] nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);

            byte[] lmv2 = createLMv2Response(username, ntlmHash, nonce, domain);

            byte[] blob = createNTLMv2Blob(nonce);

            byte[] ntlmv2_hash = createNTLMv2Hash(ntlmHash, username, domain);

            byte[] nt_proof_str = createNTProofStr(blob, ntlmv2_hash);

            byte[] ntlmv2_resp = createNTLMv2Response(nt_proof_str, blob);

            //lmv2 security buffer
            message.writeUInt16LE(lmv2.length);
            message.writeUInt16LE(lmv2.length);
            message.writeUInt32LE(dataPos);
            messageTrailer.write(lmv2);
            dataPos+= lmv2.length;

            //ntlmv2 security buffer
            message.writeUInt16LE(ntlmv2_resp.length);
            message.writeUInt16LE(ntlmv2_resp.length);
            message.writeUInt32LE(dataPos);
            messageTrailer.write(ntlmv2_resp);
            dataPos+= ntlmv2_resp.length;

            byte[] user_session_key = createUserSessionKey(ntlmv2_hash, nt_proof_str);

            exported_session_key = new byte[16];
            new SecureRandom().nextBytes(exported_session_key);

            try {
                Cipher cipher = Cipher.getInstance("RC4/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(user_session_key, "RC4"));
                encrypted_session_key = cipher.update(exported_session_key);
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            initializeSignAndSeal();
        }
        else {
        }

        //target name security buffer
        if (domain==null) {
            message.writeUInt16LE(0);
            message.writeUInt16LE(0);
            message.writeUInt32LE(dataPos);
            dataPos += 0;
        }
        else {
            message.writeUInt16LE(domain.getBytes(encoding).length);
            message.writeUInt16LE(domain.getBytes(encoding).length);
            message.writeUInt32LE(dataPos);
            messageTrailer.write(domain.getBytes(encoding));
            dataPos += domain.getBytes(encoding).length;
        }

        //user name security buffer
        message.writeUInt16LE(username.getBytes(encoding).length);
        message.writeUInt16LE(username.getBytes(encoding).length);
        message.writeUInt32LE(dataPos);
        messageTrailer.write(username.toUpperCase().getBytes(encoding));
        dataPos+= username.getBytes(encoding).length;

        //workstation name security buffer
        if (workstation==null) {
            message.writeUInt16LE(0);
            message.writeUInt16LE(0);
            message.writeUInt32LE(dataPos);
            dataPos += 0;
        }
        else {
            message.writeUInt16LE(workstation.getBytes(encoding).length);
            message.writeUInt16LE(workstation.getBytes(encoding).length);
            message.writeUInt32LE(dataPos);
            messageTrailer.write(workstation.getBytes(encoding));
            dataPos += workstation.getBytes(encoding).length;
        }

        if (version == 2) {
            //session key security buffer
            message.writeUInt16LE(16);
            message.writeUInt16LE(16);
            message.writeUInt32LE(dataPos);
            messageTrailer.write(encrypted_session_key);
            //dataPos += 16;

            //flags
            int flags3 = NTLMFLAG_NEGOTIATE_UNICODE |
                    NTLMFLAG_REQUEST_TARGET |
                    NTLMFLAG_NEGOTIATE_SIGN |
                    NTLMFLAG_NEGOTIATE_SEAL |
                    NTLMFLAG_NEGOTIATE_NTLM_KEY |
                    NTLMFLAG_NEGOTIATE_ALWAYS_SIGN |
                    NTLMFLAG_NEGOTIATE_NTLM2_KEY |
                    NTLMFLAG_NEGOTIATE_128 |
                    NTLMFLAG_NEGOTIATE_KEY_EXCHANGE |
                    NTLMFLAG_NEGOTIATE_56;
            message.writeUInt32LE(flags3);
        }
        // print(message.count);
        message.write(messageTrailer.toByteArray());

        return message.toByteArray();
    }

    public byte[] getMasterKey() {
        return exported_session_key;
    }

    public byte[] getSessionKey() {
        return encrypted_session_key;
    }

    public byte[] md5(byte[] aby) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(aby);
            return md5.digest();
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void initializeSignAndSeal() {
        try {
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            data.write(exported_session_key);
            data.write("session key to client-to-server signing key magic constant\0".getBytes(StandardCharsets.US_ASCII));
            client_sign_key = md5(data.toByteArray());

            data = new ByteArrayOutputStream();
            data.write(exported_session_key);
            data.write("session key to client-to-server sealing key magic constant\0".getBytes(StandardCharsets.US_ASCII));
            client_seal_key = md5(data.toByteArray());

            data = new ByteArrayOutputStream();
            data.write(exported_session_key);
            data.write("session key to server-to-client signing key magic constant\0".getBytes(StandardCharsets.US_ASCII));
            server_sign_key = md5(data.toByteArray());

            data = new ByteArrayOutputStream();
            data.write(exported_session_key);
            data.write("session key to server-to-client sealing key magic constant\0".getBytes(StandardCharsets.US_ASCII));
            server_seal_key = md5(data.toByteArray());

            server_cipher = Cipher.getInstance("RC4/ECB/NoPadding");
            server_cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(server_seal_key, "RC4"));

            client_cipher = Cipher.getInstance("RC4/ECB/NoPadding");
            client_cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(client_seal_key, "RC4"));

            client_seq = 0;

        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] sign_message(byte[] message) {

        byte[] sig = sign_message_internal(message, client_seq, client_sign_key, client_cipher);

        byte[] signature = new byte[4+8+4];
        WriteBuffer.enc_uint32le(1, signature, 0);
        System.arraycopy(sig, 0, signature, 4, 8);
        WriteBuffer.enc_uint32le(client_seq, signature, 12);
        client_seq += 1;

        return signature;

    }

    public byte[] sign_message_internal(byte[] message, int seq, byte[] sign_key, Cipher cipher) {

        byte[] seqbody = new byte[4+message.length];
        WriteBuffer.enc_uint32le(seq, seqbody, 0);
        System.arraycopy(message, 0, seqbody, 4, message.length);

        try {
            byte[] sig1 = HMAC_MD5(sign_key, seqbody);
            byte[] dest = new byte[8];
            cipher.update(sig1, 0, 8, dest, 0);
            return dest;
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] seal_message(byte[] aby) {
        return client_cipher.update(aby);
    }

    public byte[] unseal_message(byte[] aby) {
        return server_cipher.update(aby);
    }

    public byte[] verify_signature(byte[] message, int seq) {
        return sign_message_internal(message, seq, server_sign_key, server_cipher);
    }
}

class WriteBuffer extends ByteArrayOutputStream {

    public void writeUInt8(int i) throws IOException {
        write(i);
    }

    public void writeUInt16LE(int i) throws IOException {
        byte[] dest = new byte[2];
        enc_uint16le((short)i, dest, 0);
        write(dest);
    }

    public void writeUInt32LE(int i) throws IOException {
        byte[] dest = new byte[4];
        enc_uint32le(i, dest, 0);
        write(dest);
    }

    public void writeUInt32BE(int i) throws IOException {
        byte[] dest = new byte[4];
        enc_uint32be(i, dest, 0);
        write(dest);
    }

    public void writeUInt64BE(long i) throws IOException {
        byte[] dest = new byte[8];
        enc_uint64be(i, dest, 0);
        write(dest);
    }

    public static int enc_uint32be( int i, byte[] dst, int di ) {
        dst[di++] = (byte)((i >> 24) & 0xFF);
        dst[di++] = (byte)((i >> 16) & 0xFF);
        dst[di++] = (byte)((i >> 8) & 0xFF);
        dst[di] = (byte)(i & 0xFF);
        return 4;
    }

    public static int enc_uint16le( short s, byte[] dst, int di )
    {
        dst[di++] = (byte)(s & 0xFF);
        dst[di] = (byte)((s >> 8) & 0xFF);
        return 2;
    }
    public static int enc_uint32le( int i, byte[] dst, int di )
    {
        dst[di++] = (byte)(i & 0xFF);
        dst[di++] = (byte)((i >> 8) & 0xFF);
        dst[di++] = (byte)((i >> 16) & 0xFF);
        dst[di] = (byte)((i >> 24) & 0xFF);
        return 4;
    }

    public static int enc_uint64be( long l, byte[] dst, int di )
    {
        enc_uint32be( (int)(l & 0xFFFFFFFFL), dst, di + 4 );
        enc_uint32be( (int)(( l >> 32L ) & 0xFFFFFFFFL), dst, di );
        return 8;
    }

}

class ReadBuffer extends ByteArrayInputStream {

    public ReadBuffer(byte[] buf) {
        super(buf);
    }

    public int readUInt32LE() throws IOException {
        byte[] src = read(4);
        return dec_uint32le(src, 0);
    }

    public int readUInt32BE() throws IOException {
        byte[] src = read(4);
        return dec_uint32be(src, 0);
    }

    public long readUInt64BE() throws IOException {
        byte[] src = read(8);
        return dec_uint64be(src, 0);
    }

    public byte[] read(int length) throws  IOException {
        byte[] aby = new byte[length];
        int len = 0;
        while (len<length) {
            len += read(aby, len, length-len);
        }
        return aby;
    }


    public static short dec_uint16le( byte[] src, int si )
    {
        return (short)((src[si] & 0xFF) | ((src[si + 1] & 0xFF) << 8));
    }

    public static int dec_uint32be( byte[] src, int si )
    {
        return ((src[si] & 0xFF) << 24) | ((src[si + 1] & 0xFF) << 16) |
                ((src[si + 2] & 0xFF) << 8) | (src[si + 3] & 0xFF);
    }
    public static int dec_uint32le( byte[] src, int si )
    {
        return (src[si] & 0xFF) | ((src[si + 1] & 0xFF) << 8) |
                ((src[si + 2] & 0xFF) << 16) | ((src[si + 3] & 0xFF) << 24);
    }

    public static long dec_uint64be( byte[] src, int si )
    {
        long l;
        l = dec_uint32be( src, si ) & 0xFFFFFFFFL;
        l <<= 32L;
        l |= dec_uint32be( src, si + 4 ) & 0xFFFFFFFFL;
        return l;
    }

    public static byte read(byte[] src, int si) {
        return src[si];
    }

    public static byte[] readBytes(byte[] src, int si, int len) {
        byte[] aby = new byte[len];
        System.arraycopy(src, si, aby, 0, len);
        return aby;
    }

}
