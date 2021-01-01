/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import javax.crypto.Mac;

import com.unboundid.util.Base64;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class holds the elements associated with the client final message in a
 * SCRAM authentication sequence.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SCRAMClientFinalMessage
      implements Serializable
{
  /**
   * The input bytes to provide to the MAC when generating the client key.
   */
  @NotNull private static final byte[] CLIENT_KEY_INPUT_BYTES =
       StaticUtils.getBytes("Client Key");



  /**
   * The sequence of bytes that comprise the 32-bit representation of the number
   * one, which is used in the course of computing the salted password.
   */
  @NotNull private static final byte[] ONE_BYTES = { 0x00, 0x00, 0x00, 0x01 };



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5228385127923425294L;



  // The bytes that comprise the auth message.
  @NotNull private final byte[] authMessageBytes;

  // The salted password that was generated in the course of constructing the
  // client proof.
  @NotNull private final byte[] saltedPassword;

  // The bind request being processed.
  @NotNull private final SCRAMBindRequest bindRequest;

  // The client first message from the first stage of the authentication
  // process.
  @NotNull private final SCRAMClientFirstMessage clientFirstMessage;

  // The server first message from the first stage of the authentication
  // process.
  @NotNull private final SCRAMServerFirstMessage serverFirstMessage;

  // The string representation of the client final message.
  @NotNull private final String clientFinalMessage;

  // The base64-encoded string representation of the client proof.
  @NotNull private final String clientProofBase64;



  /**
   * Creates a new client final message with the provided information.
   *
   * @param  bindRequest         The SCRAM bind request being processed.  It
   *                             must not be {@code null}.
   * @param  clientFirstMessage  The client first message from the first stage
   *                             of the authentication process.  It must not be
   *                             {@code null}.
   * @param  serverFirstMessage  The server first message from the first stage
   *                             of the authentication process.  It must not be
   *                             {@code null}.
   *
   * @throws  LDAPBindException  If a problem is encountered while constructing
   *                             the client final message.
   */
  SCRAMClientFinalMessage(@NotNull final SCRAMBindRequest bindRequest,
       @NotNull final SCRAMClientFirstMessage clientFirstMessage,
       @NotNull final SCRAMServerFirstMessage serverFirstMessage)
       throws LDAPBindException
  {
    this.bindRequest = bindRequest;
    this.clientFirstMessage = clientFirstMessage;
    this.serverFirstMessage = serverFirstMessage;


    // Compute the salted password.  And use that to compute the client key and
    // the stored key.
    saltedPassword = computeSaltedPassword(bindRequest, serverFirstMessage);
    final byte[] clientKey =
         bindRequest.mac(saltedPassword, CLIENT_KEY_INPUT_BYTES);
    final byte[] storedKey = bindRequest.digest(clientKey);


    // Construct the client final message without proof and the auth message.
    final String clientFinalMessageWithoutProof = "c=" +
         clientFirstMessage.getGS2HeaderBase64() + ",r=" +
         serverFirstMessage.getCombinedNonce();
    final String authMessage = clientFirstMessage.getClientFirstMessageBare() +
         ',' + serverFirstMessage.getServerFirstMessage() + ',' +
         clientFinalMessageWithoutProof;
    authMessageBytes = StaticUtils.getBytes(authMessage);


    // Compute the client signature and the client proof.
    final byte[] clientSignature = bindRequest.mac(storedKey, authMessageBytes);

    final byte[] clientProof = new byte[clientKey.length];
    for (int i=0; i < clientProof.length; i++)
    {
      clientProof[i] = (byte) (clientKey[i] ^ clientSignature[i]);
    }
    clientProofBase64 = Base64.encode(clientProof);


    // Construct the client final message.
    clientFinalMessage = clientFinalMessageWithoutProof + ",p=" +
         clientProofBase64;
  }



  /**
   * Computes the salted password for this client final message from the
   * provided information.
   *
   * @param  bindRequest         The SCRAM bind request being processed.  It
   *                             must not be {@code null}.
   * @param  serverFirstMessage  The server first message from the first stage
   *                             of the authentication process.  It must not be
   *                             {@code null}.
   *
   * @return  The salted password that was computed.
   *
   * @throws  LDAPBindException  If a problem is encountered while computing the
   *                             salted password.
   */
  @NotNull()
  private static byte[] computeSaltedPassword(
               @NotNull final SCRAMBindRequest bindRequest,
               @NotNull final SCRAMServerFirstMessage serverFirstMessage)
          throws LDAPBindException
  {
    // Get a MAC generator with the password as the key.
    final Mac mac = bindRequest.getMac(bindRequest.getPasswordBytes());


    // For the first round, the MAC input will be the salt plus the bytes that
    // comprise the 32-bit representation of the number one.
    final byte[] salt = serverFirstMessage.getSalt();
    byte[] dataToMAC = new byte[salt.length + ONE_BYTES.length];
    System.arraycopy(salt, 0, dataToMAC, 0, salt.length);
    System.arraycopy(ONE_BYTES, 0, dataToMAC, salt.length, ONE_BYTES.length);


    // Complete the necessary number of rounds of cryptographic processing.
    // For the first round, just compute the MAC of the salt plus the one bytes.
    // For all subsequent rounds, compute the MAC of the previous MAC and XOR
    // that with the previous MAC.
    byte[] xorBytes = null;
    for (int i=0; i < serverFirstMessage.getIterationCount(); i++)
    {
      final byte[] macResult = mac.doFinal(dataToMAC);
      if (i == 0)
      {
        xorBytes = macResult;
      }
      else
      {
        for (int j=0; j < macResult.length; j++)
        {
          xorBytes[j] ^= macResult[j];
        }
      }

      dataToMAC = macResult;
    }


    // The final XOR result is the salted password.
    return xorBytes;
  }



  /**
   * Retrieves the SCRAM bind request being processed.
   *
   * @return  The SCRAM bind request being processed.
   */
  @NotNull()
  SCRAMBindRequest getBindRequest()
  {
    return bindRequest;
  }



  /**
   * Retrieves the client first message with which this client final message
   * is associated.
   *
   * @return  The client first message with which this client final message is
   *          associated.
   */
  @NotNull()
  SCRAMClientFirstMessage getClientFirstMessage()
  {
    return clientFirstMessage;
  }



  /**
   * Retrieves the server first message with which this client final message
   * is associated.
   *
   * @return  The server first message with which this client final message is
   *          associated.
   */
  @NotNull()
  SCRAMServerFirstMessage getServerFirstMessage()
  {
    return serverFirstMessage;
  }



  /**
   * Retrieves the salted password that was computed for this client final
   * message.
   *
   * @return  The salted password that was computed for this client final
   *          message.
   */
  @NotNull()
  byte[] getSaltedPassword()
  {
    return saltedPassword;
  }



  /**
   * Retrieves the bytes that comprise the auth message computed for this client
   * final message.
   *
   * @return  The bytes that comprise the auth message computed for this client
   *          final message;
   */
  @NotNull()
  byte[] getAuthMessageBytes()
  {
    return authMessageBytes;
  }



  /**
   * Retrieves a base64-encoded representation of the client proof computed for
   * this client final message.
   *
   * @return  A base64-encoded representation of the client proof computed for
   *          this client final message.
   */
  @NotNull()
  String getClientProofBase64()
  {
    return clientProofBase64;
  }



  /**
   * Retrieves the string representation of the complete client final message.
   *
   * @return  The string representation of the complete client final message.
   */
  @NotNull()
  String getClientFinalMessage()
  {
    return clientFinalMessage;
  }



  /**
   * Retrieves a string representation of this SCRAM client final message.
   *
   * @return  A string representation of this SCRAM client final message.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return clientFinalMessage;
  }
}
