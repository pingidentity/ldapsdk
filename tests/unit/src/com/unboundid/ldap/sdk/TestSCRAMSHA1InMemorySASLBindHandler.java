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



import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.listener.InMemorySASLBindHandler;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a mechanism for testing support for the SCRAM-SHA-1 SASL
 * mechanism in the in-memory directory server.  It is only intended for
 * testing purposes.
 */
public final class TestSCRAMSHA1InMemorySASLBindHandler
       extends InMemorySASLBindHandler
{
  // The password used to authenticate.
  private final String bindPassword;



  /**
   * Creates a new instance of this SASL bind handler.
   *
   * @param  bindPassword  The password that will be used to authenticate.
   */
  public TestSCRAMSHA1InMemorySASLBindHandler(final String bindPassword)
  {
    this.bindPassword = bindPassword;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return "SCRAM-SHA-1";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public BindResult processSASLBind(final InMemoryRequestHandler handler,
                                    final int messageID, final DN bindDN,
                                    final ASN1OctetString credentials,
                                    final List<Control> controls)
  {
    if (credentials == null)
    {
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           "No credentials", null, null, null, null);
    }

    try
    {
      final String credentialsString = credentials.stringValue();
      if (credentialsString.startsWith("n,,n="))
      {
        // This should be the initial bind.
        return processInitialBind(handler, messageID, credentialsString);
      }
      else if (credentialsString.startsWith("c=biws,r="))
      {
        // This should be the final bind.
        return processFinalBind(handler, messageID, credentialsString);
      }
      else
      {
        return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
             "Unexpected credentials:  " + credentialsString, null, null, null,
             null);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return new BindResult(messageID, ResultCode.OTHER,
           "Processing error:  " + StaticUtils.getExceptionMessage(e),
           null, null, null, null);
    }
  }



  /**
   * Performs the processing for an initial bind.
   *
   * @param  handler            The handler to use in processing.
   * @param  messageID          The message ID for the request.
   * @param  credentialsString  The credentials string to process.
   *
   * @return  The result of the processing.
   */
  private BindResult processInitialBind(final InMemoryRequestHandler handler,
                                        final int messageID,
                                        final String credentialsString)
  {
    // Extract the username and client nonce.
    final int commaRPos = credentialsString.indexOf(",r=");
    final String username = credentialsString.substring(5, commaRPos);
    final String clientNonce = credentialsString.substring(commaRPos+3);


    // Generate a server nonce and append it to the client nonce.
    final SecureRandom random = CryptoHelper.getSecureRandom();
    final byte[] serverNonceBytes = new byte[16];
    random.nextBytes(serverNonceBytes);
    final String serverNonce = Base64.urlEncode(serverNonceBytes, false);
    final String combinedNonce = clientNonce + serverNonce;


    // Generate a salt.
    final byte[] saltBytes = new byte[16];
    random.nextBytes(saltBytes);
    final String saltBase64 = Base64.encode(saltBytes);


    // Construct the server first message to return.
    final String serverFirstMessage = "r=" + combinedNonce + ",s=" +
         saltBase64 + ",i=4096";


    // Store information in the client state.
    final Map<String,Object> state = handler.getConnectionState();
    state.put("username", username);
    state.put("clientNonce", clientNonce);
    state.put("combinedNonce", combinedNonce);
    state.put("serverFirstMessage", serverFirstMessage);


    // Return the bind response.
    return new BindResult(messageID, ResultCode.SASL_BIND_IN_PROGRESS, null,
         null, null, null, new ASN1OctetString(serverFirstMessage));
  }



  /**
   * Performs the processing for a final bind.
   *
   * @param  handler            The handler to use in processing.
   * @param  messageID          The message ID for the request.
   * @param  credentialsString  The credentials string to process.
   *
   * @return  The result of the processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private BindResult processFinalBind(final InMemoryRequestHandler handler,
                                      final int messageID,
                                      final String credentialsString)
          throws Exception
  {
    // Extract the nonce and client proof.
    final int commaPPos = credentialsString.indexOf(",p=");
    final String nonce = credentialsString.substring(9, commaPPos);
    final String clientProofBase64 = credentialsString.substring(commaPPos+3);


    // Get information from the client state.
    final Map<String,Object> state = handler.getConnectionState();
    final String username = (String) state.get("username");
    final String clientNonce = (String) state.get("clientNonce");
    final String combinedNonce = (String) state.get("combinedNonce");
    final String serverFirstMessageString =
         (String) state.get("serverFirstMessage");


    // Make sure the combined nonce matches.
    if (! combinedNonce.equals(nonce))
    {
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           "Incorrect nonce", null, null, null,
           new ASN1OctetString("e=other-error"));
    }


    // Create a bind request, and all of the messages.
    final SCRAMSHA1BindRequest bindRequest =
         new SCRAMSHA1BindRequest(username, bindPassword);

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, clientNonce);

    final BindResult serverFirstResult = new BindResult(1, ResultCode.SUCCESS,
         null, null, null, null, new ASN1OctetString(serverFirstMessageString));
    final SCRAMServerFirstMessage serverFirstMessage =
         new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
              serverFirstResult);

    final SCRAMClientFinalMessage clientFinalMessage =
         new SCRAMClientFinalMessage(bindRequest, clientFirstMessage,
              serverFirstMessage);
    if (clientFinalMessage.getClientProofBase64().equals(clientProofBase64))
    {
      final byte[] serverKey = bindRequest.mac(
           clientFinalMessage.getSaltedPassword(),
           StaticUtils.getBytes("Server Key"));
      final byte[] serverSignature = bindRequest.mac(serverKey,
           clientFinalMessage.getAuthMessageBytes());
      final String serverSignatureBase64 = Base64.encode(serverSignature);
      return new BindResult(messageID, ResultCode.SUCCESS, null, null, null,
           null, new ASN1OctetString("v=" + serverSignatureBase64));
    }
    else
    {
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           "Invalid client proof", null, null, null,
           new ASN1OctetString("e=invalid-proof"));
    }
  }
}
