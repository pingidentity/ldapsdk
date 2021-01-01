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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Base64;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class holds the elements associated with the server final message in a
 * SCRAM authentication sequence.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SCRAMServerFinalMessage
      implements Serializable
{
  /**
   * The input bytes to provide to the MAC when generating the server key.
   */
  @NotNull private static final byte[] SERVER_KEY_INPUT_BYTES =
       StaticUtils.getBytes("Server Key");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8799438618265483051L;



  // The bind result containing the server final message.
  @NotNull private final BindResult bindResult;

  // The bind request being processed.
  @NotNull private final SCRAMBindRequest bindRequest;

  // The client first message that was sent to the server.
  @NotNull private final SCRAMClientFirstMessage clientFirstMessage;

  // The client first message that was sent to the server.
  @NotNull private final SCRAMClientFinalMessage clientFinalMessage;

  // The string representation of the server first message included in the bind
  // result.
  @NotNull private final String serverFinalMessage;

  // The base64-encoded server signature included in the server final message.
  @NotNull private final String serverSignatureBase64;



  /**
   * Creates a new server final message with the provided information.
   *
   * @param  bindRequest         The SCRAM bind request being processed.  It
   *                             must not be {@code null}.
   * @param  clientFirstMessage  The client first message that was sent to the
   *                             server.  It must not be {@code null}.
   * @param  clientFinalMessage  The client final message that was sent to the
   *                             server.  It must not be {@code null}.
   * @param  bindResult          The bind result from which to extract the
   *                             server final message.  It must not be
   *                             {@code null}.
   *
   * @throws  LDAPBindException  If a problem is encountered while parsing the
   *                             server final message from the provided bind
   *                             result.
   */
  SCRAMServerFinalMessage(@NotNull final SCRAMBindRequest bindRequest,
       @NotNull final SCRAMClientFirstMessage clientFirstMessage,
       @NotNull final SCRAMClientFinalMessage clientFinalMessage,
       @NotNull final BindResult bindResult)
       throws LDAPBindException
  {
    this.bindRequest = bindRequest;
    this.clientFirstMessage = clientFirstMessage;
    this.clientFinalMessage = clientFinalMessage;
    this.bindResult = bindResult;


    // Make sure that the bind result included server SASL credentials.
    final ASN1OctetString serverSASLCredentials =
         bindResult.getServerSASLCredentials();
    if (serverSASLCredentials == null)
    {
      if (bindResult.getResultCode() == ResultCode.SUCCESS)
      {
        throw new LDAPBindException(new BindResult(bindResult.getMessageID(),
             ResultCode.DECODING_ERROR,
             ERR_SCRAM_SERVER_FINAL_MESSAGE_NO_CREDS.get(
                  bindRequest.getSASLMechanismName()),
             bindResult.getMatchedDN(), bindResult.getReferralURLs(),
             bindResult.getResponseControls(), serverSASLCredentials));
      }
      else
      {
        throw new LDAPBindException(bindResult);
      }
    }


    // If the result code is not SUCCESS and we have server SASL credentials,
    // then it must start with "e=" and contain the error type.
    serverFinalMessage = serverSASLCredentials.stringValue();
    if (bindResult.getResultCode() != ResultCode.SUCCESS)
    {
      if (serverFinalMessage.startsWith("e="))
      {
        final String errorValue;
        final int commaPos = serverFinalMessage.indexOf(',');
        if (commaPos > 0)
        {
          errorValue = serverFinalMessage.substring(2, commaPos);
        }
        else
        {
          errorValue = serverFinalMessage.substring(2);
        }

        final String diagnosticMessage = bindResult.getDiagnosticMessage();
        if (diagnosticMessage == null)
        {
          throw new LDAPBindException(new BindResult(bindResult.getMessageID(),
               bindResult.getResultCode(),
               ERR_SCRAM_SERVER_FINAL_MESSAGE_ERROR_VALUE_NO_DIAG.get(
                    bindRequest.getSASLMechanismName(), errorValue),
               bindResult.getMatchedDN(), bindResult.getReferralURLs(),
               bindResult.getResponseControls(), serverSASLCredentials));
        }
        else
        {
          throw new LDAPBindException(new BindResult(bindResult.getMessageID(),
               bindResult.getResultCode(),
               ERR_SCRAM_SERVER_FINAL_MESSAGE_ERROR_VALUE_WITH_DIAG.get(
                    bindRequest.getSASLMechanismName(), errorValue,
                    diagnosticMessage),
               bindResult.getMatchedDN(), bindResult.getReferralURLs(),
               bindResult.getResponseControls(), serverSASLCredentials));
        }
      }
      else
      {
        throw new LDAPBindException(bindResult);
      }
    }


    // The server final message must consist of "v=" followed by the server
    // signature.  Note that it's possible that there will be extensions
    // after the signature, and if so then we will ignore them.
    if (! serverFinalMessage.startsWith("v="))
    {
      throw new LDAPBindException(new BindResult(bindResult.getMessageID(),
           ResultCode.DECODING_ERROR,
           ERR_SCRAM_SERVER_FINAL_MESSAGE_NO_VERIFIER.get(
                bindRequest.getSASLMechanismName(), serverFinalMessage),
           bindResult.getMatchedDN(), bindResult.getReferralURLs(),
           bindResult.getResponseControls(), serverSASLCredentials));
    }

    final int commaPos = serverFinalMessage.indexOf(',');
    if (commaPos > 0)
    {
      serverSignatureBase64 = serverFinalMessage.substring(2, commaPos);
    }
    else
    {
      serverSignatureBase64 = serverFinalMessage.substring(2);
    }


    // Compute the expected server signature and verify that it matches what we
    // got.
    final byte[] serverKey = bindRequest.mac(
         clientFinalMessage.getSaltedPassword(), SERVER_KEY_INPUT_BYTES);
    final byte[] serverSignature = bindRequest.mac(serverKey,
         clientFinalMessage.getAuthMessageBytes());
    final String expectedServerSignatureBase64 = Base64.encode(serverSignature);
    if (! expectedServerSignatureBase64.equals(serverSignatureBase64))
    {
      throw new LDAPBindException(new BindResult(bindResult.getMessageID(),
           ResultCode.DECODING_ERROR,
           ERR_SCRAM_SERVER_FINAL_MESSAGE_INCORRECT_VERIFIER.get(
                bindRequest.getSASLMechanismName(), serverFinalMessage,
                serverSignatureBase64, expectedServerSignatureBase64),
           bindResult.getMatchedDN(), bindResult.getReferralURLs(),
           bindResult.getResponseControls(), serverSASLCredentials));
    }
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
   * Retrieves the client first message with which this server final message
   * is associated.
   *
   * @return  The client first message with which this server final message is
   *          associated.
   */
  @NotNull()
  SCRAMClientFirstMessage getClientFirstMessage()
  {
    return clientFirstMessage;
  }



  /**
   * Retrieves the client final message with which this server final message
   * is associated.
   *
   * @return  The client final message with which this server final message is
   *          associated.
   */
  @NotNull()
  SCRAMClientFinalMessage getClientFinalMessage()
  {
    return clientFinalMessage;
  }



  /**
   * Retrieves a base64-encoded representation of the server signature included
   * in the server final message.
   *
   * @return  A base64-encoded representation of the server signature included
   *          in the server final message.
   */
  @NotNull()
  String getServerSignatureBase64()
  {
    return serverSignatureBase64;
  }



  /**
   * Retrieves a string representation of the server final message.
   *
   * @return  A string representation of the server final message.
   */
  @NotNull()
  String getServerFinalMessage()
  {
    return serverFinalMessage;
  }



  /**
   * Retrieves a string representation of this SCRAM server final message.
   *
   * @return  A string representation of this SCRAM server final message.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return serverFinalMessage;
  }
}
