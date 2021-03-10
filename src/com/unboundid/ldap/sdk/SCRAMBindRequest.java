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



import java.security.MessageDigest;
import java.util.List;
import java.util.logging.Level;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides the basis for bind requests that use the salted
 * challenge-response authentication mechanism (SCRAM) described in
 * <A HREF="http://www.ietf.org/rfc/rfc5802.txt">RFC 5802</A> and updated in
 * <A HREF="https://tools.ietf.org/html/rfc7677">RFC 7677</A>.  Subclasses
 * should extend this class to provide support for specific algorithms.
 * <BR><BR>
 * Note that this implementation does not support the PLUS variants of these
 * algorithms, which requires channel binding support.
 */
@Extensible()
@ThreadSafety(level= ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class SCRAMBindRequest
       extends SASLBindRequest
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1141722265190138366L;



  // The password for this bind request.
  @NotNull private final ASN1OctetString password;

  // The username for this bind request.
  @NotNull private final String username;



  /**
   * Creates a new SCRAM bind request with the provided information.
   *
   * @param  username  The username for this bind request.  It must not be
   *                   {@code null} or empty.
   * @param  password  The password for this bind request.  It must not be
   *                   {@code null} or empty.
   * @param  controls  The set of controls to include in the bind request.  It
   *                   may be {@code null} or empty if no controls are needed.
   */
  public SCRAMBindRequest(@NotNull final String username,
                          @NotNull final ASN1OctetString password,
                          @Nullable final Control... controls)
  {
    super(controls);

    Validator.ensureNotNullOrEmpty(username,
         "SCRAMBindRequest.username must not be null or empty");
    Validator.ensureTrue(
         ((password != null) && (password.getValueLength() > 0)),
         "SCRAMBindRequest.password must not be null or empty");

    this.username = username;
    this.password = password;
  }



  /**
   * Retrieves the username for this bind request.
   *
   * @return  The password for this bind request.
   */
  @NotNull()
  public final String getUsername()
  {
    return username;
  }



  /**
   * Retrieves the password for this bind request, as a string.
   *
   * @return  The password for this bind request, as a string.
   */
  @NotNull()
  public final String getPasswordString()
  {
    return password.stringValue();
  }



  /**
   * Retrieves the bytes that comprise the password for this bind request.
   *
   * @return  The bytes that comprise the password for this bind request.
   */
  @NotNull()
  public final byte[] getPasswordBytes()
  {
    return password.getValue();
  }



  /**
   * Retrieves the name of the digest algorithm that will be used in the
   * authentication processing.
   *
   * @return  The name of the digest algorithm that will be used in the
   *          authentication processing.
   */
  @NotNull()
  protected abstract String getDigestAlgorithmName();



  /**
   * Retrieves the name of the MAC algorithm that will be used in the
   * authentication processing.
   *
   * @return  The name of the MAC algorithm that will be used in the
   *          authentication processing.
   */
  @NotNull()
  protected abstract String getMACAlgorithmName();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected final BindResult process(@NotNull final LDAPConnection connection,
                                     final int depth)
            throws LDAPException
  {
    // Generate the client first message and send it to the server.
    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(this);
    if (Debug.debugEnabled())
    {
      Debug.debug(Level.INFO, DebugType.LDAP,
           "Sending " + getSASLMechanismName() + " client first message " +
                clientFirstMessage);
    }

    final BindResult serverFirstResult = sendBindRequest(connection, null,
         new ASN1OctetString(clientFirstMessage.getClientFirstMessage()),
         getControls(), getResponseTimeoutMillis(connection));


    // If the result code from the server first result is anything other than
    // SASL_BIND_IN_PROGRESS, then return that result as a failure.
    if (serverFirstResult.getResultCode() != ResultCode.SASL_BIND_IN_PROGRESS)
    {
      return serverFirstResult;
    }


    // Parse the server first result, and use it to compute the client final
    // message.
    final SCRAMServerFirstMessage serverFirstMessage =
         new SCRAMServerFirstMessage(this, clientFirstMessage,
              serverFirstResult);
    if (Debug.debugEnabled())
    {
      Debug.debug(Level.INFO, DebugType.LDAP,
           "Received " + getSASLMechanismName() + " server first message " +
                serverFirstMessage);
    }

    final SCRAMClientFinalMessage clientFinalMessage =
         new SCRAMClientFinalMessage(this, clientFirstMessage,
              serverFirstMessage);
    if (Debug.debugEnabled())
    {
      Debug.debug(Level.INFO, DebugType.LDAP,
           "Sending " + getSASLMechanismName() + " client final message " +
                clientFinalMessage);
    }


    // Send the server final bind request to the server and get the result.
    // We don't care what the result code was, because the server final message
    // processing will handle both success and failure.
    final BindResult serverFinalResult = sendBindRequest(connection, null,
         new ASN1OctetString(clientFinalMessage.getClientFinalMessage()),
         getControls(), getResponseTimeoutMillis(connection));

    final SCRAMServerFinalMessage serverFinalMessage =
         new SCRAMServerFinalMessage(this, clientFirstMessage,
              clientFinalMessage, serverFinalResult);
    if (Debug.debugEnabled())
    {
      Debug.debug(Level.INFO, DebugType.LDAP,
           "Received " + getSASLMechanismName() + " server final message " +
                serverFinalMessage);
    }


    // If we've gotten here, then the bind was successful.  Return the server
    // final result.
    return serverFinalResult;
  }



  /**
   * Computes a MAC of the provided data with the given key.
   *
   * @param  key   The bytes to use as the key for the MAC.
   * @param  data  The data for which to generate the MAC.
   *
   * @return  The MAC that was computed.
   *
   * @throws  LDAPBindException  If a problem is encountered while computing the
   *                             MAC.
   */
  @NotNull()
  final byte[] mac(@NotNull final byte[] key, @NotNull final byte[] data)
        throws LDAPBindException
  {
    return getMac(key).doFinal(data);
  }



  /**
   * Retrieves a MAC generator for the provided key.
   *
   * @param  key  The bytes to use as the key for the MAC.
   *
   * @return  The MAC generator.
   *
   * @throws  LDAPBindException  If a problem is encountered while obtaining the
   *                             MAC generator.
   */
  @NotNull()
  final Mac getMac(@NotNull final byte[] key)
        throws LDAPBindException
  {
    try
    {
      final Mac mac = CryptoHelper.getMAC(getMACAlgorithmName());
      final SecretKeySpec macKey =
           new SecretKeySpec(key, getMACAlgorithmName());
      mac.init(macKey);
      return mac;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPBindException(new BindResult(-1,
           ResultCode.LOCAL_ERROR,
           ERR_SCRAM_BIND_REQUEST_CANNOT_GET_MAC.get(getSASLMechanismName(),
                getMACAlgorithmName()),
           null, null, null, null));
    }
  }



  /**
   * Computes a message digest of the provided data with the given key.
   *
   * @param  data  The data for which to generate the digest.
   *
   * @return  The digest that was computed.
   *
   * @throws  LDAPBindException  If a problem is encountered while computing the
   *                             digest.
   */
  @NotNull()
  final byte[] digest(@NotNull final byte[] data)
        throws LDAPBindException
  {
    try
    {
      final MessageDigest digest =
           CryptoHelper.getMessageDigest(getDigestAlgorithmName());
      return digest.digest(data);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPBindException(new BindResult(-1,
           ResultCode.LOCAL_ERROR,
           ERR_SCRAM_BIND_REQUEST_CANNOT_GET_DIGEST.get(
                getSASLMechanismName(), getDigestAlgorithmName()),
           null, null, null, null));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public abstract SCRAMBindRequest getRebindRequest(
                                        @NotNull final String host,
                                        final int port);



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public abstract SCRAMBindRequest duplicate();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public abstract SCRAMBindRequest duplicate(@NotNull final Control[] controls);



  /**
   * {@inheritDoc}
   */
  @Override()
  public abstract void toString(@NotNull final StringBuilder buffer);



  /**
   * {@inheritDoc}
   */
  @Override()
  public abstract void toCode(@NotNull final List<String> lineList,
                              @NotNull final String requestID,
                              final int indentSpaces,
                              final boolean includeProcessing);
}
