/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SASLBindRequest;
import com.unboundid.ldap.sdk.ToCodeArgHelper;
import com.unboundid.ldap.sdk.ToCodeHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides support for an UnboundID-proprietary SASL mechanism that
 * may be used to indicate that a user has attempted authentication, whether
 * successfully or not, through some mechanism that is external to the Directory
 * Server.  If this mechanism is supported in the server, then attempting to
 * authenticate with it will not change the identity of the client connection,
 * but will perform additional processing that would normally be completed
 * during a more traditional authentication attempt.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * This SASL bind request has a mechanism of
 * "UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION" and must
 * include SASL credentials with the following encoding:
 * <PRE>
 *   ExternallyProcessedAuthenticationCredentials ::= SEQUENCE {
 *        authenticationID                          [0] OCTET STRING,
 *        externalMechanismName                     [1] OCTET STRING,
 *        externalAuthenticationWasSuccessful       [2] BOOLEAN,
 *        externalAuthenticationFailureReason       [3] OCTET STRING OPTIONAL,
 *        externalAuthenticationWasPasswordBased    [4] BOOLEAN DEFAULT TRUE,
 *        externalAuthenticationWasSecure           [5] BOOLEAN DEFAULT FALSE,
 *        endClientIPAddress                        [6] OCTET STRING OPTIONAL,
 *        additionalAccessLogProperties             [7] SEQUENCE OF SEQUENCE {
 *             propertyName      OCTET STRING,
 *             propertyValue     OCTET STRING } OPTIONAL,
 *        ... }
 * </PRE>
 * <BR><BR>
 * In the event that the external authentication was considered successful, the
 * server will ensure that the target user's account is in a usable state and,
 * if not, will return a failure response.  If the external authentication was
 * successful and the user's account is usable, then the server will make any
 * appropriate password policy state updates (e.g., clearing previous
 * authentication failures, updating the user's last login time and IP address,
 * etc.) and return a success result.
 * <BR><BR>
 * In the event that the external authentication was not considered successful,
 * the server may also make corresponding password policy state updates (e.g.,
 * incrementing the number of authentication failures and locking the account if
 * appropriate) before returning a failure result.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class UnboundIDExternallyProcessedAuthenticationBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the UnboundID externally-processed authentication SASL
   * mechanism.
   */
  @NotNull public static final String
       UNBOUNDID_EXTERNALLY_PROCESSED_AUTH_MECHANISM_NAME =
            "UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION";



  /**
   * The BER type for the authenticationID element of the bind request.
   */
  private static final byte TYPE_AUTHENTICATION_ID = (byte) 0x80;



  /**
   * The BER type for the externalMechanismName element of the bind request.
   */
  private static final byte TYPE_EXTERNAL_MECHANISM_NAME = (byte) 0x81;



  /**
   * The BER type for the externalAuthenticationWasSuccessful element of the
   * bind request.
   */
  private static final byte TYPE_EXTERNAL_AUTH_WAS_SUCCESSFUL = (byte) 0x82;



  /**
   * The BER type for the externalAuthenticationFailureReason element of the
   * bind request.
   */
  private static final byte TYPE_EXTERNAL_AUTH_FAILURE_REASON = (byte) 0x83;



  /**
   * The BER type for the externalAuthenticationWasPasswordBased element of the
   * bind request.
   */
  private static final byte TYPE_EXTERNAL_AUTH_WAS_PASSWORD_BASED = (byte) 0x84;



  /**
   * The BER type for the externalAuthenticationWasSecure element of the bind
   * request.
   */
  private static final byte TYPE_EXTERNAL_AUTH_WAS_SECURE = (byte) 0x85;



  /**
   * The BER type for the endClientIPAddress element of the bind request.
   */
  private static final byte TYPE_END_CLIENT_IP_ADDRESS = (byte) 0x86;



  /**
   * The BER type for the additionalAccessLogProperties element of the bind
   * request.
   */
  private static final byte TYPE_ADDITIONAL_ACCESS_LOG_PROPERTIES = (byte) 0xA7;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4312237491980971019L;



  // The encoded SASL credentials for this bind request.
  @Nullable private volatile ASN1OctetString encodedCredentials;

  // Indicates whether the external authentication processing involved a
  // password.
  private final boolean externalAuthWasPasswordBased;

  // Indicates whether the external authentication processing is considered to
  // have been secure.
  private final boolean externalAuthWasSecure;

  // Indicates whether the external authentication attempt is considered to have
  // been successful.
  private final boolean externalAuthWasSuccessful;

  // The message ID from the last LDAP message sent from this request.
  private volatile int messageID;

  // A map of additional properties that should be recorded in the server's
  // access log.
  @NotNull private final Map<String,String> additionalAccessLogProperties;

  // The authentication ID that identifies the user for whom the external
  // authentication processing was performed.
  @NotNull private final String authenticationID;

  // The IPv4 or IPv6 address of the end client, if available.
  @Nullable private final String endClientIPAddress;

  // The reason that the external authentication attempt was considered a
  // failure.
  @Nullable private final String externalAuthFailureReason;

  // The name of the mechanism used for the external authentication attempt.
  @NotNull private final String externalMechanismName;



  /**
   * Creates a new UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION bind request
   * with the provided information.
   *
   * @param  authenticationID               The authentication ID that
   *                                        identifies the user for whom the
   *                                        external authentication processing
   *                                        was performed.  This should be
   *                                        either "dn:" followed by the DN of
   *                                        the target user's entry, or "u:"
   *                                        followed by a username.  This must
   *                                        not be {@code null}.
   * @param  externalMechanismName          The name of the mechanism used for
   *                                        the external authentication attempt.
   *                                        This must not be {@code null}.
   * @param  externalAuthWasSuccessful      Indicates whether the external
   *                                        authentication attempt is considered
   *                                        to have been successful.
   * @param  externalAuthFailureReason      The reason that the external
   *                                        authentication attempt was
   *                                        considered a failure.  This should
   *                                        be {@code null} if the external
   *                                        authentication attempt succeeded,
   *                                        and may be {@code null} if the
   *                                        external authentication attempt
   *                                        failed but no failure reason is
   *                                        available.
   * @param  externalAuthWasPasswordBased   Indicates whether the external
   *                                        authentication processing involved a
   *                                        password.
   * @param  externalAuthWasSecure          Indicates whether the external
   *                                        authentication processing was
   *                                        considered secure.  A mechanism
   *                                        should only be considered secure if
   *                                        all credentials were protected in
   *                                        all communication.
   * @param  endClientIPAddress             The IPv4 or IPv6 address of the end
   *                                        client involved in the external
   *                                        authentication processing.  This may
   *                                        be {@code null} if the end client
   *                                        address is not available.
   * @param  additionalAccessLogProperties  A map of additional properties that
   *                                        should be recorded in the server's
   *                                        access log for the external
   *                                        authentication attempt.  This may be
   *                                        {@code null} or empty if no
   *                                        additional access log properties are
   *                                        required.
   * @param  controls                       The set of controls to include in
   *                                        the request.  It may be {@code null}
   *                                        or empty if no request controls are
   *                                        needed.
   */
  public UnboundIDExternallyProcessedAuthenticationBindRequest(
              @NotNull final String authenticationID,
              @NotNull final String externalMechanismName,
              final boolean externalAuthWasSuccessful,
              @Nullable final String externalAuthFailureReason,
              final boolean externalAuthWasPasswordBased,
              final boolean externalAuthWasSecure,
              @Nullable final String endClientIPAddress,
              @Nullable final Map<String,String> additionalAccessLogProperties,
              @Nullable final Control... controls)
  {
    super(controls);

    Validator.ensureNotNull(authenticationID);
    Validator.ensureNotNull(externalMechanismName);

    this.authenticationID             = authenticationID;
    this.externalMechanismName        = externalMechanismName;
    this.externalAuthWasSuccessful    = externalAuthWasSuccessful;
    this.externalAuthFailureReason    = externalAuthFailureReason;
    this.externalAuthWasPasswordBased = externalAuthWasPasswordBased;
    this.externalAuthWasSecure        = externalAuthWasSecure;
    this.endClientIPAddress           = endClientIPAddress;

    if (additionalAccessLogProperties == null)
    {
      this.additionalAccessLogProperties = Collections.emptyMap();
    }
    else
    {
      this.additionalAccessLogProperties = Collections.unmodifiableMap(
           new LinkedHashMap<>(additionalAccessLogProperties));
    }

    messageID = -1;
    encodedCredentials = null;
  }



  /**
   * Creates a new UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION bind request
   * decoded from the provided information.
   *
   * @param  saslCredentials  The encoded SASL credentials to be decoded.  It
   *                          must not be {@code null}.
   * @param  controls         The set of controls to include in the request.  It
   *                          may be {@code null} or empty if no request
   *                          controls are needed.
   *
   * @return  The decoded UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION bind
   *          request.
   *
   * @throws  LDAPException  If the provided SASL credentials are not valid for
   *                         am UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION
   *                         bind request
   */
  @NotNull()
  public static UnboundIDExternallyProcessedAuthenticationBindRequest
              decodeSASLCredentials(
                   @NotNull final ASN1OctetString saslCredentials,
                   @Nullable final Control... controls)
         throws LDAPException
  {
    Validator.ensureNotNull(saslCredentials);

    boolean passwordBased = true;
    boolean secure = false;
    Boolean successful = null;
    String failureReason = null;
    String ipAddress = null;
    String mechanism = null;
    String authID = null;

    final LinkedHashMap<String,String> logProperties =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));

    try
    {
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(saslCredentials.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_AUTHENTICATION_ID:
            authID = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_EXTERNAL_MECHANISM_NAME:
            mechanism = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_EXTERNAL_AUTH_WAS_SUCCESSFUL:
            successful = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_EXTERNAL_AUTH_FAILURE_REASON:
            failureReason =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_EXTERNAL_AUTH_WAS_PASSWORD_BASED:
            passwordBased = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_EXTERNAL_AUTH_WAS_SECURE:
            secure = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_END_CLIENT_IP_ADDRESS:
            ipAddress = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_ADDITIONAL_ACCESS_LOG_PROPERTIES:
            for (final ASN1Element propertiesElement :
                 ASN1Sequence.decodeAsSequence(e).elements())
            {
              final ASN1Element[] logPairElements =
                   ASN1Sequence.decodeAsSequence(propertiesElement).elements();
              final String name = ASN1OctetString.decodeAsOctetString(
                   logPairElements[0]).stringValue();
              final String value = ASN1OctetString.decodeAsOctetString(
                   logPairElements[1]).stringValue();
              logProperties.put(name, value);
            }
            break;
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTERNALLY_PROCESSED_AUTH_CANNOT_DECODE_CREDS.get(
                UNBOUNDID_EXTERNALLY_PROCESSED_AUTH_MECHANISM_NAME,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (authID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTERNALLY_PROCESSED_AUTH_NO_AUTH_ID.get(
                UNBOUNDID_EXTERNALLY_PROCESSED_AUTH_MECHANISM_NAME));
    }

    if (mechanism == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTERNALLY_PROCESSED_AUTH_NO_MECH.get(
                UNBOUNDID_EXTERNALLY_PROCESSED_AUTH_MECHANISM_NAME));
    }

    if (successful == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTERNALLY_PROCESSED_AUTH_NO_WAS_SUCCESSFUL.get(
                UNBOUNDID_EXTERNALLY_PROCESSED_AUTH_MECHANISM_NAME));
    }

    final UnboundIDExternallyProcessedAuthenticationBindRequest bindRequest =
         new UnboundIDExternallyProcessedAuthenticationBindRequest(authID,
              mechanism, successful, failureReason, passwordBased, secure,
              ipAddress, logProperties, controls);
    bindRequest.encodedCredentials = saslCredentials;

    return bindRequest;
  }



  /**
   * Retrieves the authentication ID that identifies the user for whom the
   * external authentication processing was performed.
   *
   * @return  The authentication ID that identifies the user for whom the
   *          external authentication processing was performed.
   */
  @NotNull()
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Retrieves the name of the mechanism used for the external authentication
   * attempt.
   *
   * @return  The name of the mechanism used for the external authentication
   *          attempt.
   */
  @NotNull()
  public String getExternalMechanismName()
  {
    return externalMechanismName;
  }



  /**
   * Indicates whether the external authentication attempt is considered to have
   * been successful.
   *
   * @return  {@code true} if the external authentication attempt was considered
   *          successful, or {@code false} if not.
   */
  public boolean externalAuthenticationWasSuccessful()
  {
    return externalAuthWasSuccessful;
  }



  /**
   * Retrieves the reason that the external authentication attempt was
   * considered a failure, if available.
   *
   * @return  The reason that the external authentication attempt was considered
   *          a failure, or {@code null} if no failure reason is available.
   */
  @Nullable()
  public String getExternalAuthenticationFailureReason()
  {
    return externalAuthFailureReason;
  }



  /**
   * Indicates whether the external authentication processing involved a
   * password.
   *
   * @return  {@code true} if the external authentication processing involved a
   *          password, or {@code false} if not.
   */
  public boolean externalAuthenticationWasPasswordBased()
  {
    return externalAuthWasPasswordBased;
  }



  /**
   * Indicates whether the external authentication processing is considered to
   * have been secure.
   *
   * @return  {@code true} if the external authentication processing was
   *          considered secure, or {@code false} if not.
   */
  public boolean externalAuthenticationWasSecure()
  {
    return externalAuthWasSecure;
  }



  /**
   * Retrieves the IPv4 or IPv6 address of the end client involved in the
   * external authentication processing, if available.
   *
   * @return  The IPv4 or IPv6 address of the end client involved in the
   *          external authentication processing, or {@code null} if this is not
   *          available.
   */
  @Nullable()
  public String getEndClientIPAddress()
  {
    return endClientIPAddress;
  }



  /**
   * Retrieves a map of additional properties that should be recorded in the
   * server's access log for the external authentication attempt.
   *
   * @return  A map of additional properties that should be recorded in the
   *          server's access log for the external authentication attempt, or an
   *          empty map if there are no additional log properties.
   */
  @NotNull()
  public Map<String,String> getAdditionalAccessLogProperties()
  {
    return additionalAccessLogProperties;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return UNBOUNDID_EXTERNALLY_PROCESSED_AUTH_MECHANISM_NAME;
  }



  /**
   * Retrieves an encoded representation of the SASL credentials for this bind
   * request.
   *
   * @return  An encoded representation of the SASL credentials for this bind
   *          request.
   */
  @NotNull()
  public ASN1OctetString getEncodedCredentials()
  {
    if (encodedCredentials == null)
    {
      final ArrayList<ASN1Element> credElements = new ArrayList<>(8);

      credElements.add(new ASN1OctetString(TYPE_AUTHENTICATION_ID,
           authenticationID));
      credElements.add(new ASN1OctetString(TYPE_EXTERNAL_MECHANISM_NAME,
           externalMechanismName));
      credElements.add(new ASN1Boolean(TYPE_EXTERNAL_AUTH_WAS_SUCCESSFUL,
           externalAuthWasSuccessful));

      if (externalAuthFailureReason != null)
      {
        credElements.add(new ASN1OctetString(TYPE_EXTERNAL_AUTH_FAILURE_REASON,
             externalAuthFailureReason));
      }

      if (! externalAuthWasPasswordBased)
      {
        credElements.add(new ASN1Boolean(TYPE_EXTERNAL_AUTH_WAS_PASSWORD_BASED,
             false));
      }

      if (externalAuthWasSecure)
      {
        credElements.add(new ASN1Boolean(TYPE_EXTERNAL_AUTH_WAS_SECURE, true));
      }

      if (endClientIPAddress != null)
      {
        credElements.add(new ASN1OctetString(TYPE_END_CLIENT_IP_ADDRESS,
             endClientIPAddress));
      }

      if (! additionalAccessLogProperties.isEmpty())
      {
        final ArrayList<ASN1Element> logElements =
             new ArrayList<>(additionalAccessLogProperties.size());
        for (final Map.Entry<String,String> e :
             additionalAccessLogProperties.entrySet())
        {
          logElements.add(new ASN1Sequence(
               new ASN1OctetString(e.getKey()),
               new ASN1OctetString(e.getValue())));
        }

        credElements.add(new ASN1Sequence(TYPE_ADDITIONAL_ACCESS_LOG_PROPERTIES,
             logElements));
      }

      final ASN1Sequence credSequence = new ASN1Sequence(credElements);
      encodedCredentials = new ASN1OctetString(credSequence.encode());
    }

    return encodedCredentials;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected BindResult process(@NotNull final LDAPConnection connection,
                               final int depth)
            throws LDAPException
  {
    messageID = InternalSDKHelper.nextMessageID(connection);
    return sendBindRequest(connection, "", getEncodedCredentials(),
         getControls(), getResponseTimeoutMillis(connection));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnboundIDExternallyProcessedAuthenticationBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnboundIDExternallyProcessedAuthenticationBindRequest duplicate(
              @Nullable final Control[] controls)
  {
    final UnboundIDExternallyProcessedAuthenticationBindRequest bindRequest =
         new UnboundIDExternallyProcessedAuthenticationBindRequest(
              authenticationID, externalMechanismName,
              externalAuthWasSuccessful, externalAuthFailureReason,
              externalAuthWasPasswordBased, externalAuthWasSecure,
              endClientIPAddress, additionalAccessLogProperties, controls);
    bindRequest.encodedCredentials = encodedCredentials;

    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnboundIDExternallyProcessedAuthenticationBindRequest getRebindRequest(
              @NotNull final String host, final int port)
  {
    return duplicate();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("UnboundIDExternallyProcessedAuthenticationBindRequest(" +
         "authenticationID='");
    buffer.append(authenticationID);
    buffer.append("', externalMechanismName='");
    buffer.append(externalMechanismName);
    buffer.append("', externalAuthenticationWasSuccessful=");
    buffer.append(externalAuthWasSuccessful);
    buffer.append('\'');

    if (externalAuthFailureReason != null)
    {
      buffer.append(", externalAuthenticationFailureReason='");
      buffer.append(externalAuthFailureReason);
      buffer.append('\'');
    }

    buffer.append(", externalAuthenticationWasPasswordBased=");
    buffer.append(externalAuthWasPasswordBased);
    buffer.append(", externalAuthenticationWasSecure=");
    buffer.append(externalAuthWasSecure);

    if (endClientIPAddress != null)
    {
      buffer.append(", endClientIPAddress='");
      buffer.append(endClientIPAddress);
      buffer.append('\'');
    }

    if (! additionalAccessLogProperties.isEmpty())
    {
      buffer.append(", additionalAccessLogProperties={");

      final Iterator<Map.Entry<String,String>> iterator =
           additionalAccessLogProperties.entrySet().iterator();
      while (iterator.hasNext())
      {
        final Map.Entry<String,String> e = iterator.next();

        buffer.append('\'');
        buffer.append(e.getKey());
        buffer.append("'='");
        buffer.append(e.getValue());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }


    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the map of additional log properties.
    final ArrayList<ToCodeArgHelper> mapConstructorArgs = new ArrayList<>(1);
    mapConstructorArgs.add(ToCodeArgHelper.createInteger(
         additionalAccessLogProperties.size(), "Initial Capacity"));

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "LinkedHashMap<String,String>",
         requestID + "AdditionalAccessLogProperties",
         "new LinkedHashMap<String,String>",
         mapConstructorArgs);


    // Create the method calls used to populate the map.
    for (final Map.Entry<String,String> e :
         additionalAccessLogProperties.entrySet())
    {
      final ArrayList<ToCodeArgHelper> putArgs = new ArrayList<>(2);
      putArgs.add(ToCodeArgHelper.createString(e.getKey(),
           "Log Property Key"));
      putArgs.add(ToCodeArgHelper.createString(e.getValue(),
           "Log Property Value"));

      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "AdditionalAccessLogProperties.put", putArgs);
    }


    // Create the request variable.
    final ArrayList<ToCodeArgHelper> requestConstructorArgs =
         new ArrayList<>(8);
    requestConstructorArgs.add(ToCodeArgHelper.createString(authenticationID,
         "Authentication ID"));
    requestConstructorArgs.add(ToCodeArgHelper.createString(
         externalMechanismName, "External Mechanism Name"));
    requestConstructorArgs.add(ToCodeArgHelper.createBoolean(
         externalAuthWasSuccessful, "External Authentication Was Successful"));
    requestConstructorArgs.add(ToCodeArgHelper.createString(
         externalAuthFailureReason, "External Authentication Failure Reason"));
    requestConstructorArgs.add(ToCodeArgHelper.createBoolean(
         externalAuthWasPasswordBased,
         "External Authentication Was Password Based"));
    requestConstructorArgs.add(ToCodeArgHelper.createBoolean(
         externalAuthWasSecure, "External Authentication Was Secure"));
    requestConstructorArgs.add(ToCodeArgHelper.createString(endClientIPAddress,
         "End Client IP Address"));
    requestConstructorArgs.add(ToCodeArgHelper.createRaw(
         requestID + "AdditionalAccessLogProperties",
         "Additional AccessLogProperties"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      requestConstructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    lineList.add("");
    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "UnboundIDExternallyProcessedAuthenticationBindRequest",
         requestID + "Request",
         "new UnboundIDExternallyProcessedAuthenticationBindRequest",
         requestConstructorArgs);


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The bind failed.  Maybe the following will " +
           "help explain why.");
      lineList.add(indent + "  // Note that the connection is now likely in " +
           "an unauthenticated state.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");
      lineList.add(indent + '}');
    }
  }
}
