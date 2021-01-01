/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SASLBindRequest;
import com.unboundid.ldap.sdk.ToCodeArgHelper;
import com.unboundid.ldap.sdk.ToCodeHelper;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides support for an UnboundID-proprietary SASL mechanism that
 * provides multifactor authentication using the combination of a client
 * certificate (presented during SSL/TLS negotiation) and a static password.
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
 * The name for this SASL mechanism is "UNBOUNDID-CERTIFICATE-PLUS-PASSWORD".
 * The SASL credentials consist simply of the static password for the user
 * identified by the certificate, to make the SASL mechanism as easy as possible
 * to use from other client APIs.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class UnboundIDCertificatePlusPasswordBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the UnboundID certificate plus password SASL mechanism.
   */
  @NotNull public static final String UNBOUNDID_CERT_PLUS_PW_MECHANISM_NAME =
       "UNBOUNDID-CERTIFICATE-PLUS-PASSWORD";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8863298749835036708L;



  // The password to use to authenticate.
  @NotNull private final ASN1OctetString password;

  // The message ID from the last LDAP message sent from this request.
  private volatile int messageID = -1;



  /**
   * Creates a new certificate plus password bind request with the provided
   * information.
   *
   * @param  password  The password to use to authenticate as user identified by
   *                   the certificate.  It must not be {@code null} or empty.
   * @param  controls  The set of controls to include in the bind request.  It
   *                   may be {@code null} or empty if no request controls are
   *                   needed.
   */
  public UnboundIDCertificatePlusPasswordBindRequest(
              @NotNull final String password,
              @Nullable final Control... controls)
  {
    this(new ASN1OctetString(CRED_TYPE_SASL, password), controls);
  }



  /**
   * Creates a new certificate plus password bind request with the provided
   * information.
   *
   * @param  password  The password to use to authenticate as user identified by
   *                   the certificate.  It must not be {@code null} or empty.
   * @param  controls  The set of controls to include in the bind request.  It
   *                   may be {@code null} or empty if no request controls are
   *                   needed.
   */
  public UnboundIDCertificatePlusPasswordBindRequest(
              @NotNull final byte[] password,
              @Nullable final Control... controls)
  {
    this(new ASN1OctetString(CRED_TYPE_SASL, password), controls);
  }



  /**
   * Creates a new certificate plus password bind request with the provided
   * information.
   *
   * @param  password  The password to use to authenticate as user identified by
   *                   the certificate.  It must not be {@code null} or empty.
   * @param  controls  The set of controls to include in the bind request.  It
   *                   may be {@code null} or empty if no request controls are
   *                   needed.
   */
  private UnboundIDCertificatePlusPasswordBindRequest(
               @NotNull final ASN1OctetString password,
               @Nullable final Control... controls)
  {
    super(controls);

    Validator.ensureFalse((password.getValueLength() == 0),
         "The bind password must not be empty");

    this.password = password;
  }



  /**
   * Retrieves the password to use to authenticate as the user identified by the
   * certificate.
   *
   * @return  The password to use to authenticate as the user identified by the
   *          certificate.
   */
  @NotNull()
  public ASN1OctetString getPassword()
  {
    return password;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return UNBOUNDID_CERT_PLUS_PW_MECHANISM_NAME;
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
    return sendBindRequest(connection, "", password, getControls(),
         getResponseTimeoutMillis(connection));
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
  public UnboundIDCertificatePlusPasswordBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnboundIDCertificatePlusPasswordBindRequest duplicate(
              @Nullable final Control[] controls)
  {
    final UnboundIDCertificatePlusPasswordBindRequest bindRequest =
         new UnboundIDCertificatePlusPasswordBindRequest(password, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnboundIDCertificatePlusPasswordBindRequest getRebindRequest(
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
    buffer.append("UnboundIDCertificatePlusPasswordBindRequest(");

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append("controls={");
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
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(2);
    constructorArgs.add(ToCodeArgHelper.createString("---redacted-password---",
         "Bind Password"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "UnboundIDCertificatePlusPasswordBindRequest", requestID + "Request",
         "new UnboundIDCertificatePlusPasswordBindRequest", constructorArgs);


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
