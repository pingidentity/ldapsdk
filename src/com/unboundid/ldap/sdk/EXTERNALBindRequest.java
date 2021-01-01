/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a SASL EXTERNAL bind request implementation as described
 * in <A HREF="http://www.ietf.org/rfc/rfc4422.txt">RFC 4422</A>.  The
 * EXTERNAL mechanism is used to authenticate using information that is
 * available outside of the LDAP layer (e.g., a certificate presented by the
 * client during SSL or StartTLS negotiation).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing an EXTERNAL
 * bind against a directory server:
 * <PRE>
 * EXTERNALBindRequest bindRequest = new EXTERNALBindRequest("");
 * BindResult bindResult;
 * try
 * {
 *   bindResult = connection.bind(bindRequest);
 *   // If we get here, then the bind was successful.
 * }
 * catch (LDAPException le)
 * {
 *   // The bind failed for some reason.
 *   bindResult = new BindResult(le.toLDAPResult());
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class EXTERNALBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the EXTERNAL SASL mechanism.
   */
  @NotNull public static final String EXTERNAL_MECHANISM_NAME = "EXTERNAL";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7520760039662616663L;



  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The authorization ID to send to the server in the bind request.  It may be
  // null, empty, or non-empty.
  @Nullable private final String authzID;



  /**
   * Creates a new SASL EXTERNAL bind request with no authorization ID and no
   * controls.
   */
  public EXTERNALBindRequest()
  {
    this(null, StaticUtils.NO_CONTROLS);
  }



  /**
   * Creates a new SASL EXTERNAL bind request with the specified authorization
   * ID and no controls.
   *
   * @param  authzID  The authorization ID to use for the bind request.  It may
   *                  be {@code null} if the client should not send any
   *                  authorization ID at all (which may be required by some
   *                  servers).  It may be an empty string if the server should
   *                  determine the authorization identity from what it knows
   *                  about the client (e.g., a client certificate).  It may be
   *                  a non-empty string if the authorization identity should
   *                  be different from the authentication identity.
   */
  public EXTERNALBindRequest(@Nullable final String authzID)
  {
    this(authzID, StaticUtils.NO_CONTROLS);
  }



  /**
   * Creates a new SASL EXTERNAL bind request with the provided set of controls.
   *
   * @param  controls  The set of controls to include in this SASL EXTERNAL
   *                   bind request.
   */
  public EXTERNALBindRequest(@Nullable final Control... controls)
  {
    this(null, controls);
  }



  /**
   * Creates a new SASL EXTERNAL bind request with the provided set of controls.
   *
   *
   * @param  authzID   The authorization ID to use for the bind request.  It may
   *                   be {@code null} if the client should not send any
   *                   authorization ID at all (which may be required by some
   *                   servers).  It may be an empty string if the server should
   *                   determine the authorization identity from what it knows
   *                   about the client (e.g., a client certificate).  It may be
   *                   a non-empty string if the authorization identity should
   *                   be different from the authentication identity.
   * @param  controls  The set of controls to include in this SASL EXTERNAL
   *                   bind request.
   */
  public EXTERNALBindRequest(@Nullable final String authzID,
                             @Nullable final Control... controls)
  {
    super(controls);

    this.authzID = authzID;
  }



  /**
   * Retrieves the authorization ID that should be included in the bind request,
   * if any.
   *
   * @return  The authorization ID that should be included in the bind request,
   *          or {@code null} if the bind request should be sent without an
   *          authorization ID (which is a form that some servers require).  It
   *          may be an empty string if the authorization identity should be the
   *          same as the authentication identity and should be determined from
   *          what the server already knows about the client.
   */
  @Nullable()
  public String getAuthorizationID()
  {
    return authzID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return EXTERNAL_MECHANISM_NAME;
  }



  /**
   * Sends this bind request to the target server over the provided connection
   * and returns the corresponding response.
   *
   * @param  connection  The connection to use to send this bind request to the
   *                     server and read the associated response.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  The bind response read from the server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  protected BindResult process(@NotNull final LDAPConnection connection,
                               final int depth)
            throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();

    final ASN1OctetString creds;
    if (authzID == null)
    {
      creds = null;
    }
    else
    {
      creds = new ASN1OctetString(authzID);
    }

    return sendBindRequest(connection, "", creds, getControls(),
                           getResponseTimeoutMillis(connection));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public EXTERNALBindRequest getRebindRequest(@NotNull final String host,
                                              final int port)
  {
    return new EXTERNALBindRequest(authzID, getControls());
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
  public EXTERNALBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public EXTERNALBindRequest duplicate(@Nullable final Control[] controls)
  {
    final EXTERNALBindRequest bindRequest =
         new EXTERNALBindRequest(authzID, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("EXTERNALBindRequest(");

    boolean added = false;
    if (authzID != null)
    {
      buffer.append("authzID='");
      buffer.append(authzID);
      buffer.append('\'');
      added = true;
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      if (added)
      {
        buffer.append(", ");
      }

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

    if (authzID != null)
    {
      constructorArgs.add(ToCodeArgHelper.createString(authzID,
           "Authorization ID"));
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "EXTERNALBindRequest", requestID + "Request",
         "new EXTERNALBindRequest", constructorArgs);


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
