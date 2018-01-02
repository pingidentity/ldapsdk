/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a SASL PLAIN bind request implementation as described in
 * <A HREF="http://www.ietf.org/rfc/rfc4616.txt">RFC 4616</A>.  The SASL PLAIN
 * mechanism allows the client to authenticate with an authentication ID and
 * password, and optionally allows the client to provide an authorization ID for
 * use in performing subsequent operations.
 * <BR><BR>
 * Elements included in a PLAIN bind request include:
 * <UL>
 *   <LI>Authentication ID -- A string which identifies the user that is
 *       attempting to authenticate.  It should be an "authzId" value as
 *       described in section 5.2.1.8 of
 *       <A HREF="http://www.ietf.org/rfc/rfc4513.txt">RFC 4513</A>.  That is,
 *       it should be either "dn:" followed by the distinguished name of the
 *       target user, or "u:" followed by the username.  If the "u:" form is
 *       used, then the mechanism used to resolve the provided username to an
 *       entry may vary from server to server.</LI>
 *   <LI>Authorization ID -- An optional string which specifies an alternate
 *       authorization identity that should be used for subsequent operations
 *       requested on the connection.  Like the authentication ID, the
 *       authorization ID should use the "authzId" syntax.</LI>
 *   <LI>Password -- The clear-text password for the target user.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a PLAIN bind
 * against a directory server with a username of "test.user" and a password of
 * "password":
 * <PRE>
 * PLAINBindRequest bindRequest =
 *      new PLAINBindRequest("u:test.user", "password");
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
public final class PLAINBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the PLAIN SASL mechanism.
   */
  public static final String PLAIN_MECHANISM_NAME = "PLAIN";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5186140710317748684L;



  // The password for this bind request.
  private final ASN1OctetString password;

  // The authentication ID string for this bind request.
  private final String authenticationID;

  // The authorization ID string for this bind request, if available.
  private final String authorizationID;



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID
   * and password.  It will not include an authorization ID or set of controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public PLAINBindRequest(final String authenticationID, final String password)
  {
    this(authenticationID, null, new ASN1OctetString(password), NO_CONTROLS);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID
   * and password.  It will not include an authorization ID or set of controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public PLAINBindRequest(final String authenticationID, final byte[] password)
  {
    this(authenticationID, null, new ASN1OctetString(password), NO_CONTROLS);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID
   * and password.  It will not include an authorization ID or set of controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public PLAINBindRequest(final String authenticationID,
                          final ASN1OctetString password)
  {
    this(authenticationID, null, password, NO_CONTROLS);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID,
   * authorization ID, and password.  It will not include a set of controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request, or
   *                           {@code null} if there is to be no authorization
   *                           ID.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final String password)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         NO_CONTROLS);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID,
   * authorization ID, and password.  It will not include a set of controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request, or
   *                           {@code null} if there is to be no authorization
   *                           ID.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final byte[] password)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         NO_CONTROLS);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID,
   * authorization ID, and password.  It will not include a set of controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request, or
   *                           {@code null} if there is to be no authorization
   *                           ID.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID,
                          final ASN1OctetString password)
  {
    this(authenticationID, authorizationID, password, NO_CONTROLS);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID,
   * password, and set of controls.  It will not include an authorization ID.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include
   */
  public PLAINBindRequest(final String authenticationID, final String password,
                          final Control... controls)
  {
    this(authenticationID, null, new ASN1OctetString(password), controls);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID,
   * password, and set of controls.  It will not include an authorization ID.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include
   */
  public PLAINBindRequest(final String authenticationID, final byte[] password,
                          final Control... controls)
  {
    this(authenticationID, null, new ASN1OctetString(password), controls);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided authentication ID,
   * password, and set of controls.  It will not include an authorization ID.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include
   */
  public PLAINBindRequest(final String authenticationID,
                          final ASN1OctetString password,
                          final Control... controls)
  {
    this(authenticationID, null, password, controls);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request, or
   *                           {@code null} if there is to be no authorization
   *                           ID.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include
   */
  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final String password,
                          final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         controls);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request, or
   *                           {@code null} if there is to be no authorization
   *                           ID.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include
   */
  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final byte[] password,
                          final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         controls);

    ensureNotNull(password);
  }



  /**
   * Creates a new SASL PLAIN bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request, or
   *                           {@code null} if there is to be no authorization
   *                           ID.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include
   */
  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID,
                          final ASN1OctetString password,
                          final Control... controls)
  {
    super(controls);

    ensureNotNull(authenticationID, password);

    this.authenticationID = authenticationID;
    this.authorizationID  = authorizationID;
    this.password         = password;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return PLAIN_MECHANISM_NAME;
  }



  /**
   * Retrieves the authentication ID for this bind request.
   *
   * @return  The authentication ID for this bind request.
   */
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Retrieves the authorization ID for this bind request.
   *
   * @return  The authorization ID for this bind request, or {@code null} if
   *          there is no authorization ID.
   */
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * Retrieves the string representation of the password for this bind request.
   *
   * @return  The string representation of the password for this bind request.
   */
  public String getPasswordString()
  {
    return password.stringValue();
  }



  /**
   * Retrieves the bytes that comprise the the password for this bind request.
   *
   * @return  The bytes that comprise the password for this bind request.
   */
  public byte[] getPasswordBytes()
  {
    return password.getValue();
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
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    // Create the byte array that should comprise the credentials.
    final byte[] authZIDBytes  = getBytes(authorizationID);
    final byte[] authNIDBytes  = getBytes(authenticationID);
    final byte[] passwordBytes = password.getValue();
    final byte[] credBytes     = new byte[2 + authZIDBytes.length +
                                    authNIDBytes.length + passwordBytes.length];

    System.arraycopy(authZIDBytes, 0, credBytes, 0, authZIDBytes.length);

    int pos = authZIDBytes.length + 1;
    System.arraycopy(authNIDBytes, 0, credBytes, pos, authNIDBytes.length);

    pos += authNIDBytes.length + 1;
    System.arraycopy(passwordBytes, 0, credBytes, pos, passwordBytes.length);

    return sendBindRequest(connection, "", new ASN1OctetString(credBytes),
         getControls(), getResponseTimeoutMillis(connection));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public PLAINBindRequest getRebindRequest(final String host, final int port)
  {
    return new PLAINBindRequest(authenticationID, authorizationID, password,
                                getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public PLAINBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public PLAINBindRequest duplicate(final Control[] controls)
  {
    final PLAINBindRequest bindRequest = new PLAINBindRequest(authenticationID,
         authorizationID, password, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PLAINBindRequest(authenticationID='");
    buffer.append(authenticationID);
    buffer.append('\'');

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
      buffer.append('\'');
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
  public void toCode(final List<String> lineList, final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs =
         new ArrayList<ToCodeArgHelper>(4);
    constructorArgs.add(ToCodeArgHelper.createString(authenticationID,
         "Authentication ID"));
    constructorArgs.add(ToCodeArgHelper.createString(authorizationID,
         "Authorization ID"));
    constructorArgs.add(ToCodeArgHelper.createString("---redacted-password---",
         "Bind Password"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "PLAINBindRequest",
         requestID + "Request", "new PLAINBindRequest", constructorArgs);


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
