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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a SASL DIGEST-MD5 bind request implementation as
 * described in <A HREF="http://www.ietf.org/rfc/rfc2831.txt">RFC 2831</A>.  The
 * DIGEST-MD5 mechanism can be used to authenticate over an insecure channel
 * without exposing the credentials (although it requires that the server have
 * access to the clear-text password).  It is similar to CRAM-MD5, but provides
 * better security by combining random data from both the client and the server,
 * and allows for greater security and functionality, including the ability to
 * specify an alternate authorization identity and the ability to use data
 * integrity or confidentiality protection.
 * <BR><BR>
 * Elements included in a DIGEST-MD5 bind request include:
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
 *   <LI>Realm -- An optional string which specifies the realm into which the
 *       user should authenticate.</LI>
 *   <LI>Password -- The clear-text password for the target user.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a DIGEST-MD5
 * bind against a directory server with a username of "john.doe" and a password
 * of "password":
 * <PRE>
 * DIGESTMD5BindRequest bindRequest =
 *      new DIGESTMD5BindRequest("u:john.doe", "password");
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
public final class DIGESTMD5BindRequest
       extends SASLBindRequest
       implements CallbackHandler
{
  /**
   * The name for the DIGEST-MD5 SASL mechanism.
   */
  @NotNull public static final String DIGESTMD5_MECHANISM_NAME = "DIGEST-MD5";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 867592367640540593L;



  // The password for this bind request.
  @NotNull private final ASN1OctetString password;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The SASL quality of protection value(s) allowed for the DIGEST-MD5 bind
  // request.
  @NotNull private final List<SASLQualityOfProtection> allowedQoP;

  // A list that will be updated with messages about any unhandled callbacks
  // encountered during processing.
  @NotNull private final List<String> unhandledCallbackMessages;

  // The authentication ID string for this bind request.
  @NotNull private final String authenticationID;

  // The authorization ID string for this bind request, if available.
  @Nullable private final String authorizationID;

  // The realm form this bind request, if available.
  @Nullable private final String realm;



  /**
   * Creates a new SASL DIGEST-MD5 bind request with the provided authentication
   * ID and password.  It will not include an authorization ID, a realm, or any
   * controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public DIGESTMD5BindRequest(@NotNull final String authenticationID,
                              @NotNull final String password)
  {
    this(authenticationID, null, new ASN1OctetString(password), null,
         NO_CONTROLS);

    Validator.ensureNotNull(password);
  }



  /**
   * Creates a new SASL DIGEST-MD5 bind request with the provided authentication
   * ID and password.  It will not include an authorization ID, a realm, or any
   * controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public DIGESTMD5BindRequest(@NotNull final String authenticationID,
                              @NotNull final byte[] password)
  {
    this(authenticationID, null, new ASN1OctetString(password), null,
         NO_CONTROLS);

    Validator.ensureNotNull(password);
  }



  /**
   * Creates a new SASL DIGEST-MD5 bind request with the provided authentication
   * ID and password.  It will not include an authorization ID, a realm, or any
   * controls.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   */
  public DIGESTMD5BindRequest(@NotNull final String authenticationID,
                              @NotNull final ASN1OctetString password)
  {
    this(authenticationID, null, password, null, NO_CONTROLS);
  }



  /**
   * Creates a new SASL DIGEST-MD5 bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request.  It
   *                           may be {@code null} if there will not be an
   *                           alternate authorization identity.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  realm             The realm to use for the authentication.  It may
   *                           be {@code null} if the server supports a default
   *                           realm.
   * @param  controls          The set of controls to include in the request.
   */
  public DIGESTMD5BindRequest(@NotNull final String authenticationID,
                              @Nullable final String authorizationID,
                              @NotNull final String password,
                              @Nullable final String realm,
                              @Nullable final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         realm, controls);

    Validator.ensureNotNull(password);
  }



  /**
   * Creates a new SASL DIGEST-MD5 bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request.  It
   *                           may be {@code null} if there will not be an
   *                           alternate authorization identity.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  realm             The realm to use for the authentication.  It may
   *                           be {@code null} if the server supports a default
   *                           realm.
   * @param  controls          The set of controls to include in the request.
   */
  public DIGESTMD5BindRequest(@NotNull final String authenticationID,
                              @Nullable final String authorizationID,
                              @NotNull final byte[] password,
                              @Nullable final String realm,
                              @Nullable final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         realm, controls);

    Validator.ensureNotNull(password);
  }



  /**
   * Creates a new SASL DIGEST-MD5 bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request.  It
   *                           may be {@code null} if there will not be an
   *                           alternate authorization identity.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  realm             The realm to use for the authentication.  It may
   *                           be {@code null} if the server supports a default
   *                           realm.
   * @param  controls          The set of controls to include in the request.
   */
  public DIGESTMD5BindRequest(@NotNull final String authenticationID,
                              @Nullable final String authorizationID,
                              @NotNull final ASN1OctetString password,
                              @Nullable final String realm, final
                              @Nullable Control... controls)
  {
    super(controls);

    Validator.ensureNotNull(authenticationID, password);

    this.authenticationID = authenticationID;
    this.authorizationID  = authorizationID;
    this.password         = password;
    this.realm            = realm;

    allowedQoP = Collections.singletonList(SASLQualityOfProtection.AUTH);

    unhandledCallbackMessages = new ArrayList<>(5);
  }



  /**
   * Creates a new SASL DIGEST-MD5 bind request with the provided set of
   * properties.
   *
   * @param  properties  The properties to use for this
   * @param  controls    The set of controls to include in the request.
   */
  public DIGESTMD5BindRequest(
              @NotNull final DIGESTMD5BindRequestProperties properties,
              @Nullable final Control... controls)
  {
    super(controls);

    Validator.ensureNotNull(properties);

    authenticationID = properties.getAuthenticationID();
    authorizationID  = properties.getAuthorizationID();
    password         = properties.getPassword();
    realm            = properties.getRealm();
    allowedQoP       = properties.getAllowedQoP();

    unhandledCallbackMessages = new ArrayList<>(5);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return DIGESTMD5_MECHANISM_NAME;
  }



  /**
   * Retrieves the authentication ID for this bind request.
   *
   * @return  The authentication ID for this bind request.
   */
  @NotNull()
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Retrieves the authorization ID for this bind request, if any.
   *
   * @return  The authorization ID for this bind request, or {@code null} if
   *          there should not be a separate authorization identity.
   */
  @Nullable()
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * Retrieves the string representation of the password for this bind request.
   *
   * @return  The string representation of the password for this bind request.
   */
  @NotNull()
  public String getPasswordString()
  {
    return password.stringValue();
  }



  /**
   * Retrieves the bytes that comprise the the password for this bind request.
   *
   * @return  The bytes that comprise the password for this bind request.
   */
  @NotNull()
  public byte[] getPasswordBytes()
  {
    return password.getValue();
  }



  /**
   * Retrieves the realm for this bind request, if any.
   *
   * @return  The realm for this bind request, or {@code null} if none was
   *          defined and the server should use the default realm.
   */
  @Nullable()
  public String getRealm()
  {
    return realm;
  }



  /**
   * Retrieves the list of allowed qualities of protection that may be used for
   * communication that occurs on the connection after the authentication has
   * completed, in order from most preferred to least preferred.
   *
   * @return  The list of allowed qualities of protection that may be used for
   *          communication that occurs on the connection after the
   *          authentication has completed, in order from most preferred to
   *          least preferred.
   */
  @NotNull()
  public List<SASLQualityOfProtection> getAllowedQoP()
  {
    return allowedQoP;
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
    unhandledCallbackMessages.clear();


    final HashMap<String,Object> saslProperties =
         new HashMap<>(StaticUtils.computeMapCapacity(20));
    saslProperties.put(Sasl.QOP, SASLQualityOfProtection.toString(allowedQoP));
    saslProperties.put(Sasl.SERVER_AUTH, "false");

    final SaslClient saslClient;
    try
    {
      final String[] mechanisms = { DIGESTMD5_MECHANISM_NAME };
      saslClient = Sasl.createSaslClient(mechanisms, authorizationID, "ldap",
                                         connection.getConnectedAddress(),
                                         saslProperties, this);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_DIGESTMD5_CANNOT_CREATE_SASL_CLIENT.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final SASLClientBindHandler bindHandler = new SASLClientBindHandler(this,
         connection, DIGESTMD5_MECHANISM_NAME, saslClient, getControls(),
         getResponseTimeoutMillis(connection), unhandledCallbackMessages);

    try
    {
      return bindHandler.processSASLBind();
    }
    finally
    {
      messageID = bindHandler.getMessageID();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DIGESTMD5BindRequest getRebindRequest(@NotNull final String host,
                                               final int port)
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties(authenticationID, password);
    properties.setAuthorizationID(authorizationID);
    properties.setRealm(realm);
    properties.setAllowedQoP(allowedQoP);

    return new DIGESTMD5BindRequest(properties, getControls());
  }



  /**
   * Handles any necessary callbacks required for SASL authentication.
   *
   * @param  callbacks  The set of callbacks to be handled.
   */
  @InternalUseOnly()
  @Override()
  public void handle(@NotNull final Callback[] callbacks)
  {
    for (final Callback callback : callbacks)
    {
      if (callback instanceof NameCallback)
      {
        ((NameCallback) callback).setName(authenticationID);
      }
      else if (callback instanceof PasswordCallback)
      {
        ((PasswordCallback) callback).setPassword(
             password.stringValue().toCharArray());
      }
      else if (callback instanceof RealmCallback)
      {
        final RealmCallback rc = (RealmCallback) callback;
        if (realm == null)
        {
          final String defaultRealm = rc.getDefaultText();
          if (defaultRealm == null)
          {
            unhandledCallbackMessages.add(
                 ERR_DIGESTMD5_REALM_REQUIRED_BUT_NONE_PROVIDED.get(
                      String.valueOf(rc.getPrompt())));
          }
          else
          {
            rc.setText(defaultRealm);
          }
        }
        else
        {
          rc.setText(realm);
        }
      }
      else if (callback instanceof RealmChoiceCallback)
      {
        final RealmChoiceCallback rcc = (RealmChoiceCallback) callback;
        if (realm == null)
        {
          final String choices =
               StaticUtils.concatenateStrings("{", " '", ",", "'", " }",
                    rcc.getChoices());
          unhandledCallbackMessages.add(
               ERR_DIGESTMD5_REALM_REQUIRED_BUT_NONE_PROVIDED.get(
                    rcc.getPrompt(), choices));
        }
        else
        {
          final String[] choices = rcc.getChoices();
          for (int i=0; i < choices.length; i++)
          {
            if (choices[i].equals(realm))
            {
              rcc.setSelectedIndex(i);
              break;
            }
          }
        }
      }
      else
      {
        // This is an unexpected callback.
        if (Debug.debugEnabled(DebugType.LDAP))
        {
          Debug.debug(Level.WARNING, DebugType.LDAP,
               "Unexpected DIGEST-MD5 SASL callback of type " +
                    callback.getClass().getName());
        }

        unhandledCallbackMessages.add(ERR_DIGESTMD5_UNEXPECTED_CALLBACK.get(
             callback.getClass().getName()));
      }
    }
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
  public DIGESTMD5BindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DIGESTMD5BindRequest duplicate(@Nullable final Control[] controls)
  {
    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties(authenticationID, password);
    properties.setAuthorizationID(authorizationID);
    properties.setRealm(realm);
    properties.setAllowedQoP(allowedQoP);

    final DIGESTMD5BindRequest bindRequest =
         new DIGESTMD5BindRequest(properties, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DIGESTMD5BindRequest(authenticationID='");
    buffer.append(authenticationID);
    buffer.append('\'');

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
      buffer.append('\'');
    }

    if (realm != null)
    {
      buffer.append(", realm='");
      buffer.append(realm);
      buffer.append('\'');
    }

    buffer.append(", qop='");
    buffer.append(SASLQualityOfProtection.toString(allowedQoP));
    buffer.append('\'');

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
    // Create and update the bind request properties object.
    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "DIGESTMD5BindRequestProperties",
         requestID + "RequestProperties",
         "new DIGESTMD5BindRequestProperties",
         ToCodeArgHelper.createString(authenticationID, "Authentication ID"),
         ToCodeArgHelper.createString("---redacted-password---", "Password"));

    if (authorizationID != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setAuthorizationID",
           ToCodeArgHelper.createString(authorizationID, null));
    }

    if (realm != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setRealm",
           ToCodeArgHelper.createString(realm, null));
    }

    final ArrayList<String> qopValues = new ArrayList<>(3);
    for (final SASLQualityOfProtection qop : allowedQoP)
    {
      qopValues.add("SASLQualityOfProtection." + qop.name());
    }
    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setAllowedQoP",
         ToCodeArgHelper.createRaw(qopValues, null));


    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(2);
    constructorArgs.add(
         ToCodeArgHelper.createRaw(requestID + "RequestProperties", null));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "DIGESTMD5BindRequest", requestID + "Request",
         "new DIGESTMD5BindRequest", constructorArgs);


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
