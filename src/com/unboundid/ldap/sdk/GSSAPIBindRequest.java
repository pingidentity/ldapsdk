/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.sasl.RealmCallback;
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
 * This class provides a SASL GSSAPI bind request implementation as described in
 * <A HREF="http://www.ietf.org/rfc/rfc4752.txt">RFC 4752</A>.  It provides the
 * ability to authenticate to a directory server using Kerberos V, which can
 * serve as a kind of single sign-on mechanism that may be shared across
 * client applications that support Kerberos.
 * <BR><BR>
 * This class uses the Java Authentication and Authorization Service (JAAS)
 * behind the scenes to perform all Kerberos processing.  This framework
 * requires a configuration file to indicate the underlying mechanism to be
 * used.  It is possible for clients to explicitly specify the path to the
 * configuration file that should be used, but if none is given then a default
 * file will be created and used.  This default file should be sufficient for
 * Sun-provided JVMs, but a custom file may be required for JVMs provided by
 * other vendors.
 * <BR><BR>
 * Elements included in a GSSAPI bind request include:
 * <UL>
 *   <LI>Authentication ID -- A string which identifies the user that is
 *       attempting to authenticate.  It should be the user's Kerberos
 *       principal.</LI>
 *   <LI>Authorization ID -- An optional string which specifies an alternate
 *       authorization identity that should be used for subsequent operations
 *       requested on the connection.  Like the authentication ID, the
 *       authorization ID should be a Kerberos principal.</LI>
 *   <LI>KDC Address -- An optional string which specifies the IP address or
 *       resolvable name for the Kerberos key distribution center.  If this is
 *       not provided, an attempt will be made to determine the appropriate
 *       value from the system configuration.</LI>
 *   <LI>Realm -- An optional string which specifies the realm into which the
 *       user should authenticate.  If this is not provided, an attempt will be
 *       made to determine the appropriate value from the system
 *       configuration</LI>
 *   <LI>Password -- The clear-text password for the target user in the Kerberos
 *       realm.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a GSSAPI bind
 * against a directory server with a username of "john.doe" and a password
 * of "password":
 * <PRE>
 * GSSAPIBindRequestProperties gssapiProperties =
 *      new GSSAPIBindRequestProperties("john.doe@EXAMPLE.COM", "password");
 * gssapiProperties.setKDCAddress("kdc.example.com");
 * gssapiProperties.setRealm("EXAMPLE.COM");
 *
 * GSSAPIBindRequest bindRequest =
 *      new GSSAPIBindRequest(gssapiProperties);
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
public final class GSSAPIBindRequest
       extends SASLBindRequest
       implements CallbackHandler, PrivilegedExceptionAction<Object>
{
  /**
   * The name for the GSSAPI SASL mechanism.
   */
  @NotNull public static final String GSSAPI_MECHANISM_NAME = "GSSAPI";



  /**
   * The name of the configuration property used to specify the address of the
   * Kerberos key distribution center.
   */
  @NotNull private static final String PROPERTY_KDC_ADDRESS =
       "java.security.krb5.kdc";



  /**
   * The name of the configuration property used to specify the Kerberos realm.
   */
  @NotNull private static final String PROPERTY_REALM =
       "java.security.krb5.realm";



  /**
   * The name of the configuration property used to specify the path to the JAAS
   * configuration file.
   */
  @NotNull private static final String PROPERTY_CONFIG_FILE =
       "java.security.auth.login.config";



  /**
   * The name of the configuration property used to indicate whether credentials
   * can come from somewhere other than the location specified in the JAAS
   * configuration file.
   */
  @NotNull private static final String PROPERTY_SUBJECT_CREDS_ONLY =
       "javax.security.auth.useSubjectCredsOnly";



  /**
   * The value for the java.security.auth.login.config property at the time that
   * this class was loaded.  If this is set, then it will be used in place of
   * an automatically-generated config file.
   */
  @Nullable private static final String DEFAULT_CONFIG_FILE =
       StaticUtils.getSystemProperty(PROPERTY_CONFIG_FILE);



  /**
   * The default KDC address that will be used if none is explicitly configured.
   */
  @Nullable private static final String DEFAULT_KDC_ADDRESS =
       StaticUtils.getSystemProperty(PROPERTY_KDC_ADDRESS);



  /**
   * The default realm that will be used if none is explicitly configured.
   */
  @Nullable private static final String DEFAULT_REALM =
       StaticUtils.getSystemProperty(PROPERTY_REALM);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2511890818146955112L;



  // The password for the GSSAPI bind request.
  @Nullable private final ASN1OctetString password;

  // A reference to the connection to use for bind processing.
  @NotNull private final AtomicReference<LDAPConnection> conn;

  // Indicates whether to enable JVM-level debugging for GSSAPI processing.
  private final boolean enableGSSAPIDebugging;

  // Indicates whether the client should act as the GSSAPI initiator or the
  // acceptor.
  @Nullable private final Boolean isInitiator;

  // Indicates whether to attempt to refresh the configuration before the JAAS
  // login method is called.
  private final boolean refreshKrb5Config;

  // Indicates whether to attempt to renew the client's existing ticket-granting
  // ticket if authentication uses an existing Kerberos session.
  private final boolean renewTGT;

  // Indicates whether to require that the credentials be obtained from the
  // ticket cache such that authentication will fail if the client does not have
  // an existing Kerberos session.
  private final boolean requireCachedCredentials;

  // Indicates whether to allow the to obtain the credentials to be obtained
  // from a keytab.
  private final boolean useKeyTab;

  // Indicates whether to allow the client to use credentials that are outside
  // of the current subject.
  private final boolean useSubjectCredentialsOnly;

  // Indicates whether to enable the use pf a ticket cache.
  private final boolean useTicketCache;

  // The message ID from the last LDAP message sent from this request.
  private int messageID;

  // The SASL quality of protection value(s) allowed for the DIGEST-MD5 bind
  // request.
  @NotNull private final List<SASLQualityOfProtection> allowedQoP;

  // A list that will be updated with messages about any unhandled callbacks
  // encountered during processing.
  @NotNull private final List<String> unhandledCallbackMessages;

  // The names of any system properties that should not be altered by GSSAPI
  // processing.
  @NotNull private Set<String> suppressedSystemProperties;

  // The authentication ID string for the GSSAPI bind request.
  @Nullable private final String authenticationID;

  // The authorization ID string for the GSSAPI bind request, if available.
  @Nullable private final String authorizationID;

  // The path to the JAAS configuration file to use for bind processing.
  @Nullable private final String configFilePath;

  // The name that will be used to identify this client in the JAAS framework.
  @NotNull private final String jaasClientName;

  // The KDC address for the GSSAPI bind request, if available.
  @Nullable private final String kdcAddress;

  // The path to the keytab file to use if useKeyTab is true.
  @Nullable private final String keyTabPath;

  // The realm for the GSSAPI bind request, if available.
  @Nullable private final String realm;

  // The server name that should be used when creating the Java SaslClient, if
  // defined.
  @Nullable private final String saslClientServerName;

  // The protocol that should be used in the Kerberos service principal for
  // the server system.
  @NotNull private final String servicePrincipalProtocol;

  // The path to the Kerberos ticket cache to use.
  @Nullable private final String ticketCachePath;



  /**
   * Creates a new SASL GSSAPI bind request with the provided authentication ID
   * and password.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @NotNull final String password)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password));
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided authentication ID
   * and password.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @NotNull final byte[] password)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password));
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided authentication ID
   * and password.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @NotNull final String password,
                           @Nullable final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password), controls);
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided authentication ID
   * and password.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  controls          The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @NotNull final byte[] password,
                           @Nullable final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password), controls);
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request.  It
   *                           may be {@code null} if no alternate authorization
   *                           ID should be used.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  realm             The realm to use for the authentication.  It may
   *                           be {@code null} to attempt to use the default
   *                           realm from the system configuration.
   * @param  kdcAddress        The address of the Kerberos key distribution
   *                           center.  It may be {@code null} to attempt to use
   *                           the default KDC from the system configuration.
   * @param  configFilePath    The path to the JAAS configuration file to use
   *                           for the authentication processing.  It may be
   *                           {@code null} to use the default JAAS
   *                           configuration.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @Nullable final String authorizationID,
                           @NotNull final String password,
                           @Nullable final String realm,
                           @Nullable final String kdcAddress,
                           @Nullable final String configFilePath)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath));
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request.  It
   *                           may be {@code null} if no alternate authorization
   *                           ID should be used.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  realm             The realm to use for the authentication.  It may
   *                           be {@code null} to attempt to use the default
   *                           realm from the system configuration.
   * @param  kdcAddress        The address of the Kerberos key distribution
   *                           center.  It may be {@code null} to attempt to use
   *                           the default KDC from the system configuration.
   * @param  configFilePath    The path to the JAAS configuration file to use
   *                           for the authentication processing.  It may be
   *                           {@code null} to use the default JAAS
   *                           configuration.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @Nullable final String authorizationID,
                           @NotNull final byte[] password,
                           @Nullable final String realm,
                           @Nullable final String kdcAddress,
                           @Nullable final String configFilePath)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath));
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request.  It
   *                           may be {@code null} if no alternate authorization
   *                           ID should be used.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  realm             The realm to use for the authentication.  It may
   *                           be {@code null} to attempt to use the default
   *                           realm from the system configuration.
   * @param  kdcAddress        The address of the Kerberos key distribution
   *                           center.  It may be {@code null} to attempt to use
   *                           the default KDC from the system configuration.
   * @param  configFilePath    The path to the JAAS configuration file to use
   *                           for the authentication processing.  It may be
   *                           {@code null} to use the default JAAS
   *                           configuration.
   * @param  controls          The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @Nullable final String authorizationID,
                           @NotNull final String password,
                           @Nullable final String realm,
                           @Nullable final String kdcAddress,
                           @Nullable final String configFilePath,
                           @Nullable final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath),
         controls);
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided information.
   *
   * @param  authenticationID  The authentication ID for this bind request.  It
   *                           must not be {@code null}.
   * @param  authorizationID   The authorization ID for this bind request.  It
   *                           may be {@code null} if no alternate authorization
   *                           ID should be used.
   * @param  password          The password for this bind request.  It must not
   *                           be {@code null}.
   * @param  realm             The realm to use for the authentication.  It may
   *                           be {@code null} to attempt to use the default
   *                           realm from the system configuration.
   * @param  kdcAddress        The address of the Kerberos key distribution
   *                           center.  It may be {@code null} to attempt to use
   *                           the default KDC from the system configuration.
   * @param  configFilePath    The path to the JAAS configuration file to use
   *                           for the authentication processing.  It may be
   *                           {@code null} to use the default JAAS
   *                           configuration.
   * @param  controls          The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(@NotNull final String authenticationID,
                           @Nullable final String authorizationID,
                           @NotNull final byte[] password,
                           @Nullable final String realm,
                           @Nullable final String kdcAddress,
                           @Nullable final String configFilePath,
                           @Nullable final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath),
         controls);
  }



  /**
   * Creates a new SASL GSSAPI bind request with the provided set of properties.
   *
   * @param  gssapiProperties  The set of properties that should be used for
   *                           the GSSAPI bind request.  It must not be
   *                           {@code null}.
   * @param  controls          The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while creating the JAAS
   *                         configuration file to use during authentication
   *                         processing.
   */
  public GSSAPIBindRequest(
              @NotNull final GSSAPIBindRequestProperties gssapiProperties,
              @Nullable final Control... controls)
          throws LDAPException
  {
    super(controls);

    Validator.ensureNotNull(gssapiProperties);

    authenticationID           = gssapiProperties.getAuthenticationID();
    password                   = gssapiProperties.getPassword();
    realm                      = gssapiProperties.getRealm();
    allowedQoP                 = gssapiProperties.getAllowedQoP();
    kdcAddress                 = gssapiProperties.getKDCAddress();
    jaasClientName             = gssapiProperties.getJAASClientName();
    saslClientServerName       = gssapiProperties.getSASLClientServerName();
    servicePrincipalProtocol   = gssapiProperties.getServicePrincipalProtocol();
    enableGSSAPIDebugging      = gssapiProperties.enableGSSAPIDebugging();
    useKeyTab                  = gssapiProperties.useKeyTab();
    useSubjectCredentialsOnly  = gssapiProperties.useSubjectCredentialsOnly();
    useTicketCache             = gssapiProperties.useTicketCache();
    requireCachedCredentials   = gssapiProperties.requireCachedCredentials();
    refreshKrb5Config          = gssapiProperties.refreshKrb5Config();
    renewTGT                   = gssapiProperties.renewTGT();
    keyTabPath                 = gssapiProperties.getKeyTabPath();
    ticketCachePath            = gssapiProperties.getTicketCachePath();
    isInitiator                = gssapiProperties.getIsInitiator();
    suppressedSystemProperties =
         gssapiProperties.getSuppressedSystemProperties();

    unhandledCallbackMessages = new ArrayList<>(5);

    conn      = new AtomicReference<>();
    messageID = -1;

    final String authzID = gssapiProperties.getAuthorizationID();
    if (authzID == null)
    {
      authorizationID = null;
    }
    else
    {
      authorizationID = authzID;
    }

    final String cfgPath = gssapiProperties.getConfigFilePath();
    if (cfgPath == null)
    {
      if (DEFAULT_CONFIG_FILE == null)
      {
        configFilePath = getConfigFilePath(gssapiProperties);
      }
      else
      {
        configFilePath = DEFAULT_CONFIG_FILE;
      }
    }
    else
    {
      configFilePath = cfgPath;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return GSSAPI_MECHANISM_NAME;
  }



  /**
   * Retrieves the authentication ID for the GSSAPI bind request, if defined.
   *
   * @return  The authentication ID for the GSSAPI bind request, or {@code null}
   *          if an existing Kerberos session should be used.
   */
  @Nullable()
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
   * Retrieves the string representation of the password for this bind request,
   * if defined.
   *
   * @return  The string representation of the password for this bind request,
   *          or {@code null} if an existing Kerberos session should be used.
   */
  @Nullable()
  public String getPasswordString()
  {
    if (password == null)
    {
      return null;
    }
    else
    {
      return password.stringValue();
    }
  }



  /**
   * Retrieves the bytes that comprise the the password for this bind request,
   * if defined.
   *
   * @return  The bytes that comprise the password for this bind request, or
   *          {@code null} if an existing Kerberos session should be used.
   */
  @Nullable()
  public byte[] getPasswordBytes()
  {
    if (password == null)
    {
      return null;
    }
    else
    {
      return password.getValue();
    }
  }



  /**
   * Retrieves the realm for this bind request, if any.
   *
   * @return  The realm for this bind request, or {@code null} if none was
   *          defined and the client should attempt to determine the realm from
   *          the system configuration.
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
   * Retrieves the address of the Kerberos key distribution center.
   *
   * @return  The address of the Kerberos key distribution center, or
   *          {@code null} if none was defined and the client should attempt to
   *          determine the KDC address from the system configuration.
   */
  @Nullable()
  public String getKDCAddress()
  {
    return kdcAddress;
  }



  /**
   * Retrieves the path to the JAAS configuration file that will be used during
   * authentication processing.
   *
   * @return  The path to the JAAS configuration file that will be used during
   *          authentication processing.
   */
  @Nullable()
  public String getConfigFilePath()
  {
    return configFilePath;
  }



  /**
   * Retrieves the protocol specified in the service principal that the
   * directory server uses for its communication with the KDC.
   *
   * @return  The protocol specified in the service principal that the directory
   *          server uses for its communication with the KDC.
   */
  @NotNull()
  public String getServicePrincipalProtocol()
  {
    return servicePrincipalProtocol;
  }



  /**
   * Indicates whether to refresh the configuration before the JAAS
   * {@code login} method is called.
   *
   * @return  {@code true} if the GSSAPI implementation should refresh the
   *          configuration before the JAAS {@code login} method is called, or
   *          {@code false} if not.
   */
  public boolean refreshKrb5Config()
  {
    return refreshKrb5Config;
  }



  /**
   * Indicates whether to use a keytab to obtain the user credentials.
   *
   * @return  {@code true} if the GSSAPI login attempt should use a keytab to
   *          obtain the user credentials, or {@code false} if not.
   */
  public boolean useKeyTab()
  {
    return useKeyTab;
  }



  /**
   * Retrieves the path to the keytab file from which to obtain the user
   * credentials.  This will only be used if {@link #useKeyTab} returns
   * {@code true}.
   *
   * @return  The path to the keytab file from which to obtain the user
   *          credentials, or {@code null} if the default keytab location should
   *          be used.
   */
  @Nullable()
  public String getKeyTabPath()
  {
    return keyTabPath;
  }



  /**
   * Indicates whether to enable the use of a ticket cache to to avoid the need
   * to supply credentials if the client already has an existing Kerberos
   * session.
   *
   * @return  {@code true} if a ticket cache may be used to take advantage of an
   *          existing Kerberos session, or {@code false} if Kerberos
   *          credentials should always be provided.
   */
  public boolean useTicketCache()
  {
    return useTicketCache;
  }



  /**
   * Indicates whether GSSAPI authentication should only occur using an existing
   * Kerberos session.
   *
   * @return  {@code true} if GSSAPI authentication should only use an existing
   *          Kerberos session and should fail if the client does not have an
   *          existing session, or {@code false} if the client will be allowed
   *          to create a new session if one does not already exist.
   */
  public boolean requireCachedCredentials()
  {
    return requireCachedCredentials;
  }



  /**
   * Retrieves the path to the Kerberos ticket cache file that should be used
   * during authentication, if defined.
   *
   * @return  The path to the Kerberos ticket cache file that should be used
   *          during authentication, or {@code null} if the default ticket cache
   *          file should be used.
   */
  @Nullable()
  public String getTicketCachePath()
  {
    return ticketCachePath;
  }



  /**
   * Indicates whether to attempt to renew the client's ticket-granting ticket
   * (TGT) if an existing Kerberos session is used to authenticate.
   *
   * @return  {@code true} if the client should attempt to renew its
   *          ticket-granting ticket if the authentication is processed using an
   *          existing Kerberos session, or {@code false} if not.
   */
  public boolean renewTGT()
  {
    return renewTGT;
  }



  /**
   * Indicates whether to allow the client to use credentials that are outside
   * of the current subject, obtained via some system-specific mechanism.
   *
   * @return  {@code true} if the client will only be allowed to use credentials
   *          that are within the current subject, or {@code false} if the
   *          client will be allowed to use credentials outside the current
   *          subject.
   */
  public boolean useSubjectCredentialsOnly()
  {
    return useSubjectCredentialsOnly;
  }



  /**
   * Indicates whether the client should be configured so that it explicitly
   * indicates whether it is the initiator or the acceptor.
   *
   * @return  {@code Boolean.TRUE} if the client should explicitly indicate that
   *          it is the GSSAPI initiator, {@code Boolean.FALSE} if the client
   *          should explicitly indicate that it is the GSSAPI acceptor, or
   *          {@code null} if the client should not explicitly indicate either
   *          state (which is the default behavior unless the
   *          {@link GSSAPIBindRequestProperties#setIsInitiator}  method has
   *          been used to explicitly specify a value).
   */
  @Nullable()
  public Boolean getIsInitiator()
  {
    return isInitiator;
  }



  /**
   * Retrieves a set of system properties that will not be altered by GSSAPI
   * processing.
   *
   * @return  A set of system properties that will not be altered by GSSAPI
   *          processing.
   */
  @NotNull()
  public Set<String> getSuppressedSystemProperties()
  {
    return suppressedSystemProperties;
  }



  /**
   * Indicates whether JVM-level debugging should be enabled for GSSAPI bind
   * processing.
   *
   * @return  {@code true} if JVM-level debugging should be enabled for GSSAPI
   *          bind processing, or {@code false} if not.
   */
  public boolean enableGSSAPIDebugging()
  {
    return enableGSSAPIDebugging;
  }



  /**
   * Retrieves the path to the default JAAS configuration file that will be used
   * if no file was explicitly provided.  A new file may be created if
   * necessary.
   *
   * @param  properties  The GSSAPI properties that should be used for
   *                     authentication.
   *
   * @return  The path to the default JAAS configuration file that will be used
   *          if no file was explicitly provided.
   *
   * @throws  LDAPException  If an error occurs while attempting to create the
   *                         configuration file.
   */
  @NotNull()
  private static String getConfigFilePath(
               @NotNull final GSSAPIBindRequestProperties properties)
          throws LDAPException
  {
    try
    {
      final File f =
           File.createTempFile("GSSAPIBindRequest-JAAS-Config-", ".conf");
      f.deleteOnExit();
      final PrintWriter w = new PrintWriter(new FileWriter(f));

      try
      {
        // The JAAS configuration file may vary based on the JVM that we're
        // using. For Sun-based JVMs, the module will be
        // "com.sun.security.auth.module.Krb5LoginModule".
        try
        {
          final Class<?> sunModuleClass =
               Class.forName("com.sun.security.auth.module.Krb5LoginModule");
          if (sunModuleClass != null)
          {
            writeSunJAASConfig(w, properties);
            return f.getAbsolutePath();
          }
        }
        catch (final ClassNotFoundException cnfe)
        {
          // This is fine.
          Debug.debugException(cnfe);
        }


        // For the IBM JVMs, the module will be
        // "com.ibm.security.auth.module.Krb5LoginModule".
        try
        {
          final Class<?> ibmModuleClass =
               Class.forName("com.ibm.security.auth.module.Krb5LoginModule");
          if (ibmModuleClass != null)
          {
            writeIBMJAASConfig(w, properties);
            return f.getAbsolutePath();
          }
        }
        catch (final ClassNotFoundException cnfe)
        {
          // This is fine.
          Debug.debugException(cnfe);
        }


        // If we've gotten here, then we can't generate an appropriate
        // configuration.
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_GSSAPI_CANNOT_CREATE_JAAS_CONFIG.get(
                  ERR_GSSAPI_NO_SUPPORTED_JAAS_MODULE.get()));
      }
      finally
      {
        w.close();
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_GSSAPI_CANNOT_CREATE_JAAS_CONFIG.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Writes a JAAS configuration file in a form appropriate for Sun VMs.
   *
   * @param  w  The writer to use to create the config file.
   * @param  p  The properties to use for GSSAPI authentication.
   */
  private static void writeSunJAASConfig(@NotNull final PrintWriter w,
                          @NotNull final GSSAPIBindRequestProperties p)
  {
    w.println(p.getJAASClientName() + " {");
    w.println("  com.sun.security.auth.module.Krb5LoginModule required");
    w.println("  client=true");

    if (p.getIsInitiator() != null)
    {
      w.println("  isInitiator=" + p.getIsInitiator());
    }

    if (p.refreshKrb5Config())
    {
      w.println("  refreshKrb5Config=true");
    }

    if (p.useKeyTab())
    {
      w.println("  useKeyTab=true");
      if (p.getKeyTabPath() != null)
      {
        w.println("  keyTab=\"" + p.getKeyTabPath() + '"');
      }
    }

    if (p.useTicketCache())
    {
      w.println("  useTicketCache=true");
      w.println("  renewTGT=" + p.renewTGT());
      w.println("  doNotPrompt=" + p.requireCachedCredentials());

      final String ticketCachePath = p.getTicketCachePath();
      if (ticketCachePath != null)
      {
        w.println("  ticketCache=\"" + ticketCachePath + '"');
      }
    }
    else
    {
      w.println("  useTicketCache=false");
    }

    if (p.enableGSSAPIDebugging())
    {
      w.println(" debug=true");
    }

    w.println("  ;");
    w.println("};");
  }



  /**
   * Writes a JAAS configuration file in a form appropriate for IBM VMs.
   *
   * @param  w  The writer to use to create the config file.
   * @param  p  The properties to use for GSSAPI authentication.
   */
  private static void writeIBMJAASConfig(@NotNull final PrintWriter w,
                           @NotNull final GSSAPIBindRequestProperties p)
  {
    // NOTE:  It does not appear that the IBM GSSAPI implementation has any
    // analog for the renewTGT property, so it will be ignored.
    w.println(p.getJAASClientName() + " {");
    w.println("  com.ibm.security.auth.module.Krb5LoginModule required");
    if ((p.getIsInitiator() == null) || p.getIsInitiator().booleanValue())
    {
      w.println("  credsType=initiator");
    }
    else
    {
      w.println("  credsType=acceptor");
    }

    if (p.refreshKrb5Config())
    {
      w.println("  refreshKrb5Config=true");
    }

    if (p.useKeyTab())
    {
      w.println("  useKeyTab=true");
      if (p.getKeyTabPath() != null)
      {
        w.println("  keyTab=\"" + p.getKeyTabPath() + '"');
      }
    }

    if (p.useTicketCache())
    {
      final String ticketCachePath = p.getTicketCachePath();
      if (ticketCachePath == null)
      {
        if (p.requireCachedCredentials())
        {
          w.println("  useDefaultCcache=true");
        }
      }
      else
      {
        final File f = new File(ticketCachePath);
        final String path = f.getAbsolutePath().replace('\\', '/');
        w.println("  useCcache=\"file://" + path + '"');
      }
    }
    else
    {
      w.println("  useDefaultCcache=false");
    }

    if (p.enableGSSAPIDebugging())
    {
      w.println(" debug=true");
    }

    w.println("  ;");
    w.println("};");
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
    if (! conn.compareAndSet(null, connection))
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
                     ERR_GSSAPI_MULTIPLE_CONCURRENT_REQUESTS.get());
    }

    setProperty(PROPERTY_CONFIG_FILE, configFilePath);
    setProperty(PROPERTY_SUBJECT_CREDS_ONLY,
         String.valueOf(useSubjectCredentialsOnly));
    if (Debug.debugEnabled(DebugType.LDAP))
    {
      Debug.debug(Level.CONFIG, DebugType.LDAP,
           "Using config file property " + PROPERTY_CONFIG_FILE + " = '" +
                configFilePath + "'.");
      Debug.debug(Level.CONFIG, DebugType.LDAP,
           "Using subject creds only property " + PROPERTY_SUBJECT_CREDS_ONLY +
                " = '" + useSubjectCredentialsOnly + "'.");
    }

    if (kdcAddress == null)
    {
      if (DEFAULT_KDC_ADDRESS == null)
      {
        clearProperty(PROPERTY_KDC_ADDRESS);
        if (Debug.debugEnabled(DebugType.LDAP))
        {
          Debug.debug(Level.CONFIG, DebugType.LDAP,
               "Clearing kdcAddress property '" + PROPERTY_KDC_ADDRESS + "'.");
        }
      }
      else
      {
        setProperty(PROPERTY_KDC_ADDRESS, DEFAULT_KDC_ADDRESS);
        if (Debug.debugEnabled(DebugType.LDAP))
        {
          Debug.debug(Level.CONFIG, DebugType.LDAP,
               "Using default kdcAddress property " + PROPERTY_KDC_ADDRESS +
                    " = '" + DEFAULT_KDC_ADDRESS + "'.");
        }
      }
    }
    else
    {
      setProperty(PROPERTY_KDC_ADDRESS, kdcAddress);
      if (Debug.debugEnabled(DebugType.LDAP))
      {
        Debug.debug(Level.CONFIG, DebugType.LDAP,
             "Using kdcAddress property " + PROPERTY_KDC_ADDRESS + " = '" +
                  kdcAddress + "'.");
      }
    }

    if (realm == null)
    {
      if (DEFAULT_REALM == null)
      {
        clearProperty(PROPERTY_REALM);
        if (Debug.debugEnabled(DebugType.LDAP))
        {
          Debug.debug(Level.CONFIG, DebugType.LDAP,
               "Clearing realm property '" + PROPERTY_REALM + "'.");
        }
      }
      else
      {
        setProperty(PROPERTY_REALM, DEFAULT_REALM);
        if (Debug.debugEnabled(DebugType.LDAP))
        {
          Debug.debug(Level.CONFIG, DebugType.LDAP,
               "Using default realm property " + PROPERTY_REALM + " = '" +
                    DEFAULT_REALM + "'.");
        }
      }
    }
    else
    {
      setProperty(PROPERTY_REALM, realm);
      if (Debug.debugEnabled(DebugType.LDAP))
      {
        Debug.debug(Level.CONFIG, DebugType.LDAP,
             "Using realm property " + PROPERTY_REALM + " = '" + realm + "'.");
      }
    }

    try
    {
      // Reload the configuration before creating the login context, which may
      // work around problems that could arise if certain configuration is
      // loaded and cached before the above system properties were set.
      Configuration.getConfiguration().refresh();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      final LoginContext context;
      try
      {
        context = new LoginContext(jaasClientName, this);
        context.login();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_GSSAPI_CANNOT_INITIALIZE_JAAS_CONTEXT.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      try
      {
        return (BindResult) Subject.doAs(context.getSubject(), this);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        if (e instanceof LDAPException)
        {
          throw (LDAPException) e;
        }
        else
        {
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_GSSAPI_AUTHENTICATION_FAILED.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }
    finally
    {
      conn.set(null);
    }
  }



  /**
   * Perform the privileged portion of the authentication processing.
   *
   * @return  {@code null}, since no return value is actually needed.
   *
   * @throws  LDAPException  If a problem occurs during processing.
   */
  @InternalUseOnly()
  @Override()
  @NotNull()
  public Object run()
         throws LDAPException
  {
    unhandledCallbackMessages.clear();

    final LDAPConnection connection = conn.get();


    final HashMap<String,Object> saslProperties =
         new HashMap<>(StaticUtils.computeMapCapacity(2));
    saslProperties.put(Sasl.QOP, SASLQualityOfProtection.toString(allowedQoP));
    saslProperties.put(Sasl.SERVER_AUTH, "true");

    final SaslClient saslClient;
    try
    {
      String serverName = saslClientServerName;
      if (serverName == null)
      {
        serverName = connection.getConnectedAddress();
      }

      final String[] mechanisms = { GSSAPI_MECHANISM_NAME };
      saslClient = Sasl.createSaslClient(mechanisms, authorizationID,
           servicePrincipalProtocol, serverName, saslProperties, this);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_GSSAPI_CANNOT_CREATE_SASL_CLIENT.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final SASLClientBindHandler bindHandler = new SASLClientBindHandler(this,
         connection, GSSAPI_MECHANISM_NAME, saslClient, getControls(),
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
  public GSSAPIBindRequest getRebindRequest(@NotNull final String host,
                                            final int port)
  {
    try
    {
      final GSSAPIBindRequestProperties gssapiProperties =
           new GSSAPIBindRequestProperties(authenticationID, authorizationID,
                password, realm, kdcAddress, configFilePath);
      gssapiProperties.setAllowedQoP(allowedQoP);
      gssapiProperties.setServicePrincipalProtocol(servicePrincipalProtocol);
      gssapiProperties.setUseTicketCache(useTicketCache);
      gssapiProperties.setRequireCachedCredentials(requireCachedCredentials);
      gssapiProperties.setRenewTGT(renewTGT);
      gssapiProperties.setUseSubjectCredentialsOnly(useSubjectCredentialsOnly);
      gssapiProperties.setTicketCachePath(ticketCachePath);
      gssapiProperties.setEnableGSSAPIDebugging(enableGSSAPIDebugging);
      gssapiProperties.setJAASClientName(jaasClientName);
      gssapiProperties.setSASLClientServerName(saslClientServerName);
      gssapiProperties.setSuppressedSystemProperties(
           suppressedSystemProperties);

      return new GSSAPIBindRequest(gssapiProperties, getControls());
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Handles any necessary callbacks required for SASL authentication.
   *
   * @param  callbacks  The set of callbacks to be handled.
   *
   * @throws  UnsupportedCallbackException  If an unsupported type of callback
   *                                        was received.
   */
  @InternalUseOnly()
  @Override()
  public void handle(@NotNull final Callback[] callbacks)
         throws UnsupportedCallbackException
  {
    for (final Callback callback : callbacks)
    {
      if (callback instanceof NameCallback)
      {
        ((NameCallback) callback).setName(authenticationID);
      }
      else if (callback instanceof PasswordCallback)
      {
        if (password == null)
        {
          throw new UnsupportedCallbackException(callback,
               ERR_GSSAPI_NO_PASSWORD_AVAILABLE.get());
        }
        else
        {
          ((PasswordCallback) callback).setPassword(
               password.stringValue().toCharArray());
        }
      }
      else if (callback instanceof RealmCallback)
      {
        final RealmCallback rc = (RealmCallback) callback;
        if (realm == null)
        {
          unhandledCallbackMessages.add(
               ERR_GSSAPI_REALM_REQUIRED_BUT_NONE_PROVIDED.get(rc.getPrompt()));
        }
        else
        {
          rc.setText(realm);
        }
      }
      else
      {
        // This is an unexpected callback.
        if (Debug.debugEnabled(DebugType.LDAP))
        {
          Debug.debug(Level.WARNING, DebugType.LDAP,
                "Unexpected GSSAPI SASL callback of type " +
                callback.getClass().getName());
        }

        unhandledCallbackMessages.add(ERR_GSSAPI_UNEXPECTED_CALLBACK.get(
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
  public GSSAPIBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GSSAPIBindRequest duplicate(@Nullable final Control[] controls)
  {
    try
    {
      final GSSAPIBindRequestProperties gssapiProperties =
           new GSSAPIBindRequestProperties(authenticationID, authorizationID,
                password, realm, kdcAddress, configFilePath);
      gssapiProperties.setAllowedQoP(allowedQoP);
      gssapiProperties.setServicePrincipalProtocol(servicePrincipalProtocol);
      gssapiProperties.setUseTicketCache(useTicketCache);
      gssapiProperties.setRequireCachedCredentials(requireCachedCredentials);
      gssapiProperties.setRenewTGT(renewTGT);
      gssapiProperties.setRefreshKrb5Config(refreshKrb5Config);
      gssapiProperties.setUseKeyTab(useKeyTab);
      gssapiProperties.setKeyTabPath(keyTabPath);
      gssapiProperties.setUseSubjectCredentialsOnly(useSubjectCredentialsOnly);
      gssapiProperties.setTicketCachePath(ticketCachePath);
      gssapiProperties.setEnableGSSAPIDebugging(enableGSSAPIDebugging);
      gssapiProperties.setJAASClientName(jaasClientName);
      gssapiProperties.setSASLClientServerName(saslClientServerName);
      gssapiProperties.setIsInitiator(isInitiator);
      gssapiProperties.setSuppressedSystemProperties(
           suppressedSystemProperties);

      final GSSAPIBindRequest bindRequest =
           new GSSAPIBindRequest(gssapiProperties, controls);
      bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
      return bindRequest;
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Clears the specified system property, unless it is one that is configured
   * to be suppressed.
   *
   * @param  name  The name of the property to be suppressed.
   */
  private void clearProperty(@NotNull final String name)
  {
    if (! suppressedSystemProperties.contains(name))
    {
      StaticUtils.clearSystemProperty(name);
    }
  }



  /**
   * Sets the specified system property, unless it is one that is configured to
   * be suppressed.
   *
   * @param  name   The name of the property to be suppressed.
   * @param  value  The value of the property to be suppressed.
   */
  private void setProperty(@NotNull final String name,
                           @NotNull final String value)
  {
    if (! suppressedSystemProperties.contains(name))
    {
      StaticUtils.setSystemProperty(name, value);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GSSAPIBindRequest(authenticationID='");
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

    if (kdcAddress != null)
    {
      buffer.append(", kdcAddress='");
      buffer.append(kdcAddress);
      buffer.append('\'');
    }

    if (isInitiator != null)
    {
      buffer.append(", isInitiator=");
      buffer.append(isInitiator);
    }

    buffer.append(", jaasClientName='");
    buffer.append(jaasClientName);
    buffer.append("', configFilePath='");
    buffer.append(configFilePath);
    buffer.append("', servicePrincipalProtocol='");
    buffer.append(servicePrincipalProtocol);
    buffer.append("', enableGSSAPIDebugging=");
    buffer.append(enableGSSAPIDebugging);

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
         "GSSAPIBindRequestProperties", requestID + "RequestProperties",
         "new GSSAPIBindRequestProperties",
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

    if (kdcAddress != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setKDCAddress",
           ToCodeArgHelper.createString(kdcAddress, null));
    }

    if (jaasClientName != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setJAASClientName",
           ToCodeArgHelper.createString(jaasClientName, null));
    }

    if (configFilePath != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setConfigFilePath",
           ToCodeArgHelper.createString(configFilePath, null));
    }

    if (saslClientServerName != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setSASLClientServerName",
           ToCodeArgHelper.createString(saslClientServerName, null));
    }

    if (servicePrincipalProtocol != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setServicePrincipalProtocol",
           ToCodeArgHelper.createString(servicePrincipalProtocol, null));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setRefreshKrb5Config",
         ToCodeArgHelper.createBoolean(refreshKrb5Config, null));

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setUseKeyTab",
         ToCodeArgHelper.createBoolean(useKeyTab, null));

    if (keyTabPath != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setKeyTabPath",
           ToCodeArgHelper.createString(keyTabPath, null));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setUseSubjectCredentialsOnly",
         ToCodeArgHelper.createBoolean(useSubjectCredentialsOnly, null));

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setUseTicketCache",
         ToCodeArgHelper.createBoolean(useTicketCache, null));

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setRequireCachedCredentials",
         ToCodeArgHelper.createBoolean(requireCachedCredentials, null));

    if (ticketCachePath != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setTicketCachePath",
           ToCodeArgHelper.createString(ticketCachePath, null));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setRenewTGT",
         ToCodeArgHelper.createBoolean(renewTGT, null));

    if (isInitiator != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setIsInitiator",
           ToCodeArgHelper.createBoolean(isInitiator, null));
    }

    if ((suppressedSystemProperties != null) &&
        (! suppressedSystemProperties.isEmpty()))
    {
      final ArrayList<ToCodeArgHelper> suppressedArgs =
           new ArrayList<>(suppressedSystemProperties.size());
      for (final String s : suppressedSystemProperties)
      {
        suppressedArgs.add(ToCodeArgHelper.createString(s, null));
      }

      ToCodeHelper.generateMethodCall(lineList, indentSpaces, "List<String>",
           requestID + "SuppressedProperties", "Arrays.asList", suppressedArgs);

      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setSuppressedSystemProperties",
           ToCodeArgHelper.createRaw(requestID + "SuppressedProperties", null));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
         requestID + "RequestProperties.setEnableGSSAPIDebugging",
         ToCodeArgHelper.createBoolean(enableGSSAPIDebugging, null));


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

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "GSSAPIBindRequest",
         requestID + "Request", "new GSSAPIBindRequest", constructorArgs);


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
