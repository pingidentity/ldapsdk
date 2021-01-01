/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure that may be used to hold a number of
 * properties that may be used during processing for a SASL GSSAPI bind
 * operation.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class GSSAPIBindRequestProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6872295509330315713L;



  // The password for the GSSAPI bind request.
  @Nullable private ASN1OctetString password;

  // Indicates whether to enable JVM-level debugging for GSSAPI processing.
  private boolean enableGSSAPIDebugging;

  // Indicates whether the client should be considered the GSSAPI initiator or
  // the acceptor.
  @Nullable private Boolean isInitiator;

  // Indicates whether to attempt to refresh the configuration before the JAAS
  // login method is called.
  private boolean refreshKrb5Config;

  // Indicates whether to attempt to renew the client's existing ticket-granting
  // ticket if authentication uses an existing Kerberos session.
  private boolean renewTGT;

  // Indicates whether to require that the credentials be obtained from the
  // ticket cache such that authentication will fail if the client does not have
  // an existing Kerberos session.
  private boolean requireCachedCredentials;

  // Indicates whether to allow the to obtain the credentials to be obtained
  // from a keytab.
  private boolean useKeyTab;

  // Indicates whether to allow the client to use credentials that are outside
  // of the current subject.
  private boolean useSubjectCredentialsOnly;

  // Indicates whether to enable the use of a ticket cache.
  private boolean useTicketCache;

  // The SASL quality of protection value(s) allowed for the DIGEST-MD5 bind
  // request.
  @NotNull private List<SASLQualityOfProtection> allowedQoP;

  // The names of any system properties that should not be altered by GSSAPI
  // processing.
  @NotNull private Set<String> suppressedSystemProperties;

  // The authentication ID string for the GSSAPI bind request.
  @Nullable private String authenticationID;

  // The authorization ID string for the GSSAPI bind request, if available.
  @Nullable private String authorizationID;

  // The path to the JAAS configuration file to use for bind processing.
  @Nullable private String configFilePath;

  // The name that will be used to identify this client in the JAAS framework.
  @NotNull private String jaasClientName;

  // The KDC address for the GSSAPI bind request, if available.
  @Nullable private String kdcAddress;

  // The path to the keytab file to use if useKeyTab is true.
  @Nullable private String keyTabPath;

  // The realm for the GSSAPI bind request, if available.
  @Nullable private String realm;

  // The server name to use when creating the SASL client.
  @Nullable private String saslClientServerName;

  // The protocol that should be used in the Kerberos service principal for
  // the server system.
  @NotNull private String servicePrincipalProtocol;

  // The path to the Kerberos ticket cache to use.
  @Nullable private String ticketCachePath;



  /**
   * Creates a new set of GSSAPI bind request properties with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It may be {@code null} if an existing
   *                           Kerberos session should be used.
   * @param  password          The password for the GSSAPI bind request.  It may
   *                           be {@code null} if an existing Kerberos session
   *                           should be used.
   */
  public GSSAPIBindRequestProperties(@Nullable final String authenticationID,
                                     @Nullable final String password)
  {
    this(authenticationID, null,
         (password == null ? null : new ASN1OctetString(password)), null, null,
         null);
  }



  /**
   * Creates a new set of GSSAPI bind request properties with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It may be {@code null} if an existing
   *                           Kerberos session should be used.
   * @param  password          The password for the GSSAPI bind request.  It may
   *                           be {@code null} if an existing Kerberos session
   *                           should be used.
   */
  public GSSAPIBindRequestProperties(@Nullable final String authenticationID,
                                     @Nullable final byte[] password)
  {
    this(authenticationID, null,
         (password == null ? null : new ASN1OctetString(password)), null, null,
         null);
  }



  /**
   * Creates a new set of GSSAPI bind request properties with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It may be {@code null} if an existing
   *                           Kerberos session should be used.
   * @param  authorizationID   The authorization ID for the GSSAPI bind request.
   *                           It may be {@code null} if the authorization ID
   *                           should be the same as the authentication ID.
   * @param  password          The password for the GSSAPI bind request.  It may
   *                           be {@code null} if an existing Kerberos session
   *                           should be used.
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
   */
  GSSAPIBindRequestProperties(@Nullable final String authenticationID,
                              @Nullable final String authorizationID,
                              @Nullable final ASN1OctetString password,
                              @Nullable final String realm,
                              @Nullable final String kdcAddress,
                              @Nullable final String configFilePath)
  {
    this.authenticationID = authenticationID;
    this.authorizationID  = authorizationID;
    this.password         = password;
    this.realm            = realm;
    this.kdcAddress       = kdcAddress;
    this.configFilePath   = configFilePath;

    servicePrincipalProtocol   = "ldap";
    enableGSSAPIDebugging      = false;
    jaasClientName             = "GSSAPIBindRequest";
    isInitiator                = null;
    refreshKrb5Config          = false;
    renewTGT                   = false;
    useKeyTab                  = false;
    useSubjectCredentialsOnly  = true;
    useTicketCache             = true;
    requireCachedCredentials   = false;
    saslClientServerName       = null;
    keyTabPath                 = null;
    ticketCachePath            = null;
    suppressedSystemProperties = Collections.emptySet();
    allowedQoP                 =
         Collections.singletonList(SASLQualityOfProtection.AUTH);
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
   * Sets the authentication ID for the GSSAPI bind request.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It may be {@code null} if an existing
   *                           Kerberos session should be used.
   */
  public void setAuthenticationID(@Nullable final String authenticationID)
  {
    this.authenticationID = authenticationID;
  }



  /**
   * Retrieves the authorization ID for the GSSAPI bind request, if defined.
   *
   * @return  The authorizationID for the GSSAPI bind request, or {@code null}
   *          if the authorization ID should be the same as the authentication
   *          ID.
   */
  @Nullable()
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * Specifies the authorization ID for the GSSAPI bind request.
   *
   * @param  authorizationID  The authorization ID for the GSSAPI bind request.
   *                          It may be {@code null} if the authorization ID
   *                          should be the same as the authentication ID.
   */
  public void setAuthorizationID(@Nullable final String authorizationID)
  {
    this.authorizationID = authorizationID;
  }



  /**
   * Retrieves the password that should be used for the GSSAPI bind request, if
   * defined.
   *
   * @return  The password that should be used for the GSSAPI bind request, or
   *          {@code null} if an existing Kerberos session should be used.
   */
  @Nullable()
  public ASN1OctetString getPassword()
  {
    return password;
  }



  /**
   * Specifies the password that should be used for the GSSAPI bind request.
   *
   * @param  password  The password that should be used for the GSSAPI bind
   *                   request.  It may be {@code null} if an existing
   *                   Kerberos session should be used.
   */
  public void setPassword(@Nullable final String password)
  {
    if (password == null)
    {
      this.password = null;
    }
    else
    {
      this.password = new ASN1OctetString(password);
    }
  }



  /**
   * Specifies the password that should be used for the GSSAPI bind request.
   *
   * @param  password  The password that should be used for the GSSAPI bind
   *                   request.  It may be {@code null} if an existing
   *                   Kerberos session should be used.
   */
  public void setPassword(@Nullable final byte[] password)
  {
    if (password == null)
    {
      this.password = null;
    }
    else
    {
      this.password = new ASN1OctetString(password);
    }
  }



  /**
   * Specifies the password that should be used for the GSSAPI bind request.
   *
   * @param  password  The password that should be used for the GSSAPI bind
   *                   request.  It may be {@code null} if an existing
   *                   Kerberos session should be used.
   */
  public void setPassword(@Nullable final ASN1OctetString password)
  {
    this.password = password;
  }



  /**
   * Retrieves the realm to use for the GSSAPI bind request, if defined.
   *
   * @return  The realm to use for the GSSAPI bind request, or {@code null} if
   *          the request should attempt to use the default realm from the
   *          system configuration.
   */
  @Nullable()
  public String getRealm()
  {
    return realm;
  }



  /**
   * Specifies the realm to use for the GSSAPI bind request.
   *
   * @param  realm  The realm to use for the GSSAPI bind request.  It may be
   *                {@code null} if the request should attempt to use the
   *                default realm from the system configuration.
   */
  public void setRealm(@Nullable final String realm)
  {
    this.realm = realm;
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
   * Specifies the list of allowed qualities of protection that may be used for
   * communication that occurs on the connection after the authentication has
   * completed, in order from most preferred to least preferred.
   *
   * @param  allowedQoP  The list of allowed qualities of protection that may be
   *                     used for communication that occurs on the connection
   *                     after the authentication has completed, in order from
   *                     most preferred to least preferred.  If this is
   *                     {@code null} or empty, then a list containing only the
   *                     {@link SASLQualityOfProtection#AUTH} quality of
   *                     protection value will be used.
   */
  public void setAllowedQoP(
                   @Nullable final List<SASLQualityOfProtection> allowedQoP)
  {
    if ((allowedQoP == null) || allowedQoP.isEmpty())
    {
      this.allowedQoP = Collections.singletonList(SASLQualityOfProtection.AUTH);
    }
    else
    {
      this.allowedQoP =
           Collections.unmodifiableList(new ArrayList<>(allowedQoP));
    }
  }



  /**
   * Specifies the list of allowed qualities of protection that may be used for
   * communication that occurs on the connection after the authentication has
   * completed, in order from most preferred to least preferred.
   *
   * @param  allowedQoP  The list of allowed qualities of protection that may be
   *                     used for communication that occurs on the connection
   *                     after the authentication has completed, in order from
   *                     most preferred to least preferred.  If this is
   *                     {@code null} or empty, then a list containing only the
   *                     {@link SASLQualityOfProtection#AUTH} quality of
   *                     protection value will be used.
   */
  public void setAllowedQoP(
                   @Nullable final SASLQualityOfProtection... allowedQoP)
  {
    setAllowedQoP(StaticUtils.toList(allowedQoP));
  }



  /**
   * Retrieves the address to use for the Kerberos key distribution center,
   * if defined.
   *
   * @return  The address to use for the Kerberos key distribution center, or
   *          {@code null} if request should attempt to determine the KDC
   *          address from the system configuration.
   */
  @Nullable()
  public String getKDCAddress()
  {
    return kdcAddress;
  }



  /**
   * Specifies the address to use for the Kerberos key distribution center.
   *
   * @param  kdcAddress  The address to use for the Kerberos key distribution
   *                     center.  It may be {@code null} if the request should
   *                     attempt to determine the KDC address from the system
   *                     configuration.
   */
  public void setKDCAddress(@Nullable final String kdcAddress)
  {
    this.kdcAddress = kdcAddress;
  }



  /**
   * Retrieves the name that will be used to identify this client in the JAAS
   * framework.
   *
   * @return  The name that will be used to identify this client in the JAAS
   *          framework.
   */
  @NotNull()
  public String getJAASClientName()
  {
    return jaasClientName;
  }



  /**
   * Specifies the name that will be used to identify this client in the JAAS
   * framework.
   *
   * @param  jaasClientName  The name that will be used to identify this client
   *                         in the JAAS framework.  It must not be
   *                         {@code null} or empty.
   */
  public void setJAASClientName(@NotNull final String jaasClientName)
  {
    Validator.ensureNotNull(jaasClientName);

    this.jaasClientName = jaasClientName;
  }



  /**
   * Retrieves the path to a JAAS configuration file that should be used when
   * processing the GSSAPI bind request, if defined.
   *
   * @return  The path to a JAAS configuration file that should be used when
   *          processing the GSSAPI bind request, or {@code null} if a JAAS
   *          configuration file should be automatically constructed for the
   *          bind request.
   */
  @Nullable()
  public String getConfigFilePath()
  {
    return configFilePath;
  }



  /**
   * Specifies the path to a JAAS configuration file that should be used when
   * processing the GSSAPI bind request.
   *
   * @param  configFilePath  The path to a JAAS configuration file that should
   *                         be used when processing the GSSAPI bind request.
   *                         It may be {@code null} if a configuration file
   *                         should be automatically constructed for the bind
   *                         request.
   */
  public void setConfigFilePath(@Nullable final String configFilePath)
  {
    this.configFilePath = configFilePath;
  }



  /**
   * Retrieves the server name that should be used when creating the Java
   * {@code SaslClient}, if one is defined.
   *
   * @return  The server name that should be used when creating the Java
   *          {@code SaslClient}, or {@code null} if none is defined and the
   *          {@code SaslClient} should use the address specified when
   *          establishing the connection.
   */
  @Nullable()
  public String getSASLClientServerName()
  {
    return saslClientServerName;
  }



  /**
   * Specifies the server name that should be used when creating the Java
   * {@code SaslClient}.
   *
   * @param  saslClientServerName  The server name that should be used when
   *                               creating the Java {@code SaslClient}.  It may
   *                               be {@code null} to indicate that the
   *                               {@code SaslClient} should use the address
   *                               specified when establishing the connection.
   */
  public void setSASLClientServerName(
                   @Nullable final String saslClientServerName)
  {
    this.saslClientServerName = saslClientServerName;
  }



  /**
   * Retrieves the protocol specified in the service principal that the
   * directory server uses for its communication with the KDC.  The service
   * principal is usually something like "ldap/directory.example.com", where
   * "ldap" is the protocol and "directory.example.com" is the fully-qualified
   * address of the directory server system, but some servers may allow
   * authentication with a service principal with a protocol other than "ldap".
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
   * Specifies the protocol specified in the service principal that the
   * directory server uses for its communication with the KDC.  This should
   * generally be "ldap", but some servers may allow a service principal with a
   * protocol other than "ldap".
   *
   * @param  servicePrincipalProtocol  The protocol specified in the service
   *                                   principal that the directory server uses
   *                                   for its communication with the KDC.
   */
  public void setServicePrincipalProtocol(
                   @NotNull final String servicePrincipalProtocol)
  {
    Validator.ensureNotNull(servicePrincipalProtocol);

    this.servicePrincipalProtocol = servicePrincipalProtocol;
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
   * Specifies whether to refresh the configuration before the JAAS
   * {@code login} method is called.
   *
   * @param  refreshKrb5Config  Indicates whether to refresh the configuration
   *                            before the JAAS {@code login} method is called.
   */
  public void setRefreshKrb5Config(final boolean refreshKrb5Config)
  {
    this.refreshKrb5Config = refreshKrb5Config;
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
   * Specifies whether to allow the client to use credentials that are outside
   * the current subject.  If this is {@code false}, then a system-specific
   * mechanism may be used in an attempt to obtain credentials from an
   * existing session.
   *
   * @param  useSubjectCredentialsOnly  Indicates whether to allow the client to
   *                                    use credentials that are outside of the
   *                                    current subject.
   */
  public void setUseSubjectCredentialsOnly(
                   final boolean useSubjectCredentialsOnly)
  {
    this.useSubjectCredentialsOnly = useSubjectCredentialsOnly;
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
   * Specifies whether to use a keytab to obtain the user credentials.
   *
   * @param  useKeyTab  Indicates whether to use a keytab to obtain the user
   *                    credentials.
   */
  public void setUseKeyTab(final boolean useKeyTab)
  {
    this.useKeyTab = useKeyTab;
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
   * Specifies the path to the keytab file from which to obtain the user
   * credentials.
   *
   * @param  keyTabPath  The path to the keytab file from which to obtain the
   *                     user credentials.  It may be {@code null} if the
   *                     default keytab location should be used.
   */
  public void setKeyTabPath(@Nullable final String keyTabPath)
  {
    this.keyTabPath = keyTabPath;
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
   * Specifies whether to enable the use of a ticket cache to to avoid the need
   * to supply credentials if the client already has an existing Kerberos
   * session.
   *
   * @param  useTicketCache  Indicates whether to enable the use of a ticket
   *                         cache to to avoid the need to supply credentials if
   *                         the client already has an existing Kerberos
   *                         session.
   */
  public void setUseTicketCache(final boolean useTicketCache)
  {
    this.useTicketCache = useTicketCache;
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
   * Specifies whether an GSSAPI authentication should only occur using an
   * existing Kerberos session.
   *
   * @param  requireCachedCredentials  Indicates whether an existing Kerberos
   *                                   session will be required for
   *                                   authentication.  If {@code true}, then
   *                                   authentication will fail if the client
   *                                   does not already have an existing
   *                                   Kerberos session.  This will be ignored
   *                                   if {@code useTicketCache} is false.
   */
  public void setRequireCachedCredentials(
                   final boolean requireCachedCredentials)
  {
    this.requireCachedCredentials = requireCachedCredentials;
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
   * Specifies the path to the Kerberos ticket cache file that should be used
   * during authentication.
   *
   * @param  ticketCachePath  The path to the Kerberos ticket cache file that
   *                          should be used during authentication.  It may be
   *                          {@code null} if the default ticket cache file
   *                          should be used.
   */
  public void setTicketCachePath(@Nullable final String ticketCachePath)
  {
    this.ticketCachePath = ticketCachePath;
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
   * Specifies whether to attempt to renew the client's ticket-granting ticket
   * (TGT) if an existing Kerberos session is used to authenticate.
   *
   * @param  renewTGT  Indicates whether to attempt to renew the client's
   *                   ticket-granting ticket if an existing Kerberos session is
   *                   used to authenticate.
   */
  public void setRenewTGT(final boolean renewTGT)
  {
    this.renewTGT = renewTGT;
  }



  /**
   * Indicates whether the client should be configured so that it explicitly
   * indicates whether it is the initiator or the acceptor.
   *
   * @return  {@code Boolean.TRUE} if the client should explicitly indicate that
   *          it is the GSSAPI initiator, {@code Boolean.FALSE} if the client
   *          should explicitly indicate that it is the GSSAPI acceptor, or
   *          {@code null} if the client should not explicitly indicate either
   *          state (which is the default if the {@link #setIsInitiator}  method
   *          has not been called).
   */
  @Nullable()
  public Boolean getIsInitiator()
  {
    return isInitiator;
  }



  /**
   * Specifies whether the client should explicitly indicate whether it is the
   * GSSAPI initiator or acceptor.
   *
   * @param  isInitiator  Indicates whether the client should be considered the
   *                      GSSAPI initiator.  A value of {@code Boolean.TRUE}
   *                      means the client should explicitly indicate that it is
   *                      the GSSAPI initiator.  A value of
   *                      {@code Boolean.FALSE} means the client should
   *                      explicitly indicate that it is the GSSAPI acceptor.  A
   *                      value of  {@code null} means that the client will not
   *                      explicitly indicate one way or the other (although
   *                      this behavior will only apply to Sun/Oracle-based
   *                      implementations; on the IBM implementation, the client
   *                      will always be the initiator unless explicitly
   *                      configured otherwise).
   */
  public void setIsInitiator(@Nullable final Boolean isInitiator)
  {
    this.isInitiator = isInitiator;
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
   * Specifies a set of system properties that will not be altered by GSSAPI
   * processing.  This should generally only be used in cases in which the
   * specified system properties are known to already be set correctly for the
   * desired authentication processing.
   *
   * @param  suppressedSystemProperties  A set of system properties that will
   *                                     not be altered by GSSAPI processing.
   *                                     It may be {@code null} or empty to
   *                                     indicate that no properties should be
   *                                     suppressed.
   */
  public void setSuppressedSystemProperties(
       @Nullable final Collection<String> suppressedSystemProperties)
  {
    if (suppressedSystemProperties == null)
    {
      this.suppressedSystemProperties = Collections.emptySet();
    }
    else
    {
      this.suppressedSystemProperties = Collections.unmodifiableSet(
           new LinkedHashSet<>(suppressedSystemProperties));
    }
  }



  /**
   * Indicates whether JVM-level debugging should be enabled for GSSAPI bind
   * processing.  If this is enabled, then debug information may be written to
   * standard error when performing GSSAPI processing that could be useful for
   * debugging authentication problems.
   *
   * @return  {@code true} if JVM-level debugging should be enabled for GSSAPI
   *          bind processing, or {@code false} if not.
   */
  public boolean enableGSSAPIDebugging()
  {
    return enableGSSAPIDebugging;
  }



  /**
   * Specifies whether JVM-level debugging should be enabled for GSSAPI bind
   * processing.  If this is enabled, then debug information may be written to
   * standard error when performing GSSAPI processing that could be useful for
   * debugging authentication problems.
   *
   * @param  enableGSSAPIDebugging  Specifies whether JVM-level debugging should
   *                                be enabled for GSSAPI bind processing.
   */
  public void setEnableGSSAPIDebugging(final boolean enableGSSAPIDebugging)
  {
    this.enableGSSAPIDebugging = enableGSSAPIDebugging;
  }



  /**
   * Retrieves a string representation of the GSSAPI bind request properties.
   *
   * @return  A string representation of the GSSAPI bind request properties.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the GSSAPI bind request properties to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GSSAPIBindRequestProperties(");
    if (authenticationID != null)
    {
      buffer.append("authenticationID='");
      buffer.append(authenticationID);
      buffer.append("', ");
    }

    if (authorizationID != null)
    {
      buffer.append("authorizationID='");
      buffer.append(authorizationID);
      buffer.append("', ");
    }

    if (realm != null)
    {
      buffer.append("realm='");
      buffer.append(realm);
      buffer.append("', ");
    }

    buffer.append("qop='");
    buffer.append(SASLQualityOfProtection.toString(allowedQoP));
    buffer.append("', ");

    if (kdcAddress != null)
    {
      buffer.append("kdcAddress='");
      buffer.append(kdcAddress);
      buffer.append("', ");
    }

    buffer.append(", refreshKrb5Config=");
    buffer.append(refreshKrb5Config);
    buffer.append(", useSubjectCredentialsOnly=");
    buffer.append(useSubjectCredentialsOnly);
    buffer.append(", useKeyTab=");
    buffer.append(useKeyTab);
    buffer.append(", ");

    if (keyTabPath != null)
    {
      buffer.append("keyTabPath='");
      buffer.append(keyTabPath);
      buffer.append("', ");
    }

    if (useTicketCache)
    {
      buffer.append("useTicketCache=true, requireCachedCredentials=");
      buffer.append(requireCachedCredentials);
      buffer.append(", renewTGT=");
      buffer.append(renewTGT);
      buffer.append(", ");

      if (ticketCachePath != null)
      {
        buffer.append("ticketCachePath='");
        buffer.append(ticketCachePath);
        buffer.append("', ");
      }
    }
    else
    {
      buffer.append("useTicketCache=false, ");
    }

    if (isInitiator != null)
    {
      buffer.append("isInitiator=");
      buffer.append(isInitiator);
      buffer.append(", ");
    }

    buffer.append("jaasClientName='");
    buffer.append(jaasClientName);
    buffer.append("', ");

    if (configFilePath != null)
    {
      buffer.append("configFilePath='");
      buffer.append(configFilePath);
      buffer.append("', ");
    }

    if (saslClientServerName != null)
    {
      buffer.append("saslClientServerName='");
      buffer.append(saslClientServerName);
      buffer.append("', ");
    }

    buffer.append("servicePrincipalProtocol='");
    buffer.append(servicePrincipalProtocol);
    buffer.append("', suppressedSystemProperties={");

    final Iterator<String> propIterator = suppressedSystemProperties.iterator();
    while (propIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(propIterator.next());
      buffer.append('\'');

      if (propIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, enableGSSAPIDebugging=");
    buffer.append(enableGSSAPIDebugging);
    buffer.append(')');
  }
}
