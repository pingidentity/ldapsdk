/*
 * Copyright 2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011 UnboundID Corp.
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
import com.unboundid.util.Mutable;
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
  private static final long serialVersionUID = -8177334654843710502L;



  // The password for the GSSAPI bind request.
  private ASN1OctetString password;

  // Indicates whether to enable JVM-level debugging for GSSAPI processing.
  private boolean enableGSSAPIDebugging;

  // The authentication ID string for the GSSAPI bind request.
  private String authenticationID;

  // The authorization ID string for the GSSAPI bind request, if available.
  private String authorizationID;

  // The path to the JAAS configuration file to use for bind processing.
  private String configFilePath;

  // The KDC address for the GSSAPI bind request, if available.
  private String kdcAddress;

  // The protocol that should be used in the Kerberos service principal for
  // the server system.
  private String servicePrincipalProtocol;

  // The realm for the GSSAPI bind request, if available.
  private String realm;



  /**
   * Creates a new set of GSSAPI bind request properties with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It must not be {@code null}.
   * @param  password          The password for the GSSAPI bind request.  It
   *                           must not be {@code null}.
   */
  public GSSAPIBindRequestProperties(final String authenticationID,
                                     final String password)
  {
    this(authenticationID, null, new ASN1OctetString(password), null, null,
         null);
  }



  /**
   * Creates a new set of GSSAPI bind request properties with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It must not be {@code null}.
   * @param  password          The password for the GSSAPI bind request.  It
   *                           must not be {@code null}.
   */
  public GSSAPIBindRequestProperties(final String authenticationID,
                                     final byte[] password)
  {
    this(authenticationID, null, new ASN1OctetString(password), null, null,
         null);
  }



  /**
   * Creates a new set of GSSAPI bind request properties with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It must not be {@code null}.
   * @param  authorizationID   The authorization ID for the GSSAPI bind request.
   *                           It may be {@code null} if the authorization ID
   *                           should be the same as the authentication ID.
   * @param  password          The password for the GSSAPI bind request.  It
   *                           must not be {@code null}.
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
  GSSAPIBindRequestProperties(final String authenticationID,
                              final String authorizationID,
                              final ASN1OctetString password,
                              final String realm,
                              final String kdcAddress,
                              final String configFilePath)
  {
    Validator.ensureNotNull(authenticationID);
    Validator.ensureNotNull(password);

    this.authenticationID = authenticationID;
    this.authorizationID  = authorizationID;
    this.password         = password;
    this.realm            = realm;
    this.kdcAddress       = kdcAddress;
    this.configFilePath   = configFilePath;

    servicePrincipalProtocol = "ldap";
    enableGSSAPIDebugging    = false;
  }



  /**
   * Retrieves the authentication ID for the GSSAPI bind request.
   *
   * @return  The authentication ID for the GSSAPI bind request.
   */
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Sets the authentication ID for the GSSAPI bind request.
   *
   * @param  authenticationID  The authentication ID for the GSSAPI bind
   *                           request.  It must not be {@code null}.
   */
  public void setAuthenticationID(final String authenticationID)
  {
    Validator.ensureNotNull(authenticationID);

    this.authenticationID = authenticationID;
  }



  /**
   * Retrieves the authorization ID for the GSSAPI bind request, if defined.
   *
   * @return  The authorizationID for the GSSAPI bind request, or {@code null}
   *          if the authorization ID should be the same as the authentication
   *          ID.
   */
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
  public void setAuthorizationID(final String authorizationID)
  {
    this.authorizationID = authorizationID;
  }



  /**
   * Retrieves the password that should be used for the GSSAPI bind request.
   *
   * @return  The password that should be used for the GSSAPI bind request.
   */
  public ASN1OctetString getPassword()
  {
    return password;
  }



  /**
   * Specifies the password that should be used for the GSSAPI bind request.
   *
   * @param  password  The password that should be used for the GSSAPI bind
   *                   request.  It must not be {@code null}.
   */
  public void setPassword(final String password)
  {
    Validator.ensureNotNull(password);

    this.password = new ASN1OctetString(password);
  }



  /**
   * Specifies the password that should be used for the GSSAPI bind request.
   *
   * @param  password  The password that should be used for the GSSAPI bind
   *                   request.  It must not be {@code null}.
   */
  public void setPassword(final byte[] password)
  {
    Validator.ensureNotNull(password);

    this.password = new ASN1OctetString(password);
  }



  /**
   * Specifies the password that should be used for the GSSAPI bind request.
   *
   * @param  password  The password that should be used for the GSSAPI bind
   *                   request.  It must not be {@code null}.
   */
  public void setPassword(final ASN1OctetString password)
  {
    Validator.ensureNotNull(password);

    this.password = password;
  }



  /**
   * Retrieves the realm to use for the GSSAPI bind request, if defined.
   *
   * @return  The realm to use for the GSSAPI bind request, or {@code null} if
   *          the request should attempt to use the default realm from the
   *          system configuration.
   */
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
  public void setRealm(final String realm)
  {
    this.realm = realm;
  }



  /**
   * Retrieves the address to use for the Kerberos key distribution center,
   * if defined.
   *
   * @return  The address to use for the Kerberos key distribution center, or
   *          {@code null} if request should attempt to determine the KDC
   *          address from the system configuration.
   */
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
  public void setKDCAddress(final String kdcAddress)
  {
    this.kdcAddress = kdcAddress;
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
  public void setConfigFilePath(final String configFilePath)
  {
    this.configFilePath = configFilePath;
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
  public void setServicePrincipalProtocol(final String servicePrincipalProtocol)
  {
    Validator.ensureNotNull(servicePrincipalProtocol);

    this.servicePrincipalProtocol = servicePrincipalProtocol;
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GSSAPIBindRequestProperties(authenticationID='");
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

    if (kdcAddress != null)
    {
      buffer.append(", kdcAddress='");
      buffer.append(kdcAddress);
      buffer.append('\'');
    }

    if (configFilePath != null)
    {
      buffer.append(", configFilePath='");
      buffer.append(configFilePath);
      buffer.append('\'');
    }

    buffer.append(", servicePrincipalProtocol='");
    buffer.append(servicePrincipalProtocol);
    buffer.append("', enableGSSAPIDebugging=");
    buffer.append(enableGSSAPIDebugging);
    buffer.append(')');
  }
}
