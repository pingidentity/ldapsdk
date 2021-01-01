/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an enhanced implementation of the {@link RootDSE} class
 * that provides access to additional attributes that may be included in the
 * root DSE of a Ping Identity, UnboundID, or Nokia/Alcatel-Lucent 8661 server.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class UnboundIDRootDSE
       extends RootDSE
{
  /**
   * The name of the attribute that provides a digest of the base configuration
   * for the software version the server is currently running.
   */
  @NotNull public static final String ATTR_BASELINE_CONFIG_DIGEST =
       "baselineConfigurationDigest";



  /**
   * The name of the attribute that provides a digest of the configuration model
   * for the software version the server is currently running.
   */
  @NotNull public static final String ATTR_CONFIG_MODEL_DIGEST =
       "configurationModelDigest";



  /**
   * The name of the attribute that provides a the unique instance name for the
   * server instance.
   */
  @NotNull public static final String ATTR_INSTANCE_NAME = "ds-instance-name";



  /**
   * The name of the attribute that includes the DNs of the private naming
   * contexts defined in the server.  These are base DNs that provide some
   * content in the UnboundID server, but do not house user-provided data that
   * is expected to be accessed by normal clients.
   */
  @NotNull public static final String ATTR_PRIVATE_NAMING_CONTEXTS =
       "ds-private-naming-contexts";



  /**
   * The name of the attribute that includes unique identifier generated at
   * server startup, and can be used to determine whether an instance has been
   * restarted.
   */
  @NotNull public static final String ATTR_STARTUP_UUID = "startupUUID";



  /**
   * The name of the attribute that includes the one-time password delivery
   * mechanisms supported for use in the server.
   */
  @NotNull public static final String ATTR_SUPPORTED_OTP_DELIVERY_MECHANISM =
       "ds-supported-otp-delivery-mechanism";



  /**
   * The set of request attributes to use when attempting to retrieve the server
   * root DSE.  It will attempt to retrieve all operational attributes if the
   * server supports that capability, but will also attempt to retrieve specific
   * attributes by name in case it does not.
   */
  @NotNull private static final String[] REQUEST_ATTRS;
  static
  {
    final String[] superAttrs = RootDSE.REQUEST_ATTRS;
    REQUEST_ATTRS = new String[superAttrs.length + 6];
    System.arraycopy(superAttrs, 0, REQUEST_ATTRS, 0, superAttrs.length);

    int i = superAttrs.length;
    REQUEST_ATTRS[i++] = ATTR_BASELINE_CONFIG_DIGEST;
    REQUEST_ATTRS[i++] = ATTR_CONFIG_MODEL_DIGEST;
    REQUEST_ATTRS[i++] = ATTR_INSTANCE_NAME;
    REQUEST_ATTRS[i++] = ATTR_PRIVATE_NAMING_CONTEXTS;
    REQUEST_ATTRS[i++] = ATTR_STARTUP_UUID;
    REQUEST_ATTRS[i++] = ATTR_SUPPORTED_OTP_DELIVERY_MECHANISM;
  }



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2555047334281707615L;



  /**
   * Creates a new UnboundID root DSE object from the information in the
   * provided entry.
   *
   * @param  rootDSEEntry  The entry to use to create this UnboundID root DSE
   *                       object.  It must not be {@code null}.
   */
  public UnboundIDRootDSE(@NotNull final Entry rootDSEEntry)
  {
    super(rootDSEEntry);
  }



  /**
   * Retrieves the root DSE from an UnboundID server using the provided
   * connection.
   *
   * @param  connection  The connection to use to retrieve the server root DSE.
   *
   * @return The UnboundID server root DSE, or {@code null} if it is not
   *          available (e.g., the client does not have permission to read the
   *          entry).
   *
   * @throws LDAPException  If a problem occurs while attempting to retrieve
   *                         the server root DSE.
   */
  @Nullable()
  public static UnboundIDRootDSE getRootDSE(
                     @NotNull final LDAPInterface connection)
       throws LDAPException
  {
    final Entry rootDSEEntry = connection.getEntry("", REQUEST_ATTRS);
    if (rootDSEEntry == null)
    {
      return null;
    }

    return new UnboundIDRootDSE(rootDSEEntry);
  }



  /**
   * Retrieves a digest of the baseline configuration for the software version
   * the server is currently running.
   *
   * @return The server's baseline configuration digest, or {@code null} if
   *          that information is not available.
   */
  @Nullable()
  public String getBaselineConfigurationDigest()
  {
    return getAttributeValue(ATTR_BASELINE_CONFIG_DIGEST);
  }



  /**
   * Retrieves a digest of the configuration model for the software version the
   * server is currently running.
   *
   * @return The server's configuration model digest, or {@code null} if that
   *          information is not available.
   */
  @Nullable()
  public String getConfigurationModelDigest()
  {
    return getAttributeValue(ATTR_CONFIG_MODEL_DIGEST);
  }



  /**
   * Retrieves the unique name assigned to the server instance.
   *
   * @return The unique name assigned to the server instance, or {@code null}
   *          if that information is not available.
   */
  @Nullable()
  public String getInstanceName()
  {
    return getAttributeValue(ATTR_INSTANCE_NAME);
  }



  /**
   * Retrieves the DNs of the private naming contexts, which identify base DNs
   * for content in the server that is not intended to be accessed by normal
   * clients but instead provides some alternate function like administration
   * or monitoring.
   *
   * @return The DNs of the private naming contexts, or {@code null} if that
   *          information is not available.
   */
  @Nullable()
  public String[] getPrivateNamingContexts()
  {
    return getAttributeValues(ATTR_PRIVATE_NAMING_CONTEXTS);
  }



  /**
   * Retrieves a unique identifier that the server generated at startup and can
   * be used to determine whether a server has been restarted.
   *
   * @return The server's startup UUID, or {@code null} if that information is
   *          not available.
   */
  @Nullable()
  public String getStartupUUID()
  {
    return getAttributeValue(ATTR_STARTUP_UUID);
  }



  /**
   * Retrieves the names of the supported one-time password delivery mechanisms.
   *
   * @return The names of the supported one-time password delivery mechanisms,
   *          or {@code null} if that information is not available.
   */
  @Nullable()
  public String[] getSupportedOTPDeliveryMechanisms()
  {
    return getAttributeValues(ATTR_SUPPORTED_OTP_DELIVERY_MECHANISM);
  }



  /**
   * Indicates whether the directory server indicates that it supports the
   * specified one-time password delivery mechanism.
   *
   * @param  mechanismName  The name of the delivery mechanism for which to make
   *                        the determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the server indicates that it supports the
   *          specified one-time password delivery mechanism, or {@code false}
   *          if it does not.
   */
  public boolean supportsOTPDeliveryMechanism(
              @NotNull final String mechanismName)
  {
    return hasAttributeValue(ATTR_SUPPORTED_OTP_DELIVERY_MECHANISM,
         mechanismName);
  }
}
