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



import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure for representing the directory server
 * root DSE.  This entry provides information about the capabilities of the
 * directory server, server vendor and version information, and published naming
 * contexts.
 * <BR><BR>
 * Note a root DSE object instance represents a read-only version of an entry,
 * so all read operations allowed for an entry will succeed, but all write
 * attempts will be rejected.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for retrieving the root DSE
 * of a directory server and using it to determine whether it supports the
 * {@link com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl}:
 * <PRE>
 * RootDSE rootDSE = connection.getRootDSE();
 * if (rootDSE.supportsControl(
 *      ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID))
 * {
 *   // The directory server does support the server-side sort control.
 * }
 * else
 * {
 *   // The directory server does not support the server-side sort control.
 * }
 * </PRE>
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class RootDSE
       extends ReadOnlyEntry
{
  /**
   * The name of the attribute that includes a set of URIs (likely in the form
   * of LDAP URLs) of other servers that may be contacted if the target server
   * is unavailable, as defined in RFC 4512 section 5.1.
   */
  @NotNull public static final String ATTR_ALT_SERVER = "altServer";



  /**
   * The name of the attribute that specifies the DN that is the base of the
   * LDAP changelog data, if available, as defined in draft-good-ldap-changelog.
   */
  @NotNull public static final String ATTR_CHANGELOG_DN = "changelog";



  /**
   * The name of the attribute that may contain the change number for the first
   * entry in the LDAP changelog.  This is not defined in any public
   * specification, but is provided by a number of servers which implement
   * draft-good-ldap-changelog.
   */
  @NotNull public static final String ATTR_FIRST_CHANGE_NUMBER =
       "firstChangeNumber";



  /**
   * The name of the attribute that may contain the change number for the last
   * entry in the LDAP changelog, if available.  This is not defined in any
   * public specification, but is provided by a number of servers which
   * implement draft-good-ldap-changelog.
   */
  @NotNull public static final String ATTR_LAST_CHANGE_NUMBER =
       "lastChangeNumber";



  /**
   * The name of the attribute that may contain the change number for the last
   * entry purged from the LDAP changelog, if available.  This is not defined in
   * any public specification, but is provided by a number of servers which
   * implement draft-good-ldap-changelog.
   */
  @NotNull public static final String ATTR_LAST_PURGED_CHANGE_NUMBER =
       "lastPurgedChangeNumber";



  /**
   * The name of the attribute that includes the DNs of the public naming
   * contexts defined in the server, as defined in RFC 4512 section 5.1.
   */
  @NotNull public static final String ATTR_NAMING_CONTEXT = "namingContexts";



  /**
   * The name of the attribute that specifies the DN of the subschema subentry
   * that serves the server root DSE, as defined in RFC 4512 section 4.2.
   */
  @NotNull public static final String ATTR_SUBSCHEMA_SUBENTRY =
       "subschemaSubentry";



  /**
   * The name of the attribute that includes the names of the supported
   * authentication password storage schemes, as defined in RFC 3112.
   */
  @NotNull public static final String
       ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME =
            "supportedAuthPasswordSchemes";



  /**
   * The name of the attribute that includes the OIDs of the request controls
   * supported by the server, as defined in RFC 4512 section 5.1.
   */
  @NotNull public static final String ATTR_SUPPORTED_CONTROL =
       "supportedControl";



  /**
   * The name of the attribute that includes the OIDs of the extended operations
   * supported by the server, as defined in RFC 4512 section 5.1.
   */
  @NotNull public static final String ATTR_SUPPORTED_EXTENDED_OPERATION =
       "supportedExtension";



  /**
   * The name of the attribute that includes the OIDs of the features supported
   * by the server, as defined in RFC 4512 section 5.1.
   */
  @NotNull public static final String ATTR_SUPPORTED_FEATURE =
       "supportedFeatures";



  /**
   * The name of the attribute that includes the OIDs of the LDAP protocol
   * versions supported by the server, as defined in RFC 4512 section 5.1.
   */
  @NotNull public static final String ATTR_SUPPORTED_LDAP_VERSION =
       "supportedLDAPVersion";



  /**
   * The name of the attribute that includes the names of the SASL mechanisms
   * supported by the server, as defined in RFC 4512 section 5.1.
   */
  @NotNull public static final String ATTR_SUPPORTED_SASL_MECHANISM =
       "supportedSASLMechanisms";



  /**
   * The name of the attribute that includes the name of the server vendor,
   * as defined in RFC 3045.
   */
  @NotNull public static final String ATTR_VENDOR_NAME = "vendorName";



  /**
   * The name of the attribute that includes the server version, as defined in
   * RFC 3045.
   */
  @NotNull public static final String ATTR_VENDOR_VERSION = "vendorVersion";



  /**
   * The set of request attributes to use when attempting to retrieve the server
   * root DSE.  It will attempt to retrieve all operational attributes if the
   * server supports that capability, but will also attempt to retrieve specific
   * attributes by name in case it does not.
   */
  @NotNull protected static final String[] REQUEST_ATTRS =
  {
    "*",
    "+",
    ATTR_ALT_SERVER,
    ATTR_CHANGELOG_DN,
    ATTR_FIRST_CHANGE_NUMBER,
    ATTR_LAST_CHANGE_NUMBER,
    ATTR_LAST_PURGED_CHANGE_NUMBER,
    ATTR_NAMING_CONTEXT,
    ATTR_SUBSCHEMA_SUBENTRY,
    ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME,
    ATTR_SUPPORTED_CONTROL,
    ATTR_SUPPORTED_EXTENDED_OPERATION,
    ATTR_SUPPORTED_FEATURE,
    ATTR_SUPPORTED_LDAP_VERSION,
    ATTR_SUPPORTED_SASL_MECHANISM,
    ATTR_VENDOR_NAME,
    ATTR_VENDOR_VERSION,
  };



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1678182563511570981L;



  /**
   * Creates a new root DSE object from the information in the provided entry.
   *
   * @param  rootDSEEntry  The entry to use to create this root DSE object.  It
   *                       must not be {@code null}.
   */
  public RootDSE(@NotNull final Entry rootDSEEntry)
  {
    super(rootDSEEntry);
  }



  /**
   * Retrieves the directory server root DSE using the provided connection.
   *
   * @param  connection  The connection to use to retrieve the server root DSE.
   *
   * @return  The directory server root DSE, or {@code null} if it is not
   *          available (e.g., the client does not have permission to read the
   *          entry).
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server root DSE.
   */
  @Nullable()
  public static RootDSE getRootDSE(@NotNull final LDAPInterface connection)
         throws LDAPException
  {
    final Entry rootDSEEntry = connection.getEntry("", REQUEST_ATTRS);
    if (rootDSEEntry == null)
    {
      return null;
    }

    return new RootDSE(rootDSEEntry);
  }



  /**
   * Retrieves a set of URIs for alternate servers that may be contacted if
   * the current server becomes unavailable.
   *
   * @return  A set of URIs for alternate servers that may be contacted if the
   *          current server becomes available, or {@code null} if the server
   *          does not publish that information.
   */
  @Nullable()
  public final String[] getAltServerURIs()
  {
    return getAttributeValues(ATTR_ALT_SERVER);
  }



  /**
   * Retrieves the DN of the base entry for the directory server changelog
   * information, if available.
   *
   * @return  The DN of the base entry for the directory server changelog
   *          information, or {@code null} if the server does not publish that
   *          information or no changelog is available.
   */
  @Nullable()
  public final String getChangelogDN()
  {
    return getAttributeValue(ATTR_CHANGELOG_DN);
  }



  /**
   * Retrieves the change number for the first entry contained in the LDAP
   * changelog, if available.
   *
   * @return  The change number for the first entry contained in the LDAP
   *          changelog, if available.
   */
  @Nullable()
  public final Long getFirstChangeNumber()
  {
    return getAttributeValueAsLong(ATTR_FIRST_CHANGE_NUMBER);
  }



  /**
   * Retrieves the change number for the last entry contained in the LDAP
   * changelog, if available.
   *
   * @return  The change number for the last entry contained in the LDAP
   *          changelog, if available.
   */
  @Nullable()
  public final Long getLastChangeNumber()
  {
    return getAttributeValueAsLong(ATTR_LAST_CHANGE_NUMBER);
  }



  /**
   * Retrieves the change number for the last entry purged from the LDAP
   * changelog, if available.
   *
   * @return  The change number for the last entry purged from the LDAP
   *          changelog, if available.
   */
  @Nullable()
  public final Long getLastPurgedChangeNumber()
  {
    return getAttributeValueAsLong(ATTR_LAST_PURGED_CHANGE_NUMBER);
  }



  /**
   * Retrieves the DNs of the naming contexts provided by the directory server.
   *
   * @return  The DNs of the naming contexts provided by the directory server,
   *          or {@code null} if the server does not publish that information.
   */
  @Nullable()
  public final String[] getNamingContextDNs()
  {
    return getAttributeValues(ATTR_NAMING_CONTEXT);
  }



  /**
   * Retrieves the DN of the subschema subentry that serves the directory server
   * root DSE.
   *
   * @return  The DN of the subschema subentry that serves the directory server
   *          root DSE, or {@code null} if the server does not publish that
   *          information.
   */
  @Nullable()
  public final String getSubschemaSubentryDN()
  {
    return getAttributeValue(ATTR_SUBSCHEMA_SUBENTRY);
  }



  /**
   * Retrieves the names of the authentication password storage schemes
   * supported by the server.
   *
   * @return  The names of the authentication password storage schemes supported
   *          by the server, or {@code null} if the server does not publish
   *          that information.
   */
  @Nullable()
  public final String[] getSupportedAuthPasswordSchemeNames()
  {
    return getAttributeValues(ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME);
  }



  /**
   * Indicates whether the directory server indicates that it supports the
   * specified authentication password storage scheme.
   *
   * @param  scheme  The name of the authentication password storage scheme for
   *                 which to make the determination.  It must not be
   *                 {@code null}.
   *
   * @return  {@code true} if the directory server indicates that it supports
   *          the specified authentication password storage scheme, or
   *          {@code false} if it does not.
   */
  public final boolean supportsAuthPasswordScheme(@NotNull final String scheme)
  {
    return hasAttributeValue(ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME,
                             scheme);
  }



  /**
   * Retrieves the OIDs of the supported request controls advertised by the
   * server root DSE.
   *
   * @return  The OIDs of the supported request controls advertised by the
   *          server root DSE, or {@code null} if the server does not publish
   *          that information.
   */
  @Nullable()
  public final String[] getSupportedControlOIDs()
  {
    return getAttributeValues(ATTR_SUPPORTED_CONTROL);
  }



  /**
   * Indicates whether the directory server indicates that it supports the
   * request control with the provided OID.
   *
   * @param  controlOID  The OID of the control for which to make the
   *                     determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the server indicates that it supports the request
   *          control with the specified OID, or {@code false} if it does not.
   */
  public final boolean supportsControl(@NotNull final String controlOID)
  {
    return hasAttributeValue(ATTR_SUPPORTED_CONTROL, controlOID);
  }



  /**
   * Retrieves the OIDs of the supported extended operations advertised by the
   * server root DSE.
   *
   * @return  The OIDs of the supported extended operations advertised by the
   *          server root DSE, or {@code null} if the server does not publish
   *          that information.
   */
  @Nullable()
  public final String[] getSupportedExtendedOperationOIDs()
  {
    return getAttributeValues(ATTR_SUPPORTED_EXTENDED_OPERATION);
  }



  /**
   * Indicates whether the directory server indicates that it supports the
   * extended operation with the provided OID.
   *
   * @param  extendedOperationOID  The OID of the extended operation for which
   *                               to make the determination.  It must not be
   *                               {@code null}.
   *
   * @return  {@code true} if the server indicates that it supports the extended
   *          operation with the specified OID, or {@code false} if it does not.
   */
  public final boolean supportsExtendedOperation(
                            @NotNull final String extendedOperationOID)
  {
    return hasAttributeValue(ATTR_SUPPORTED_EXTENDED_OPERATION,
                             extendedOperationOID);
  }



  /**
   * Retrieves the OIDs of the supported features advertised by the server root
   * DSE.
   *
   * @return  The OIDs of the supported features advertised by the server root
   *          DSE, or {@code null} if the server does not publish that
   *          information.
   */
  @Nullable()
  public final String[] getSupportedFeatureOIDs()
  {
    return getAttributeValues(ATTR_SUPPORTED_FEATURE);
  }



  /**
   * Indicates whether the directory server indicates that it supports the
   * extended operation with the provided OID.
   *
   * @param  featureOID  The OID of the feature for which to make the
   *                     determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the server indicates that it supports the feature
   *          with the specified OID, or {@code false} if it does not.
   */
  public final boolean supportsFeature(@NotNull final String featureOID)
  {
    return hasAttributeValue(ATTR_SUPPORTED_FEATURE, featureOID);
  }



  /**
   * Retrieves the supported LDAP protocol versions advertised by the server
   * root DSE.
   *
   * @return  The supported LDAP protocol versions advertised by the server
   *          root DSE, or {@code null} if the server does not publish that
   *          information.
   */
  @Nullable()
  public final int[] getSupportedLDAPVersions()
  {
    final String[] versionStrs =
         getAttributeValues(ATTR_SUPPORTED_LDAP_VERSION);
    if (versionStrs == null)
    {
      return null;
    }

    final int[] versions = new int[versionStrs.length];
    for (int i=0; i < versionStrs.length; i++)
    {
      try
      {
        versions[i] = Integer.parseInt(versionStrs[i]);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        // We couldn't parse the value as an integer.
        return null;
      }
    }

    return versions;
  }



  /**
   * Indicates whether the directory server indicates that it supports the
   * provided LDAP protocol version.
   *
   * @param  ldapVersion  The LDAP protocol version for which to make the
   *                      determination.
   *
   * @return  {@code true} if the server indicates that it supports the
   *          specified LDAP protocol version, or {@code false} if it does not.
   */
  public final boolean supportsLDAPVersion(final int ldapVersion)
  {
    return hasAttributeValue(ATTR_SUPPORTED_LDAP_VERSION,
                             String.valueOf(ldapVersion));
  }



  /**
   * Retrieves the names of the supported SASL mechanisms advertised by the
   * server root DSE.
   *
   * @return  The names of the supported SASL mechanisms advertised by the
   *          server root DSE, or {@code null} if the server does not publish
   *          that information.
   */
  @Nullable()
  public final String[] getSupportedSASLMechanismNames()
  {
    return getAttributeValues(ATTR_SUPPORTED_SASL_MECHANISM);
  }



  /**
   * Indicates whether the directory server indicates that it supports the
   * specified SASL mechanism.
   *
   * @param  mechanismName  The name of the SASL mechanism for which to make the
   *                        determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the server indicates that it supports the
   *          specified SASL mechanism, or {@code false} if it does not.
   */
  public final boolean supportsSASLMechanism(
                            @NotNull final String mechanismName)
  {
    return hasAttributeValue(ATTR_SUPPORTED_SASL_MECHANISM, mechanismName);
  }



  /**
   * Retrieves the name of the directory server vendor, if available.
   *
   * @return  The name of the directory server vendor, or {@code null} if the
   *          server does not publish that information.
   */
  @Nullable()
  public final String getVendorName()
  {
    return getAttributeValue(ATTR_VENDOR_NAME);
  }



  /**
   * Retrieves the directory server version string, if available.
   *
   * @return  The directory server version string, or {@code null} if the server
   *          does not publish that information.
   */
  @Nullable()
  public final String getVendorVersion()
  {
    return getAttributeValue(ATTR_VENDOR_VERSION);
  }
}
