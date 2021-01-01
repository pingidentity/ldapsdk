/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides general information about
 * the Directory Server version.
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
 * Information that it may make available includes:
 * <UL>
 *   <LI>The full Directory Server version string, which may contain
 *       spaces.</LI>
 *   <LI>The compact Directory Server version string, which will not contain
 *       any spaces and may use a more compact representation than the full
 *       version string.</LI>
 *   <LI>The Directory Server product name.</LI>
 *   <LI>A compact representation of the Directory Server product name.</LI>
 *   <LI>The server major version number.</LI>
 *   <LI>The server minor version number.</LI>
 *   <LI>The server point version number.</LI>
 *   <LI>A version qualifier string which may provide a more descriptive name
 *       for the build of the server.</LI>
 *   <LI>The server build ID string.</LI>
 *   <LI>The server promoted build number.</LI>
 *   <LI>The source control revision number for the source used to build the
 *       server.</LI>
 *   <LI>A list of the bugfix IDs for any special fixes included in the
 *       server.</LI>
 * </UL>
 * The server should present at most one version monitor entry.  It can be
 * retrieved using the {@link MonitorManager#getVersionMonitorEntry} method.
 * This entry provides specific methods for accessing this version information
 * (e.g., the {@link VersionMonitorEntry#getFullVersion} method can be used to
 * retrieve the full version string for the server).  Alternately, this
 * information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class VersionMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in version monitor entries.
   */
  @NotNull protected static final String VERSION_MONITOR_OC =
       "ds-version-monitor-entry";



  /**
   * The name of the attribute used to provide the server build ID.
   */
  @NotNull private static final String ATTR_BUILD_ID = "buildID";



  /**
   * The name of the attribute used to provide the server promoted build number.
   */
  @NotNull private static final String ATTR_BUILD_NUMBER = "buildNumber";



  /**
   * The name of the attribute used to provide a compact server version string.
   */
  @NotNull private static final String ATTR_COMPACT_VERSION = "compactVersion";



  /**
   * The name of the attribute used to provide the list of bugfix IDs.
   */
  @NotNull private static final String ATTR_FIX_IDS = "fixIDs";



  /**
   * The name of the attribute used to provide a full server version string.
   */
  @NotNull private static final String ATTR_FULL_VERSION = "fullVersion";



  /**
   * The name of the attribute used to hold the Groovy library version.
   */
  @NotNull private static final String ATTR_GROOVY_VERSION = "groovyVersion";



  /**
   * The name of the attribute used to hold the Berkeley DB JE library version.
   */
  @NotNull private static final String ATTR_JE_VERSION = "jeVersion";



  /**
   * The name of the attribute used to hold the jzlib library version.
   */
  @NotNull private static final String ATTR_JZLIB_VERSION = "jzlibVersion";



  /**
   * The name of the attribute used to hold the LDAP SDK library version.
   */
  @NotNull private static final String ATTR_LDAP_SDK_VERSION = "ldapSDKVersion";



  /**
   * The name of the attribute used to provide the major version number.
   */
  @NotNull private static final String ATTR_MAJOR_VERSION = "majorVersion";



  /**
   * The name of the attribute used to provide the minor version number.
   */
  @NotNull private static final String ATTR_MINOR_VERSION = "minorVersion";



  /**
   * The name of the attribute used to provide the point version number.
   */
  @NotNull private static final String ATTR_POINT_VERSION = "pointVersion";



  /**
   * The name of the attribute used to provide the product name.
   */
  @NotNull private static final String ATTR_PRODUCT_NAME = "productName";



  /**
   * The name of the attribute used to provide the source revision identifier.
   */
  @NotNull private static final String ATTR_REVISION_ID = "revisionID";



  /**
   * The name of the attribute used to provide the source revision number.
   */
  @NotNull private static final String ATTR_REVISION_NUMBER = "revisionNumber";



  /**
   * The name of the attribute used to hold the server SDK library version.
   */
  @NotNull private static final String ATTR_SERVER_SDK_VERSION =
       "serverSDKVersion";



  /**
   * The name of the attribute used to provide the short product name.
   */
  @NotNull private static final String ATTR_SHORT_NAME = "shortName";



  /**
   * The name of the attribute used to hold the server SNMP4J library version.
   */
  @NotNull private static final String ATTR_SNMP4J_VERSION = "snmp4jVersion";



  /**
   * The name of the attribute used to hold the server SNMP4J agent library
   * version.
   */
  @NotNull private static final String ATTR_SNMP4J_AGENT_VERSION =
       "snmp4jAgentVersion";



  /**
   * The name of the attribute used to hold the server SNMP4J AgentX library
   * version.
   */
  @NotNull private static final String ATTR_SNMP4J_AGENTX_VERSION =
       "snmp4jAgentXVersion";



  /**
   * The name of the attribute used to provide the server's version qualifier.
   */
  @NotNull private static final String ATTR_VERSION_QUALIFIER =
       "versionQualifier";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8501846678698542926L;



  // The server build number.
  @Nullable private final Long buildNumber;

  // The server major version number.
  @Nullable private final Long majorVersion;

  // The server minor version number.
  @Nullable private final Long minorVersion;

  // The server point version number.
  @Nullable private final Long pointVersion;

  // The server source revision number.
  @Nullable private final Long revisionNumber;

  // The server build ID.
  @Nullable private final String buildID;

  // The compact server version string.
  @Nullable private final String compactVersion;

  // The list of bugfix IDs.
  @Nullable private final String fixIDs;

  // The Groovy library version.
  @Nullable private final String groovyVersion;

  // The full server version string.
  @Nullable private final String fullVersion;

  // The Berkeley DB JE library version.
  @Nullable private final String jeVersion;

  // The jzlib library version.
  @Nullable private final String jzlibVersion;

  // The LDAP SDK library version.
  @Nullable private final String ldapSDKVersion;

  // The server product name.
  @Nullable private final String productName;

  // A string that identifies the source revision from which the server was
  // built.
  @Nullable private final String revisionID;

  // The server SDK library version.
  @Nullable private final String serverSDKVersion;

  // The server short product name.
  @Nullable private final String shortName;

  // The SNMP4J library version.
  @Nullable private final String snmp4jVersion;

  // The SNMP4J agent library version.
  @Nullable private final String snmp4jAgentVersion;

  // The SNMP4J AgentX library version.
  @Nullable private final String snmp4jAgentXVersion;

  // The server version qualifier string.
  @Nullable private final String versionQualifier;



  /**
   * Creates a new version monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a version monitor entry.  It must
   *                not be {@code null}.
   */
  public VersionMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    buildNumber         = getLong(ATTR_BUILD_NUMBER);
    majorVersion        = getLong(ATTR_MAJOR_VERSION);
    minorVersion        = getLong(ATTR_MINOR_VERSION);
    pointVersion        = getLong(ATTR_POINT_VERSION);
    revisionNumber      = getLong(ATTR_REVISION_NUMBER);
    buildID             = getString(ATTR_BUILD_ID);
    compactVersion      = getString(ATTR_COMPACT_VERSION);
    fixIDs              = getString(ATTR_FIX_IDS);
    groovyVersion       = getString(ATTR_GROOVY_VERSION);
    fullVersion         = getString(ATTR_FULL_VERSION);
    jeVersion           = getString(ATTR_JE_VERSION);
    jzlibVersion        = getString(ATTR_JZLIB_VERSION);
    ldapSDKVersion      = getString(ATTR_LDAP_SDK_VERSION);
    productName         = getString(ATTR_PRODUCT_NAME);
    revisionID          = getString(ATTR_REVISION_ID);
    serverSDKVersion    = getString(ATTR_SERVER_SDK_VERSION);
    shortName           = getString(ATTR_SHORT_NAME);
    snmp4jVersion       = getString(ATTR_SNMP4J_VERSION);
    snmp4jAgentVersion  = getString(ATTR_SNMP4J_AGENT_VERSION);
    snmp4jAgentXVersion = getString(ATTR_SNMP4J_AGENTX_VERSION);
    versionQualifier    = getString(ATTR_VERSION_QUALIFIER);
  }



  /**
   * Retrieves the Directory Server build ID string.
   *
   * @return  The Directory Server build ID string, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public String getBuildID()
  {
    return buildID;
  }



  /**
   * Retrieves the Directory Server promoted build number.
   *
   * @return  The Directory Server promoted build number, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getBuildNumber()
  {
    return buildNumber;
  }



  /**
   * Retrieves a compact representation of the Directory Server version string.
   * It will not contain any spaces.
   *
   * @return  A compact representation of the Directory Server version string,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getCompactVersion()
  {
    return compactVersion;
  }



  /**
   * Retrieves a space-delimited list of the bugfix IDs for special fixes
   * included in the Directory Server.
   *
   * @return  A space-delimited list of the bugfix IDs for special fixes
   *          included in the Directory Server, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getFixIDs()
  {
    return fixIDs;
  }



  /**
   * Retrieves the full Directory Server version string.
   *
   * @return  The full Directory Server version string, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getFullVersion()
  {
    return fullVersion;
  }



  /**
   * Retrieves the Groovy library version string.
   *
   * @return  The Groovy library version string, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getGroovyVersion()
  {
    return groovyVersion;
  }



  /**
   * Retrieves the Berkeley DB Java Edition library version string.
   *
   * @return  The Berkeley DB Java Edition library version string, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getBerkeleyDBJEVersion()
  {
    return jeVersion;
  }



  /**
   * Retrieves the jzlib library version string.
   *
   * @return  The jzlib library version string, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getJZLibVersion()
  {
    return jzlibVersion;
  }



  /**
   * Retrieves the UnboundID LDAP SDK for Java library version string.
   *
   * @return  The UnboundID LDAP SDK for Java library version string, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getLDAPSDKVersion()
  {
    return ldapSDKVersion;
  }



  /**
   * Retrieves the Directory Server major version number.
   *
   * @return  The Directory Server major version number, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getMajorVersion()
  {
    return majorVersion;
  }



  /**
   * Retrieves the Directory Server minor version number.
   *
   * @return  The Directory Server minor version number, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getMinorVersion()
  {
    return minorVersion;
  }



  /**
   * Retrieves the Directory Server point version number.
   *
   * @return  The Directory Server point version number, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getPointVersion()
  {
    return pointVersion;
  }



  /**
   * Retrieves the Directory Server product name (e.g., "Ping Identity Directory
   * Server").
   *
   * @return  The Directory Server product name, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getProductName()
  {
    return productName;
  }



  /**
   * Retrieves the source revision number from which the Directory Server was
   * built.
   *
   * @return  The source revision number from which the Directory Server was
   *          built, or {@code null} if it was not included in the monitor
   *          entry or if it was not numeric.
   *
   * @deprecated   Use {@link #getRevisionID} instead, as the version control
   *               system might not use numeric revision identifiers.
   */
  @Deprecated()
  @Nullable()
  public Long getRevisionNumber()
  {
    return revisionNumber;
  }



  /**
   * Retrieves a string that identifies the source revision from which the
   * server was built.
   *
   * @return  A string that identifies the source revision from which the server
   *          was built.
   */
  @Nullable()
  public String getRevisionID()
  {
    return revisionID;
  }



  /**
   * Retrieves the UnboundID Server SDK library version string.
   *
   * @return  The UnboundID Server SDK library version string, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public String getServerSDKVersion()
  {
    return serverSDKVersion;
  }



  /**
   * Retrieves the Directory Server short product name (e.g.,
   * "Ping-Identity-DS").
   *
   * @return  The Directory Server short product name, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public String getShortProductName()
  {
    return shortName;
  }



  /**
   * Retrieves the SNMP4J library version string.
   *
   * @return  The SNMP4J library version string, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getSNMP4JVersion()
  {
    return snmp4jVersion;
  }



  /**
   * Retrieves the SNMP4J agent library version string.
   *
   * @return  The SNMP4J agent library version string, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public String getSNMP4JAgentVersion()
  {
    return snmp4jAgentVersion;
  }



  /**
   * Retrieves the SNMP4J AgentX library version string.
   *
   * @return  The SNMP4J AgentX library version string, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getSNMP4JAgentXVersion()
  {
    return snmp4jAgentXVersion;
  }



  /**
   * Retrieves the Directory Server version qualifier string (e.g., "-beta1").
   *
   * @return  The Directory Server version qualifier string, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public String getVersionQualifier()
  {
    return versionQualifier;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_VERSION_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_VERSION_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));

    if (productName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PRODUCT_NAME,
           INFO_VERSION_DISPNAME_PRODUCT_NAME.get(),
           INFO_VERSION_DESC_PRODUCT_NAME.get(),
           productName);
    }

    if (shortName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SHORT_NAME,
           INFO_VERSION_DISPNAME_SHORT_NAME.get(),
           INFO_VERSION_DESC_SHORT_NAME.get(),
           shortName);
    }

    if (fullVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_FULL_VERSION,
           INFO_VERSION_DISPNAME_FULL_VERSION.get(),
           INFO_VERSION_DESC_FULL_VERSION.get(),
           fullVersion);
    }

    if (compactVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPACT_VERSION,
           INFO_VERSION_DISPNAME_COMPACT_VERSION.get(),
           INFO_VERSION_DESC_COMPACT_VERSION.get(),
           compactVersion);
    }

    if (buildID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BUILD_ID,
           INFO_VERSION_DISPNAME_BUILD_ID.get(),
           INFO_VERSION_DESC_BUILD_ID.get(),
           buildID);
    }

    if (majorVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAJOR_VERSION,
           INFO_VERSION_DISPNAME_MAJOR_VERSION.get(),
           INFO_VERSION_DESC_MAJOR_VERSION.get(),
           majorVersion);
    }

    if (minorVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MINOR_VERSION,
           INFO_VERSION_DISPNAME_MINOR_VERSION.get(),
           INFO_VERSION_DESC_MINOR_VERSION.get(),
           minorVersion);
    }

    if (pointVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_POINT_VERSION,
           INFO_VERSION_DISPNAME_POINT_VERSION.get(),
           INFO_VERSION_DESC_POINT_VERSION.get(),
           pointVersion);
    }

    if (buildNumber != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BUILD_NUMBER,
           INFO_VERSION_DISPNAME_BUILD_NUMBER.get(),
           INFO_VERSION_DESC_BUILD_NUMBER.get(),
           buildNumber);
    }

    if (versionQualifier != null)
    {
      addMonitorAttribute(attrs,
           ATTR_VERSION_QUALIFIER,
           INFO_VERSION_DISPNAME_VERSION_QUALIFIER.get(),
           INFO_VERSION_DESC_VERSION_QUALIFIER.get(),
           versionQualifier);
    }

    if (revisionNumber != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REVISION_NUMBER,
           INFO_VERSION_DISPNAME_REVISION_NUMBER.get(),
           INFO_VERSION_DESC_REVISION_NUMBER.get(),
           revisionNumber);
    }

    if (revisionID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REVISION_ID,
           INFO_VERSION_DISPNAME_REVISION_ID.get(),
           INFO_VERSION_DESC_REVISION_ID.get(),
           revisionID);
    }

    if (fixIDs != null)
    {
      addMonitorAttribute(attrs,
           ATTR_FIX_IDS,
           INFO_VERSION_DISPNAME_FIX_IDS.get(),
           INFO_VERSION_DESC_FIX_IDS.get(),
           fixIDs);
    }

    if (groovyVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_GROOVY_VERSION,
           INFO_VERSION_DISPNAME_GROOVY_VERSION.get(),
           INFO_VERSION_DESC_GROOVY_VERSION.get(),
           groovyVersion);
    }

    if (jeVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JE_VERSION,
           INFO_VERSION_DISPNAME_JE_VERSION.get(),
           INFO_VERSION_DESC_JE_VERSION.get(),
           jeVersion);
    }

    if (jzlibVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JZLIB_VERSION,
           INFO_VERSION_DISPNAME_JZLIB_VERSION.get(),
           INFO_VERSION_DESC_JZLIB_VERSION.get(),
           jzlibVersion);
    }

    if (ldapSDKVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LDAP_SDK_VERSION,
           INFO_VERSION_DISPNAME_LDAP_SDK_VERSION.get(),
           INFO_VERSION_DESC_LDAP_SDK_VERSION.get(),
           ldapSDKVersion);
    }

    if (serverSDKVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SERVER_SDK_VERSION,
           INFO_VERSION_DISPNAME_SERVER_SDK_VERSION.get(),
           INFO_VERSION_DESC_SERVER_SDK_VERSION.get(),
           serverSDKVersion);
    }

    if (snmp4jVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SNMP4J_VERSION,
           INFO_VERSION_DISPNAME_SNMP4J_VERSION.get(),
           INFO_VERSION_DESC_SNMP4J_VERSION.get(),
           snmp4jVersion);
    }

    if (snmp4jAgentVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SNMP4J_AGENT_VERSION,
           INFO_VERSION_DISPNAME_SNMP4J_AGENT_VERSION.get(),
           INFO_VERSION_DESC_SNMP4J_AGENT_VERSION.get(),
           snmp4jAgentVersion);
    }

    if (snmp4jAgentXVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SNMP4J_AGENTX_VERSION,
           INFO_VERSION_DISPNAME_SNMP4J_AGENTX_VERSION.get(),
           INFO_VERSION_DESC_SNMP4J_AGENTX_VERSION.get(),
           snmp4jAgentXVersion);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
