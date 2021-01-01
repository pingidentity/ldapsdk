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



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
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
 * This class defines a monitor entry that provides information about the system
 * and JVM on which the Directory Server is running.
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
 * The information that may be available includes:
 * <UL>
 *   <LI>The name of the operating system on which the server is running.</LI>
 *   <LI>The number of CPUs available to the JVM.</LI>
 *   <LI>The Java classpath in use by the server.</LI>
 *   <LI>The amount of memory currently used by the JVM.</LI>
 *   <LI>The maximum amount of memory that the JVM will be allowed to use.</LI>
 *   <LI>The amount of memory held by the JVM that is marked as "free" and can
 *       be used to allocate new objects.</LI>
 *   <LI>The hostname for the underlying system.</LI>
 *   <LI>The location in which the server is installed on the
 *       underlying system.</LI>
 *   <LI>The current working directory for the server process.</LI>
 *   <LI>The path to the Java installation being used to run the server.</LI>
 *   <LI>The vendor that provides the Java installation being used to run the
 *       server.</LI>
 *   <LI>The Java version string for the Java installation being used to run
 *       the server.</LI>
 *   <LI>The vendor that provides the JVM being used by the Java installation
 *       being used to run the server.</LI>
 *   <LI>The JVM version string for the Java installation being used to run the
 *       server.</LI>
 *   <LI>The JVM architecture data model (i.e., whether it is a 32-bit or 64-bit
 *       JVM).</LI>
 *   <LI>The arguments provided to the JVM when running the server.</LI>
 * </UL>
 * The server should present at most one system info monitor entry.  It can be
 * retrieved using the {@link MonitorManager#getSystemInfoMonitorEntry} method.
 * This entry provides specific methods for accessing this system information
 * (e.g., the {@link SystemInfoMonitorEntry#getOperatingSystem}
 * method can be used to retrieve the name of the operating system).
 * Alternately, this information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SystemInfoMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in system info monitor entries.
   */
  @NotNull static final String SYSTEM_INFO_MONITOR_OC =
       "ds-system-info-monitor-entry";



  /**
   * The name of the attribute that provides the number of CPUs available to the
   * JVM.
   */
  @NotNull private static final String ATTR_AVAILABLE_CPUS = "availableCPUs";



  /**
   * The name of the attribute that provides the server Java classpath.
   */
  @NotNull private static final String ATTR_CLASSPATH = "classPath";



  /**
   * The name of the attribute that provides the environment variables defined
   * for the server process.
   */
  @NotNull private static final String ATTR_ENVIRONMENT_VARIABLE =
       "environmentVariable";



  /**
   * The name of the attribute that provides the amount of free memory within
   * the JVM.
   */
  @NotNull private static final String ATTR_FREE_MEMORY = "freeUsedMemory";



  /**
   * The name of the attribute that provides the system hostname.
   */
  @NotNull private static final String ATTR_HOSTNAME = "systemName";



  /**
   * The name of the attribute that provides the server instance root.
   */
  @NotNull private static final String ATTR_INSTANCE_ROOT = "instanceRoot";



  /**
   * The name of the attribute that provides the server Java home.
   */
  @NotNull private static final String ATTR_JAVA_HOME = "javaHome";



  /**
   * The name of the attribute that provides the server Java vendor.
   */
  @NotNull private static final String ATTR_JAVA_VENDOR = "javaVendor";



  /**
   * The name of the attribute that provides the server Java version.
   */
  @NotNull private static final String ATTR_JAVA_VERSION = "javaVersion";



  /**
   * The name of the attribute that provides the server JVM architecture (e.g.,
   * 32-bit / 64-bit).
   */
  @NotNull private static final String ATTR_JVM_ARCHITECTURE =
       "jvmArchitecture";



  /**
   * The name of the attribute that provides the set of arguments provided when
   * starting the JVM.
   */
  @NotNull private static final String ATTR_JVM_ARGUMENTS = "jvmArguments";



  /**
   * The name of the attribute that provides the process ID of the JVM in which
   * the server is running.
   */
  @NotNull private static final String ATTR_JVM_PID = "jvmPID";



  /**
   * The name of the attribute that provides the server JVM vendor.
   */
  @NotNull private static final String ATTR_JVM_VENDOR = "jvmVendor";



  /**
   * The name of the attribute that provides the server JVM version.
   */
  @NotNull private static final String ATTR_JVM_VERSION = "jvmVersion";



  /**
   * The name of the attribute that provides the maximum amount of memory
   * available to the JVM.
   */
  @NotNull private static final String ATTR_MAX_MEMORY = "maxMemory";



  /**
   * The name of the attribute that provides information about the server's
   * operating system.
   */
  @NotNull private static final String ATTR_OPERATING_SYSTEM =
       "operatingSystem";



  /**
   * The name of the attribute that provides the name of the default SSL context
   * protocol that has been selected by the server.
   */
  @NotNull private static final String ATTR_SSL_CONTEXT_PROTOCOL =
       "sslContextProtocol";



  /**
   * The name of the attribute that provides the set of system properties
   * defined in the JVM.
   */
  @NotNull private static final String ATTR_SYSTEM_PROPERTY = "systemProperty";



  /**
   * The name of the attribute that provides the amount of memory currently used
   * by the JVM.
   */
  @NotNull private static final String ATTR_USED_MEMORY = "usedMemory";



  /**
   * The name of the attribute that provides the name of the user as whom the
   * server is running.
   */
  @NotNull private static final String ATTR_USER_NAME = "userName";



  /**
   * The name of the attribute that provides the server working directory.
   */
  @NotNull private static final String ATTR_WORKING_DIRECTORY =
       "workingDirectory";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2709857663883498069L;



  // The number of available CPUs.
  @Nullable private final Long availableCPUs;

  // The amount of free memory held by the JVM.
  @Nullable private final Long freeMemory;

  // The PID of the JVM in which the server is running.
  @Nullable private final Long jvmPID;

  // The maximum amount of memory the JVM can use.
  @Nullable private final Long maxMemory;

  // The amount of memory currently held by the JVM.
  @Nullable private final Long usedMemory;

  // The set of environment variables defined in the server process.
  @NotNull private final Map<String,String> environmentVariables;

  // The set of system properties defined in the JVM.
  @NotNull private final Map<String,String> systemProperties;

  // The server's classpath.
  @Nullable private final String classpath;

  // The server's hostname.
  @Nullable private final String hostname;

  // The path to the server instance root.
  @Nullable private final String instanceRoot;

  // The server's Java home.
  @Nullable private final String javaHome;

  // The server's Java vendor string.
  @Nullable private final String javaVendor;

  // The server's Java version string.
  @Nullable private final String javaVersion;

  // The server's JVM architecture.
  @Nullable private final String jvmArchitecture;

  // The set of arguments provided to the JVM.
  @Nullable private final String jvmArguments;

  // The server's JVM vendor string.
  @Nullable private final String jvmVendor;

  // The server's JVM version string.
  @Nullable private final String jvmVersion;

  // The name of the operating system on which the server is running.
  @Nullable private final String operatingSystem;

  // The name of the default SSL context protocol that has been selected by the
  // server.
  @Nullable private final String sslContextProtocol;

  // The name of the user as whom the server is running.
  @Nullable private final String userName;

  // The path to the server's current working directory.
  @Nullable private final String workingDirectory;



  /**
   * Creates a new system info monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a system info monitor entry.  It
   *                must not be {@code null}.
   */
  public SystemInfoMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    availableCPUs      = getLong(ATTR_AVAILABLE_CPUS);
    classpath          = getString(ATTR_CLASSPATH);
    freeMemory         = getLong(ATTR_FREE_MEMORY);
    hostname           = getString(ATTR_HOSTNAME);
    instanceRoot       = getString(ATTR_INSTANCE_ROOT);
    javaHome           = getString(ATTR_JAVA_HOME);
    javaVendor         = getString(ATTR_JAVA_VENDOR);
    javaVersion        = getString(ATTR_JAVA_VERSION);
    jvmArchitecture    = getString(ATTR_JVM_ARCHITECTURE);
    jvmArguments       = getString(ATTR_JVM_ARGUMENTS);
    jvmPID             = getLong(ATTR_JVM_PID);
    jvmVendor          = getString(ATTR_JVM_VENDOR);
    jvmVersion         = getString(ATTR_JVM_VERSION);
    maxMemory          = getLong(ATTR_MAX_MEMORY);
    operatingSystem    = getString(ATTR_OPERATING_SYSTEM);
    sslContextProtocol = getString(ATTR_SSL_CONTEXT_PROTOCOL);
    usedMemory         = getLong(ATTR_USED_MEMORY);
    userName           = getString(ATTR_USER_NAME);
    workingDirectory   = getString(ATTR_WORKING_DIRECTORY);

    final List<String> envValues = getStrings(ATTR_ENVIRONMENT_VARIABLE);
    final LinkedHashMap<String,String> envMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(envValues.size()));
    for (final String s : envValues)
    {
      final int eqPos = s.indexOf("='");
      if (eqPos > 0)
      {
        final String name = s.substring(0, eqPos);
        if (eqPos != (s.length() - 2))
        {
          envMap.put(name, s.substring(eqPos+2, (s.length() - 1)));
        }
      }
    }
    environmentVariables = Collections.unmodifiableMap(envMap);

    final List<String> propValues = getStrings(ATTR_SYSTEM_PROPERTY);
    final LinkedHashMap<String,String> propMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(propValues.size()));
    for (final String s : propValues)
    {
      final int eqPos = s.indexOf("='");
      if (eqPos > 0)
      {
        final String name = s.substring(0, eqPos);
        if (eqPos != (s.length() - 2))
        {
          propMap.put(name, s.substring(eqPos+2, (s.length() - 1)));
        }
      }
    }
    systemProperties = Collections.unmodifiableMap(propMap);
  }



  /**
   * Retrieves the number of CPUs available to the JVM.
   *
   * @return  The number of CPUs available to the JVM, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public Long getAvailableCPUs()
  {
    return availableCPUs;
  }



  /**
   * Retrieves the server's Java classpath.
   *
   * @return  The server's Java classpath, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getClassPath()
  {
    return classpath;
  }



  /**
   * Retrieves the environment variables available to the server process, mapped
   * from variable name to the corresponding value.
   *
   * @return  The environment variables available to the server process, or an
   *          empty map if it was not included in the monitor entry.
   */
  @NotNull()
  public Map<String,String> getEnvironmentVariables()
  {
    return environmentVariables;
  }



  /**
   * Retrieves the amount of memory in bytes held by the JVM that is currently
   * marked as free.
   *
   * @return  The amount of memory in bytes held by the JVM that is currently
   *          marked as free, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getFreeMemory()
  {
    return freeMemory;
  }



  /**
   * Retrieves the server's hostname.
   *
   * @return  The server's hostname, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public String getHostname()
  {
    return hostname;
  }



  /**
   * Retrieves the path to the directory in which the Directory Server is
   * installed.
   *
   * @return  The path to the directory in which the Directory Server is
   *          installed, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public String getInstanceRoot()
  {
    return instanceRoot;
  }



  /**
   * Retrieves the path to the Java installation used by the server.
   *
   * @return  The path to the Java installation used by the server, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getJavaHome()
  {
    return javaHome;
  }



  /**
   * Retrieves the server's Java vendor string.
   *
   * @return  The server's Java vendor string, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getJavaVendor()
  {
    return javaVendor;
  }



  /**
   * Retrieves the server's Java version string.
   *
   * @return  The server's Java version string, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getJavaVersion()
  {
    return javaVersion;
  }



  /**
   * Retrieves the server's JVM architecture data mode, which should indicate
   * whether the server is running a 32-bit or 64-bit JVM.
   *
   * @return  The server's JVM architecture data model, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getJVMArchitectureDataModel()
  {
    return jvmArchitecture;
  }



  /**
   * Retrieves a list of the arguments provided to the JVM when the server was
   * started.
   *
   * @return  A list of the arguments provided to the JVM when the server was
   *          started, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public String getJVMArguments()
  {
    return jvmArguments;
  }



  /**
   * Retrieves the process ID of the JVM in which the server is running.
   *
   * @return  The process ID of the JVM in which the server is running, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getJVMPID()
  {
    return jvmPID;
  }



  /**
   * Retrieves the server's JVM vendor string.
   *
   * @return  The server's JVM vendor string, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getJVMVendor()
  {
    return jvmVendor;
  }



  /**
   * Retrieves the server's JVM version string.
   *
   * @return  The server's JVM version string, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getJVMVersion()
  {
    return jvmVersion;
  }



  /**
   * Retrieves the maximum amount of memory in bytes that the JVM will be
   * allowed to use.
   *
   * @return  The maximum amount of memory in bytes that the JVM will be allowed
   *          to use, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getMaxMemory()
  {
    return maxMemory;
  }



  /**
   * Retrieves information about the operating system on which the server is
   * running.
   *
   * @return  Information about the operating system on which the server is
   *          running, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public String getOperatingSystem()
  {
    return operatingSystem;
  }



  /**
   * Retrieves the name of the default SSL context protocol that has been
   * selected by the server.
   *
   * @return  The name of the default SSL context protocol that has been
   *          selected by the server.
   */
  @Nullable()
  public String getSSLContextProtocol()
  {
    return sslContextProtocol;
  }



  /**
   * Retrieves the system properties defined in the server JVM, mapped from
   * property name to the corresponding value.
   *
   * @return  The system properties defined in the server JVM, or an empty map
   *          if it was not included in the monitor entry.
   */
  @NotNull()
  public Map<String,String> getSystemProperties()
  {
    return systemProperties;
  }



  /**
   * Retrieves the amount of memory in bytes currently held by the JVM used to
   * run the server.
   *
   * @return  The amount of memory in bytes currently held by the JVM used to
   *          run the server, or {@code null} if it was not included in the
   *          monitor entry
   */
  @Nullable()
  public Long getUsedMemory()
  {
    return usedMemory;
  }



  /**
   * Retrieves the name of the user as whom the server is running.
   *
   * @return  The name of the user as whom the server is running, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getUserName()
  {
    return userName;
  }



  /**
   * Retrieves the path to the server's current working directory.  This is
   * generally the path to the directory from which the server was started.
   *
   * @return  The path to the server's current working directory, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getWorkingDirectory()
  {
    return workingDirectory;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_SYSTEM_INFO_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_SYSTEM_INFO_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(30));

    if (hostname != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HOSTNAME,
           INFO_SYSTEM_INFO_DISPNAME_HOSTNAME.get(),
           INFO_SYSTEM_INFO_DESC_HOSTNAME.get(),
           hostname);
    }

    if (operatingSystem != null)
    {
      addMonitorAttribute(attrs,
           ATTR_OPERATING_SYSTEM,
           INFO_SYSTEM_INFO_DISPNAME_OPERATING_SYSTEM.get(),
           INFO_SYSTEM_INFO_DESC_OPERATING_SYSTEM.get(),
           operatingSystem);
    }

    if (jvmArchitecture != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_ARCHITECTURE,
           INFO_SYSTEM_INFO_DISPNAME_JVM_ARCHITECTURE.get(),
           INFO_SYSTEM_INFO_DESC_JVM_ARCHITECTURE.get(),
           jvmArchitecture);
    }

    if (javaHome != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JAVA_HOME,
           INFO_SYSTEM_INFO_DISPNAME_JAVA_HOME.get(),
           INFO_SYSTEM_INFO_DESC_JAVA_HOME.get(),
           javaHome);
    }

    if (javaVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JAVA_VERSION,
           INFO_SYSTEM_INFO_DISPNAME_JAVA_VERSION.get(),
           INFO_SYSTEM_INFO_DESC_JAVA_VERSION.get(),
           javaVersion);
    }

    if (javaVendor != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JAVA_VENDOR,
           INFO_SYSTEM_INFO_DISPNAME_JAVA_VENDOR.get(),
           INFO_SYSTEM_INFO_DESC_JAVA_VENDOR.get(),
           javaVendor);
    }

    if (jvmVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_VERSION,
           INFO_SYSTEM_INFO_DISPNAME_JVM_VERSION.get(),
           INFO_SYSTEM_INFO_DESC_JVM_VERSION.get(),
           jvmVersion);
    }

    if (jvmVendor != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_VENDOR,
           INFO_SYSTEM_INFO_DISPNAME_JVM_VENDOR.get(),
           INFO_SYSTEM_INFO_DESC_JVM_VENDOR.get(),
           jvmVendor);
    }

    if (jvmArguments != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_ARGUMENTS,
           INFO_SYSTEM_INFO_DISPNAME_JVM_ARGUMENTS.get(),
           INFO_SYSTEM_INFO_DESC_JVM_ARGUMENTS.get(),
           jvmArguments);
    }

    if (jvmPID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_PID,
           INFO_SYSTEM_INFO_DISPNAME_JVM_PID.get(),
           INFO_SYSTEM_INFO_DESC_JVM_PID.get(),
           jvmPID);
    }

    if (sslContextProtocol != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SSL_CONTEXT_PROTOCOL,
           INFO_SYSTEM_INFO_DISPNAME_SSL_CONTEXT_PROTOCOL.get(),
           INFO_SYSTEM_INFO_DESC_SSL_CONTEXT_PROTOCOL.get(),
           sslContextProtocol);
    }

    if (classpath != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CLASSPATH,
           INFO_SYSTEM_INFO_DISPNAME_CLASSPATH.get(),
           INFO_SYSTEM_INFO_DESC_CLASSPATH.get(),
           classpath);
    }

    if (instanceRoot != null)
    {
      addMonitorAttribute(attrs,
           ATTR_INSTANCE_ROOT,
           INFO_SYSTEM_INFO_DISPNAME_INSTANCE_ROOT.get(),
           INFO_SYSTEM_INFO_DESC_INSTANCE_ROOT.get(),
           instanceRoot);
    }

    if (workingDirectory != null)
    {
      addMonitorAttribute(attrs,
           ATTR_WORKING_DIRECTORY,
           INFO_SYSTEM_INFO_DISPNAME_WORKING_DIRECTORY.get(),
           INFO_SYSTEM_INFO_DESC_WORKING_DIRECTORY.get(),
           workingDirectory);
    }

    if (availableCPUs != null)
    {
      addMonitorAttribute(attrs,
           ATTR_AVAILABLE_CPUS,
           INFO_SYSTEM_INFO_DISPNAME_AVAILABLE_CPUS.get(),
           INFO_SYSTEM_INFO_DESC_AVAILABLE_CPUS.get(),
           availableCPUs);
    }

    if (usedMemory != null)
    {
      addMonitorAttribute(attrs,
           ATTR_USED_MEMORY,
           INFO_SYSTEM_INFO_DISPNAME_USED_MEMORY.get(),
           INFO_SYSTEM_INFO_DESC_USED_MEMORY.get(),
           usedMemory);
    }

    if (maxMemory != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_MEMORY,
           INFO_SYSTEM_INFO_DISPNAME_MAX_MEMORY.get(),
           INFO_SYSTEM_INFO_DESC_MAX_MEMORY.get(),
           maxMemory);
    }

    if (freeMemory != null)
    {
      addMonitorAttribute(attrs,
           ATTR_FREE_MEMORY,
           INFO_SYSTEM_INFO_DISPNAME_FREE_MEMORY.get(),
           INFO_SYSTEM_INFO_DESC_FREE_MEMORY.get(),
           freeMemory);
    }

    if (userName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_USER_NAME,
           INFO_SYSTEM_INFO_DISPNAME_USER_NAME.get(),
           INFO_SYSTEM_INFO_DESC_USER_NAME.get(),
           userName);
    }

    if (! environmentVariables.isEmpty())
    {
      final ArrayList<String> envList =
           new ArrayList<>(environmentVariables.size());
      for (final Map.Entry<String,String> e : environmentVariables.entrySet())
      {
        envList.add(e.getKey() + "='" + e.getValue() + '\'');
      }

      addMonitorAttribute(attrs,
           ATTR_ENVIRONMENT_VARIABLE,
           INFO_SYSTEM_INFO_DISPNAME_ENV_VAR.get(),
           INFO_SYSTEM_INFO_DESC_ENV_VAR.get(),
           envList);
    }

    if (! systemProperties.isEmpty())
    {
      final ArrayList<String> propList =
           new ArrayList<>(systemProperties.size());
      for (final Map.Entry<String,String> e : systemProperties.entrySet())
      {
        propList.add(e.getKey() + "='" + e.getValue() + '\'');
      }

      addMonitorAttribute(attrs,
           ATTR_SYSTEM_PROPERTY,
           INFO_SYSTEM_INFO_DISPNAME_SYSTEM_PROP.get(),
           INFO_SYSTEM_INFO_DESC_SYSTEM_PROP.get(),
           propList);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
