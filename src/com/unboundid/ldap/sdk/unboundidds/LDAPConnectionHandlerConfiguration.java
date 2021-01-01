/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides a data structure that holds information about an LDAP
 * connection handler defined in the configuration of a Ping Identity Directory
 * Server instance.  It also provides a utility method for reading a Directory
 * Server configuration file to obtain information about the listener instances
 * it contains, and it implements the {@code Comparable} interface for ranking
 * connection handlers by relative preference for use.
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
public final class LDAPConnectionHandlerConfiguration
       implements Comparable<LDAPConnectionHandlerConfiguration>,
                  Comparator<LDAPConnectionHandlerConfiguration>,
                  Serializable
{
  /**
   * The name of the LDAP object class that will be used in LDAP connection
   * handler configuration entries.
   */
  @NotNull private static final String OC_LDAP_CONN_HANDLER =
       "ds-cfg-ldap-connection-handler";



  /**
   * The name for the LDAP attribute that indicates whether the connection
   * handler allows StartTLS.
   */
  @NotNull private static final String ATTR_ALLOW_START_TLS =
       "ds-cfg-allow-start-tls";



  /**
   * The name fo the LDAP attribute that indicates whether the connection
   * handler is enabled.
   */
  @NotNull private static final String ATTR_ENABLED = "ds-cfg-enabled";



  /**
   * The name for the LDAP attribute that specifies the set of addresses on
   * which the connection handler will listen.
   */
  @NotNull private static final String ATTR_LISTEN_ADDRESS =
       "ds-cfg-listen-address";



  /**
   * The name for the LDAP attribute that specifies the port on which the
   * connection handler will listen.
   */
  @NotNull private static final String ATTR_LISTEN_PORT = "ds-cfg-listen-port";



  /**
   * The name for the LDAP attribute that specifies the name of the connection
   * handler.
   */
  @NotNull private static final String ATTR_NAME = "cn";



  /**
   * The name for the LDAP attribute that indicates whether the connection
   * handler uses SSL.
   */
  @NotNull private static final String ATTR_USE_SSL = "ds-cfg-use-ssl";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6824077978334156627L;



  // Indicates whether the connection handler is enabled for use.
  private final boolean isEnabled;

  // Indicates whether the connection handler supports StartTLS for encrypting
  // communication.
  private final boolean supportsStartTLS;

  // Indicates whether the connection handler uses SSL to encrypt communication.
  private final boolean usesSSL;

  // The port on which the connection handler accepts client connections.
  private final int port;

  // The set of addresses on which the connection handler accepts client
  // connections.
  @NotNull private final List<String> listenAddresses;

  // The name for the connection handler.
  @NotNull private final String name;



  /**
   * Creates a new LDAP connection handler configuration object with the
   * provided information.
   *
   * @param  name              The name for the connection handler.
   * @param  isEnabled         Indicates whether the connection handler is
   *                           enabled for use.
   * @param  listenAddresses   The set of addresses on which the connection
   *                           handler accepts client connections.  It must not
   *                           be {@code null} but may be empty.
   * @param  port              The port on which the connection handler accepts
   *                           client connections.
   * @param  usesSSL           Indicates whether the connection handler uses
   *                           SSL to encrypt communication.
   * @param  supportsStartTLS  Indicates whether the connection handler supports
   *                           StartTLS for encrypting communication.
   */
  LDAPConnectionHandlerConfiguration(@NotNull final String name,
       final boolean isEnabled, @NotNull final List<String> listenAddresses,
       final int port, final boolean usesSSL, final boolean supportsStartTLS)
  {
    this.name = name;
    this.isEnabled = isEnabled;
    this.listenAddresses = listenAddresses;
    this.port = port;
    this.usesSSL = usesSSL;
    this.supportsStartTLS = supportsStartTLS;
  }



  /**
   * Retrieves the name for the connection handler.
   *
   * @return  The name for the connection handler.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Indicates whether the connection handler is enabled for use.
   *
   * @return  {@code true} if the connection handler is enabled, or
   *          {@code false} if not.
   */
  public boolean isEnabled()
  {
    return isEnabled;
  }



  /**
   * Retrieves the set of addresses on which the connection handler accepts
   * client connections, if available.
   *
   * @return  The set of addresses on which the connection handler accepts
   *          client connections, or an empty set if the connection handler
   *          listens on all addresses on all interfaces.
   */
  @NotNull()
  public List<String> getListenAddresses()
  {
    return listenAddresses;
  }



  /**
   * Retrieves the port on which the connection handler accepts client
   * connections.
   *
   * @return  The port on which the connection handler accepts client
   *          connections.
   */
  public int getPort()
  {
    return port;
  }



  /**
   * Indicates whether the connection handler uses SSL to encrypt communication.
   *
   * @return  {@code true} if the connection handler uses SSL to encrypt
   *          communication, or {@code false} if not.
   */
  public boolean usesSSL()
  {
    return usesSSL;
  }



  /**
   * Indicates whether the connection handler supports StartTLS for encrypting
   * communication.
   *
   * @return  {@code true} if the connection handler supports StartTLS for
   *          encrypting communication, or {@code false} if not.
   */
  public boolean supportsStartTLS()
  {
    return supportsStartTLS;
  }



  /**
   * Retrieves the LDAP connection handler configuration objects from the
   * specified configuration file.  The configuration objects will be ordered
   * from most preferred to least preferred, using the logic described in the
   * {@link #compareTo} method documentation.
   *
   * @param  configFile   The configuration file to examine.  It must not be
   *                      {@code null}, and it must exist.
   * @param  onlyEnabled  Indicates whether to only include information about
   *                      connection handlers that are enabled.
   *
   * @return  A list of the LDAP connection handler configuration objects read
   *          from the specified configuration file, or an empty set if no LDAP
   *          connection handler configuration entries were found in the
   *          configuration.
   *
   * @throws  LDAPException  If a problem interferes with reading the
   *                         connection handler configuration objects from the
   *                         configuration file.
   */
  @NotNull()
  public static List<LDAPConnectionHandlerConfiguration> readConfiguration(
                     @NotNull final File configFile, final boolean onlyEnabled)
         throws LDAPException
  {
    try (LDIFReader ldifReader = new LDIFReader(configFile))
    {
      final List<LDAPConnectionHandlerConfiguration> configs =
           new ArrayList<>();
      while (true)
      {
        final Entry entry;
        try
        {
          entry = ldifReader.readEntry();
        }
        catch (final LDIFException e)
        {
          Debug.debugException(e);
          if (e.mayContinueReading())
          {
            continue;
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_LDAP_HANDLER_CANNOT_READ_CONFIG.get(
                      configFile.getAbsolutePath(),
                      StaticUtils.getExceptionMessage(e)));
          }
        }

        if (entry == null)
        {
          break;
        }

        if (! entry.hasObjectClass(OC_LDAP_CONN_HANDLER))
        {
          continue;
        }

        final String name = entry.getAttributeValue(ATTR_NAME);
        if (name == null)
        {
          continue;
        }

        final boolean isEnabled =
             entry.hasAttributeValue(ATTR_ENABLED, "true");
        if ((! isEnabled) && onlyEnabled)
        {
          continue;
        }

        final Integer port = entry.getAttributeValueAsInteger(ATTR_LISTEN_PORT);
        if ((port == null) || (port < 1) || (port > 65535))
        {
          continue;
        }


        final boolean usesSSL = entry.hasAttributeValue(ATTR_USE_SSL, "true");

        final boolean supportsStartTLS;
        if (usesSSL)
        {
          supportsStartTLS = false;
        }
        else
        {
          supportsStartTLS =
               entry.hasAttributeValue(ATTR_ALLOW_START_TLS, "true");
        }

        final List<String> listenAddresses;
        final String[] addressArray =
             entry.getAttributeValues(ATTR_LISTEN_ADDRESS);
        if (addressArray == null)
        {
          listenAddresses = Collections.emptyList();
        }
        else
        {
          final Set<String> s = new LinkedHashSet<>();
          for (final String address : addressArray)
          {
            try
            {
              final InetAddress a = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
                   getByName(address);
              if (a.isAnyLocalAddress())
              {
                continue;
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }

            s.add(address);
          }

          listenAddresses = Collections.unmodifiableList(new ArrayList<>(s));
        }

        configs.add(new LDAPConnectionHandlerConfiguration(name, isEnabled,
             listenAddresses, port, usesSSL, supportsStartTLS));
      }

      if (configs.size() <= 1)
      {
        return Collections.unmodifiableList(configs);
      }

      final SortedSet<LDAPConnectionHandlerConfiguration> configSet =
           new TreeSet<>(configs.get(0));
      configSet.addAll(configs);
      return Collections.unmodifiableList(new ArrayList<>(configSet));
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAP_HANDLER_CANNOT_READ_CONFIG.get(configFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)));
    }
  }



  /**
   * Retrieves a hash code for the connection handler configuration.
   *
   * @return  A hash code for the connection handler configuration.
   */
  @Override()
  public int hashCode()
  {
    return name.toLowerCase().hashCode();
  }



  /**
   * Indicates whether the provided object is considered logically equivalent to
   * this LDAP connection handler configuration.
   *
   * @param  o  If the provided object is considered logically equivalent to
   *            this LDAP connection handler configuration, or {@code false} if
   *            not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof LDAPConnectionHandlerConfiguration))
    {
      return false;
    }

    final LDAPConnectionHandlerConfiguration c =
         (LDAPConnectionHandlerConfiguration) o;
    return (name.equalsIgnoreCase(c.name) &&
         (isEnabled == c.isEnabled) &&
         listenAddresses.equals(c.listenAddresses) &&
         (port == c.port) &&
         (usesSSL == c.usesSSL) &&
         (supportsStartTLS == c.supportsStartTLS));
  }



  /**
   * Compares the provided configuration to this configuration to determine the
   * relative orders in which they should appear in a supported list.  Sorting
   * will use the following criteria:
   * <UL>
   *   <LI>Connection handlers that are enabled will be ordered before those
   *       that are disabled.</LI>
   *   <LI>Connection handlers that use SSL will be ordered before those that
   *       support StartTLS, and those that support StartTLS will be ordered
   *       before those that do not support StartTLS.</LI>
   *   <LI>An SSL-enabled connection handler named "LDAPS Connection Handler"
   *       will be ordered before an SSL-enabled connection handler with some
   *       other name.  A non-SSL-enabled connection handler named "LDAP
   *       Connection Handler" will be ordered before a non-SSL-enabled
   *       connection handler with some other name.</LI>
   *   <LI>Connection handlers that do not use listen addresses (and therefore
   *       listen on all interfaces) will be ordered before those that are
   *       configured with one or more listen addresses.</LI>
   *   <LI>Connection handlers with a lower port number will be ordered before
   *       those with a higher port number.</LI>
   *   <LI>As a last resort, then connection handlers will be ordered
   *       lexicographically by name.</LI>
   * </UL>
   *
   * @param  config  The LDAP connection handler configuration to compare
   *                 against this configuration.
   *
   * @return  A negative value if this configuration should be ordered before
   *          the provided configuration, a positive value if the provided
   *          configuration should be ordered before this configuration, or
   *          zero if the configurations are considered logically equivalent.
   */
  @Override()
  public int compareTo(
       @Nullable final LDAPConnectionHandlerConfiguration config)
  {
    if (config == null)
    {
      return -1;
    }

    if (isEnabled != config.isEnabled)
    {
      if (isEnabled)
      {
        return -1;
      }
      else
      {
        return 1;
      }
    }

    if (usesSSL != config.usesSSL)
    {
      if (usesSSL)
      {
        return -1;
      }
      else
      {
        return 1;
      }
    }

    if (supportsStartTLS != config.supportsStartTLS)
    {
      if (supportsStartTLS)
      {
        return -1;
      }
      else
      {
        return 1;
      }
    }

    if (! name.equalsIgnoreCase(config.name))
    {
      if (usesSSL)
      {
        if (name.equalsIgnoreCase("LDAPS Connection Handler"))
        {
          return -1;
        }

        if (config.name.equalsIgnoreCase("LDAPS Connection Handler"))
        {
          return 1;
        }
      }
      else
      {
        if (name.equalsIgnoreCase("LDAP Connection Handler"))
        {
          return -1;
        }

        if (config.name.equalsIgnoreCase("LDAP Connection Handler"))
        {
          return 1;
        }
      }
    }


    if (! listenAddresses.equals(config.listenAddresses))
    {
      if (listenAddresses.isEmpty())
      {
        return -1;
      }
      else if (config.listenAddresses.isEmpty())
      {
        return 1;
      }
    }

    if (port != config.port)
    {
      if (port < config.port)
      {
        return -1;
      }
      else
      {
        return 1;
      }
    }

    return name.toLowerCase().compareTo(config.name.toLowerCase());
  }



  /**
   * Compares the provided configurations to determine their relative orders in
   * which they should appear in a supported list.  Sorting will use the
   * criteria described in the documentation for the {@link #compareTo} method.
   *
   * @param  c1  The first LDAP connection handler configuration to compare.
   * @param  c2  The second LDAP connection handler configuration to compare.
   *
   * @return  A negative value if the first configuration should be ordered
   *          before the second configuration, a positive value if the first
   *          configuration should be ordered after the second configuration, or
   *          zero if the configurations are considered logically equivalent.
   */
  @Override()
  public int compare(@NotNull final LDAPConnectionHandlerConfiguration c1,
                     @NotNull final LDAPConnectionHandlerConfiguration c2)
  {
    return c1.compareTo(c2);
  }



  /**
   * Retrieves a string representation of this LDAP connection handler
   * configuration.
   *
   * @return  A string representation of this LDAP connection handler
   *          configuration.
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
   * Appends a string representation of this LDAP connection handler
   * configuration to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionHandlerConfiguration(name='");
    buffer.append(name);
    buffer.append("', isEnabled=");
    buffer.append(isEnabled);
    buffer.append(", usesSSL=");
    buffer.append(usesSSL);
    buffer.append(", supportsStartTLS=");
    buffer.append(supportsStartTLS);
    buffer.append(", listenAddresses={");

    final Iterator<String> iterator = listenAddresses.iterator();
    while (iterator.hasNext())
    {
      buffer.append(" '");
      buffer.append(iterator.next());
      buffer.append('\'');

      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append(" }, listenPort=");
    buffer.append(port);
    buffer.append(')');
  }
}
