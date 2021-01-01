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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a set of utility methods for working with LDAP DNs.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link DN} class should be
 * used instead.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPDN
{
  /**
   * Prevent this class from being instantiated.
   */
  private LDAPDN()
  {
    // No implementation required.
  }



  /**
   * Retrieves a normalized representation of the provided DN.  If the provided
   * string does not represent a valid distinguished name, then the value
   * returned by this method will not be reliable.
   *
   * @param  dn  The string representation of the DN to be normalized.
   *
   * @return  A normalized representation of the provided DN.
   */
  @NotNull()
  public static String normalize(@NotNull final String dn)
  {
    try
    {
      return DN.normalize(dn);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return StaticUtils.toLowerCase(dn.trim());
    }
  }



  /**
   * Explodes the provided DN into individual RDN components.  If the provided
   * string does not represent a valid distinguished name, then the value
   * returned by this method will not be reliable.
   *
   * @param  dn       The DN to be exploded into its RDN components.
   * @param  noTypes  Indicates whether to exclude the attribute names and
   *                  equal signs and only include the values of the RDN
   *                  components.
   *
   * @return  An exploded representation of the provided DN.
   */
  @NotNull()
  public static String[] explodeDN(@NotNull final String dn,
                                   final boolean noTypes)
  {
    try
    {
      final RDN[] rdns = new DN(dn).getRDNs();
      final String[] rdnStrings = new String[rdns.length];
      for (int i=0; i < rdns.length; i++)
      {
        if (noTypes)
        {
          final StringBuilder buffer = new StringBuilder();
          for (final String s : rdns[i].getAttributeValues())
          {
            if (buffer.length() > 0)
            {
              buffer.append('+');
            }
            buffer.append(s);
          }
          rdnStrings[i] = buffer.toString();
        }
        else
        {
          rdnStrings[i] = rdns[i].toString();
        }
      }
      return rdnStrings;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return new String[] { dn };
    }
  }



  /**
   * Explodes the provided RDN into individual name-value pairs.  If the
   * provided string does not represent a valid relative distinguished name,
   * then the value returned by this method will not be reliable.
   *
   * @param  rdn      The RDN to be exploded into its name-value pairs.
   * @param  noTypes  Indicates whether to exclude the attribute names and
   *                  equal signs and only include the values of the components.
   *
   * @return  An exploded representation of the provided DN.
   */
  @NotNull()
  public static String[] explodeRDN(@NotNull final String rdn,
                                    final boolean noTypes)
  {
    try
    {
      final RDN      rdnObject  = new RDN(rdn);

      final String[] values = rdnObject.getAttributeValues();
      if (noTypes)
      {
        return values;
      }

      final String[] names      = rdnObject.getAttributeNames();
      final String[] returnStrs = new String[names.length];

      for (int i=0; i < names.length; i++)
      {
        returnStrs[i] = names[i] + '=' + values[i];
      }

      return returnStrs;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return new String[] { rdn };
    }
  }



  /**
   * Indicates whether the provided strings represent the same distinguished
   * name.
   *
   * @param  dn1  The first DN to be compared.
   * @param  dn2  The second DN to be compared.
   *
   * @return  {@code true} if the provided strings represent the same
   *          distinguished name, or {@code false} if not or if either of the
   *          values cannot be parsed as a valid DN.
   */
  public static boolean equals(@NotNull final String dn1,
                               @NotNull final String dn2)
  {
    try
    {
      return DN.equals(dn1, dn2);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }
  }
}
