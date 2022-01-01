/*
 * Copyright 2021-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2022 Ping Identity Corporation
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
 * Copyright (C) 2021-2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used to represent a DN for
 * use in the {@link LDAPDiff} tool in a form that is as compact as possible.
 * The stored value will be the bytes that comprise the normalized
 * representation of a DN, but with the common base DN stripped off, and with
 * the RDNs in reverse order, which makes it fast to sort DNs lexicographically.
 * For example, if the common base DN is "dc=example,dc=com", the compact
 * representation of "uid=test.user,ou=People,dc=example,dc=com" would be the
 * bytes of the string "ou=people,uid=test.user".
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
final class LDAPDiffCompactDN
      implements Serializable, Comparable<LDAPDiffCompactDN>
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final   long   serialVersionUID = 7451332045273475301L;



  // The bytes that are used to store this compact representation.
  @NotNull private final byte[] compactDNBytes;



  /**
   * Creates a new compact DN from the provided information.
   *
   * @param  dn            The DN to represent.  It must not be {@code null},
   *                       and it must be equivalent or subordinate to the
   *                       provided common base DN.
   * @param  commonBaseDN  The common base DN that will be stripped off from
   *                       the provided DN.  It must not be {@code null}.
   */
  LDAPDiffCompactDN(@NotNull final DN dn, @NotNull final DN commonBaseDN)
  {
    final RDN[] rdns = dn.getRDNs();
    final RDN[] commonRDNs = commonBaseDN.getRDNs();
    final int numRDNsToPreserve = rdns.length - commonRDNs.length;

    final RDN[] reversedRDNsWithoutCommonBaseDN = new RDN[numRDNsToPreserve];
    for (int i=0; i < numRDNsToPreserve; i++)
    {
      reversedRDNsWithoutCommonBaseDN[i] = rdns[numRDNsToPreserve - i - 1];
    }

    final DN compactDN = new DN(reversedRDNsWithoutCommonBaseDN);
    compactDNBytes = StaticUtils.getBytes(compactDN.toNormalizedString());
  }



  /**
   * Converts this compact DN to a full DN with the provided information.
   *
   * @param  commonBaseDN  The common base DN that will be appended to the
   *                       RDN components extracted from this compact DN.  It
   *                       must not be {@code null}.
   * @param  schema        The schema to use for the DN that is created.  It may
   *                       optionally be {@code null} if no schema is available.
   *
   * @return  The full DN created from this compact DN.
   */
  @NotNull()
  DN toDN(@NotNull final DN commonBaseDN, @Nullable final Schema schema)
  {
    try
    {
      if (compactDNBytes.length == 0)
      {
        return commonBaseDN;
      }

      final DN compactDN =
           new DN(StaticUtils.toUTF8String(compactDNBytes), schema);
      final RDN[] compactRDNs = compactDN.getRDNs();

      final RDN[] commonRDNs = commonBaseDN.getRDNs();
      final List<RDN> rdnList =
           new ArrayList<>(compactRDNs.length + commonRDNs.length);
      for (int i=(compactRDNs.length - 1); i >= 0; i--)
      {
        rdnList.add(compactRDNs[i]);
      }

      for (final RDN commonRDN : commonRDNs)
      {
        rdnList.add(commonRDN);
      }

      return new DN(rdnList);
    }
    catch (final LDAPException e)
    {
      // This should never happen, but if it does, then throw a runtime
      // exception.
      Debug.debugException(e);
      throw new LDAPRuntimeException(e);
    }
  }



  /**
   * Retrieves an integer value that indicates the order in which this compact
   * DN should appear relative to the provided compact DN in an ordered list.
   * It uses a lexicographic comparison.
   *
   * @param  compactDN  The compact DN to compare to this compact DN.  It must
   *                    not be {@code null}.
   *
   * @return  A negative value if this compact DN should appear before the
   *          provided compact DN in an ordered list, a positive value if this
   *          compact DN should appear after the provided compact DN in an
   *          ordered list, or zero if the provided compact DN is equivalent to
   *          this compact DN.
   */
  @Override()
  public int compareTo(@NotNull final LDAPDiffCompactDN compactDN)
  {
    final int minLength =
         Math.min(compactDNBytes.length, compactDN.compactDNBytes.length);
    for (int i=0; i < minLength; i++)
    {
      final byte thisByte = compactDNBytes[i];
      final byte thatByte = compactDN.compactDNBytes[i];
      if (thisByte < thatByte)
      {
        return -1;
      }
      else if (thisByte > thatByte)
      {
        return 1;
      }
    }

    return compactDNBytes.length - compactDN.compactDNBytes.length;
  }



  /**
   * Retrieves a hash code for this compact DN.
   *
   * @return  A hash code for this compact DN.
   */
  @Override()
  public int hashCode()
  {
    return Arrays.hashCode(compactDNBytes);
  }



  /**
   * Indicates whether the provided object is considered equivalent to this
   * compact DN.
   *
   * @param  o  The object for which to make the determination.  It may
   *            optionally be {@code null}.
   *
   * @return  {@code true} if the provided object is considered equivalent to
   *          this compact DN, or {@code false} if not.
   */
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

    if (o instanceof LDAPDiffCompactDN)
    {
      return Arrays.equals(compactDNBytes,
           ((LDAPDiffCompactDN) o).compactDNBytes);
    }
    else
    {
      return false;
    }
  }



  /**
   * Retrieves a string representation of this compact DN.
   *
   * @return  A string representation of this compact DN.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return StaticUtils.toUTF8String(compactDNBytes);
  }
}
