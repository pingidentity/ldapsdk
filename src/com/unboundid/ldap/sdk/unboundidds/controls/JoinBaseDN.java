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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.io.Serializable;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a data structure which may be used to indicate the base
 * DN to use for a join request.  See the class-level documentation for the
 * {@link JoinRequestControl} class for additional information and an example
 * demonstrating its use.
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
public final class JoinBaseDN
       implements Serializable
{
  /**
   * The base type which indicates that the base DN for join processing should
   * be the same as the base DN from the search request.
   */
  public static final byte BASE_TYPE_SEARCH_BASE = (byte) 0x80;



  /**
   * The base type which indicates that the base DN for join processing should
   * be the DN of the source entry.
   */
  public static final byte BASE_TYPE_SOURCE_ENTRY_DN = (byte) 0x81;



  /**
   * The base type which indicates that the base DN for join processing should
   * be a custom base DN.
   */
  public static final byte BASE_TYPE_CUSTOM = (byte) 0x82;



  /**
   * The singleton instance that will be used for the "useSearchBaseDN" type.
   */
  @NotNull private static final JoinBaseDN USE_SEARCH_BASE_DN = new JoinBaseDN(
       BASE_TYPE_SEARCH_BASE, null);



  /**
   * The singleton instance that will be used for the "useSourceEntryDN" type.
   */
  @NotNull private static final JoinBaseDN USE_SOURCE_ENTRY_DN = new JoinBaseDN(
       BASE_TYPE_SOURCE_ENTRY_DN, null);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -330303461586380445L;



  // The base type value for this join base DN.
  private final byte type;

  // The base DN value to use if the custom type is used.
  @Nullable private final String customBaseDN;



  /**
   * Creates a new join base DN with the provided information.
   *
   * @param  type          The base type value for this join base DN.
   * @param  customBaseDN  The custom base DN to use, if appropriate.
   */
  private JoinBaseDN(final byte type, @Nullable final String customBaseDN)
  {
    this.type         = type;
    this.customBaseDN = customBaseDN;
  }



  /**
   * Creates a join base DN object which indicates that join processing should
   * use the base DN from the search request.
   *
   * @return  A join base DN object which indicates that join processing should
   *          use the base DN from the search request.
   */
  @NotNull()
  public static JoinBaseDN createUseSearchBaseDN()
  {
    return USE_SEARCH_BASE_DN;
  }



  /**
   * Creates a join base DN object which indicates that join processing should
   * use the DN of the source entry.
   *
   * @return  A join base DN object which indicates that join processing should
   *          use the DN of the source entry.
   */
  @NotNull()
  public static JoinBaseDN createUseSourceEntryDN()
  {
    return USE_SOURCE_ENTRY_DN;
  }



  /**
   * Creates a join base DN object which indicates that join processing should
   * use the provided base DN.
   *
   * @param  baseDN  The custom base DN to use.  It must not be {@code null}.
   *
   * @return  A join base DN object which indicates that join processing should
   *          use the provided base DN.
   */
  @NotNull()
  public static JoinBaseDN createUseCustomBaseDN(@NotNull final String baseDN)
  {
    Validator.ensureNotNull(baseDN);
    return new JoinBaseDN(BASE_TYPE_CUSTOM, baseDN);
  }



  /**
   * Retrieves the base type for this join base DN.
   *
   * @return  The base type for this join base DN.
   */
  public byte getType()
  {
    return type;
  }



  /**
   * Retrieves the base DN value to use for the custom base DN type.
   *
   * @return  The base DN value to use for the custom base DN type, or
   *          {@code null} if the base DN should be the search base DN or the
   *          source entry DN.
   */
  @Nullable()
  public String getCustomBaseDN()
  {
    return customBaseDN;
  }



  /**
   * Encodes this join base DN as appropriate for inclusion in an LDAP join
   * request control.
   *
   * @return  The encoded representation of this join base DN.
   */
  @NotNull()
  ASN1Element encode()
  {
    switch (type)
    {
      case BASE_TYPE_SEARCH_BASE:
      case BASE_TYPE_SOURCE_ENTRY_DN:
        return new ASN1Null(type);

      case BASE_TYPE_CUSTOM:
        return new ASN1OctetString(type, customBaseDN);

      default:
        // This should never happen.
        return null;
    }
  }



  /**
   * Decodes the provided ASN.1 element as a join rule.
   *
   * @param  element  The element to be decoded.
   *
   * @return  The decoded join rule.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided element as a join rule.
   */
  @NotNull()
  static JoinBaseDN decode(@NotNull final ASN1Element element)
         throws LDAPException
  {
    switch (element.getType())
    {
      case BASE_TYPE_SEARCH_BASE:
        return USE_SEARCH_BASE_DN;

      case BASE_TYPE_SOURCE_ENTRY_DN:
        return USE_SOURCE_ENTRY_DN;

      case BASE_TYPE_CUSTOM:
        return new JoinBaseDN(element.getType(),
             element.decodeAsOctetString().stringValue());

      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JOIN_BASE_DECODE_INVALID_TYPE.get(
                  StaticUtils.toHex(element.getType())));
    }
  }



  /**
   * Retrieves a string representation of this join base DN.
   *
   * @return  A string representation of this join base DN.
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
   * Appends a string representation of this join base DN to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    switch (type)
    {
      case BASE_TYPE_SEARCH_BASE:
        buffer.append("useSearchBaseDN");
        break;

      case BASE_TYPE_SOURCE_ENTRY_DN:
        buffer.append("useSourceEntryDN");
        break;

      case BASE_TYPE_CUSTOM:
        buffer.append("useCustomBaseDN(baseDN='");
        buffer.append(customBaseDN);
        buffer.append("')");
        break;
    }
  }
}
