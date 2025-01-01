/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides helper functions for access log field syntax
 * implementations that operate on fields whose values contain one or more
 * attribute names and values.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class AttributeBasedLogFieldSyntaxHelper
{
  /**
   * Prevents this utility class from being instantiated.
   */
  private AttributeBasedLogFieldSyntaxHelper()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a set containing the lowercase names and OIDs of the provided
   * attributes, potentially including alternative names and OIDs for the
   * attributes.
   *
   * @param  schema  The schema to use in processing.  If this is
   *                 non-{@code null}, then the returned set will include the
   *                 OID and all names for each attribute in the set that is
   *                 defined in the schema.  If this is {@code null}, or if the
   *                 provided schema does not include an attribute type for any
   *                 of the named attributes, then only the provided name will
   *                 be included in the resulting set.
   * @param  attrs   The names or OIDs of attributes to include in the set.  It
   *                 may be {@code null} or empty if the resulting set should be
   *                 empty.
   *
   * @return  A set containing the lowercase names and OIDs of the provided
   *          attributes.
   */
  @NotNull()
  static Set<String> getAttributeSet(@Nullable final Schema schema,
                                     @Nullable final Collection<String> attrs)
  {
    if ((attrs == null) || attrs.isEmpty())
    {
      return Collections.emptySet();
    }

    final Set<String> attrSet = new HashSet<>();
    for (final String attr : attrs)
    {
      final AttributeTypeDefinition attrType;
      if (schema == null)
      {
        attrType = null;
      }
      else
      {
        attrType = schema.getAttributeType(attr);
      }

      if (attrType == null)
      {
        attrSet.add(StaticUtils.toLowerCase(attr));
      }
      else
      {
        attrSet.add(StaticUtils.toLowerCase(attrType.getOID()));
        for (final String name : attrType.getNames())
        {
          attrSet.add(StaticUtils.toLowerCase(name));
        }
      }
    }

    return Collections.unmodifiableSet(attrSet);
  }



  /**
   * Obtains a token for the specified attribute value.
   *
   * @param  syntax          The associated log field syntax instance.  It must
   *                         not be {@code null}.
   * @param  schema          The schema to use in processing.  It may be
   *                         {@code null} if no schema is available.
   * @param  attributeName   The name of the attribute containing the provided
   *                         value.  It must not be {@code null}.
   * @param  attributeValue  The attribute value to tokenize.  It must not be
   *                         {@code null}.
   * @param  pepper          A pepper used to provide brute-force protection for
   *                         the resulting token.  The pepper value should be
   *                         kept secret so that it is not available to
   *                         unauthorized users who might be able to view log
   *                         information, although the same pepper value should
   *                         be consistently provided when tokenizing values so
   *                         that the same value will consistently yield the
   *                         same token.  It must not be {@code null} and should
   *                         not be empty.
   *
   * @return  The token for the provided attribute value.
   */
  @NotNull()
  static String tokenizeValue(@NotNull final LogFieldSyntax<?> syntax,
                              @Nullable final Schema schema,
                              @NotNull final String attributeName,
                              @NotNull final byte[] attributeValue,
                              @NotNull final byte[] pepper)
  {
    // Normalize the attribute value.
    ASN1OctetString normalizedValue;
    final ASN1OctetString nonNormalizedValue =
         new ASN1OctetString(attributeValue);
    try
    {
      final MatchingRule matchingRule = MatchingRule.selectEqualityMatchingRule(
           attributeName, schema);
      normalizedValue = matchingRule.normalize(nonNormalizedValue);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      normalizedValue = nonNormalizedValue;
    }


    // Tokenize the normalized value.
    final ByteStringBuffer tokenizeBuffer = syntax.getTemporaryBuffer();
    try
    {
      syntax.tokenize(normalizedValue.getValue(), pepper, tokenizeBuffer);
      return tokenizeBuffer.toString();
    }
    finally
    {
      syntax.releaseTemporaryBuffer(tokenizeBuffer);
    }
  }
}
