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
import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class contains a data structure which provides information about the
 * value of an LDAP join request control, which may or may not include a nested
 * join.  See the class-level documentation for the {@link JoinRequestControl}
 * class for additional information and an example demonstrating its use.
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
 * The value of the join request control is encoded as follows:
 * <PRE>
 *   LDAPJoin ::= SEQUENCE {
 *        joinRule         JoinRule,
 *        baseObject       CHOICE {
 *             useSearchBaseDN      [0] NULL,
 *             useSourceEntryDN     [1] NULL,
 *             useCustomBaseDN      [2] LDAPDN,
 *             ... },
 *        scope            [0] ENUMERATED {
 *             baseObject             (0),
 *             singleLevel            (1),
 *             wholeSubtree           (2),
 *             subordinateSubtree     (3),
 *             ... } OPTIONAL,
 *        derefAliases     [1] ENUMERATED {
 *             neverDerefAliases       (0),
 *             derefInSearching        (1),
 *             derefFindingBaseObj     (2),
 *             derefAlways             (3),
 *             ... } OPTIONAL,
 *        sizeLimit        [2] INTEGER (0 .. maxInt) OPTIONAL,
 *        filter           [3] Filter OPTIONAL,
 *        attributes       [4] AttributeSelection OPTIONAL,
 *        requireMatch     [5] BOOLEAN DEFAULT FALSE,
 *        nestedJoin       [6] LDAPJoin OPTIONAL,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JoinRequestValue
       implements Serializable
{
  /**
   * The set of attributes that will be used if all user attributes should be
   * requested.
   */
  @NotNull private static final String[] NO_ATTRIBUTES = StaticUtils.NO_STRINGS;



  /**
   * The BER type to use for the scope element.
   */
  private static final byte TYPE_SCOPE = (byte) 0x80;



  /**
   * The BER type to use for the dereference policy element.
   */
  private static final byte TYPE_DEREF_POLICY = (byte) 0x81;



  /**
   * The BER type to use for the size limit element.
   */
  private static final byte TYPE_SIZE_LIMIT = (byte) 0x82;



  /**
   * The BER type to use for the filter element.
   */
  private static final byte TYPE_FILTER = (byte) 0xA3;



  /**
   * The BER type to use for the attributes element.
   */
  private static final byte TYPE_ATTRIBUTES = (byte) 0xA4;



  /**
   * The BER type to use for the require match element.
   */
  private static final byte TYPE_REQUIRE_MATCH = (byte) 0x85;



  /**
   * The BER type to use for the nested join element.
   */
  private static final byte TYPE_NESTED_JOIN = (byte) 0xA6;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4675881185117657177L;



  // Indicates whether to require at least one entry to match the join
  // criteria for the entry to be returned.
  private final boolean requireMatch;

  // The dereference policy for this join request value.
  @Nullable private final DereferencePolicy derefPolicy;

  // The filter for this join request value.
  @Nullable private final Filter filter;

  // The client-requested size limit for this join request value.
  @Nullable private final Integer sizeLimit;

  // The base DN to use for this join request value.
  @NotNull private final JoinBaseDN baseDN;

  // The nested join criteria for this join request value.
  @Nullable private final JoinRequestValue nestedJoin;

  // The join rule for this join request value.
  @NotNull private final JoinRule joinRule;

  // The scope for this join request value.
  @Nullable private final SearchScope scope;

  // The set of attributes to include in entries matching the join criteria.
  @NotNull  private final String[] attributes;



  /**
   * Creates a new join request value with the provided information.
   *
   * @param  joinRule      The join rule for this join request value.  It must
   *                       not be {@code null}.
   * @param  baseDN        The base DN for this join request value.  It must
   *                       not be {@code null}.
   * @param  scope         The scope for this join request value.  It may be
   *                       {@code null} if the scope from the associated search
   *                       request should be used.
   * @param  derefPolicy   The alias dereferencing policy for this join request
   *                       value.  It may be {@code null} if the dereference
   *                       policy from the associated search request should be
   *                       used.
   * @param  sizeLimit     The client-requested maximum number of entries to
   *                       allow when performing the join.  It may be
   *                       {@code null} if the size limit from the associated
   *                       search request should be used.  Note that the server
   *                       will impose a maximum size limit of 1000 entries, so
   *                       size limit values greater than 1000 will be limited
   *                       to 1000.
   * @param  filter        An additional filter which must match target entries
   *                       for them to be included in the join.  This may be
   *                       {@code null} if no additional filter is required and
   *                       the join rule should be the only criteria used when
   *                       performing the join.
   * @param  attributes    The set of attributes that the client wishes to be
   *                       included in joined entries.  It may be {@code null}
   *                       or empty to indicate that all user attributes should
   *                       be included.  It may also contain special values like
   *                       "1.1" to indicate that no attributes should be
   *                       included, "*" to indicate that all user attributes
   *                       should be included, "+" to indicate that all
   *                       operational attributes should be included, or
   *                       "@ocname" to indicate that all required and optional
   *                       attributes associated with the "ocname" object class
   *                       should be included.
   * @param  requireMatch  Indicates whether a search result entry is required
   *                       to be joined with at least one entry for it to be
   *                       returned to the client.
   * @param  nestedJoin    A set of join criteria that should be applied to
   *                       entries joined with this join request value.  It may
   *                       be {@code null} if no nested join is needed.
   */
  public JoinRequestValue(@NotNull final JoinRule joinRule,
                          @NotNull final JoinBaseDN baseDN,
                          @Nullable final SearchScope scope,
                          @Nullable final DereferencePolicy derefPolicy,
                          @Nullable final Integer sizeLimit,
                          @Nullable final Filter filter,
                          @Nullable final String[] attributes,
                          final boolean requireMatch,
                          @Nullable final JoinRequestValue nestedJoin)
  {
    Validator.ensureNotNull(joinRule, baseDN);

    this.joinRule     = joinRule;
    this.baseDN       = baseDN;
    this.scope        = scope;
    this.derefPolicy  = derefPolicy;
    this.sizeLimit    = sizeLimit;
    this.filter       = filter;
    this.requireMatch = requireMatch;
    this.nestedJoin   = nestedJoin;

    if (attributes == null)
    {
      this.attributes = NO_ATTRIBUTES;
    }
    else
    {
      this.attributes = attributes;
    }
  }



  /**
   * Retrieves the join rule for this join request value.
   *
   * @return  The join rule for this join request value.
   */
  @NotNull()
  public JoinRule getJoinRule()
  {
    return joinRule;
  }



  /**
   * Retrieves the join base DN for this join request value.
   *
   * @return  The join base DN for this join request value.
   */
  @NotNull()
  public JoinBaseDN getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the scope for this join request value.
   *
   * @return  The scope for this join request value, or {@code null} if the
   *          scope from the associated search request should be used.
   */
  @Nullable()
  public SearchScope getScope()
  {
    return scope;
  }



  /**
   * Retrieves the alias dereferencing policy for this join request value.
   *
   * @return  The alias dereferencing policy for this join request value, or
   *          {@code null} if the policy from the associated search request
   *          should be used.
   */
  @Nullable()
  public DereferencePolicy getDerefPolicy()
  {
    return derefPolicy;
  }



  /**
   * Retrieves the client-requested size limit for this join request value.
   * Note that the server will impose a maximum size limit of 1000 entries, so
   * if the client-requested size limit is greater than 1000, the server will
   * limit it to 1000 entries.
   *
   * @return  The size limit for this join request value, or {@code null} if the
   *          size limit from the associated search request should be used.
   */
  @Nullable()
  public Integer getSizeLimit()
  {
    return sizeLimit;
  }



  /**
   * Retrieves a filter with additional criteria that must match a target entry
   * for it to be joined with a search result entry.
   *
   * @return  A filter with additional criteria that must match a target entry
   *          for it to be joined with a search result entry, or {@code null} if
   *          no additional filter is needed.
   */
  @Nullable()
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Retrieves the set of requested attributes that should be included in
   * joined entries.
   *
   * @return  The set of requested attributes that should be included in joined
   *          entries, or an empty array if all user attributes should be
   *          requested.
   */
  @NotNull()
  public String[] getAttributes()
  {
    return attributes;
  }



  /**
   * Indicates whether a search result entry will be required to be joined with
   * at least one entry for that entry to be returned to the client.
   *
   * @return  {@code true} if a search result entry must be joined with at least
   *          one other entry for it to be returned to the client, or
   *          {@code false} if a search result entry may be returned even if it
   *          is not joined with any other entries.
   */
  public boolean requireMatch()
  {
    return requireMatch;
  }



  /**
   * Retrieves the nested join for this join request value, if defined.
   *
   * @return  The nested join for this join request value, or {@code null} if
   *          there is no nested join for this join request value.
   */
  @Nullable()
  public JoinRequestValue getNestedJoin()
  {
    return nestedJoin;
  }



  /**
   * Encodes this join request value as appropriate for inclusion in the join
   * request control.
   *
   * @return  The ASN.1 element containing the encoded join request value.
   */
  @NotNull()
  ASN1Element encode()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(9);

    elements.add(joinRule.encode());
    elements.add(baseDN.encode());

    if (scope != null)
    {
      elements.add(new ASN1Enumerated(TYPE_SCOPE, scope.intValue()));
    }

    if (derefPolicy != null)
    {
      elements.add(new ASN1Enumerated(TYPE_DEREF_POLICY,
           derefPolicy.intValue()));
    }

    if (sizeLimit != null)
    {
      elements.add(new ASN1Integer(TYPE_SIZE_LIMIT, sizeLimit));
    }

    if (filter != null)
    {
      elements.add(new ASN1OctetString(TYPE_FILTER, filter.encode().encode()));
    }

    if ((attributes != null) && (attributes.length > 0))
    {
      final ASN1Element[] attrElements = new ASN1Element[attributes.length];
      for (int i=0; i < attributes.length; i++)
      {
        attrElements[i] = new ASN1OctetString(attributes[i]);
      }
      elements.add(new ASN1Sequence(TYPE_ATTRIBUTES, attrElements));
    }

    if (requireMatch)
    {
      elements.add(new ASN1Boolean(TYPE_REQUIRE_MATCH, requireMatch));
    }

    if (nestedJoin != null)
    {
      elements.add(new ASN1OctetString(TYPE_NESTED_JOIN,
           nestedJoin.encode().getValue()));
    }

    return new ASN1Sequence(elements);
  }



  /**
   * Decodes the provided ASN.1 element as a join request value.
   *
   * @param  element  The element to be decoded.
   *
   * @return  The decoded join request value.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a join request value.
   */
  @NotNull()
  static JoinRequestValue decode(@NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final JoinRule   joinRule = JoinRule.decode(elements[0]);
      final JoinBaseDN baseDN   = JoinBaseDN.decode(elements[1]);

      SearchScope       scope        = null;
      DereferencePolicy derefPolicy  = null;
      Integer           sizeLimit    = null;
      Filter            filter       = null;
      String[]          attributes   = NO_ATTRIBUTES;
      boolean           requireMatch = false;
      JoinRequestValue  nestedJoin   = null;

      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_SCOPE:
            scope = SearchScope.valueOf(
                 ASN1Enumerated.decodeAsEnumerated(elements[i]).intValue());
            break;

          case TYPE_DEREF_POLICY:
            derefPolicy = DereferencePolicy.valueOf(
                 ASN1Enumerated.decodeAsEnumerated(elements[i]).intValue());
            break;

          case TYPE_SIZE_LIMIT:
            sizeLimit = ASN1Integer.decodeAsInteger(elements[i]).intValue();
            break;

          case TYPE_FILTER:
            filter = Filter.decode(ASN1Element.decode(elements[i].getValue()));
            break;

          case TYPE_ATTRIBUTES:
            final ASN1Element[] attrElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            final ArrayList<String> attrList =
                 new ArrayList<>(attrElements.length);
            for (final ASN1Element e : attrElements)
            {
              attrList.add(
                   ASN1OctetString.decodeAsOctetString(e).stringValue());
            }

            attributes = new String[attrList.size()];
            attrList.toArray(attributes);
            break;

          case TYPE_REQUIRE_MATCH:
            requireMatch =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_NESTED_JOIN:
            nestedJoin = decode(elements[i]);
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_JOIN_REQUEST_VALUE_INVALID_ELEMENT_TYPE.get(
                      elements[i].getType()));
        }
      }

      return new JoinRequestValue(joinRule, baseDN, scope, derefPolicy,
           sizeLimit, filter, attributes, requireMatch, nestedJoin);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_VALUE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves a string representation of this join request value.
   *
   * @return  A string representation of this join request value.
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
   * Appends a string representation of this join request value to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("JoinRequestValue(joinRule=");
    joinRule.toString(buffer);
    buffer.append(", baseDN=");
    baseDN.toString(buffer);
    buffer.append(", scope=");
    buffer.append(String.valueOf(scope));
    buffer.append(", derefPolicy=");
    buffer.append(String.valueOf(derefPolicy));
    buffer.append(", sizeLimit=");
    buffer.append(sizeLimit);
    buffer.append(", filter=");

    if (filter == null)
    {
      buffer.append("null");
    }
    else
    {
      buffer.append('\'');
      filter.toString(buffer);
      buffer.append('\'');
    }

    buffer.append(", attributes={");

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      buffer.append(attributes[i]);
    }

    buffer.append("}, requireMatch=");
    buffer.append(requireMatch);
    buffer.append(", nestedJoin=");

    if (nestedJoin == null)
    {
      buffer.append("null");
    }
    else
    {
      nestedJoin.toString(buffer);
    }

    buffer.append(')');
  }
}
