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
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
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
 * This class provides an implementation of a join rule as used by the LDAP join
 * request control.  See the class-level documentation for the
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
 * <BR>
 * Join rules are encoded as follows:
 * <PRE>
 *   JoinRule ::= CHOICE {
 *        and               [0] SET (1 .. MAX) of JoinRule,
 *        or                [1] SET (1 .. MAX) of JoinRule,
 *        dnJoin            [2] AttributeDescription,
 *        equalityJoin      [3] JoinRuleAssertion,
 *        containsJoin      [4] JoinRuleAssertion,
 *        reverseDNJoin     [5] AttributeDescription,
 *        ... }
 *
 *   JoinRuleAssertion ::= SEQUENCE {
 *        sourceAttribute     AttributeDescription,
 *        targetAttribute     AttributeDescription,
 *        matchAll            BOOLEAN DEFAULT FALSE }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JoinRule
       implements Serializable
{
  /**
   * The join rule type that will be used for AND join rules.
   */
  public static final byte JOIN_TYPE_AND = (byte) 0xA0;



  /**
   * The join rule type that will be used for OR join rules.
   */
  public static final byte JOIN_TYPE_OR = (byte) 0xA1;



  /**
   * The join rule type that will be used for DN join rules.
   */
  public static final byte JOIN_TYPE_DN = (byte) 0x82;



  /**
   * The join rule type that will be used for equality join rules.
   */
  public static final byte JOIN_TYPE_EQUALITY = (byte) 0xA3;



  /**
   * The join rule type that will be used for contains join rules.
   */
  public static final byte JOIN_TYPE_CONTAINS = (byte) 0xA4;



  /**
   * The join rule type that will be used for reverse DN join rules.
   */
  public static final byte JOIN_TYPE_REVERSE_DN = (byte) 0x85;



  /**
   * An empty array of join rules that will be used as the set of components
   * for DN and equality join rules.
   */
  @NotNull private static final JoinRule[] NO_RULES = new JoinRule[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9041070342511946580L;



  // Indicates whether all values of a multivalued source attribute must be
  // present in the target entry for it to be considered a match.
  private final boolean matchAll;

  // The BER type for this join rule.
  private final byte type;

  // The set of subordinate components for this join rule.
  @NotNull private final JoinRule[] components;

  // The name of the source attribute for this join rule.
  @Nullable private final String sourceAttribute;

  // The name of the target attribute for this join rule.
  @Nullable private final String targetAttribute;



  /**
   * Creates a new join rule with the provided information.
   *
   * @param  type             The BER type for this join rule.
   * @param  components       The set of subordinate components for this join
   *                          rule.
   * @param  sourceAttribute  The name of the source attribute for this join
   *                          rule.
   * @param  targetAttribute  The name of the target attribute for this join
   *                          rule.
   * @param  matchAll         Indicates whether all values of a multivalued
   *                          source attribute must be present in the target
   *                          entry for it to be considered a match.
   */
  private JoinRule(final byte type, @NotNull final JoinRule[] components,
                   @Nullable final String sourceAttribute,
                   @Nullable final String targetAttribute,
                   final boolean matchAll)
  {
    this.type            = type;
    this.components      = components;
    this.sourceAttribute = sourceAttribute;
    this.targetAttribute = targetAttribute;
    this.matchAll        = matchAll;
  }



  /**
   * Creates an AND join rule in which all of the contained join rules must
   * match an entry for it to be included in the join.
   *
   * @param  components  The set of components to include in this join.  It must
   *                     not be {@code null} or empty.
   *
   * @return  The created AND join rule.
   */
  @NotNull()
  public static JoinRule createANDRule(@NotNull final JoinRule... components)
  {
    Validator.ensureNotNull(components);
    Validator.ensureFalse(components.length == 0);

    return new JoinRule(JOIN_TYPE_AND, components, null, null, false);
  }



  /**
   * Creates an AND join rule in which all of the contained join rules must
   * match an entry for it to be included in the join.
   *
   * @param  components  The set of components to include in this join.  It must
   *                     not be {@code null} or empty.
   *
   * @return  The created AND join rule.
   */
  @NotNull()
  public static JoinRule createANDRule(@NotNull final List<JoinRule> components)
  {
    Validator.ensureNotNull(components);
    Validator.ensureFalse(components.isEmpty());

    final JoinRule[] compArray = new JoinRule[components.size()];
    return new JoinRule(JOIN_TYPE_AND, components.toArray(compArray), null,
                        null, false);
  }



  /**
   * Creates an OR join rule in which at least one of the contained join rules
   * must match an entry for it to be included in the join.
   *
   * @param  components  The set of components to include in this join.  It must
   *                     not be {@code null} or empty.
   *
   * @return  The created OR join rule.
   */
  @NotNull()
  public static JoinRule createORRule(@NotNull final JoinRule... components)
  {
    Validator.ensureNotNull(components);
    Validator.ensureFalse(components.length == 0);

    return new JoinRule(JOIN_TYPE_OR, components, null, null, false);
  }



  /**
   * Creates an OR join rule in which at least one of the contained join rules
   * must match an entry for it to be included in the join.
   *
   * @param  components  The set of components to include in this join.  It must
   *                     not be {@code null} or empty.
   *
   * @return  The created OR join rule.
   */
  @NotNull()
  public static JoinRule createORRule(@NotNull final List<JoinRule> components)
  {
    Validator.ensureNotNull(components);
    Validator.ensureFalse(components.isEmpty());

    final JoinRule[] compArray = new JoinRule[components.size()];
    return new JoinRule(JOIN_TYPE_OR, components.toArray(compArray), null,
                        null, false);
  }



  /**
   * Creates a DN join rule in which the value(s) of the source attribute must
   * specify the DN(s) of the target entries to include in the join.
   *
   * @param  sourceAttribute  The name or OID of the attribute in the source
   *                          entry whose values contain the DNs of the entries
   *                          to be included in the join.  It must not be
   *                          {@code null}, and it must be associated with a
   *                          distinguished name or name and optional UID
   *                          syntax.
   *
   * @return  The created DN join rule.
   */
  @NotNull()
  public static JoinRule createDNJoin(@NotNull final String sourceAttribute)
  {
    Validator.ensureNotNull(sourceAttribute);

    return new JoinRule(JOIN_TYPE_DN, NO_RULES, sourceAttribute, null, false);
  }



  /**
   * Creates an equality join rule in which the value(s) of the source attribute
   * in the source entry must be equal to the value(s) of the target attribute
   * of a target entry for it to be included in the join.
   *
   * @param  sourceAttribute  The name or OID of the attribute in the source
   *                          entry whose value(s) should be matched in target
   *                          entries to be included in the join.  It must not
   *                          be {@code null}.
   * @param  targetAttribute  The name or OID of the attribute whose value(s)
   *                          must match the source value(s) in entries included
   *                          in the join.  It must not be {@code null}.
   * @param  matchAll         Indicates whether all values of a multivalued
   *                          source attribute must be present in the target
   *                          entry for it to be considered a match.
   *
   * @return  The created equality join rule.
   */
  @NotNull()
  public static JoinRule createEqualityJoin(
              @NotNull final String sourceAttribute,
              @NotNull final String targetAttribute,
              final boolean matchAll)
  {
    Validator.ensureNotNull(sourceAttribute, targetAttribute);

    return new JoinRule(JOIN_TYPE_EQUALITY, NO_RULES, sourceAttribute,
                        targetAttribute, matchAll);
  }



  /**
   * Creates an equality join rule in which the value(s) of the source attribute
   * in the source entry must be equal to or a substring of the value(s) of the
   * target attribute of a target entry for it to be included in the join.
   *
   * @param  sourceAttribute  The name or OID of the attribute in the source
   *                          entry whose value(s) should be matched in target
   *                          entries to be included in the join.  It must not
   *                          be {@code null}.
   * @param  targetAttribute  The name or OID of the attribute whose value(s)
   *                          must equal or contain the source value(s) in
   *                          entries included in the join.  It must not be
   *                          {@code null}.
   * @param  matchAll         Indicates whether all values of a multivalued
   *                          source attribute must be present in the target
   *                          entry for it to be considered a match.
   *
   * @return  The created equality join rule.
   */
  @NotNull()
  public static JoinRule createContainsJoin(
              @NotNull final String sourceAttribute,
              @NotNull final String targetAttribute,
              final boolean matchAll)
  {
    Validator.ensureNotNull(sourceAttribute, targetAttribute);

    return new JoinRule(JOIN_TYPE_CONTAINS, NO_RULES, sourceAttribute,
                        targetAttribute, matchAll);
  }



  /**
   * Creates a reverse DN join rule in which the target entries to include in
   * the join must include a specified attribute that contains the DN of the
   * source entry.
   *
   * @param  targetAttribute  The name or OID of the attribute in the target
   *                          entries which must contain the DN of the source
   *                          entry.  It must not be {@code null}, and it must
   *                          be associated with a distinguished nme or name and
   *                          optional UID syntax.
   *
   * @return  The created reverse DN join rule.
   */
  @NotNull()
  public static JoinRule createReverseDNJoin(
              @NotNull final String targetAttribute)
  {
    Validator.ensureNotNull(targetAttribute);

    return new JoinRule(JOIN_TYPE_REVERSE_DN, NO_RULES, null, targetAttribute,
         false);
  }



  /**
   * Retrieves the join rule type for this join rule.
   *
   * @return  The join rule type for this join rule.
   */
  public byte getType()
  {
    return type;
  }



  /**
   * Retrieves the set of subordinate components for this AND or OR join rule.
   *
   * @return  The set of subordinate components for this AND or OR join rule, or
   *          an empty list if this is not an AND or OR join rule.
   */
  @NotNull()
  public JoinRule[] getComponents()
  {
    return components;
  }



  /**
   * Retrieves the name of the source attribute for this DN, equality, or
   * contains join rule.
   *
   * @return  The name of the source attribute for this DN, equality, or
   *          contains join rule, or {@code null} if this is some other type of
   *          join rule.
   */
  @Nullable()
  public String getSourceAttribute()
  {
    return sourceAttribute;
  }



  /**
   * Retrieves the name of the target attribute for this reverse DN, equality,
   * or contains join rule.
   *
   * @return  The name of the target attribute for this reverse DN, equality, or
   *          contains join rule, or {@code null} if this is some other type of
   *          join rule.
   */
  @Nullable()
  public String getTargetAttribute()
  {
    return targetAttribute;
  }



  /**
   * Indicates whether all values of a multivalued source attribute must be
   * present in a target entry for it to be considered a match.  The return
   * value will only be meaningful for equality join rules.
   *
   * @return  {@code true} if all values of the source attribute must be
   *          included in the target attribute of an entry for it to be
   *          considered for inclusion in the join, or {@code false} if it is
   *          only necessary for at least one of the values to be included in a
   *          target entry for it to be considered for inclusion in the join.
   */
  public boolean matchAll()
  {
    return matchAll;
  }



  /**
   * Encodes this join rule as appropriate for inclusion in an LDAP join
   * request control.
   *
   * @return  The encoded representation of this join rule.
   */
  @NotNull()
  ASN1Element encode()
  {
    switch (type)
    {
      case JOIN_TYPE_AND:
      case JOIN_TYPE_OR:
        final ASN1Element[] compElements = new ASN1Element[components.length];
        for (int i=0; i < components.length; i++)
        {
          compElements[i] = components[i].encode();
        }
        return new ASN1Set(type, compElements);

      case JOIN_TYPE_DN:
        return new ASN1OctetString(type, sourceAttribute);

      case JOIN_TYPE_EQUALITY:
      case JOIN_TYPE_CONTAINS:
        if (matchAll)
        {
          return new ASN1Sequence(type,
               new ASN1OctetString(sourceAttribute),
               new ASN1OctetString(targetAttribute),
               new ASN1Boolean(matchAll));
        }
        else
        {
          return new ASN1Sequence(type,
               new ASN1OctetString(sourceAttribute),
               new ASN1OctetString(targetAttribute));
        }
    case JOIN_TYPE_REVERSE_DN:
      return new ASN1OctetString(type, targetAttribute);

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
  static JoinRule decode(@NotNull final ASN1Element element)
         throws LDAPException
  {
    final byte elementType = element.getType();
    switch (elementType)
    {
      case JOIN_TYPE_AND:
      case JOIN_TYPE_OR:
        try
        {
          final ASN1Element[] elements =
               ASN1Set.decodeAsSet(element).elements();
          final JoinRule[] rules = new JoinRule[elements.length];
          for (int i=0; i < rules.length; i++)
          {
            rules[i] = decode(elements[i]);
          }

          return new JoinRule(elementType, rules, null, null, false);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_RULE_CANNOT_DECODE.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }


      case JOIN_TYPE_DN:
        return new JoinRule(elementType, NO_RULES,
             ASN1OctetString.decodeAsOctetString(element).stringValue(), null,
             false);


      case JOIN_TYPE_EQUALITY:
      case JOIN_TYPE_CONTAINS:
        try
        {
          final ASN1Element[] elements =
               ASN1Sequence.decodeAsSequence(element).elements();

          final String sourceAttribute =
               elements[0].decodeAsOctetString().stringValue();
          final String targetAttribute =
               elements[1].decodeAsOctetString().stringValue();

          boolean matchAll = false;
          if (elements.length == 3)
          {
            matchAll = elements[2].decodeAsBoolean().booleanValue();
          }

          return new JoinRule(elementType, NO_RULES, sourceAttribute,
               targetAttribute, matchAll);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_RULE_CANNOT_DECODE.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }


    case JOIN_TYPE_REVERSE_DN:
      return new JoinRule(elementType, NO_RULES, null,
           ASN1OctetString.decodeAsOctetString(element).stringValue(), false);


      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JOIN_RULE_DECODE_INVALID_TYPE.get(
                  StaticUtils.toHex(elementType)));
    }
  }



  /**
   * Retrieves a string representation of this join rule.
   *
   * @return  A string representation of this join rule.
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
   * Appends a string representation of this join rule to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    switch (type)
    {
      case JOIN_TYPE_AND:
        buffer.append("ANDJoinRule(components={");
        for (int i=0; i < components.length; i++)
        {
          if (i > 0)
          {
            buffer.append(", ");
          }
          components[i].toString(buffer);
        }
        buffer.append("})");
        break;

      case JOIN_TYPE_OR:
        buffer.append("ORJoinRule(components={");
        for (int i=0; i < components.length; i++)
        {
          if (i > 0)
          {
            buffer.append(", ");
          }
          components[i].toString(buffer);
        }
        buffer.append("})");
        break;

      case JOIN_TYPE_DN:
        buffer.append("DNJoinRule(sourceAttr=");
        buffer.append(sourceAttribute);
        buffer.append(')');
        break;

      case JOIN_TYPE_EQUALITY:
        buffer.append("EqualityJoinRule(sourceAttr=");
        buffer.append(sourceAttribute);
        buffer.append(", targetAttr=");
        buffer.append(targetAttribute);
        buffer.append(", matchAll=");
        buffer.append(matchAll);
        buffer.append(')');
        break;

      case JOIN_TYPE_CONTAINS:
        buffer.append("ContainsJoinRule(sourceAttr=");
        buffer.append(sourceAttribute);
        buffer.append(", targetAttr=");
        buffer.append(targetAttribute);
        buffer.append(", matchAll=");
        buffer.append(matchAll);
        buffer.append(')');
        break;

    case JOIN_TYPE_REVERSE_DN:
      buffer.append("ReverseDNJoinRule(targetAttr=");
      buffer.append(targetAttribute);
      buffer.append(')');
      break;
    }
  }
}
