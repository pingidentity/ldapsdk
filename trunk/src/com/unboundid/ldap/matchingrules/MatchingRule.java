/*
 * Copyright 2007-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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
package com.unboundid.ldap.matchingrules;



import java.io.Serializable;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class defines the API for an LDAP matching rule, which may be used to
 * determine whether two values are equal to each other, and to normalize values
 * so that they may be more easily compared.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class MatchingRule
       implements Serializable
{
  /**
   * The substring element type used for subInitial substring assertion
   * components.
   */
  public static final byte SUBSTRING_TYPE_SUBINITIAL = (byte) 0x80;



  /**
   * The substring element type used for subAny substring assertion components.
   */
  public static final byte SUBSTRING_TYPE_SUBANY = (byte) 0x81;



  /**
   * The substring element type used for subFinal substring assertion
   * components.
   */
  public static final byte SUBSTRING_TYPE_SUBFINAL = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6050276733546358513L;



  /**
   * Creates a new instance of this matching rule.
   */
  protected MatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Indicates whether the provided values are equal to each other, according to
   * the constraints of this matching rule.
   *
   * @param  value1  The first value for which to make the determination.
   * @param  value2  The second value for which to make the determination.
   *
   * @return  {@code true} if the provided values are considered equal, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while making the determination,
   *                         or if this matching rule does not support equality
   *                         matching.
   */
  public abstract boolean valuesMatch(final ASN1OctetString value1,
                                      final ASN1OctetString value2)
         throws LDAPException;



  /**
   * Indicates whether the provided value matches the given substring assertion,
   * according to the constraints of this matching rule.
   *
   * @param  value       The value for which to make the determination.
   * @param  subInitial  The subInitial portion of the substring assertion, or
   *                     {@code null} if there is no subInitial element.
   * @param  subAny      The subAny elements of the substring assertion, or
   *                     {@code null} if there are no subAny elements.
   * @param  subFinal    The subFinal portion of the substring assertion, or
   *                     {@code null} if there is no subFinal element.
   *
   * @return  {@code true} if the provided value matches the substring
   *          assertion, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while making the determination,
   *                         or if this matching rule does not support substring
   *                         matching.
   */
  public abstract boolean matchesSubstring(final ASN1OctetString value,
                                           final ASN1OctetString subInitial,
                                           final ASN1OctetString[] subAny,
                                           final ASN1OctetString subFinal)
         throws LDAPException;



  /**
   * Compares the provided values to determine their relative order in a sorted
   * list.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @return  A negative value if {@code value1} should come before
   *          {@code value2} in a sorted list, a positive value if
   *          {@code value1} should come after {@code value2} in a sorted list,
   *          or zero if the values are equal or there is no distinction between
   *          their orders in a sorted list.
   *
   * @throws  LDAPException  If a problem occurs while making the determination,
   *                         or if this matching rule does not support ordering
   *                         matching.
   */
  public abstract int compareValues(final ASN1OctetString value1,
                                    final ASN1OctetString value2)
         throws LDAPException;



  /**
   * Normalizes the provided value for easier matching.
   *
   * @param  value  The value to be normalized.
   *
   * @return  The normalized form of the provided value.
   *
   * @throws  LDAPException  If a problem occurs while normalizing the provided
   *                         value.
   */
  public abstract ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException;



  /**
   * Normalizes the provided value for use as part of a substring assertion.
   *
   * @param  value          The value to be normalized for use as part of a
   *                        substring assertion.
   * @param  substringType  The substring assertion component type for the
   *                        provided value.  It should be one of
   *                        {@code SUBSTRING_TYPE_SUBINITIAL},
   *                        {@code SUBSTRING_TYPE_SUBANY}, or
   *                        {@code SUBSTRING_TYPE_SUBFINAL}.
   *
   * @return  The normalized form of the provided value.
   *
   * @throws  LDAPException  If a problem occurs while normalizing the provided
   *                         value.
   */
  public abstract ASN1OctetString normalizeSubstring(
                                       final ASN1OctetString value,
                                       final byte substringType)
         throws LDAPException;



  /**
   * Attempts to select the appropriate matching rule to use for equality
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the case-ignore string matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null}, then a
   *                   case-ignore string matching rule will be selected.
   *
   * @return  The selected matching rule.
   */
  public static MatchingRule selectEqualityMatchingRule(final String attrName,
                                                        final Schema schema)
  {
    if ((attrName == null) || (schema == null))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }

    final String mrName = attrType.getEqualityMatchingRule(schema);
    if (mrName != null)
    {
      final String lowerName = toLowerCase(mrName);
      if (lowerName.equals("booleanmatch") ||
          lowerName.equals("2.5.13.13"))
      {
        return BooleanMatchingRule.getInstance();
      }
      else if (lowerName.equals("caseexactmatch") ||
               lowerName.equals("2.5.13.5") ||
               lowerName.equals("caseexactia5match") ||
               lowerName.equals("1.3.6.1.4.1.1466.109.114.1"))
      {
        return CaseExactStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("caseignorematch") ||
               lowerName.equals("2.5.13.2") ||
               lowerName.equals("caseignoreia5match") ||
               lowerName.equals("1.3.6.1.4.1.1466.109.114.2"))
      {
        return CaseIgnoreStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("distinguishednamematch") ||
               lowerName.equals("2.5.13.1") ||
               lowerName.equals("uniquemembermatch") ||
               lowerName.equals("2.5.13.23"))
      {
        // NOTE -- Technically uniqueMember should use a name and optional UID
        // matching rule, but the SDK doesn't currently provide one and the
        // distinguished name matching rule should be sufficient the vast
        // majority of the time.
        return DistinguishedNameMatchingRule.getInstance();
      }
      else if (lowerName.equals("generalizedtimematch") ||
               lowerName.equals("2.5.13.27"))
      {
        return GeneralizedTimeMatchingRule.getInstance();
      }
      else if (lowerName.equals("integermatch") ||
               lowerName.equals("2.5.13.14"))
      {
        return IntegerMatchingRule.getInstance();
      }
      else if (lowerName.equals("numericstringmatch") ||
               lowerName.equals("2.5.13.8"))
      {
        return NumericStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("octetstringmatch") ||
               lowerName.equals("2.5.13.17"))
      {
        return OctetStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("telephonenumbermatch") ||
               lowerName.equals("2.5.13.20"))
      {
        return TelephoneNumberMatchingRule.getInstance();
      }
    }

    final String syntaxOID = attrType.getSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Attempts to select the appropriate matching rule to use for ordering
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the case-ignore string matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null}, then a
   *                   case-ignore string matching rule will be selected.
   *
   * @return  The selected matching rule.
   */
  public static MatchingRule selectOrderingMatchingRule(final String attrName,
                                                        final Schema schema)
  {
    if ((attrName == null) || (schema == null))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }

    final String mrName = attrType.getOrderingMatchingRule(schema);
    if (mrName != null)
    {
      final String lowerName = toLowerCase(mrName);
      if (lowerName.equals("caseexactorderingmatch") ||
          lowerName.equals("2.5.13.6"))
      {
        return CaseExactStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("caseignoreorderingmatch") ||
               lowerName.equals("2.5.13.3"))
      {
        return CaseIgnoreStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("generalizedtimeorderingmatch") ||
               lowerName.equals("2.5.13.28"))
      {
        return GeneralizedTimeMatchingRule.getInstance();
      }
      else if (lowerName.equals("integerorderingmatch") ||
               lowerName.equals("2.5.13.15"))
      {
        return IntegerMatchingRule.getInstance();
      }
      else if (lowerName.equals("numericstringorderingmatch") ||
               lowerName.equals("2.5.13.9"))
      {
        return NumericStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("octetstringorderingmatch") ||
               lowerName.equals("2.5.13.18"))
      {
        return OctetStringMatchingRule.getInstance();
      }
    }

    final String syntaxOID = attrType.getSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Attempts to select the appropriate matching rule to use for substring
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the case-ignore string matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null}, then a
   *                   case-ignore string matching rule will be selected.
   *
   * @return  The selected matching rule.
   */
  public static MatchingRule selectSubstringMatchingRule(final String attrName,
                                                         final Schema schema)
  {
    if ((attrName == null) || (schema == null))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }

    final String mrName = attrType.getSubstringMatchingRule(schema);
    if (mrName != null)
    {
      final String lowerName = toLowerCase(mrName);
      if (lowerName.equals("caseexactsubstringsmatch") ||
          lowerName.equals("2.5.13.7") ||
          lowerName.equals("caseexactia5substringsmatch"))
      {
        return CaseExactStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("caseignoresubstringsmatch") ||
               lowerName.equals("2.5.13.4") ||
               lowerName.equals("caseignoreia5substringsmatch") ||
               lowerName.equals("1.3.6.1.4.1.1466.109.114.3"))
      {
        return CaseIgnoreStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("numericstringsubstringsmatch") ||
               lowerName.equals("2.5.13.10"))
      {
        return NumericStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("octetstringsubstringsmatch") ||
               lowerName.equals("2.5.13.19"))
      {
        return OctetStringMatchingRule.getInstance();
      }
      else if (lowerName.equals("telephonenumbersubstringsmatch") ||
               lowerName.equals("2.5.13.21"))
      {
        return TelephoneNumberMatchingRule.getInstance();
      }
    }

    final String syntaxOID = attrType.getSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Attempts to select the appropriate matching rule for use with the syntax
   * with the specified OID.  If an appropriate matching rule cannot be
   * determined, then the case-ignore string matching rule will be selected.
   *
   * @param  syntaxOID  The OID of the attribute syntax for which to make the
   *                    determination.
   *
   * @return  The selected matching rule.
   */
  private static MatchingRule selectMatchingRuleForSyntax(
                                   final String syntaxOID)
  {
    if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.7"))
    {
      return BooleanMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.12") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.34")) // name&optional UID
    {
      return DistinguishedNameMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.24") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.53")) // UTC time
    {
      return GeneralizedTimeMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.27"))
    {
      return IntegerMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.36"))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.4203.1.1.2") || // auth password
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.5") || // binary
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.8") || // certificate
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.9") || // cert list
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.10") || // cert pair
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.28") || // JPEG
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.40")) // octet string
    {
      return OctetStringMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.50"))
    {
      return TelephoneNumberMatchingRule.getInstance();
    }
    else
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
  }
}
