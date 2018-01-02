/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of the simple filter item for use with
 * the {@link MatchedValuesRequestControl} as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc3876.txt">RFC 3876</A>.  It is similar to
 * a search filter (see the {@link com.unboundid.ldap.sdk.Filter} class), but
 * may only contain a single element (i.e., no AND, OR, or NOT components are
 * allowed), and extensible matching does not allow the use of the dnAttributes
 * field.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MatchedValuesFilter
       implements Serializable
{
  /**
   * The match type that will be used for equality match filters.
   */
  public static final byte MATCH_TYPE_EQUALITY = (byte) 0xA3;



  /**
   * The match type that will be used for substring match filters.
   */
  public static final byte MATCH_TYPE_SUBSTRINGS = (byte) 0xA4;



  /**
   * The match type that will be used for greater-or-equal match filters.
   */
  public static final byte MATCH_TYPE_GREATER_OR_EQUAL = (byte) 0xA5;



  /**
   * The match type that will be used for less-or-equal match filters.
   */
  public static final byte MATCH_TYPE_LESS_OR_EQUAL = (byte) 0xA6;



  /**
   * The match type that will be used for presence match filters.
   */
  public static final byte MATCH_TYPE_PRESENT = (byte) 0x87;



  /**
   * The match type that will be used for approximate match filters.
   */
  public static final byte MATCH_TYPE_APPROXIMATE = (byte) 0xA8;



  /**
   * The match type that will be used for extensible match filters.
   */
  public static final byte MATCH_TYPE_EXTENSIBLE = (byte) 0xA9;



  /**
   * The BER type for the subInitial substring filter element.
   */
  private static final byte SUBSTRING_TYPE_SUBINITIAL = (byte) 0x80;



  /**
   * The BER type for the subAny substring filter element.
   */
  private static final byte SUBSTRING_TYPE_SUBANY = (byte) 0x81;



  /**
   * The BER type for the subFinal substring filter element.
   */
  private static final byte SUBSTRING_TYPE_SUBFINAL = (byte) 0x82;



  /**
   * The BER type for the matching rule ID extensible match filter element.
   */
  private static final byte EXTENSIBLE_TYPE_MATCHING_RULE_ID = (byte) 0x81;



  /**
   * The BER type for the attribute name extensible match filter element.
   */
  private static final byte EXTENSIBLE_TYPE_ATTRIBUTE_NAME = (byte) 0x82;



  /**
   * The BER type for the match value extensible match filter element.
   */
  private static final byte EXTENSIBLE_TYPE_MATCH_VALUE = (byte) 0x83;



  /**
   * An empty array that will be used if there are no subAny elements.
   */
  private static final ASN1OctetString[] NO_SUB_ANY = new ASN1OctetString[0];



  /**
   * An empty array that will be used if there are no subAny elements.
   */
  private static final String[] NO_SUB_ANY_STRINGS = NO_STRINGS;



  /**
   * An empty array that will be used if there are no subAny elements.
   */
  private static final byte[][] NO_SUB_ANY_BYTES = new byte[0][];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8144732301100674661L;



  // The name of the attribute type to include in this filter, if appropriate.
  private final ASN1OctetString assertionValue;

  // The subFinal value for this filter, if appropriate.
  private final ASN1OctetString subFinalValue;

  // The subInitial value for this filter, if appropriate.
  private final ASN1OctetString subInitialValue;

  // The subAny values for this filter, if appropriate.
  private final ASN1OctetString[] subAnyValues;

  // The filter type for this filter.
  private final byte matchType;

  // The name of the attribute type to include in this filter, if appropriate.
  private final String attributeType;

  // The matching rule ID for this filter, if appropriate.
  private final String matchingRuleID;



  /**
   * Creates a new matched values filter with the provided information.
   *
   * @param  matchType        The filter type for this filter.
   * @param  attributeType    The name of the attribute type.  It may be
   *                          {@code null} only for extensible match filters and
   *                          only if a non-{@code null} matching rule ID is
   *                          provided.
   * @param  assertionValue   The assertion value for this filter.  It may only
   *                          be {@code null} for substring and presence
   *                          filters.
   * @param  subInitialValue  The subInitial value for this filter.  It may only
   *                          be provided for substring filters.
   * @param  subAnyValues     The set of subAny values for this filter.  It may
   *                          only be provided for substring filters.
   * @param  subFinalValue    The subFinal value for this filter.  It may only
   *                          be provided for substring filters.
   * @param  matchingRuleID   The matching rule ID for this filter.  It may only
   *                          be provided for extensible match filters.
   */
  private MatchedValuesFilter(final byte matchType, final String attributeType,
                              final ASN1OctetString assertionValue,
                              final ASN1OctetString subInitialValue,
                              final ASN1OctetString[] subAnyValues,
                              final ASN1OctetString subFinalValue,
                              final String matchingRuleID)
  {
    this.matchType       = matchType;
    this.attributeType   = attributeType;
    this.assertionValue  = assertionValue;
    this.subInitialValue = subInitialValue;
    this.subAnyValues    = subAnyValues;
    this.subFinalValue   = subFinalValue;
    this.matchingRuleID  = matchingRuleID;
  }



  /**
   * Creates a new matched values filter for equality matching with the provided
   * information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created equality match filter.
   */
  public static MatchedValuesFilter createEqualityFilter(
                                         final String attributeType,
                                         final String assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_EQUALITY, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for equality matching with the provided
   * information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created equality match filter.
   */
  public static MatchedValuesFilter createEqualityFilter(
                                         final String attributeType,
                                         final byte[] assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_EQUALITY, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for substring matching with the
   * provided information.  At least one substring filter element must be
   * provided.
   *
   * @param  attributeType    The attribute type for the filter.  It must not be
   *                          {@code null}.
   * @param  subInitialValue  The subInitial value for the filter, or
   *                          {@code null} if there is no subInitial element.
   * @param  subAnyValues     The set of subAny values for the filter, or
   *                          {@code null} if there are no subAny elements.
   * @param  subFinalValue    The subFinal value for the filter, or {@code null}
   *                          if there is no subFinal element.
   *
   * @return  The created equality match filter.
   */
  public static MatchedValuesFilter createSubstringFilter(
                                         final String attributeType,
                                         final String subInitialValue,
                                         final String[] subAnyValues,
                                         final String subFinalValue)
  {
    ensureNotNull(attributeType);
    ensureTrue((subInitialValue != null) ||
               ((subAnyValues != null) && (subAnyValues.length > 0)) ||
               (subFinalValue != null));

    final ASN1OctetString subInitialOS;
    if (subInitialValue == null)
    {
      subInitialOS = null;
    }
    else
    {
      subInitialOS = new ASN1OctetString(SUBSTRING_TYPE_SUBINITIAL,
                                         subInitialValue);
    }

    final ASN1OctetString[] subAnyOS;
    if ((subAnyValues == null) || (subAnyValues.length == 0))
    {
      subAnyOS = NO_SUB_ANY;
    }
    else
    {
      subAnyOS = new ASN1OctetString[subAnyValues.length];
      for (int i=0; i < subAnyValues.length; i++)
      {
        subAnyOS[i] = new ASN1OctetString(SUBSTRING_TYPE_SUBANY,
                                          subAnyValues[i]);
      }
    }

    final ASN1OctetString subFinalOS;
    if (subFinalValue == null)
    {
      subFinalOS = null;
    }
    else
    {
      subFinalOS = new ASN1OctetString(SUBSTRING_TYPE_SUBFINAL, subFinalValue);
    }

    return new MatchedValuesFilter(MATCH_TYPE_SUBSTRINGS, attributeType, null,
                                   subInitialOS, subAnyOS, subFinalOS, null);
  }



  /**
   * Creates a new matched values filter for substring matching with the
   * provided information.  At least one substring filter element must be
   * provided.
   *
   * @param  attributeType    The attribute type for the filter.  It must not be
   *                          {@code null}.
   * @param  subInitialValue  The subInitial value for the filter, or
   *                          {@code null} if there is no subInitial element.
   * @param  subAnyValues     The set of subAny values for the filter, or
   *                          {@code null} if there are no subAny elements.
   * @param  subFinalValue    The subFinal value for the filter, or {@code null}
   *                          if there is no subFinal element.
   *
   * @return  The created equality match filter.
   */
  public static MatchedValuesFilter createSubstringFilter(
                                         final String attributeType,
                                         final byte[] subInitialValue,
                                         final byte[][] subAnyValues,
                                         final byte[] subFinalValue)
  {
    ensureNotNull(attributeType);
    ensureTrue((subInitialValue != null) ||
               ((subAnyValues != null) && (subAnyValues.length > 0)) ||
               (subFinalValue != null));

    final ASN1OctetString subInitialOS;
    if (subInitialValue == null)
    {
      subInitialOS = null;
    }
    else
    {
      subInitialOS = new ASN1OctetString(SUBSTRING_TYPE_SUBINITIAL,
                                         subInitialValue);
    }

    final ASN1OctetString[] subAnyOS;
    if ((subAnyValues == null) || (subAnyValues.length == 0))
    {
      subAnyOS = NO_SUB_ANY;
    }
    else
    {
      subAnyOS = new ASN1OctetString[subAnyValues.length];
      for (int i=0; i < subAnyValues.length; i++)
      {
        subAnyOS[i] = new ASN1OctetString(SUBSTRING_TYPE_SUBANY,
                                          subAnyValues[i]);
      }
    }

    final ASN1OctetString subFinalOS;
    if (subFinalValue == null)
    {
      subFinalOS = null;
    }
    else
    {
      subFinalOS = new ASN1OctetString(SUBSTRING_TYPE_SUBFINAL, subFinalValue);
    }

    return new MatchedValuesFilter(MATCH_TYPE_SUBSTRINGS, attributeType, null,
                                   subInitialOS, subAnyOS, subFinalOS, null);
  }



  /**
   * Creates a new matched values filter for greater-or-equal matching with the
   * provided information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created greater-or-equal match filter.
   */
  public static MatchedValuesFilter createGreaterOrEqualFilter(
                                         final String attributeType,
                                         final String assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_GREATER_OR_EQUAL, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for greater-or-equal matching with the
   * provided information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created greater-or-equal match filter.
   */
  public static MatchedValuesFilter createGreaterOrEqualFilter(
                                         final String attributeType,
                                         final byte[] assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_GREATER_OR_EQUAL, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for less-or-equal matching with the
   * provided information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created less-or-equal match filter.
   */
  public static MatchedValuesFilter createLessOrEqualFilter(
                                         final String attributeType,
                                         final String assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_LESS_OR_EQUAL, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for less-or-equal matching with the
   * provided information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created less-or-equal match filter.
   */
  public static MatchedValuesFilter createLessOrEqualFilter(
                                         final String attributeType,
                                         final byte[] assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_LESS_OR_EQUAL, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for presence matching with the provided
   * information.
   *
   * @param  attributeType  The attribute type for the filter.  It must not be
   *                        {@code null}.
   *
   * @return  The created present match filter.
   */
  public static MatchedValuesFilter createPresentFilter(
                                         final String attributeType)
  {
    ensureNotNull(attributeType);

    return new MatchedValuesFilter(MATCH_TYPE_PRESENT, attributeType, null,
                                   null, NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for approximate matching with the
   * provided information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created approximate match filter.
   */
  public static MatchedValuesFilter createApproximateFilter(
                                         final String attributeType,
                                         final String assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_APPROXIMATE, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for approximate matching with the
   * provided information.
   *
   * @param  attributeType   The attribute type for the filter.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created greater-or-equal match filter.
   */
  public static MatchedValuesFilter createApproximateFilter(
                                         final String attributeType,
                                         final byte[] assertionValue)
  {
    ensureNotNull(attributeType, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_APPROXIMATE, attributeType,
                                   new ASN1OctetString(assertionValue), null,
                                   NO_SUB_ANY, null, null);
  }



  /**
   * Creates a new matched values filter for extensible matching with the
   * provided information.  At least one of the attribute type and matching rule
   * ID must be provided.
   *
   * @param  attributeType   The attribute type for the filter, or {@code null}
   *                         if there is no attribute type.
   * @param  matchingRuleID  The matching rule ID for the filter, or
   *                         {@code null} if there is no matching rule ID.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created extensible match filter.
   */
  public static MatchedValuesFilter createExtensibleMatchFilter(
                                         final String attributeType,
                                         final String matchingRuleID,
                                         final String assertionValue)
  {
    ensureNotNull(assertionValue);
    ensureTrue((attributeType != null) || (matchingRuleID != null));

    final ASN1OctetString matchValue =
         new ASN1OctetString(EXTENSIBLE_TYPE_MATCH_VALUE, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_EXTENSIBLE, attributeType,
                                   matchValue, null, NO_SUB_ANY, null,
                                   matchingRuleID);
  }



  /**
   * Creates a new matched values filter for extensible matching with the
   * provided information.  At least one of the attribute type and matching rule
   * ID must be provided.
   *
   * @param  attributeType   The attribute type for the filter, or {@code null}
   *                         if there is no attribute type.
   * @param  matchingRuleID  The matching rule ID for the filter, or
   *                         {@code null} if there is no matching rule ID.
   * @param  assertionValue  The assertion value for the filter.  It must not be
   *                         {@code null}.
   *
   * @return  The created extensible match filter.
   */
  public static MatchedValuesFilter createExtensibleMatchFilter(
                                         final String attributeType,
                                         final String matchingRuleID,
                                         final byte[] assertionValue)
  {
    ensureNotNull(assertionValue);
    ensureTrue((attributeType != null) || (matchingRuleID != null));

    final ASN1OctetString matchValue =
         new ASN1OctetString(EXTENSIBLE_TYPE_MATCH_VALUE, assertionValue);

    return new MatchedValuesFilter(MATCH_TYPE_EXTENSIBLE, attributeType,
                                   matchValue, null, NO_SUB_ANY, null,
                                   matchingRuleID);
  }



  /**
   * Creates a new matched values filter from the provided search filter, if
   * possible.
   *
   * @param  filter  The search filter to use to create this matched values
   *                 filter.
   *
   * @return  The search filter that corresponds to this matched values filter.
   *
   * @throws  LDAPException  If the provided search filter cannot be represented
   *                         as a matched values filter.
   */
  public static MatchedValuesFilter create(final Filter filter)
         throws LDAPException
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_MV_FILTER_AND_NOT_SUPPORTED.get());

      case Filter.FILTER_TYPE_OR:
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_MV_FILTER_OR_NOT_SUPPORTED.get());

      case Filter.FILTER_TYPE_NOT:
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_MV_FILTER_NOT_NOT_SUPPORTED.get());

      case Filter.FILTER_TYPE_EQUALITY:
        return createEqualityFilter(filter.getAttributeName(),
                    filter.getAssertionValueBytes());

      case Filter.FILTER_TYPE_SUBSTRING:
        return createSubstringFilter(filter.getAttributeName(),
                    filter.getSubInitialBytes(), filter.getSubAnyBytes(),
                    filter.getSubFinalBytes());

      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
        return createGreaterOrEqualFilter(filter.getAttributeName(),
                    filter.getAssertionValueBytes());

      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
        return createLessOrEqualFilter(filter.getAttributeName(),
                    filter.getAssertionValueBytes());

      case Filter.FILTER_TYPE_PRESENCE:
        return createPresentFilter(filter.getAttributeName());

      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        return createApproximateFilter(filter.getAttributeName(),
                    filter.getAssertionValueBytes());

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        if (filter.getDNAttributes())
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MV_FILTER_DNATTRS_NOT_SUPPORTED.get());
        }

        return createExtensibleMatchFilter(filter.getAttributeName(),
                    filter.getMatchingRuleID(),
                    filter.getAssertionValueBytes());

      default:
        // This should never happen.
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MV_FILTER_INVALID_FILTER_TYPE.get(
                  toHex(filter.getFilterType())));
    }
  }



  /**
   * Retrieves the match type for this matched values filter.
   *
   * @return  The match type for this matched values filter.
   */
  public byte getMatchType()
  {
    return matchType;
  }



  /**
   * Retrieves the name of the attribute type for this matched values filter,
   * if available.
   *
   * @return  The name of the attribute type for this matched values filter, or
   *          {@code null} if there is none.
   */
  public String getAttributeType()
  {
    return attributeType;
  }



  /**
   * Retrieves the string representation of the assertion value for this matched
   * values filter, if available.
   *
   * @return  The string representation of the assertion value for this matched
   *          values filter, or {@code null} if there is none.
   */
  public String getAssertionValue()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.stringValue();
    }
  }



  /**
   * Retrieves the binary representation of the assertion value for this matched
   * values filter, if available.
   *
   * @return  The binary representation of the assertion value for this matched
   *          values filter, or {@code null} if there is none.
   */
  public byte[] getAssertionValueBytes()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.getValue();
    }
  }



  /**
   * Retrieves raw assertion value for this matched values filter, if available.
   *
   * @return  The raw assertion value for this matched values filter, or
   *          {@code null} if there is none.
   */
  public ASN1OctetString getRawAssertionValue()
  {
    return assertionValue;
  }



  /**
   * Retrieves the string representation of the subInitial element for this
   * matched values filter, if available.
   *
   * @return  The string representation of the subInitial element for this
   *          matched values filter, or {@code null} if there is none.
   */
  public String getSubInitialValue()
  {
    if (subInitialValue == null)
    {
      return null;
    }
    else
    {
      return subInitialValue.stringValue();
    }
  }



  /**
   * Retrieves the binary representation of the subInitial element for this
   * matched values filter, if available.
   *
   * @return  The binary representation of the subInitial element for this
   *          matched values filter, or {@code null} if there is none.
   */
  public byte[] getSubInitialValueBytes()
  {
    if (subInitialValue == null)
    {
      return null;
    }
    else
    {
      return subInitialValue.getValue();
    }
  }



  /**
   * Retrieves the raw subInitial element for this matched values filter, if
   * available.
   *
   * @return  The raw subInitial element for this matched values filter, or
   *          {@code null} if there is none.
   */
  public ASN1OctetString getRawSubInitialValue()
  {
    return subInitialValue;
  }



  /**
   * Retrieves the string representations of the subAny elements for this
   * matched values filter, if available.
   *
   * @return  The string representations of the subAny element for this matched
   *          values filter, or an empty array if there are none.
   */
  public String[] getSubAnyValues()
  {
    if (subAnyValues.length == 0)
    {
      return NO_SUB_ANY_STRINGS;
    }
    else
    {
      final String[] subAnyStrings = new String[subAnyValues.length];
      for (int i=0; i < subAnyValues.length; i++)
      {
        subAnyStrings[i] = subAnyValues[i].stringValue();
      }

      return subAnyStrings;
    }
  }



  /**
   * Retrieves the binary representations of the subAny elements for this
   * matched values filter, if available.
   *
   * @return  The binary representations of the subAny element for this matched
   *          values filter, or an empty array if there are none.
   */
  public byte[][] getSubAnyValueBytes()
  {
    if (subAnyValues.length == 0)
    {
      return NO_SUB_ANY_BYTES;
    }
    else
    {
      final byte[][] subAnyBytes = new byte[subAnyValues.length][];
      for (int i=0; i < subAnyValues.length; i++)
      {
        subAnyBytes[i] = subAnyValues[i].getValue();
      }

      return subAnyBytes;
    }
  }



  /**
   * Retrieves the raw subAny elements for this matched values filter, if
   * available.
   *
   * @return  The raw subAny element for this matched values filter, or an empty
   *          array if there are none.
   */
  public ASN1OctetString[] getRawSubAnyValues()
  {
    return subAnyValues;
  }



  /**
   * Retrieves the string representation of the subFinal element for this
   * matched values filter, if available.
   *
   * @return  The string representation of the subFinal element for this
   *          matched values filter, or {@code null} if there is none.
   */
  public String getSubFinalValue()
  {
    if (subFinalValue == null)
    {
      return null;
    }
    else
    {
      return subFinalValue.stringValue();
    }
  }



  /**
   * Retrieves the binary representation of the subFinal element for this
   * matched values filter, if available.
   *
   * @return  The binary representation of the subFinal element for this matched
   *          values filter, or {@code null} if there is none.
   */
  public byte[] getSubFinalValueBytes()
  {
    if (subFinalValue == null)
    {
      return null;
    }
    else
    {
      return subFinalValue.getValue();
    }
  }



  /**
   * Retrieves the raw subFinal element for this matched values filter, if
   * available.
   *
   * @return  The raw subFinal element for this matched values filter, or
   *          {@code null} if there is none.
   */
  public ASN1OctetString getRawSubFinalValue()
  {
    return subFinalValue;
  }



  /**
   * Retrieves the matching rule ID for this matched values filter, if
   * available.
   *
   * @return  The matching rule ID for this matched values filter, or
   *          {@code null} if there is none.
   */
  public String getMatchingRuleID()
  {
    return matchingRuleID;
  }



  /**
   * Encodes this matched values filter for use in the matched values control.
   *
   * @return  The ASN.1 element containing the encoded representation of this
   *          matched values filter.
   */
  public ASN1Element encode()
  {
    switch (matchType)
    {
      case MATCH_TYPE_EQUALITY:
      case MATCH_TYPE_GREATER_OR_EQUAL:
      case MATCH_TYPE_LESS_OR_EQUAL:
      case MATCH_TYPE_APPROXIMATE:
        ASN1Element[] elements =
        {
          new ASN1OctetString(attributeType),
          assertionValue
        };
        return new ASN1Sequence(matchType, elements);

      case MATCH_TYPE_SUBSTRINGS:
        final ArrayList<ASN1Element> subElements =
             new ArrayList<ASN1Element>(3);
        if (subInitialValue != null)
        {
          subElements.add(subInitialValue);
        }

        if (subAnyValues.length > 0)
        {
          subElements.addAll(Arrays.asList(subAnyValues));
        }

        if (subFinalValue != null)
        {
          subElements.add(subFinalValue);
        }

        elements = new ASN1Element[]
        {
          new ASN1OctetString(attributeType),
          new ASN1Sequence(subElements)
        };
        return new ASN1Sequence(matchType, elements);

      case MATCH_TYPE_PRESENT:
        return new ASN1OctetString(matchType, attributeType);

      case MATCH_TYPE_EXTENSIBLE:
        final ArrayList<ASN1Element> extElements =
             new ArrayList<ASN1Element>(3);
        if (attributeType != null)
        {
          extElements.add(new ASN1OctetString(EXTENSIBLE_TYPE_ATTRIBUTE_NAME,
                                              attributeType));
        }

        if (matchingRuleID != null)
        {
          extElements.add(new ASN1OctetString(EXTENSIBLE_TYPE_MATCHING_RULE_ID,
                                              matchingRuleID));
        }

        extElements.add(assertionValue);
        return new ASN1Sequence(matchType, extElements);

      default:
        // This should never happen.
        return null;
    }
  }



  /**
   * Decodes the provided ASN.1 element as a matched values filter.
   *
   * @param  element  The ASN.1 element to decode as a matched values filter.
   *
   * @return  The decoded matched values filter.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a matched values filter.
   */
  public static MatchedValuesFilter decode(final ASN1Element element)
         throws LDAPException
  {
    ASN1OctetString   assertionValue  = null;
    ASN1OctetString   subInitialValue = null;
    ASN1OctetString   subFinalValue   = null;
    ASN1OctetString[] subAnyValues    = NO_SUB_ANY;
    final byte        matchType       = element.getType();
    String            attributeType   = null;
    String            matchingRuleID  = null;

    switch (matchType)
    {
      case MATCH_TYPE_EQUALITY:
      case MATCH_TYPE_GREATER_OR_EQUAL:
      case MATCH_TYPE_LESS_OR_EQUAL:
      case MATCH_TYPE_APPROXIMATE:
        try
        {
          final ASN1Element[] elements =
               ASN1Sequence.decodeAsSequence(element).elements();
          attributeType =
               ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
          assertionValue =
               ASN1OctetString.decodeAsOctetString(elements[1]);
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MV_FILTER_NOT_AVA.get(e), e);
        }
        break;

      case MATCH_TYPE_SUBSTRINGS:
        try
        {
          final ASN1Element[] elements =
               ASN1Sequence.decodeAsSequence(element).elements();
          attributeType =
               ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

          ArrayList<ASN1OctetString> subAnyList = null;
          final ASN1Element[] subElements =
               ASN1Sequence.decodeAsSequence(elements[1]).elements();
          for (final ASN1Element e : subElements)
          {
            switch (e.getType())
            {
              case SUBSTRING_TYPE_SUBINITIAL:
                if (subInitialValue == null)
                {
                  subInitialValue = ASN1OctetString.decodeAsOctetString(e);
                }
                else
                {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                 ERR_MV_FILTER_MULTIPLE_SUBINITIAL.get());
                }
                break;

              case SUBSTRING_TYPE_SUBANY:
                if (subAnyList == null)
                {
                  subAnyList =
                       new ArrayList<ASN1OctetString>(subElements.length);
                }
                subAnyList.add(ASN1OctetString.decodeAsOctetString(e));
                break;

              case SUBSTRING_TYPE_SUBFINAL:
                if (subFinalValue == null)
                {
                  subFinalValue = ASN1OctetString.decodeAsOctetString(e);
                }
                else
                {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                 ERR_MV_FILTER_MULTIPLE_SUBFINAL.get());
                }
                break;

              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                                        ERR_MV_FILTER_INVALID_SUB_TYPE.get(
                                             toHex(e.getType())));
            }
          }

          if (subAnyList != null)
          {
            subAnyValues =
                 subAnyList.toArray(new ASN1OctetString[subAnyList.size()]);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
          throw le;
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MV_FILTER_CANNOT_DECODE_SUBSTRING.get(e),
                                  e);
        }

        if ((subInitialValue == null) && (subAnyValues.length == 0) &&
            (subFinalValue == null))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MV_FILTER_NO_SUBSTRING_ELEMENTS.get());
        }
        break;

      case MATCH_TYPE_PRESENT:
        attributeType =
             ASN1OctetString.decodeAsOctetString(element).stringValue();
        break;

      case MATCH_TYPE_EXTENSIBLE:
        try
        {
          final ASN1Element[] elements =
               ASN1Sequence.decodeAsSequence(element).elements();
          for (final ASN1Element e : elements)
          {
            switch (e.getType())
            {
              case EXTENSIBLE_TYPE_ATTRIBUTE_NAME:
                if (attributeType == null)
                {
                  attributeType =
                       ASN1OctetString.decodeAsOctetString(e).stringValue();
                }
                else
                {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                          ERR_MV_FILTER_EXT_MULTIPLE_AT.get());
                }
                break;

              case EXTENSIBLE_TYPE_MATCHING_RULE_ID:
                if (matchingRuleID == null)
                {
                  matchingRuleID =
                       ASN1OctetString.decodeAsOctetString(e).stringValue();
                }
                else
                {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                          ERR_MV_FILTER_MULTIPLE_MRID.get());
                }
                break;

              case EXTENSIBLE_TYPE_MATCH_VALUE:
                if (assertionValue == null)
                {
                  assertionValue =
                       ASN1OctetString.decodeAsOctetString(e);
                }
                else
                {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                 ERR_MV_FILTER_EXT_MULTIPLE_VALUE.get());
                }
                break;

              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                                        ERR_MV_FILTER_EXT_INVALID_TYPE.get(
                                             toHex(e.getType())));
            }
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
          throw le;
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MV_FILTER_EXT_NOT_SEQUENCE.get(e), e);
        }

        if ((attributeType == null) && (matchingRuleID == null))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MV_FILTER_NO_ATTR_OR_MRID.get());
        }

        if (assertionValue == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MV_FILTER_EXT_NO_VALUE.get());
        }
        break;

      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_MV_FILTER_INVALID_TYPE.get(
                                     toHex(matchType)));
    }

    return new MatchedValuesFilter(matchType, attributeType,  assertionValue,
                                   subInitialValue, subAnyValues, subFinalValue,
                                   matchingRuleID);
  }



  /**
   * Creates a search filter that is the equivalent of this matched values
   * filter.
   *
   * @return  A search filter that is the equivalent of this matched values
   *          filter.
   */
  public Filter toFilter()
  {
    switch (matchType)
    {
      case MATCH_TYPE_EQUALITY:
        return Filter.createEqualityFilter(attributeType,
                    assertionValue.getValue());

      case MATCH_TYPE_SUBSTRINGS:
        return Filter.createSubstringFilter(attributeType,
                    getSubInitialValueBytes(), getSubAnyValueBytes(),
                    getSubFinalValueBytes());

      case MATCH_TYPE_GREATER_OR_EQUAL:
        return Filter.createGreaterOrEqualFilter(attributeType,
                    assertionValue.getValue());

      case MATCH_TYPE_LESS_OR_EQUAL:
        return Filter.createLessOrEqualFilter(attributeType,
                    assertionValue.getValue());

      case MATCH_TYPE_PRESENT:
        return Filter.createPresenceFilter(attributeType);

      case MATCH_TYPE_APPROXIMATE:
        return Filter.createApproximateMatchFilter(attributeType,
                    assertionValue.getValue());

      case MATCH_TYPE_EXTENSIBLE:
        return Filter.createExtensibleMatchFilter(attributeType, matchingRuleID,
                    false, assertionValue.getValue());

      default:
        // This should never happen.
        return null;
    }
  }



  /**
   * Retrieves a string representation of this matched values filter.
   *
   * @return  A string representation of this matched values filter.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this matched values filter to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this matched values filter.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append('(');

    switch (matchType)
    {
      case MATCH_TYPE_EQUALITY:
        buffer.append(attributeType);
        buffer.append('=');
        buffer.append(assertionValue.stringValue());
        break;

      case MATCH_TYPE_SUBSTRINGS:
        buffer.append(attributeType);
        buffer.append('=');

        if (subInitialValue != null)
        {
          buffer.append(subInitialValue.stringValue());
        }

        for (final ASN1OctetString s : subAnyValues)
        {
          buffer.append('*');
          buffer.append(s.stringValue());
        }

        buffer.append('*');
        if (subFinalValue != null)
        {
          buffer.append(subFinalValue.stringValue());
        }
        break;

      case MATCH_TYPE_GREATER_OR_EQUAL:
        buffer.append(attributeType);
        buffer.append(">=");
        buffer.append(assertionValue.stringValue());
        break;

      case MATCH_TYPE_LESS_OR_EQUAL:
        buffer.append(attributeType);
        buffer.append("<=");
        buffer.append(assertionValue.stringValue());
        break;

      case MATCH_TYPE_PRESENT:
        buffer.append(attributeType);
        buffer.append("=*");
        break;

      case MATCH_TYPE_APPROXIMATE:
        buffer.append(attributeType);
        buffer.append("~=");
        buffer.append(assertionValue.stringValue());
        break;

      case MATCH_TYPE_EXTENSIBLE:
        if (attributeType != null)
        {
          buffer.append(attributeType);
        }

        if (matchingRuleID != null)
        {
          buffer.append(':');
          buffer.append(matchingRuleID);
        }

        buffer.append(":=");
        buffer.append(assertionValue.stringValue());
        break;
    }

    buffer.append(')');
  }
}
