/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.jsonfilter;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.jsonfilter.JFMessages.*;



/**
 * This class provides an implementation of a matching rule that can be used in
 * conjunction with JSON objects.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONObjectExactMatchingRule
       extends MatchingRule
{
  /**
   * The singleton instance that will be returned from the {@link #getInstance}
   * method.
   */
  private static final JSONObjectExactMatchingRule INSTANCE =
       new JSONObjectExactMatchingRule();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4476702301631553228L;



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return A singleton instance of this matching rule.
   */
  public static JSONObjectExactMatchingRule getInstance()
  {
    return INSTANCE;
  }



  /**
   * Creates a new instance of this JSON matching rule.
   */
  public JSONObjectExactMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getEqualityMatchingRuleName()
  {
    return "jsonObjectExactMatch";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getEqualityMatchingRuleOID()
  {
    return "1.3.6.1.4.1.30221.2.4.12";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getOrderingMatchingRuleName()
  {
    // Ordering matching is not supported.
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getOrderingMatchingRuleOID()
  {
    // Ordering matching is not supported.
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSubstringMatchingRuleName()
  {
    // Substring matching is not supported.
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSubstringMatchingRuleOID()
  {
    // Substring matching is not supported.
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valuesMatch(final ASN1OctetString value1,
                             final ASN1OctetString value2)
         throws LDAPException
  {
    final JSONObject o1;
    try
    {
      o1 = new JSONObject(value1.stringValue());
    }
    catch (final JSONException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           e.getMessage(), e);
    }

    final JSONObject o2;
    try
    {
      o2 = new JSONObject(value2.stringValue());
    }
    catch (final JSONException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           e.getMessage(), e);
    }

    return o1.equals(o2, false, true, false);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesSubstring(final ASN1OctetString value,
                                  final ASN1OctetString subInitial,
                                  final ASN1OctetString[] subAny,
                                  final ASN1OctetString subFinal)
         throws LDAPException
  {
    // Substring matching is not supported for this matching rule.
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_JSON_MATCHING_RULE_SUBSTRING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    // Ordering matching is not supported for this matching rule.
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_JSON_MATCHING_RULE_ORDERING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    final JSONObject o;
    try
    {
      o = new JSONObject(value.stringValue());
    }
    catch (final JSONException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           e.getMessage(), e);
    }

    return new ASN1OctetString(o.toNormalizedString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    // Substring matching is not supported for this matching rule.
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_JSON_MATCHING_RULE_SUBSTRING_NOT_SUPPORTED.get());
  }
}
