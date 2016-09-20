/*
 * Copyright 2009-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2016 UnboundID Corp.
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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an implementation of an LDAP control which can be
 * included in a search request to indicate that search result entries should be
 * returned along with related entries based on a given set of criteria, much
 * like an SQL join in a relational database.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * <BR>
 * <H2>Example</H2>
 * Consider the case in which user entries include an account number, but
 * additional information about those accounts are available in separate
 * entries.    If you wish to retrieve both the user and account entries for a
 * user given only a user ID, then you may accomplish that using the join
 * request control as follows:
 * <PRE>
 * SearchRequest searchRequest = new SearchRequest(
 *      "ou=People,dc=example,dc=com", SearchScope.SUB,
 *      Filter.createEqualityFilter("uid", userID));
 * searchRequest.addControl(new JoinRequestControl(new JoinRequestValue(
 *      JoinRule.createEqualityJoin("accountNumber", "accountNumber", false),
 *      JoinBaseDN.createUseCustomBaseDN("ou=Accounts,dc=example,dc=com"),
 *      SearchScope.SUB, DereferencePolicy.NEVER, null,
 *      Filter.createEqualityFilter("objectClass", "accountEntry"),
 *      new String[0], false, null)));
 * SearchResult searchResult = connection.search(searchRequest);
 *
 * for (SearchResultEntry userEntry : searchResult.getSearchEntries())
 * {
 *   JoinResultControl c = JoinResultControl.get(userEntry);
 *   for (JoinedEntry accountEntry : c.getJoinResults())
 *   {
 *     // User userEntry was joined with account accountEntry
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JoinRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.9) for the join request control.
   */
  public static final String JOIN_REQUEST_OID = "1.3.6.1.4.1.30221.2.5.9";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1321645105838145996L;



  // The join request value for this control.
  private final JoinRequestValue joinRequestValue;



  /**
   * Creates a new join request control with the provided join request value.
   *
   * @param  joinRequestValue  The join request value to use for this control.
   */
  public JoinRequestControl(final JoinRequestValue joinRequestValue)
  {
    super(JOIN_REQUEST_OID, true,
          new ASN1OctetString(joinRequestValue.encode().encode()));

    this.joinRequestValue = joinRequestValue;
  }



  /**
   * Creates a new join request control which is decoded from the provided
   * generic control.
   *
   * @param  control  The generic control to be decoded as a join request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         virtual attributes only request control.
   */
  public JoinRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_CONTROL_NO_VALUE.get());
    }

    final ASN1Element valueElement;
    try
    {
      valueElement = ASN1Element.decode(value.getValue());
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_VALUE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }

    joinRequestValue = JoinRequestValue.decode(valueElement);
  }



  /**
   * Retrieves the join request value for this join request control.
   *
   * @return  The join request value for this join request control.
   */
  public JoinRequestValue getJoinRequestValue()
  {
    return joinRequestValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_JOIN_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("JoinRequestControl(value=");
    joinRequestValue.toString(buffer);
    buffer.append(')');
  }
}
