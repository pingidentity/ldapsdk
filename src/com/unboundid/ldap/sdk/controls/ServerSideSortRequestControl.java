/*
 * Copyright 2007-2018 Ping Identity Corporation
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



import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of the server-side sort request
 * control, as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc2891.txt">RFC 2891</A>.  It may be
 * included in a search request to indicate that the server should sort the
 * results before returning them to the client.
 * <BR><BR>
 * The order in which the entries are to be sorted is specified by one or more
 * {@link SortKey} values.  Each sort key includes an attribute name and a flag
 * that indicates whether to sort in ascending or descending order.  It may also
 * specify a custom matching rule that should be used to specify which logic
 * should be used to perform the sorting.
 * <BR><BR>
 * If the search is successful, then the search result done message may include
 * the {@link ServerSideSortResponseControl} to provide information about the
 * status of the sort processing.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the server-side sort controls
 * to retrieve users in different sort orders.
 * <PRE>
 * // Perform a search to get all user entries sorted by last name, then by
 * // first name, both in ascending order.
 * SearchRequest searchRequest = new SearchRequest(
 *      "ou=People,dc=example,dc=com", SearchScope.SUB,
 *      Filter.createEqualityFilter("objectClass", "person"));
 * searchRequest.addControl(new ServerSideSortRequestControl(
 *      new SortKey("sn"), new SortKey("givenName")));
 * SearchResult lastNameAscendingResult;
 * try
 * {
 *   lastNameAscendingResult = connection.search(searchRequest);
 *   // If we got here, then the search was successful.
 * }
 * catch (LDAPSearchException lse)
 * {
 *   // The search failed for some reason.
 *   lastNameAscendingResult = lse.getSearchResult();
 *   ResultCode resultCode = lse.getResultCode();
 *   String errorMessageFromServer = lse.getDiagnosticMessage();
 * }
 *
 * // Get the response control and retrieve the result code for the sort
 * // processing.
 * LDAPTestUtils.assertHasControl(lastNameAscendingResult,
 *      ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID);
 * ServerSideSortResponseControl lastNameAscendingResponseControl =
 *      ServerSideSortResponseControl.get(lastNameAscendingResult);
 * ResultCode lastNameSortResult =
 *      lastNameAscendingResponseControl.getResultCode();
 *
 *
 * // Perform the same search, but this time request the results to be sorted
 * // in descending order by first name, then last name.
 * searchRequest.setControls(new ServerSideSortRequestControl(
 *      new SortKey("givenName", true), new SortKey("sn", true)));
 * SearchResult firstNameDescendingResult;
 * try
 * {
 *   firstNameDescendingResult = connection.search(searchRequest);
 *   // If we got here, then the search was successful.
 * }
 * catch (LDAPSearchException lse)
 * {
 *   // The search failed for some reason.
 *   firstNameDescendingResult = lse.getSearchResult();
 *   ResultCode resultCode = lse.getResultCode();
 *   String errorMessageFromServer = lse.getDiagnosticMessage();
 * }
 *
 * // Get the response control and retrieve the result code for the sort
 * // processing.
 * LDAPTestUtils.assertHasControl(firstNameDescendingResult,
 *      ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID);
 * ServerSideSortResponseControl firstNameDescendingResponseControl =
 *      ServerSideSortResponseControl.get(firstNameDescendingResult);
 * ResultCode firstNameSortResult =
 *      firstNameDescendingResponseControl.getResultCode();
 * </PRE>
 * <BR><BR>
 * <H2>Client-Side Sorting</H2>
 * The UnboundID LDAP SDK for Java provides support for client-side sorting as
 * an alternative to server-side sorting.  Client-side sorting may be useful in
 * cases in which the target server does not support the use of the server-side
 * sort control, or when it is desirable to perform the sort processing on the
 * client systems rather than on the directory server systems.  See the
 * {@link com.unboundid.ldap.sdk.EntrySorter} class for details on performing
 * client-side sorting in the LDAP SDK.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ServerSideSortRequestControl
       extends Control
{
  /**
   * The OID (1.2.840.113556.1.4.473) for the server-side sort request control.
   */
  public static final String SERVER_SIDE_SORT_REQUEST_OID =
       "1.2.840.113556.1.4.473";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3021901578330574772L;



  // The set of sort keys to use with this control.
  private final SortKey[] sortKeys;



  /**
   * Creates a new server-side sort control that will sort the results based on
   * the provided set of sort keys.
   *
   * @param  sortKeys  The set of sort keys to define the desired order in which
   *                   the results should be returned.  It must not be
   *                   {@code null} or empty.
   */
  public ServerSideSortRequestControl(final SortKey... sortKeys)
  {
    this(false, sortKeys);
  }



  /**
   * Creates a new server-side sort control that will sort the results based on
   * the provided set of sort keys.
   *
   * @param  sortKeys  The set of sort keys to define the desired order in which
   *                   the results should be returned.  It must not be
   *                   {@code null} or empty.
   */
  public ServerSideSortRequestControl(final List<SortKey> sortKeys)
  {
    this(false, sortKeys);
  }



  /**
   * Creates a new server-side sort control that will sort the results based on
   * the provided set of sort keys.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  sortKeys    The set of sort keys to define the desired order in
   *                     which the results should be returned.  It must not be
   *                     {@code null} or empty.
   */
  public ServerSideSortRequestControl(final boolean isCritical,
                                      final SortKey... sortKeys)
  {
    super(SERVER_SIDE_SORT_REQUEST_OID, isCritical, encodeValue(sortKeys));

    this.sortKeys = sortKeys;
  }



  /**
   * Creates a new server-side sort control that will sort the results based on
   * the provided set of sort keys.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  sortKeys    The set of sort keys to define the desired order in
   *                     which the results should be returned.  It must not be
   *                     {@code null} or empty.
   */
  public ServerSideSortRequestControl(final boolean isCritical,
                                      final List<SortKey> sortKeys)
  {
    this(isCritical, sortKeys.toArray(new SortKey[sortKeys.size()]));
  }



  /**
   * Creates a new server-side sort request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a server-side sort
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         server-side sort request control.
   */
  public ServerSideSortRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      sortKeys = new SortKey[elements.length];
      for (int i=0; i < elements.length; i++)
      {
        sortKeys[i] = SortKey.decode(elements[i]);
      }
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  sortKeys  The set of sort keys to define the desired order in which
   *                   the results should be returned.  It must not be
   *                   {@code null} or empty.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  private static ASN1OctetString encodeValue(final SortKey[] sortKeys)
  {
    ensureNotNull(sortKeys);
    ensureTrue(sortKeys.length > 0,
               "ServerSideSortRequestControl.sortKeys must not be empty.");

    final ASN1Element[] valueElements = new ASN1Element[sortKeys.length];
    for (int i=0; i < sortKeys.length; i++)
    {
      valueElements[i] = sortKeys[i].encode();
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Retrieves the set of sort keys that define the desired order in which the
   * results should be returned.
   *
   * @return  The set of sort keys that define the desired order in which the
   *          results should be returned.
   */
  public SortKey[] getSortKeys()
  {
    return sortKeys;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SORT_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ServerSideSortRequestControl(sortKeys={");

    for (int i=0; i < sortKeys.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append('\'');
      sortKeys[i].toString(buffer);
      buffer.append('\'');
    }

    buffer.append("})");
  }
}
