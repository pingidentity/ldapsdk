/*
 * Copyright 2007-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2022 Ping Identity Corporation
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
 * Copyright (C) 2007-2022 Ping Identity Corporation
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



import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the simple paged results control as
 * defined in <A HREF="http://www.ietf.org/rfc/rfc2696.txt">RFC 2696</A>.  It
 * allows the client to iterate through a potentially large set of search
 * results in subsets of a specified number of entries (i.e., "pages").
 * <BR><BR>
 * The same control encoding is used for both the request control sent by
 * clients and the response control returned by the server.  It may contain
 * two elements:
 * <UL>
 *   <LI>Size -- In a request control, this provides the requested page size,
 *       which is the maximum number of entries that the server should return
 *       in the next iteration of the search.  In a response control, it is an
 *       estimate of the total number of entries that match the search
 *       criteria.</LI>
 *   <LI>Cookie -- A token which is used by the server to keep track of its
 *       position in the set of search results.  The first request sent by the
 *       client should not include a cookie, and the last response sent by the
 *       server should not include a cookie.  For all other intermediate search
 *       requests and responses,  the server will include a cookie value in its
 *       response that the client should include in its next request.</LI>
 * </UL>
 * When the client wishes to use the paged results control, the first search
 * request should include a version of the paged results request control that
 * was created with a requested page size but no cookie.  The corresponding
 * response from the server will include a version of the paged results control
 * that may include an estimate of the total number of matching entries, and
 * may also include a cookie.  The client should include this cookie in the
 * next request (with the same set of search criteria) to retrieve the next page
 * of results.  This process should continue until the response control returned
 * by the server does not include a cookie, which indicates that the end of the
 * result set has been reached.
 * <BR><BR>
 * Note that the simple paged results control is similar to the
 * {@link VirtualListViewRequestControl} in that both allow the client to
 * request that only a portion of the result set be returned at any one time.
 * However, there are significant differences between them, including:
 * <UL>
 *   <LI>In order to use the virtual list view request control, it is also
 *       necessary to use the {@link ServerSideSortRequestControl} to ensure
 *       that the entries are sorted.  This is not a requirement for the
 *       simple paged results control.</LI>
 *   <LI>The simple paged results control may only be used to iterate
 *       sequentially through the set of search results.  The virtual list view
 *       control can retrieve pages out of order, can retrieve overlapping
 *       pages, and can re-request pages that it had already retrieved.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the use of the simple paged results
 * control.  It will iterate through all users, retrieving up to 10 entries at a
 * time:
 * <PRE>
 * // Perform a search to retrieve all users in the server, but only retrieving
 * // ten at a time.
 * int numSearches = 0;
 * int totalEntriesReturned = 0;
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("objectClass", "person"));
 * ASN1OctetString resumeCookie = null;
 * while (true)
 * {
 *   searchRequest.setControls(
 *        new SimplePagedResultsControl(10, resumeCookie));
 *   SearchResult searchResult = connection.search(searchRequest);
 *   numSearches++;
 *   totalEntriesReturned += searchResult.getEntryCount();
 *   for (SearchResultEntry e : searchResult.getSearchEntries())
 *   {
 *     // Do something with each entry...
 *   }
 *
 *   LDAPTestUtils.assertHasControl(searchResult,
 *        SimplePagedResultsControl.PAGED_RESULTS_OID);
 *   SimplePagedResultsControl responseControl =
 *        SimplePagedResultsControl.get(searchResult);
 *   if (responseControl.moreResultsToReturn())
 *   {
 *     // The resume cookie can be included in the simple paged results
 *     // control included in the next search to get the next page of results.
 *     resumeCookie = responseControl.getCookie();
 *   }
 *   else
 *   {
 *     break;
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SimplePagedResultsControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.2.840.113556.1.4.319) for the paged results control.
   */
  @NotNull public static final String PAGED_RESULTS_OID =
       "1.2.840.113556.1.4.319";



  /**
   * The name of the field used to hold the cookie in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_FIELD_COOKIE = "cookie";



  /**
   * The name of the field used to hold the size in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_FIELD_SIZE = "size";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2186787148024999291L;



  // The encoded cookie returned from the server (for a response control) or
  // that should be included in the next request to the server (for a request
  // control).
  @NotNull private final ASN1OctetString cookie;

  // The maximum requested page size (for a request control), or the estimated
  // total result set size (for a response control).
  private final int size;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  SimplePagedResultsControl()
  {
    size   = 0;
    cookie = new ASN1OctetString();
  }



  /**
   * Creates a new paged results control with the specified page size.  This
   * version of the constructor should only be used when creating the first
   * search as part of the set of paged results.  Subsequent searches to
   * retrieve additional pages should use the response control returned by the
   * server in their next request, until the response control returned by the
   * server does not include a cookie.
   *
   * @param  pageSize  The maximum number of entries that the server should
   *                   return in the first page.
   */
  public SimplePagedResultsControl(final int pageSize)
  {
    super(PAGED_RESULTS_OID, false, encodeValue(pageSize, null));

    size   = pageSize;
    cookie = new ASN1OctetString();
  }



  /**
   * Creates a new paged results control with the specified page size.  This
   * version of the constructor should only be used when creating the first
   * search as part of the set of paged results.  Subsequent searches to
   * retrieve additional pages should use the response control returned by the
   * server in their next request, until the response control returned by the
   * server does not include a cookie.
   *
   * @param  pageSize    The maximum number of entries that the server should
   *                     return in the first page.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public SimplePagedResultsControl(final int pageSize, final boolean isCritical)
  {
    super(PAGED_RESULTS_OID, isCritical, encodeValue(pageSize, null));

    size   = pageSize;
    cookie = new ASN1OctetString();
  }



  /**
   * Creates a new paged results control with the specified page size and the
   * provided cookie.  This version of the constructor should be used to
   * continue iterating through an existing set of results, but potentially
   * using a different page size.
   *
   * @param  pageSize  The maximum number of entries that the server should
   *                   return in the next page of the results.
   * @param  cookie    The cookie provided by the server after returning the
   *                   previous page of results, or {@code null} if this request
   *                   will retrieve the first page of results.
   */
  public SimplePagedResultsControl(final int pageSize,
                                   @Nullable final ASN1OctetString cookie)
  {
    super(PAGED_RESULTS_OID, false, encodeValue(pageSize, cookie));

    size = pageSize;

    if (cookie == null)
    {
      this.cookie = new ASN1OctetString();
    }
    else
    {
      this.cookie = cookie;
    }
  }



  /**
   * Creates a new paged results control with the specified page size and the
   * provided cookie.  This version of the constructor should be used to
   * continue iterating through an existing set of results, but potentially
   * using a different page size.
   *
   * @param  pageSize    The maximum number of entries that the server should
   *                     return in the first page.
   * @param  cookie      The cookie provided by the server after returning the
   *                     previous page of results, or {@code null} if this
   *                     request will retrieve the first page of results.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public SimplePagedResultsControl(final int pageSize,
                                   @Nullable final ASN1OctetString cookie,
                                   final boolean isCritical)
  {
    super(PAGED_RESULTS_OID, isCritical, encodeValue(pageSize, cookie));

    size = pageSize;

    if (cookie == null)
    {
      this.cookie = new ASN1OctetString();
    }
    else
    {
      this.cookie = cookie;
    }
  }



  /**
   * Creates a new paged results control from the control with the provided set
   * of information.  This should be used to decode the paged results response
   * control returned by the server with a page of results.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         simple paged results control.
   */
  public SimplePagedResultsControl(@NotNull final String oid,
                                   final boolean isCritical,
                                   @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    try
    {
      size = ASN1Integer.decodeAsInteger(valueElements[0]).intValue();
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PAGED_RESULTS_FIRST_NOT_INTEGER.get(ae), ae);
    }

    cookie = ASN1OctetString.decodeAsOctetString(valueElements[1]);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SimplePagedResultsControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new SimplePagedResultsControl(oid, isCritical, value);
  }



  /**
   * Extracts a simple paged results response control from the provided result.
   *
   * @param  result  The result from which to retrieve the simple paged results
   *                 response control.
   *
   * @return  The simple paged results response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          simple paged results response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the simple paged results response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static SimplePagedResultsControl get(
                     @NotNull final SearchResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PAGED_RESULTS_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof SimplePagedResultsControl)
    {
      return (SimplePagedResultsControl) c;
    }
    else
    {
      return new SimplePagedResultsControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  pageSize  The maximum number of entries that the server should
   *                   return in the next page of the results.
   * @param  cookie    The cookie provided by the server after returning the
   *                   previous page of results, or {@code null} if this request
   *                   will retrieve the first page of results.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final int pageSize,
                      @Nullable final ASN1OctetString cookie)
  {
    final ASN1Element[] valueElements;
    if (cookie == null)
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Integer(pageSize),
        new ASN1OctetString()
      };
    }
    else
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Integer(pageSize),
        cookie
      };
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Retrieves the size for this paged results control.  For a request control,
   * it may be used to specify the number of entries that should be included in
   * the next page of results.  For a response control, it may be used to
   * specify the estimated number of entries in the complete result set.
   *
   * @return  The size for this paged results control.
   */
  public int getSize()
  {
    return size;
  }



  /**
   * Retrieves the cookie for this control, which may be used in a subsequent
   * request to resume reading entries from the next page of results.  The
   * value should have a length of zero when used to retrieve the first page of
   * results for a given search, and also in the response from the server when
   * there are no more entries to send.  It should be non-empty for all other
   * conditions.
   *
   * @return  The cookie for this control, or an empty cookie (with a value
   *          length of zero) if there is none.
   */
  @NotNull()
  public ASN1OctetString getCookie()
  {
    return cookie;
  }



  /**
   * Indicates whether there are more results to return as part of this search.
   *
   * @return  {@code true} if there are more results to return, or
   *          {@code false} if not.
   */
  public boolean moreResultsToReturn()
  {
    return (cookie.getValue().length > 0);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PAGED_RESULTS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();
    valueFields.put(JSON_FIELD_SIZE, new JSONNumber(size));

    final byte[] cookieBytes = cookie.getValue();
    if (cookieBytes.length > 0)
    {
      valueFields.put(JSON_FIELD_COOKIE,
           new JSONString(Base64.encode(cookieBytes)));
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              PAGED_RESULTS_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_PAGED_RESULTS.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * simple paged results control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The simple paged results control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid simple paged results control.
   */
  @NotNull()
  public static SimplePagedResultsControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new SimplePagedResultsControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final Integer pageSize = valueObject.getFieldAsInteger(JSON_FIELD_SIZE);
    if (pageSize == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PAGED_RESULTS_JSON_MISSING_PAGE_SIZE.get(
                controlObject.toSingleLineString(), JSON_FIELD_SIZE));
    }

    final ASN1OctetString cookie;
    final String cookieBase64 = valueObject.getFieldAsString(JSON_FIELD_COOKIE);
    if ((cookieBase64 == null) || cookieBase64.isEmpty())
    {
      cookie = new ASN1OctetString();
    }
    else
    {
      try
      {
        cookie = new ASN1OctetString(Base64.decode(cookieBase64));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PAGED_RESULTS_JSON_COOKIE_NOT_BASE64.get(
                  controlObject.toSingleLineString(), JSON_FIELD_COOKIE),
             e);
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_SIZE, JSON_FIELD_COOKIE);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PAGED_RESULTS_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new SimplePagedResultsControl(pageSize, cookie,
         jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SimplePagedResultsControl(pageSize=");
    buffer.append(size);
    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
