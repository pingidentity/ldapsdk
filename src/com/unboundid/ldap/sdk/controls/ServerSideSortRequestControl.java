/*
 * Copyright 2007-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2024 Ping Identity Corporation
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
 * Copyright (C) 2007-2024 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



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
  @NotNull public static final String SERVER_SIDE_SORT_REQUEST_OID =
       "1.2.840.113556.1.4.473";



  /**
   * The name of the field used to hold the attribute name in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ATTRIBUTE_NAME =
       "attribute-name";



  /**
   * The name of the field used to hold the matching rule ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MATCHING_RULE_ID =
       "matching-rule-id";



  /**
   * The name of the field used to hold the reverse-order flag in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_REVERSE_ORDER =
       "reverse-order";



  /**
   * The name of the field used to hold the sort keys in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_FIELD_SORT_KEYS = "sort-keys";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3021901578330574772L;



  // The set of sort keys to use with this control.
  @NotNull private final SortKey[] sortKeys;



  /**
   * Creates a new server-side sort control that will sort the results based on
   * the provided set of sort keys.
   *
   * @param  sortKeys  The set of sort keys to define the desired order in which
   *                   the results should be returned.  It must not be
   *                   {@code null} or empty.
   */
  public ServerSideSortRequestControl(@NotNull final SortKey... sortKeys)
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
  public ServerSideSortRequestControl(@NotNull final List<SortKey> sortKeys)
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
                                      @NotNull final SortKey... sortKeys)
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
                                      @NotNull final List<SortKey> sortKeys)
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
  public ServerSideSortRequestControl(@NotNull final Control control)
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
      Debug.debugException(e);
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
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final SortKey[] sortKeys)
  {
    Validator.ensureNotNull(sortKeys);
    Validator.ensureTrue(sortKeys.length > 0,
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
  @NotNull()
  public SortKey[] getSortKeys()
  {
    return sortKeys;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SORT_REQUEST.get();
  }



  /**
   * Retrieves a representation of this server-side sort request control as a
   * JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the server-side sort request control,
   *     the OID is "1.2.840.113556.1.4.473".
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   *   <LI>
   *     {@code value-base64} -- An optional string field whose value is a
   *     base64-encoded representation of the raw value for this server-side
   *     sort request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this server-side sort
   *     request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code sort-keys} -- A mandatory array field whose values are JSON
   *         objects used to specify the requested sort order.  Each of the JSON
   *         objects with the following fields:
   *         <UL>
   *           <LI>
   *             {@code attribute-name} -- A mandatory string field whose value
   *             is the name of the attribute to use for sorting.
   *           </LI>
   *           <LI>
   *             {@code reverse-order} -- A mandatory Boolean field that
   *             indicates whether the results should be sorted in descending
   *             order rather than ascending.
   *           </LI>
   *           <LI>
   *             {@code matching-rule-id} -- An optional string field whose
   *             value is the name or OID of the ordering matching rule to use
   *             to perform the sorting.
   *           </LI>
   *         </UL>
   *       </LI>
   *     </UL>
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final List<JSONValue> sortKeyValues = new ArrayList<>(sortKeys.length);
    for (final SortKey sortKey : sortKeys)
    {
      final Map<String,JSONValue> fields = new LinkedHashMap<>();
      fields.put(JSON_FIELD_ATTRIBUTE_NAME,
           new JSONString(sortKey.getAttributeName()));
      fields.put(JSON_FIELD_REVERSE_ORDER,
           new JSONBoolean(sortKey.reverseOrder()));

      if (sortKey.getMatchingRuleID() != null)
      {
        fields.put(JSON_FIELD_MATCHING_RULE_ID,
             new JSONString(sortKey.getMatchingRuleID()));
      }

      sortKeyValues.add(new JSONObject(fields));
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              SERVER_SIDE_SORT_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_SORT_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_SORT_KEYS,
                        new JSONArray(sortKeyValues)))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * server-side sort request control.
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
   * @return  The server-side sort request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid server-side sort request control.
   */
  @NotNull()
  public static ServerSideSortRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new ServerSideSortRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final List<JSONValue> sortKeyValues =
         valueObject.getFieldAsArray(JSON_FIELD_SORT_KEYS);
    if (sortKeyValues == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SORT_REQUEST_JSON_MISSING_SORT_KEYS.get(
                controlObject.toSingleLineString(), JSON_FIELD_SORT_KEYS));
    }

    if (sortKeyValues.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SORT_REQUEST_JSON_EMPTY_SORT_KEYS.get(
                controlObject.toSingleLineString(), JSON_FIELD_SORT_KEYS));
    }


    final List<SortKey> sortKeys = new ArrayList<>(sortKeyValues.size());
    for (final JSONValue sortKeyValue : sortKeyValues)
    {
      if (sortKeyValue instanceof JSONObject)
      {
        final JSONObject sortKeyObject = (JSONObject) sortKeyValue;

        final String attributeName =
             sortKeyObject.getFieldAsString(JSON_FIELD_ATTRIBUTE_NAME);
        if (attributeName == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SORT_REQUEST_JSON_SORT_KEY_MISSING_FIELD.get(
                    controlObject.toSingleLineString(), JSON_FIELD_SORT_KEYS,
                    JSON_FIELD_ATTRIBUTE_NAME));
        }

        final Boolean reverseOrder =
             sortKeyObject.getFieldAsBoolean(JSON_FIELD_REVERSE_ORDER);
        if (reverseOrder == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SORT_REQUEST_JSON_SORT_KEY_MISSING_FIELD.get(
                    controlObject.toSingleLineString(), JSON_FIELD_SORT_KEYS,
                    JSON_FIELD_REVERSE_ORDER));
        }

        final String matchingRuleID =
             sortKeyObject.getFieldAsString(JSON_FIELD_MATCHING_RULE_ID);

        if (strict)
        {
          final List<String> unrecognizedFields =
               JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                    sortKeyObject, JSON_FIELD_ATTRIBUTE_NAME,
                    JSON_FIELD_REVERSE_ORDER, JSON_FIELD_MATCHING_RULE_ID);
          if (! unrecognizedFields.isEmpty())
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SORT_REQUEST_JSON_UNRECOGNIZED_SORT_KEY_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_SORT_KEYS, unrecognizedFields.get(0)));
          }
        }

        sortKeys.add(new SortKey(attributeName, matchingRuleID, reverseOrder));
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SORT_REQUEST_JSON_SORT_KEY_VALUE_NOT_OBJECT.get(
                  controlObject.toSingleLineString(), JSON_FIELD_SORT_KEYS));
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_SORT_KEYS);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SORT_REQUEST_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new ServerSideSortRequestControl(jsonControl.getCriticality(),
         sortKeys);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
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
