/*
 * Copyright 2008-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2022 Ping Identity Corporation
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
 * Copyright (C) 2008-2022 Ping Identity Corporation
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
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
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
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the matched values request control
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc3876.txt">RFC 3876</A>.  It
 * should only be used with a search request, in which case it indicates that
 * only attribute values matching at least one of the provided
 * {@link MatchedValuesFilter}s should be included in matching entries.  That
 * is, this control may be used to restrict the set of values included in the
 * entries that are returned.  This is particularly useful for multivalued
 * attributes with a large number of values when only a small number of values
 * are of interest to the client.
 * <BR><BR>
 * There are no corresponding response controls included in the search result
 * entry, search result reference, or search result done messages returned for
 * the associated search request.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the matched values request
 * control.  It will cause only values of the "{@code description}" attribute
 * to be returned in which those values start with the letter f:
 * <PRE>
 * // Ensure that a test user has multiple description values.
 * LDAPResult modifyResult = connection.modify(
 *      "uid=test.user,ou=People,dc=example,dc=com",
 *      new Modification(ModificationType.REPLACE,
 *           "description", // Attribute name
 *           "first", "second", "third", "fourth")); // Attribute values.
 * assertResultCodeEquals(modifyResult, ResultCode.SUCCESS);
 *
 * // Perform a search to retrieve the test user entry without using the
 * // matched values request control.  This should return all four description
 * // values.
 * SearchRequest searchRequest = new SearchRequest(
 *      "uid=test.user,ou=People,dc=example,dc=com", // Base DN
 *      SearchScope.BASE, // Scope
 *      Filter.createPresenceFilter("objectClass"), // Filter
 *      "description"); // Attributes to return.
 * SearchResultEntry entryRetrievedWithoutControl =
 *      connection.searchForEntry(searchRequest);
 * Attribute fullDescriptionAttribute =
 *      entryRetrievedWithoutControl.getAttribute("description");
 * int numFullDescriptionValues = fullDescriptionAttribute.size();
 *
 * // Update the search request to include a matched values control that will
 * // only return values that start with the letter "f".  In our test entry,
 * // this should just match two values ("first" and "fourth").
 * searchRequest.addControl(new MatchedValuesRequestControl(
 *      MatchedValuesFilter.createSubstringFilter("description", // Attribute
 *           "f", // subInitial component
 *           null, // subAny components
 *           null))); // subFinal component
 * SearchResultEntry entryRetrievedWithControl =
 *      connection.searchForEntry(searchRequest);
 * Attribute partialDescriptionAttribute =
 *      entryRetrievedWithControl.getAttribute("description");
 * int numPartialDescriptionValues = partialDescriptionAttribute.size();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MatchedValuesRequestControl
       extends Control
{
  /**
   * The OID (1.2.826.0.1.3344810.2.3) for the matched values request control.
   */
  @NotNull public static final String MATCHED_VALUES_REQUEST_OID =
       "1.2.826.0.1.3344810.2.3";



  /**
   * The name of the field used to hold the matched values filters in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_FILTERS = "filters";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6799850686547208774L;



  // The set of matched values filters for this control.
  @NotNull private final MatchedValuesFilter[] filters;



  /**
   * Creates a new matched values request control with the provided set of
   * filters.  It will not be be marked as critical.
   *
   * @param  filters  The set of filters to use for this control.  At least one
   *                  filter must be provided.
   */
  public MatchedValuesRequestControl(
              @NotNull final MatchedValuesFilter... filters)
  {
    this(false, filters);
  }



  /**
   * Creates a new matched values request control with the provided set of
   * filters.  It will not be be marked as critical.
   *
   * @param  filters  The set of filters to use for this control.  At least one
   *                  filter must be provided.
   */
  public MatchedValuesRequestControl(
              @NotNull final List<MatchedValuesFilter> filters)
  {
    this(false, filters);
  }



  /**
   * Creates a new matched values request control with the provided criticality
   * and set of filters.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  filters     The set of filters to use for this control.  At least
   *                     one filter must be provided.
   */
  public MatchedValuesRequestControl(final boolean isCritical,
              @NotNull final MatchedValuesFilter... filters)
  {
    super(MATCHED_VALUES_REQUEST_OID, isCritical,  encodeValue(filters));

    this.filters = filters;
  }



  /**
   * Creates a new matched values request control with the provided criticality
   * and set of filters.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  filters     The set of filters to use for this control.  At least
   *                     one filter must be provided.
   */
  public MatchedValuesRequestControl(final boolean isCritical,
              @NotNull final List<MatchedValuesFilter> filters)
  {
    this(isCritical, filters.toArray(new MatchedValuesFilter[filters.size()]));
  }



  /**
   * Creates a new matched values request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a matched values
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         matched values request control.
   */
  public MatchedValuesRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MV_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] filterElements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      filters = new MatchedValuesFilter[filterElements.length];
      for (int i=0; i < filterElements.length; i++)
      {
        filters[i] = MatchedValuesFilter.decode(filterElements[i]);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MV_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }



  /**
   * Encodes the provided set of filters into a value appropriate for use with
   * the matched values control.
   *
   * @param  filters  The set of filters to include in the value.  It must not
   *                  be {@code null} or empty.
   *
   * @return  The ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final MatchedValuesFilter[] filters)
  {
    Validator.ensureNotNull(filters);
    Validator.ensureTrue(filters.length > 0,
         "MatchedValuesRequestControl.filters must not be empty.");

    final ASN1Element[] elements = new ASN1Element[filters.length];
    for (int i=0; i < filters.length; i++)
    {
      elements[i] = filters[i].encode();
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the set of filters for this matched values request control.
   *
   * @return  The set of filters for this matched values request control.
   */
  @NotNull()
  public MatchedValuesFilter[] getFilters()
  {
    return filters;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_MATCHED_VALUES_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final List<JSONValue> filterValues = new ArrayList<>(filters.length);
    for (final MatchedValuesFilter filter : filters)
    {
      filterValues.add(new JSONString(filter.toString()));
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              MATCHED_VALUES_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_MATCHED_VALUES_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_FILTERS,
                        new JSONArray(filterValues)))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * matched values request control.
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
   * @return  The matched values request control that was decoded from the
   *          provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid matched values request control.
   */
  @NotNull()
  public static MatchedValuesRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new MatchedValuesRequestControl(new Control(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final List<JSONValue> filterValues =
         valueObject.getFieldAsArray(JSON_FIELD_FILTERS);
    if (filterValues == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MV_REQUEST_JSON_NO_FILTERS.get(
                controlObject.toSingleLineString(), JSON_FIELD_FILTERS));
    }

    if (filterValues.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MV_REQUEST_JSON_EMPTY_FILTERS.get(
                controlObject.toSingleLineString(), JSON_FIELD_FILTERS));
    }


    final List<MatchedValuesFilter> filters =
         new ArrayList<>(filterValues.size());
    for (final JSONValue filterValue : filterValues)
    {
      if (filterValue instanceof JSONString)
      {
        final String filterString = ((JSONString) filterValue).stringValue();

        try
        {
          final Filter filter = Filter.create(filterString);
          filters.add(MatchedValuesFilter.create(filter));
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MV_REQUEST_JSON_INVALID_FILTER.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_FILTERS, filterString, e.getMessage()),
               e);
        }
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MV_REQUEST_JSON_FILTER_NOT_STRING.get(
                  controlObject.toSingleLineString(), JSON_FIELD_FILTERS));
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_FILTERS);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MV_REQUEST_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new MatchedValuesRequestControl(jsonControl.getCriticality(),
         filters);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MatchedValuesRequestControl(filters={");

    for (int i=0; i < filters.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append('\'');
      filters[i].toString(buffer);
      buffer.append('\'');
    }

    buffer.append("}, isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
