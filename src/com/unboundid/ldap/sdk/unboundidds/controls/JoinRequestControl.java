/*
 * Copyright 2009-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2025 Ping Identity Corporation
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
 * Copyright (C) 2009-2025 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of an LDAP control which can be
 * included in a search request to indicate that search result entries should be
 * returned along with related entries based on a given set of criteria, much
 * like an SQL join in a relational database.
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
 * This request control has an OID of 1.3.6.1.4.1.30221.2.5.9, and the
 * criticality is generally true.  It must have a value, and the format of that
 * value is described in the class-level documentation for the
 * {@link JoinRequestValue} class.
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
  @NotNull public static final String JOIN_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.9";



  /**
   * The name of the field used to hold the alias dereferencing behavior in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR =
       "alias-dereferencing-behavior";



  /**
   * The name of the field used to hold the requested attributes in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ATTRIBUTES = "attributes";



  /**
   * The name of the field used to hold the base DN type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_BASE_DN_TYPE = "base-dn-type";



  /**
   * The name of the field used to hold the base DN value in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_BASE_DN_VALUE =
       "base-dn-value";



  /**
   * The name of the field used to hold the filter in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_FIELD_FILTER = "filter";



  /**
   * The name of the field used to hold the join rule in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_FIELD_JOIN_RULE = "join-rule";



  /**
   * The name of the field used to hold a nested join value in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_NESTED_JOIN = "nested-join";



  /**
   * The name of the field used to hold the require-match flag in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_REQUIRE_MATCH =
       "require-match";



  /**
   * The name of the field used to hold the scope in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_FIELD_SCOPE = "scope";



  /**
   * The name of the field used to hold the size limit in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SIZE_LIMIT = "size-limit";



  /**
   * The neverDerefAliases alias dereferencing behavior that will be used in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_ALIAS_BEHAVIOR_ALWAYS =
       "derefAlways";



  /**
   * The neverDerefAliases alias dereferencing behavior that will be used in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_ALIAS_BEHAVIOR_FINDING =
       "derefInFindingBaseObj";



  /**
   * The neverDerefAliases alias dereferencing behavior that will be used in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_ALIAS_BEHAVIOR_NEVER =
       "neverDerefAliases";



  /**
   * The neverDerefAliases alias dereferencing behavior that will be used in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_ALIAS_BEHAVIOR_SEARCHING =
       "derefInSearching";



  /**
   * The base DN type value that will indicate that a custom base DN should be
   * used as the join base DN in the JSON representation of this control.
   */
  @NotNull private static final String JSON_BASE_DN_TYPE_USE_CUSTOM_BASE_DN =
       "use-custom-base-dn";



  /**
   * The base DN type value that will indicate that the search base DN should
   * be used as the join base DN in the JSON representation of this control.
   */
  @NotNull private static final String JSON_BASE_DN_TYPE_USE_SEARCH_BASE_DN =
       "use-search-base-dn";



  /**
   * The base DN type value that will indicate that the source entry DN should
   * be used as the join base DN in the JSON representation of this control.
   */
  @NotNull private static final String JSON_BASE_DN_TYPE_USE_SOURCE_ENTRY_DN =
       "use-source-entry-dn";



  /**
   * The baseObject scope value that will be used in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_SCOPE_BASE_OBJECT = "baseObject";



  /**
   * The singleLevel scope value that will be used in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_SCOPE_SINGLE_LEVEL = "singleLevel";



  /**
   * The subordinateSubtree scope value that will be used in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_SCOPE_SUBORDINATE_SUBTREE =
       "subordinateSubtree";



  /**
   * The wholeSubtree scope value that will be used in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_SCOPE_WHOLE_SUBTREE =
       "wholeSubtree";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1321645105838145996L;



  // The join request value for this control.
  @NotNull private final JoinRequestValue joinRequestValue;



  /**
   * Creates a new join request control with the provided join request value.
   *
   * @param  joinRequestValue  The join request value to use for this control.
   */
  public JoinRequestControl(@NotNull final JoinRequestValue joinRequestValue)
  {
    this(true, joinRequestValue);
  }



  /**
   * Creates a new join request control with the provided join request value.
   *
   * @param  isCritical        Indicates whether this control should be
   *                           considered critical.
   * @param  joinRequestValue  The join request value to use for this control.
   */
  public JoinRequestControl(final boolean isCritical,
                            @NotNull final JoinRequestValue joinRequestValue)
  {
    super(JOIN_REQUEST_OID, isCritical,
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
  public JoinRequestControl(@NotNull final Control control)
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
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_VALUE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    joinRequestValue = JoinRequestValue.decode(valueElement);
  }



  /**
   * Retrieves the join request value for this join request control.
   *
   * @return  The join request value for this join request control.
   */
  @NotNull()
  public JoinRequestValue getJoinRequestValue()
  {
    return joinRequestValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_JOIN_REQUEST.get();
  }



  /**
   * Retrieves a representation of this join request control as a JSON object.
   * The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the join request control, the OID is
   *     "1.3.6.1.4.1.30221.2.5.9".
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
   *     base64-encoded representation of the raw value for this join request
   *     control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this join request
   *     control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code join-rule} -- A mandatory JSON object field that provides
   *         the primary criteria to use when selecting entries to be joined
   *         with search result entries.  The format for join rule objects will
   *         be described in more detail below.
   *       </LI>
   *       <LI>
   *         {@code base-dn-type} -- A mandatory string field that indicates
   *         who the server should determine the base DN to use for join
   *         processing.  The value must be one of "{@code use-search-base-dn}",
   *         "{@code use-source-entry-dn}", or "{@code use-custom-base-dn}".
   *       </LI>
   *       <LI>
   *         {@code base-dn-value} -- An optional string field that provides the
   *         custom base DN value to use if the {@code base-dn-type} value was
   *         "{@code use-custom-base-dn}".  This field must be present if the
   *         {@code base-dn-type} value was "{@code use-custom-base-dn}", and it
   *         must be absent for other {@code base-dn-type} values.
   *       </LI>
   *       <LI>
   *         {@code scope} -- An optional string field whose value specifies the
   *         scope to use for join processing.  If present, the value must be
   *         one of "{@code baseObject}", "{@code singleLevel}",
   *         "{@code wholeSubtree}", or "{@code subordinateSubtree}".  If this
   *         is not specified, the scope from the search request will be used.
   *       </LI>
   *       <LI>
   *         {@code alias-dereferencing-behavior} -- An optional string field
   *         whose value specifies the behavior to use for dereferencing any
   *         aliases encountered during join processing.  If present, the value
   *         must be one of "{@code neverDerefAliases}",
   *         "{@code derefInSearching}", "{@code derefInFindingBaseObj}", or
   *         {@code derefAlways}".  If this is not specified, the dereferencing
   *         behavior from the search request will be used.
   *       </LI>
   *       <LI>
   *         {@code size-limit} -- An optional integer field whose value
   *         specifies the maximum number of entries that may be joined with any
   *         single search
   *         result entry.
   *       </LI>
   *       <LI>
   *         {@code filter} -- An optional string field whose value is the
   *         string representation of a filter that will be required to match an
   *         entry for it to be joined with a search result entry.
   *       </LI>
   *       <LI>
   *         {@code attributes} -- An optional array field whose values are
   *         strings that are the names of attributes to include in joined
   *         entries.
   *       </LI>
   *       <LI>
   *         {@code require-match} -- A mandatory Boolean field that indicates
   *         whether to suppress a search result entry from the set of results
   *         to the client if it is not joined with any other entries.
   *       </LI>
   *       <LI>
   *         {@code nested-join} -- An optional JSON object field whose value
   *         represents the join criteria for a nested join operation.  If
   *         present, the fields in this object are the same as the fields that
   *         may be used in the top-level {@code value-json} field (optionally
   *         including another {@code nested-jon} element if desired).
   *       </LI>
   *     </UL>
   *   </LI>
   * </UL>
   * <BR><BR>
   * The following encodings may be used for different types of join rules:
   * <UL>
   *   <LI>
   *     The fields that may be used for a DN join include:
   *     <UL>
   *       <LI>
   *         {@code type} -- A mandatory string field whose value must be
   *         "{@code dn}".
   *       </LI>
   *       <LI>
   *         {@code source-attribute} -- A mandatory string field whose value is
   *         the name of the attribute in the source entry that contains the DNs
   *         of the entries to be joined with that entry.
   *       </LI>
   *     </UL>
   *   </LI>
   *   <LI>
   *     The fields that may be used for a reverse DN join include:
   *     <UL>
   *       <LI>
   *         {@code type} -- A mandatory string field whose value must be
   *         "{@code reverse-dn}".
   *       </LI>
   *       <LI>
   *         {@code target-attribute} -- A mandatory string field whose value is
   *         the name of the attribute in joined entries that contains a value
   *         that matches the DN of the source entry.
   *       </LI>
   *     </UL>
   *   </LI>
   *   <LI>
   *     The fields that may be used for an equality join include:
   *     <UL>
   *       <LI>
   *         {@code type} -- A mandatory string field whose value must be
   *         "{@code equality}".
   *       </LI>
   *       <LI>
   *         {@code source-attribute} -- A mandatory string field whose value is
   *         the name of an attribute in the source entry whose values will be
   *         used to identify entries to be joined with that source entry.
   *       </LI>
   *       <LI>
   *         {@code target-attribute} -- A mandatory string field whose value is
   *         the name of the attribute in joined entries that must contain at
   *         least one of the values from the source attribute in the source
   *         entry.
   *       </LI>
   *       <LI>
   *         {@code match-all} -- A mandatory Boolean field that indicates
   *         whether to only join entries in which the target attribute contains
   *         all of the values of the source attribute.
   *       </LI>
   *     </UL>
   *   </LI>
   *   <LI>
   *     The fields that may be used for a contains join include:
   *     <UL>
   *       <LI>
   *         {@code type} -- A mandatory string field whose value must be
   *         "{@code contains}".
   *       </LI>
   *       <LI>
   *         {@code source-attribute} -- A mandatory string field whose value is
   *         the name of an attribute in the source entry whose values will be
   *         used to identify entries to be joined with that source entry.
   *       </LI>
   *       <LI>
   *         {@code target-attribute} -- A mandatory string field whose value is
   *         the name of the attribute in joined entries that must contain at
   *         least one value that includes the value of a source attribute as a
   *         substring.
   *       </LI>
   *       <LI>
   *         {@code match-all} -- A mandatory Boolean field that indicates
   *         whether to only join entries in which the target attribute contains
   *         values that contain all of the values of the source attribute as
   *         substrings.
   *       </LI>
   *     </UL>
   *   </LI>
   *   <LI>
   *     The fields that may be used for an AND join include:
   *     <UL>
   *       <LI>
   *         {@code type} -- A mandatory string field whose value must be
   *         "{@code and}".
   *       </LI>
   *       <LI>
   *         {@code rules} -- A mandatory, non-empty array field whose values
   *         are the JSON objects that represent the nested join rules that must
   *         all match an entry for it to be joined with the source entry.
   *       </LI>
   *     </UL>
   *   </LI>
   *   <LI>
   *     The fields that may be used for an OR join include:
   *     <UL>
   *       <LI>
   *         {@code type} -- A mandatory string field whose value must be
   *         "{@code or}".
   *       </LI>
   *       <LI>
   *         {@code rules} -- A mandatory, non-empty array field whose values
   *         are the JSON objects that represent the nested join rules of which
   *         at least one must match an entry for it to be joined with the
   *         source entry.
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
    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              JOIN_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_JOIN_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              encodeValueJSON(joinRequestValue)));
  }



  /**
   * Encodes the provided join request value to a JSON object.
   *
   * @param  value  The join request value to encode.  It must not be
   *                {@code null}.
   *
   * @return  The JSON object containing the encoded join request value.
   */
  @NotNull()
  private static JSONObject encodeValueJSON(
               @NotNull final JoinRequestValue value)
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>();
    fields.put(JSON_FIELD_JOIN_RULE, value.getJoinRule().toJSON());


    final JoinBaseDN joinBaseDN = value.getBaseDN();
    switch (joinBaseDN.getType())
    {
      case JoinBaseDN.BASE_TYPE_SEARCH_BASE:
        fields.put(JSON_FIELD_BASE_DN_TYPE,
             new JSONString(JSON_BASE_DN_TYPE_USE_SEARCH_BASE_DN));
        break;

      case JoinBaseDN.BASE_TYPE_SOURCE_ENTRY_DN:
        fields.put(JSON_FIELD_BASE_DN_TYPE,
             new JSONString(JSON_BASE_DN_TYPE_USE_SOURCE_ENTRY_DN));
        break;

      case JoinBaseDN.BASE_TYPE_CUSTOM:
        fields.put(JSON_FIELD_BASE_DN_TYPE,
             new JSONString(JSON_BASE_DN_TYPE_USE_CUSTOM_BASE_DN));
        fields.put(JSON_FIELD_BASE_DN_VALUE,
             new JSONString(joinBaseDN.getCustomBaseDN()));
        break;
    }


    final SearchScope scope = value.getScope();
    if (scope != null)
    {
      switch (scope.intValue())
      {
        case SearchScope.BASE_INT_VALUE:
          fields.put(JSON_FIELD_SCOPE,
               new JSONString(JSON_SCOPE_BASE_OBJECT));
          break;

        case SearchScope.ONE_INT_VALUE:
          fields.put(JSON_FIELD_SCOPE,
               new JSONString(JSON_SCOPE_SINGLE_LEVEL));
          break;

        case SearchScope.SUB_INT_VALUE:
          fields.put(JSON_FIELD_SCOPE,
               new JSONString(JSON_SCOPE_WHOLE_SUBTREE));
          break;

        case SearchScope.SUBORDINATE_SUBTREE_INT_VALUE:
          fields.put(JSON_FIELD_SCOPE,
               new JSONString(JSON_SCOPE_SUBORDINATE_SUBTREE));
          break;
      }
    }


    final DereferencePolicy derefPolicy = value.getDerefPolicy();
    if (derefPolicy != null)
    {
      switch(derefPolicy.intValue())
      {
        case 0:
          fields.put(JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR,
               new JSONString(JSON_ALIAS_BEHAVIOR_NEVER));
          break;
        case 1:
          fields.put(JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR,
               new JSONString(JSON_ALIAS_BEHAVIOR_SEARCHING));
          break;
        case 2:
          fields.put(JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR,
               new JSONString(JSON_ALIAS_BEHAVIOR_FINDING));
          break;
        case 3:
          fields.put(JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR,
               new JSONString(JSON_ALIAS_BEHAVIOR_ALWAYS));
          break;
      }
    }


    final Integer sizeLimit = value.getSizeLimit();
    if (sizeLimit != null)
    {
      fields.put(JSON_FIELD_SIZE_LIMIT, new JSONNumber(sizeLimit));
    }


    final Filter filter = value.getFilter();
    if (filter != null)
    {
      fields.put(JSON_FIELD_FILTER, new JSONString(filter.toString()));
    }


    final String[] attributes = value.getAttributes();
    if ((attributes != null) && (attributes.length > 0))
    {
      final List<JSONValue> attrValues = new ArrayList<>(attributes.length);
      for (final String attr : attributes)
      {
        attrValues.add(new JSONString(attr));
      }

      fields.put(JSON_FIELD_ATTRIBUTES, new JSONArray(attrValues));
    }


    fields.put(JSON_FIELD_REQUIRE_MATCH,
         new JSONBoolean(value.requireMatch()));


    final JoinRequestValue nestedJoin = value.getNestedJoin();
    if (nestedJoin != null)
    {
      fields.put(JSON_FIELD_NESTED_JOIN, encodeValueJSON(nestedJoin));
    }

    return new JSONObject(fields);
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a join
   * request control.
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
   * @return  The join request control that was decoded from the provided JSON
   *          object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid join request control.
   */
  @NotNull()
  public static JoinRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new JoinRequestControl(new Control(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue));
    }


    final JoinRequestValue joinRequestValue =
         decodeJoinRequestValueJSON(controlObject, jsonControl.getValueObject(),
              strict);
    return new JoinRequestControl(jsonControl.getCriticality(),
         joinRequestValue);
  }



  /**
   * Decodes the provided value object as a join request value.
   *
   * @param  controlObject  A JSON object that represents the join request
   *                        control being decoded.  It must not be {@code null}.
   * @param  valueObject    A JSON object that represents the join request value
   *                        being decoded.  It must not be {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The join request value that was decoded.
   *
   * @throws  LDAPException  If the provided value object does not represent a
   *                         valid join request control.
   */
  @NotNull()
  private static JoinRequestValue decodeJoinRequestValueJSON(
               @NotNull final JSONObject controlObject,
               @NotNull final JSONObject valueObject,
               final boolean strict)
          throws LDAPException
  {
    final JSONObject joinRuleObject =
         valueObject.getFieldAsObject(JSON_FIELD_JOIN_RULE);
    if (joinRuleObject == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_JOIN_RULE));
    }

    final JoinRule joinRule;
    try
    {
      joinRule = JoinRule.decodeJSONJoinRule(joinRuleObject, strict);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_JSON_INVALID_JOIN_RULE.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_JOIN_RULE, e.getMessage()),
           e);
    }


    final JoinBaseDN baseDN;
    final String baseDNType =
         valueObject.getFieldAsString(JSON_FIELD_BASE_DN_TYPE);
    final String baseDNValue =
         valueObject.getFieldAsString(JSON_FIELD_BASE_DN_VALUE);
    if (baseDNType == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_BASE_DN_TYPE));
    }

    switch (baseDNType)
    {
      case JSON_BASE_DN_TYPE_USE_SEARCH_BASE_DN:
        if (baseDNValue != null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_REQUEST_JSON_DISALLOWED_BASE_DN_VALUE.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_BASE_DN_VALUE, JSON_FIELD_BASE_DN_TYPE,
                    baseDNType));
        }

        baseDN = JoinBaseDN.createUseSearchBaseDN();
        break;

      case JSON_BASE_DN_TYPE_USE_SOURCE_ENTRY_DN:
        if (baseDNValue != null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_REQUEST_JSON_DISALLOWED_BASE_DN_VALUE.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_BASE_DN_VALUE, JSON_FIELD_BASE_DN_TYPE,
                    baseDNType));
        }

        baseDN = JoinBaseDN.createUseSourceEntryDN();
        break;

      case JSON_BASE_DN_TYPE_USE_CUSTOM_BASE_DN:
        if (baseDNValue == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_REQUEST_JSON_MISSING_BASE_DN_VALUE.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_BASE_DN_VALUE, JSON_FIELD_BASE_DN_TYPE,
                    baseDNType));
        }

        baseDN = JoinBaseDN.createUseCustomBaseDN(baseDNValue);
        break;

      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JOIN_REQUEST_JSON_INVALID_BASE_DN_TYPE.get(
                  controlObject.toSingleLineString(), baseDNType,
                  JSON_FIELD_BASE_DN_TYPE, JSON_BASE_DN_TYPE_USE_SEARCH_BASE_DN,
                  JSON_BASE_DN_TYPE_USE_SOURCE_ENTRY_DN,
                  JSON_BASE_DN_TYPE_USE_CUSTOM_BASE_DN));
    }


    final SearchScope scope;
    final String scopeStr =
         valueObject.getFieldAsString(JSON_FIELD_SCOPE);
    if (scopeStr == null)
    {
      scope = null;
    }
    else
    {
      switch (scopeStr)
      {
        case JSON_SCOPE_BASE_OBJECT:
          scope = SearchScope.BASE;
          break;
        case JSON_SCOPE_SINGLE_LEVEL:
          scope = SearchScope.ONE;
          break;
        case JSON_SCOPE_WHOLE_SUBTREE:
          scope = SearchScope.SUB;
          break;
        case JSON_SCOPE_SUBORDINATE_SUBTREE:
          scope = SearchScope.SUBORDINATE_SUBTREE;
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_REQUEST_JSON_INVALID_SCOPE.get(
                    controlObject.toSingleLineString(), scopeStr,
                    JSON_FIELD_SCOPE, JSON_SCOPE_BASE_OBJECT,
                    JSON_SCOPE_SINGLE_LEVEL, JSON_SCOPE_WHOLE_SUBTREE,
                    JSON_SCOPE_SUBORDINATE_SUBTREE));
      }
    }


    final DereferencePolicy derefPolicy;
    final String derefStr =
         valueObject.getFieldAsString(JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR);
    if (derefStr == null)
    {
      derefPolicy = null;
    }
    else
    {
      switch (derefStr)
      {
        case JSON_ALIAS_BEHAVIOR_NEVER:
          derefPolicy = DereferencePolicy.NEVER;
          break;
        case JSON_ALIAS_BEHAVIOR_SEARCHING:
          derefPolicy = DereferencePolicy.SEARCHING;
          break;
        case JSON_ALIAS_BEHAVIOR_FINDING:
          derefPolicy = DereferencePolicy.FINDING;
          break;
        case JSON_ALIAS_BEHAVIOR_ALWAYS:
          derefPolicy = DereferencePolicy.ALWAYS;
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_REQUEST_JSON_INVALID_DEREF.get(
                    controlObject.toSingleLineString(), derefStr,
                    JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR,
                    JSON_ALIAS_BEHAVIOR_NEVER, JSON_ALIAS_BEHAVIOR_SEARCHING,
                    JSON_ALIAS_BEHAVIOR_FINDING, JSON_ALIAS_BEHAVIOR_ALWAYS));
      }
    }


    final Integer sizeLimit =
         valueObject.getFieldAsInteger(JSON_FIELD_SIZE_LIMIT);


    final Filter filter;
    final String filterStr =  valueObject.getFieldAsString(JSON_FIELD_FILTER);
    if (filterStr == null)
    {
      filter = null;
    }
    else
    {
      try
      {
        filter = Filter.create(filterStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JOIN_REQUEST_JSON_INVALID_FILTER.get(
                  controlObject.toSingleLineString(), filterStr,
                  JSON_FIELD_FILTER),
             e);
      }
    }


    final String[] attributes;
    final List<JSONValue> attrValues =
         valueObject.getFieldAsArray(JSON_FIELD_ATTRIBUTES);
    if (attrValues == null)
    {
      attributes = null;
    }
    else
    {
      attributes = new String[attrValues.size()];
      for (int i=0; i < attributes.length; i++)
      {
        final JSONValue v = attrValues.get(i);
        if (v instanceof JSONString)
        {
          attributes[i] = ((JSONString) v).stringValue();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_REQUEST_JSON_ATTR_NOT_STRING.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_ATTRIBUTES));
        }
      }
    }


    final Boolean requireMatch =
         valueObject.getFieldAsBoolean(JSON_FIELD_REQUIRE_MATCH);
    if (requireMatch == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_REQUEST_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_REQUIRE_MATCH));
    }


    final JoinRequestValue nestedJoin;
    final JSONObject nestedJoinObject =
         valueObject.getFieldAsObject(JSON_FIELD_NESTED_JOIN);
    if (nestedJoinObject == null)
    {
      nestedJoin = null;
    }
    else
    {
      nestedJoin =
           decodeJoinRequestValueJSON(controlObject, nestedJoinObject, strict);
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_JOIN_RULE, JSON_FIELD_BASE_DN_TYPE,
                JSON_FIELD_BASE_DN_VALUE, JSON_FIELD_SCOPE,
                JSON_FIELD_ALIAS_DEREFERENCING_BEHAVIOR, JSON_FIELD_SIZE_LIMIT,
                JSON_FIELD_FILTER, JSON_FIELD_ATTRIBUTES,
                JSON_FIELD_REQUIRE_MATCH, JSON_FIELD_NESTED_JOIN);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JOIN_REQUEST_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new JoinRequestValue(joinRule, baseDN, scope, derefPolicy, sizeLimit,
    filter, attributes, requireMatch, nestedJoin);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("JoinRequestControl(value=");
    joinRequestValue.toString(buffer);
    buffer.append(')');
  }
}
