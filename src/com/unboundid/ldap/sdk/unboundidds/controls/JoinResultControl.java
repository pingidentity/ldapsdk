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
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control that may be included in a
 * search result entry in response to a join request control to provide a set of
 * entries related to the search result entry.    See the class-level
 * documentation for the {@link JoinRequestControl} class for additional
 * information and an example demonstrating its use.
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
 * The value of the join result control is encoded as follows:
 * <PRE>
 *   JoinResult ::= SEQUENCE {
 *        COMPONENTS OF LDAPResult,
 *        entries     [4] SEQUENCE OF JoinedEntry }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JoinResultControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.9) for the join result control.
   */
  @NotNull public static final String JOIN_RESULT_OID =
       "1.3.6.1.4.1.30221.2.5.9";



  /**
   * The BER type for the referral URLs element.
   */
  private static final byte TYPE_REFERRAL_URLS = (byte) 0xA3;



  /**
   * The BER type for the join results element.
   */
  private static final byte TYPE_JOIN_RESULTS = (byte) 0xA4;



  /**
   * The name of the field used to hold the diagnostic message in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_DIAGNOSTIC_MESSAGE =
       "diagnostic-message";



  /**
   * The name of the field used to hold the DN of an entry in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ENTRY_DN = "_dn";



  /**
   * The name of the field used to hold the set of joined entries in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_JOINED_ENTRIES =
       "joined-entries";



  /**
   * The name of the field used to hold the matched DN in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MATCHED_DN = "matched-dn";



  /**
   * The name of the field used to hold the nested join results in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_NESTED_JOIN_RESULTS =
       "_nested-join-results";



  /**
   * The name of the field used to hold the referral URLs in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_REFERRAL_URLS =
       "referral-urls";



  /**
   * The name of the field used to hold the join result code in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_RESULT_CODE = "result-code";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 681831114773253358L;



  // The set of entries which have been joined with the associated search result
  // entry.
  @NotNull private final List<JoinedEntry> joinResults;

  // The set of referral URLs for this join result.
  @NotNull private final List<String> referralURLs;

  // The result code for this join result.
  @NotNull private final ResultCode resultCode;

  // The diagnostic message for this join result.
  @Nullable private final String diagnosticMessage;

  // The matched DN for this join result.
  @Nullable private final String matchedDN;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  JoinResultControl()
  {
    resultCode        = null;
    diagnosticMessage = null;
    matchedDN         = null;
    referralURLs      = null;
    joinResults       = null;
  }



  /**
   * Creates a new join result control indicating a successful join.
   *
   * @param  joinResults  The set of entries that have been joined with the
   *                      associated search result entry.  It may be
   *                      {@code null} or empty if no entries were joined with
   *                      the search result entry.
   */
  public JoinResultControl(@Nullable final List<JoinedEntry> joinResults)
  {
    this(ResultCode.SUCCESS, null, null, null, joinResults);
  }



  /**
   * Creates a new join result control with the provided information.
   *
   * @param  resultCode         The result code for the join processing.  It
   *                            must not be {@code null}.
   * @param  diagnosticMessage  A message with additional information about the
   *                            result of the join processing.  It may be
   *                            {@code null} if no message is needed.
   * @param  matchedDN          The matched DN for the join processing.  It may
   *                            be {@code null} if no matched DN is needed.
   * @param  referralURLs       The set of referral URLs for any referrals
   *                            encountered while processing the join.  It may
   *                            be {@code null} or empty if no referral URLs
   *                            are needed.
   * @param  joinResults        The set of entries that have been joined with
   *                            associated search result entry.    It may be
   *                            {@code null} or empty if no entries were joined
   *                            with the search result entry.
   */
  public JoinResultControl(@NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final List<String> referralURLs,
              @Nullable final List<JoinedEntry> joinResults)
  {
    super(JOIN_RESULT_OID, false,
          encodeValue(resultCode, diagnosticMessage, matchedDN, referralURLs,
                      joinResults));

    this.resultCode        = resultCode;
    this.diagnosticMessage = diagnosticMessage;
    this.matchedDN         = matchedDN;

    if (referralURLs == null)
    {
      this.referralURLs = Collections.emptyList();
    }
    else
    {
      this.referralURLs = Collections.unmodifiableList(referralURLs);
    }

    if (joinResults == null)
    {
      this.joinResults = Collections.emptyList();
    }
    else
    {
      this.joinResults = Collections.unmodifiableList(joinResults);
    }
  }



  /**
   * Creates a new join result control with the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         account usable response control.
   */
  public JoinResultControl(@NotNull final String oid, final boolean isCritical,
                           @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_RESULT_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();

      resultCode = ResultCode.valueOf(
           ASN1Enumerated.decodeAsEnumerated(elements[0]).intValue());

      final String matchedDNStr =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      if (matchedDNStr.isEmpty())
      {
        matchedDN = null;
      }
      else
      {
        matchedDN = matchedDNStr;
      }

      final String diagnosticMessageStr =
           ASN1OctetString.decodeAsOctetString(elements[2]).stringValue();
      if (diagnosticMessageStr.isEmpty())
      {
        diagnosticMessage = null;
      }
      else
      {
        diagnosticMessage = diagnosticMessageStr;
      }

      final ArrayList<String>      refs    = new ArrayList<>(5);
      final ArrayList<JoinedEntry> entries = new ArrayList<>(20);
      for (int i=3; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_REFERRAL_URLS:
            final ASN1Element[] refElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            for (final ASN1Element e : refElements)
            {
              refs.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
            break;

          case TYPE_JOIN_RESULTS:
            final ASN1Element[] entryElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            for (final ASN1Element e : entryElements)
            {
              entries.add(JoinedEntry.decode(e));
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_JOIN_RESULT_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      referralURLs = Collections.unmodifiableList(refs);
      joinResults  = Collections.unmodifiableList(entries);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_RESULT_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information as appropriate for use as the value of
   * this control.
   *
   * @param  resultCode         The result code for the join processing.  It
   *                            must not be {@code null}.
   * @param  diagnosticMessage  A message with additional information about the
   *                            result of the join processing.  It may be
   *                            {@code null} if no message is needed.
   * @param  matchedDN          The matched DN for the join processing.  It may
   *                            be {@code null} if no matched DN is needed.
   * @param  referralURLs       The set of referral URLs for any referrals
   *                            encountered while processing the join.  It may
   *                            be {@code null} or empty if no referral URLs
   *                            are needed.
   * @param  joinResults        The set of entries that have been joined with
   *                            associated search result entry.    It may be
   *                            {@code null} or empty if no entries were joined
   *                            with the search result entry.
   *
   * @return  An ASN.1 element containing an encoded representation of the
   *          value for this control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final ResultCode resultCode,
                      @Nullable final String diagnosticMessage,
                      @Nullable final String matchedDN,
                      @Nullable final List<String> referralURLs,
                      @Nullable final List<JoinedEntry> joinResults)
  {
    Validator.ensureNotNull(resultCode);

    final ArrayList<ASN1Element> elements = new ArrayList<>(5);
    elements.add(new ASN1Enumerated(resultCode.intValue()));

    if (matchedDN == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(matchedDN));
    }

    if (diagnosticMessage == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(diagnosticMessage));
    }

    if ((referralURLs != null) && (! referralURLs.isEmpty()))
    {
      final ArrayList<ASN1Element> refElements =
           new ArrayList<>(referralURLs.size());
      for (final String s : referralURLs)
      {
        refElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_REFERRAL_URLS, refElements));
    }

    if ((joinResults == null) || joinResults.isEmpty())
    {
      elements.add(new ASN1Sequence(TYPE_JOIN_RESULTS));
    }
    else
    {
      final ArrayList<ASN1Element> entryElements =
           new ArrayList<>(joinResults.size());
      for (final JoinedEntry e : joinResults)
      {
        entryElements.add(e.encode());
      }
      elements.add(new ASN1Sequence(TYPE_JOIN_RESULTS, entryElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the result code for this join result.
   *
   * @return  The result code for this join result.
   */
  @NotNull()
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the diagnostic message for this join result.
   *
   * @return  The diagnostic message for this join result, or {@code null} if
   *          there is no diagnostic message.
   */
  @Nullable()
  public String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves the matched DN for this join result.
   *
   * @return  The matched DN for this join result, or {@code null} if there is
   *          no matched DN.
   */
  @Nullable()
  public String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the set of referral URLs for this join result.
   *
   * @return  The set of referral URLs for this join result, or an empty list
   *          if there are no referral URLs.
   */
  @NotNull()
  public List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the set of entries that have been joined with the associated
   * search result entry.
   *
   * @return  The set of entries that have been joined with the associated
   *          search result entry.
   */
  @NotNull()
  public List<JoinedEntry> getJoinResults()
  {
    return joinResults;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JoinResultControl decodeControl(@NotNull final String oid,
                                         final boolean isCritical,
                                         @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new JoinResultControl(oid, isCritical, value);
  }



  /**
   * Extracts a join result control from the provided search result entry.
   *
   * @param  entry  The search result entry from which to retrieve the join
   *                result control.
   *
   * @return  The join result control contained in the provided search result
   *          entry, or {@code null} if the entry did not contain a join result
   *          control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the join result control contained in the
   *                         provided search result entry.
   */
  @Nullable()
  public static JoinResultControl get(@NotNull final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(JOIN_RESULT_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof JoinResultControl)
    {
      return (JoinResultControl) c;
    }
    else
    {
      return new JoinResultControl(c.getOID(), c.isCritical(), c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_JOIN_RESULT.get();
  }



  /**
   * Retrieves a representation of this join result control as a JSON object.
   * The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the join result control, the OID is
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
   *     base64-encoded representation of the raw value for this join result
   *     control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this join result control.
   *     Exactly one of the {@code value-base64} and {@code value-json} fields
   *     must be present, and if the {@code value-json} field is used, then it
   *     will use the following fields:
   *     <UL>
   *       <LI>
   *         {@code result-code} -- An integer field whose value is the numeric
   *         representation of the LDAP result code for join processing.
   *       </LI>
   *       <LI>
   *         {@code matched-dn} -- An optional string field whose value is the
   *         matched DN for the join processing.
   *       </LI>
   *       <LI>
   *         {@code diagnostic-message} -- An optional string field whose value
   *         is a diagnostic message with additional information about the join
   *         processing.
   *       </LI>
   *       <LI>
   *         {@code referral-urls} -- An optional array field whose values are
   *         strings that represent referral URLs encountered while performing
   *         join processing.
   *       </LI>
   *       <LI>
   *         {@code joined-entries} -- An array field whose values are JSON
   *         objects that reference entries that were joined with the source
   *         entry.  Each of these JSON objects will include a
   *         "{@code _dn}" string field whose value is the DN of the entry and
   *         an optional "{@code _nested-join-results}" array field whose values
   *         are JSON objects that represent nested join results.  Any other
   *         fields in the JSON objects represent attributes in the joined
   *         entry, with the name of the field representing the name of the
   *         attribute, and the value of the field being an array of strings
   *         representing the values of that attribute.
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
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();
    valueFields.put(JSON_FIELD_RESULT_CODE,
         new JSONNumber(resultCode.intValue()));

    if (matchedDN != null)
    {
      valueFields.put(JSON_FIELD_MATCHED_DN, new JSONString(matchedDN));
    }

    if (diagnosticMessage != null)
    {
      valueFields.put(JSON_FIELD_DIAGNOSTIC_MESSAGE,
           new JSONString(diagnosticMessage));
    }

    if ((referralURLs != null) && (! referralURLs.isEmpty()))
    {
      final List<JSONValue> referralValues =
           new ArrayList<>(referralURLs.size());
      for (final String referralURL : referralURLs)
      {
        referralValues.add(new JSONString(referralURL));
      }

      valueFields.put(JSON_FIELD_REFERRAL_URLS, new JSONArray(referralValues));
    }

    final List<JSONValue> entryValues = new ArrayList<>(joinResults.size());
    for (final JoinedEntry entry : joinResults)
    {
      entryValues.add(encodeEntryJSON(entry));
    }
    valueFields.put(JSON_FIELD_JOINED_ENTRIES, new JSONArray(entryValues));

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID, JOIN_RESULT_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_JOIN_RESULT.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Encodes the provided joined entry to a JSON object.
   *
   * @param  entry  The entry to be encoded.  It must not be {@code null}.
   *
   * @return  The JSON object containing the encoded entry.
   */
  @NotNull()
  private static JSONObject encodeEntryJSON(@NotNull final JoinedEntry entry)
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>();
    fields.put(JSON_FIELD_ENTRY_DN, new JSONString(entry.getDN()));

    for (final Attribute a : entry.getAttributes())
    {
      final List<JSONValue> attrValueValues = new ArrayList<>(a.size());
      for (final String value : a.getValues())
      {
        attrValueValues.add(new JSONString(value));
      }

      fields.put(a.getName(), new JSONArray(attrValueValues));
    }

    final List<JoinedEntry> nestedEntries = entry.getNestedJoinResults();
    if (! nestedEntries.isEmpty())
    {
      final List<JSONValue> nestedEntryValues =
           new ArrayList<>(nestedEntries.size());
      for (final JoinedEntry nestedEntry : nestedEntries)
      {
        nestedEntryValues.add(encodeEntryJSON(nestedEntry));
      }

      fields.put(JSON_FIELD_NESTED_JOIN_RESULTS,
           new JSONArray(nestedEntryValues));
    }

    return new JSONObject(fields);
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a join
   * result control.
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
   * @return  The join result control that was decoded from the provided JSON
   *          object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid join result control.
   */
  @NotNull()
  public static JoinResultControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new JoinResultControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final Integer resultCodeValue =
         valueObject.getFieldAsInteger(JSON_FIELD_RESULT_CODE);
    if (resultCodeValue == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_RESULT_JSON_MISSING_VALUE_FIELD.get(
                controlObject.toSingleLineString(), JSON_FIELD_RESULT_CODE));
    }

    final ResultCode resultCode = ResultCode.valueOf(resultCodeValue);

    final String matchedDN =
         valueObject.getFieldAsString(JSON_FIELD_MATCHED_DN);

    final String diagnosticMessage =
         valueObject.getFieldAsString(JSON_FIELD_DIAGNOSTIC_MESSAGE);

    final List<String> referralURLs;
    final List<JSONValue> referralURLValues =
         valueObject.getFieldAsArray(JSON_FIELD_REFERRAL_URLS);
    if (referralURLValues == null)
    {
      referralURLs = null;
    }
    else
    {
      referralURLs = new ArrayList<>(referralURLValues.size());
      for (final JSONValue referralURLValue : referralURLValues)
      {
        if (referralURLValue instanceof JSONString)
        {
          referralURLs.add(((JSONString) referralURLValue).stringValue());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_RESULT_JSON_REFERRAL_URL_NOT_STRING.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_REFERRAL_URLS));
        }
      }
    }


    final List<JSONValue> joinedEntryValues =
         valueObject.getFieldAsArray(JSON_FIELD_JOINED_ENTRIES);
    if (joinedEntryValues == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_RESULT_JSON_MISSING_VALUE_FIELD.get(
                controlObject.toSingleLineString(), JSON_FIELD_JOINED_ENTRIES));
    }

    final List<JoinedEntry> joinedEntries =
         new ArrayList<>(joinedEntryValues.size());
    for (final JSONValue joinedEntryValue : joinedEntryValues)
    {
      if (joinedEntryValue instanceof JSONObject)
      {
        joinedEntries.add(decodeEntryJSON(controlObject,
             (JSONObject) joinedEntryValue));
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JOIN_RESULT_JSON_ENTRY_NOT_OBJECT.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_JOINED_ENTRIES));
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_RESULT_CODE, JSON_FIELD_MATCHED_DN,
                JSON_FIELD_DIAGNOSTIC_MESSAGE, JSON_FIELD_REFERRAL_URLS,
                JSON_FIELD_JOINED_ENTRIES);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JOIN_RESULT_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new JoinResultControl(resultCode, diagnosticMessage, matchedDN,
         referralURLs, joinedEntries);
  }



  /**
   * Decodes the provided JSON object as a joined entry.
   *
   * @param  controlObject  The JSON object representing the entire control
   *                        being decoded.  It must not be {@code null}.
   * @param  entryObject    The JSON object representing the entry to decode.
   *                        It must not be {@code null}.
   *
   * @return  The joined entry that was decoded.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid joined entry.
   */
  @NotNull()
  private static JoinedEntry decodeEntryJSON(
               @NotNull final JSONObject controlObject,
               @NotNull final JSONObject entryObject)
          throws LDAPException
  {
    String entryDN = null;
    List<JoinedEntry> nestedResults = null;
    final List<Attribute> attributes =
         new ArrayList<>(entryObject.getFields().size());
    for (final Map.Entry<String,JSONValue> e :
         entryObject.getFields().entrySet())
    {
      final String fieldName = e.getKey();
      final JSONValue fieldValue = e.getValue();

      if (fieldName.equals(JSON_FIELD_ENTRY_DN))
      {
        if (fieldValue instanceof JSONString)
        {
          entryDN = ((JSONString) fieldValue).stringValue();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_RESULT_JSON_ENTRY_DN_NOT_STRING.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_ENTRY_DN));
        }
      }
      else if (fieldName.equals(JSON_FIELD_NESTED_JOIN_RESULTS))
      {
        if (fieldValue instanceof JSONArray)
        {
          final List<JSONValue> nestedEntryValues =
               ((JSONArray) fieldValue).getValues();
          nestedResults = new ArrayList<>(nestedEntryValues.size());
          for (final JSONValue nestedEntryValue : nestedEntryValues)
          {
            if (nestedEntryValue instanceof JSONObject)
            {
              nestedResults.add(decodeEntryJSON(controlObject,
                   (JSONObject) nestedEntryValue));
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_JON_RESULT_JSON_ENTRY_NESTED_ENTRY_NOT_OBJECT.get(
                        controlObject.toSingleLineString(),
                        JSON_FIELD_NESTED_JOIN_RESULTS));
            }
          }
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_RESULT_JSON_ENTRY_NESTED_ENTRIES_NOT_ARRAY.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_NESTED_JOIN_RESULTS));
        }
      }
      else
      {
        if (fieldValue instanceof JSONArray)
        {
          final List<JSONValue> attrValueValues =
               ((JSONArray) fieldValue).getValues();
          final List<String> attributeValues =
               new ArrayList<>(attrValueValues.size());
          for (final JSONValue v : attrValueValues)
          {
            if (v instanceof JSONString)
            {
              attributeValues.add(((JSONString) v).stringValue());
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_JOIN_RESULT_JSON_ENTRY_ATTR_VALUE_NOT_STRING.get(
                        controlObject.toSingleLineString(), fieldName));
            }
          }

          attributes.add(new Attribute(fieldName, attributeValues));
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JOIN_RESULT_JSON_ENTRY_ATTR_VALUES_NOT_ARRAY.get(
                    controlObject.toSingleLineString(), fieldName));
        }
      }
    }


    if (entryDN == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JON_RESULT_JSON_ENTRY_MISSING_DN.get(
                controlObject.toSingleLineString(), JSON_FIELD_ENTRY_DN));
    }

    return new JoinedEntry(entryDN, attributes, nestedResults);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("JoinResultControl(resultCode='");
    buffer.append(resultCode.getName());
    buffer.append("', diagnosticMessage='");

    if (diagnosticMessage != null)
    {
      buffer.append(diagnosticMessage);
    }

    buffer.append("', matchedDN='");
    if (matchedDN != null)
    {
      buffer.append(matchedDN);
    }

    buffer.append("', referralURLs={");
    final Iterator<String> refIterator = referralURLs.iterator();
    while (refIterator.hasNext())
    {
      buffer.append(refIterator.next());
      if (refIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, joinResults={");
    final Iterator<JoinedEntry> entryIterator = joinResults.iterator();
    while (entryIterator.hasNext())
    {
      entryIterator.next().toString(buffer);
      if (entryIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
