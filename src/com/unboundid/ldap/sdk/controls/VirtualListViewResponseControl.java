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
import com.unboundid.asn1.ASN1Enumerated;
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
 * This class provides an implementation of the virtual list view (VLV) response
 * control, as defined in draft-ietf-ldapext-ldapv3-vlv.  It may be used to
 * provide information about the result of virtual list view processing for a
 * search containing the {@link VirtualListViewRequestControl}.
 * <BR><BR>
 * The virtual list view response control may include the following elements:
 * <UL>
 *   <LI>{@code resultCode} -- A result code that indicates the result of the
 *       virtual list view processing.  It may be the same as or different from
 *       the result code contained in the search result done message.</LI>
 *   <LI>{@code targetPosition} -- The offset of the target entry specified by
 *       the client in the result set.</LI>
 *   <LI>{@code contentCount} -- The estimated total number of entries in the
 *       entire result set.</LI>
 *   <LI>{@code contextID} -- An optional cookie that the client should include
 *       in the next request as part of the virtual list view sequence.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class VirtualListViewResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (2.16.840.1.113730.3.4.10) for the virtual list view response
   * control.
   */
  @NotNull public static final String VIRTUAL_LIST_VIEW_RESPONSE_OID =
       "2.16.840.1.113730.3.4.10";



  /**
   * The name of the field used to hold the content count in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CONTENT_COUNT =
       "content-count";



  /**
   * The name of the field used to hold the context ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CONTEXT_ID = "context-id";



  /**
   * The name of the field used to hold the result code in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_RESULT_CODE = "result-code";



  /**
   * The name of the field used to hold the target position in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_TARGET_POSITION =
       "target-position";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -534656674756287217L;



  // The context ID for this VLV response control, if available.
  @Nullable private final ASN1OctetString contextID;

  // The estimated total number of entries in the result set.
  private final int contentCount;

  // The result code for this VLV response control.
  @NotNull private final ResultCode resultCode;

  // The offset of the target entry for this VLV response control.
  private final int targetPosition;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  VirtualListViewResponseControl()
  {
    targetPosition = -1;
    contentCount   = -1;
    resultCode     = null;
    contextID      = null;
  }



  /**
   * Creates a new virtual list view response control with the provided
   * information.  It will not be marked critical.
   *
   * @param  targetPosition  The offset of the target entry for this VLV
   *                         response control.
   * @param  contentCount    The estimated total number of entries in the
   *                         result set.
   * @param  resultCode      The result code for this VLV response control.
   * @param  contextID       The context ID for this VLV response control.  It
   *                         may be {@code null} if no context ID is available.
   */
  public VirtualListViewResponseControl(final int targetPosition,
              final int contentCount, @NotNull final ResultCode resultCode,
              @Nullable final ASN1OctetString contextID)
  {
    super(VIRTUAL_LIST_VIEW_RESPONSE_OID, false,
          encodeValue(targetPosition, contentCount, resultCode, contextID));

    this.targetPosition = targetPosition;
    this.contentCount   = contentCount;
    this.resultCode     = resultCode;
    this.contextID      = contextID;
  }



  /**
   * Creates a new virtual list view response control from the information
   * contained in the provided control.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided control as a virtual list view response
   *                         control.
   */
  public VirtualListViewResponseControl(@NotNull final String oid,
                                        final boolean isCritical,
                                        @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement =
           ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if ((valueElements.length < 3) || (valueElements.length > 4))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    try
    {
      targetPosition = ASN1Integer.decodeAsInteger(valueElements[0]).intValue();
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_FIRST_NOT_INTEGER.get(ae), ae);
    }

    try
    {
      contentCount = ASN1Integer.decodeAsInteger(valueElements[1]).intValue();
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_SECOND_NOT_INTEGER.get(ae), ae);
    }

    try
    {
      final int rc =
           ASN1Enumerated.decodeAsEnumerated(valueElements[2]).intValue();
      resultCode = ResultCode.valueOf(rc);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_THIRD_NOT_ENUM.get(ae), ae);
    }

    if (valueElements.length == 4)
    {
      contextID = ASN1OctetString.decodeAsOctetString(valueElements[3]);
    }
    else
    {
      contextID = null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public VirtualListViewResponseControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new VirtualListViewResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a virtual list view response control from the provided result.
   *
   * @param  result  The result from which to retrieve the virtual list view
   *                 response control.
   *
   * @return  The virtual list view response  control contained in the provided
   *          result, or {@code null} if the result did not contain a virtual
   *          list view response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the virtual list view response  control
   *                         contained in the provided result.
   */
  @Nullable()
  public static VirtualListViewResponseControl get(
                     @NotNull final SearchResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(VIRTUAL_LIST_VIEW_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof VirtualListViewResponseControl)
    {
      return (VirtualListViewResponseControl) c;
    }
    else
    {
      return new VirtualListViewResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  targetPosition  The offset of the target entry for this VLV
   *                         response control.
   * @param  contentCount    The estimated total number of entries in the
   *                         result set.
   * @param  resultCode      The result code for this VLV response control.
   * @param  contextID       The context ID for this VLV response control.  It
   *                         may be {@code null} if no context ID is available.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final int targetPosition,
                      final int contentCount,
                      @NotNull final ResultCode resultCode,
                      @Nullable final ASN1OctetString contextID)
  {
    final ASN1Element[] vlvElements;
    if (contextID == null)
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(targetPosition),
        new ASN1Integer(contentCount),
        new ASN1Enumerated(resultCode.intValue())
      };
    }
    else
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(targetPosition),
        new ASN1Integer(contentCount),
        new ASN1Enumerated(resultCode.intValue()),
        contextID
      };
    }

    return new ASN1OctetString(new ASN1Sequence(vlvElements).encode());
  }



  /**
   * Retrieves the offset of the target entry for this virtual list view
   * response control.
   *
   * @return  The offset of the target entry for this virtual list view response
   *          control.
   */
  public int getTargetPosition()
  {
    return targetPosition;
  }



  /**
   * Retrieves the estimated total number of entries in the result set.
   *
   * @return  The estimated total number of entries in the result set.
   */
  public int getContentCount()
  {
    return contentCount;
  }



  /**
   * Retrieves the result code for this virtual list view response control.
   *
   * @return  The result code for this virtual list view response control.
   */
  @NotNull()
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the context ID for this virtual list view response control, if
   * available.
   *
   * @return  The context ID for this virtual list view response control, or
   *          {@code null} if none was provided.
   */
  @Nullable()
  public ASN1OctetString getContextID()
  {
    return contextID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_VLV_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();

    valueFields.put(JSON_FIELD_RESULT_CODE,
         new JSONNumber(resultCode.intValue()));
    valueFields.put(JSON_FIELD_TARGET_POSITION, new JSONNumber(targetPosition));
    valueFields.put(JSON_FIELD_CONTENT_COUNT, new JSONNumber(contentCount));

    if (contextID != null)
    {
      valueFields.put(JSON_FIELD_CONTEXT_ID,
           new JSONString(Base64.encode(contextID.getValue())));
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              VIRTUAL_LIST_VIEW_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_VLV_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * virtual list view response control.
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
   * @return  The virtual list view response control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid virtual list view response control.
   */
  @NotNull()
  public static VirtualListViewResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new VirtualListViewResponseControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final Integer resultCodeInt =
         valueObject.getFieldAsInteger(JSON_FIELD_RESULT_CODE);
    if (resultCodeInt == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VLV_RESPONSE_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(), JSON_FIELD_RESULT_CODE));
    }

    final ResultCode resultCode = ResultCode.valueOf(resultCodeInt);


    final Integer targetPosition =
         valueObject.getFieldAsInteger(JSON_FIELD_TARGET_POSITION);
    if (targetPosition == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VLV_RESPONSE_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_TARGET_POSITION));
    }


    final Integer contentCount =
         valueObject.getFieldAsInteger(JSON_FIELD_CONTENT_COUNT);
    if (contentCount == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VLV_RESPONSE_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_CONTENT_COUNT));
    }


    final ASN1OctetString contextID;
    final String contextIDBase64 =
         valueObject.getFieldAsString(JSON_FIELD_CONTEXT_ID);
    if (contextIDBase64 == null)
    {
      contextID = null;
    }
    else
    {
      try
      {
        contextID = new ASN1OctetString(Base64.decode(contextIDBase64));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_VLV_RESPONSE_JSON_CONTEXT_ID_NOT_BASE64.get(
                  controlObject.toSingleLineString(), JSON_FIELD_CONTEXT_ID),
             e);
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_RESULT_CODE, JSON_FIELD_TARGET_POSITION,
                JSON_FIELD_CONTENT_COUNT, JSON_FIELD_CONTEXT_ID);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_VLV_RESPONSE_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new VirtualListViewResponseControl(targetPosition, contentCount,
         resultCode, contextID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("VirtualListViewResponseControl(targetPosition=");
    buffer.append(targetPosition);
    buffer.append(", contentCount=");
    buffer.append(contentCount);
    buffer.append(", resultCode=");
    buffer.append(resultCode);
    buffer.append(')');
  }
}
