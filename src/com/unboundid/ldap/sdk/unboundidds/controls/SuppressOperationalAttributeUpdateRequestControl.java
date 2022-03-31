/*
 * Copyright 2012-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2022 Ping Identity Corporation
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
 * Copyright (C) 2012-2022 Ping Identity Corporation
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control that can be used to
 * indicate that the server should suppress the update to one or more
 * operational attributes for the associated request.
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
 * The request control has an OID of 1.3.6.1.4.1.30221.2.5.27, and the
 * criticality may be either {@code true} or {@code false}.  The control must
 * have a value with the following encoding:
 * <PRE>
 *   SuppressOperationalAttributeUpdateRequestValue ::= SEQUENCE {
 *        suppressTypes     [0] SEQUENCE OF ENUMERATED {
 *             last-access-time     (0),
 *             last-login-time      (1),
 *             last-login-ip        (2),
 *             lastmod              (3),
 *             ... },
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SuppressOperationalAttributeUpdateRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.27) for the suppress operational attribute
   * update request control.
   */
  @NotNull public static final String SUPPRESS_OP_ATTR_UPDATE_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.27";



  /**
   * The BER type to use for the set of suppress types.
   */
  private static final byte TYPE_SUPPRESS_TYPES = (byte) 0x80;



  /**
   * The name of the field used to hold the suppress types in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SUPPRESS_TYPES =
       "suppress-types";



  /**
   * The last-access-time suppress type value to use in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_SUPPRESS_TYPE_LAST_ACCESS_TIME =
       "last-access-time";



  /**
   * The last-login-ip-address suppress type value to use in the JSON
   * representation of this control.
   */
  @NotNull private static final String
       JSON_SUPPRESS_TYPE_LAST_LOGIN_IP_ADDRESS = "last-login-ip-address";



  /**
   * The last-login-time suppress type value to use in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_SUPPRESS_TYPE_LAST_LOGIN_TIME =
       "last-login-time";



  /**
   * The lastmod suppress type value to use in the JSON representation of this
   * control.
   */
  @NotNull private static final String JSON_SUPPRESS_TYPE_LASTMOD = "lastmod";


  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4603958484615351672L;



  // The set of suppress types to include in the control.
  @NotNull private final Set<SuppressType> suppressTypes;



  /**
   * Creates a new instance of this control that will suppress updates to the
   * specified kinds of operational attributes.  It will not be critical.
   *
   * @param  suppressTypes  The set of suppress types to include in the control.
   *                        It must not be {@code null} or empty.
   */
  public SuppressOperationalAttributeUpdateRequestControl(
              @NotNull final SuppressType... suppressTypes)
  {
    this(false, suppressTypes);
  }



  /**
   * Creates a new instance of this control that will suppress updates to the
   * specified kinds of operational attributes.  It will not be critical.
   *
   * @param  suppressTypes  The set of suppress types to include in the control.
   *                        It must not be {@code null} or empty.
   */
  public SuppressOperationalAttributeUpdateRequestControl(
              @NotNull final Collection<SuppressType> suppressTypes)
  {
    this(false, suppressTypes);
  }



  /**
   * Creates a new instance of this control that will suppress updates to the
   * specified kinds of operational attributes.
   *
   * @param  isCritical     Indicates whether the control should be considered
   *                        critical.
   * @param  suppressTypes  The set of suppress types to include in the control.
   *                        It must not be {@code null} or empty.
   */
  public SuppressOperationalAttributeUpdateRequestControl(
              final boolean isCritical,
              @NotNull final SuppressType... suppressTypes)
  {
    this(isCritical, Arrays.asList(suppressTypes));
  }



  /**
   * Creates a new instance of this control that will suppress updates to the
   * specified kinds of operational attributes.
   *
   * @param  isCritical     Indicates whether the control should be considered
   *                        critical.
   * @param  suppressTypes  The set of suppress types to include in the control.
   *                        It must not be {@code null} or empty.
   */
  public SuppressOperationalAttributeUpdateRequestControl(
              final boolean isCritical,
              @NotNull final Collection<SuppressType> suppressTypes)
  {
    super(SUPPRESS_OP_ATTR_UPDATE_REQUEST_OID, isCritical,
         encodeValue(suppressTypes));

    Validator.ensureFalse(suppressTypes.isEmpty());

    final EnumSet<SuppressType> s = EnumSet.noneOf(SuppressType.class);
    for (final SuppressType t : suppressTypes)
    {
      s.add(t);
    }

    this.suppressTypes = Collections.unmodifiableSet(s);
  }



  /**
   * Decodes the provided generic control as a suppress operational attribute
   * update request control.
   *
   * @param  control  The generic control to be decoded as a suppress
   *                  operational attribute update request control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided control.
   */
  public SuppressOperationalAttributeUpdateRequestControl(
              @NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SUPPRESS_OP_ATTR_UPDATE_REQUEST_MISSING_VALUE.get());
    }

    try
    {
      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(value.getValue());
      final ASN1Sequence suppressTypesSequence =
           ASN1Sequence.decodeAsSequence(valueSequence.elements()[0]);

      final EnumSet<SuppressType> s = EnumSet.noneOf(SuppressType.class);
      for (final ASN1Element e : suppressTypesSequence.elements())
      {
        final ASN1Enumerated ae = ASN1Enumerated.decodeAsEnumerated(e);
        final SuppressType t = SuppressType.valueOf(ae.intValue());
        if (t == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SUPPRESS_OP_ATTR_UNRECOGNIZED_SUPPRESS_TYPE.get(
                    ae.intValue()));
        }
        else
        {
          s.add(t);
        }
      }

      suppressTypes = Collections.unmodifiableSet(s);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SUPPRESS_OP_ATTR_UPDATE_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an octet string suitable for use as
   * the value of this control.
   *
   * @param  suppressTypes  The set of suppress types to include in the control.
   *                        It must not be {@code null} or empty.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final Collection<SuppressType> suppressTypes)
  {
    final ArrayList<ASN1Element> suppressTypeElements =
         new ArrayList<>(suppressTypes.size());
    for (final SuppressType t : suppressTypes)
    {
      suppressTypeElements.add(new ASN1Enumerated(t.intValue()));
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(TYPE_SUPPRESS_TYPES, suppressTypeElements));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the set of suppress types for this control.
   *
   * @return  The set of suppress types for this control.
   */
  @NotNull()
  public Set<SuppressType> getSuppressTypes()
  {
    return suppressTypes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SUPPRESS_OP_ATTR_UPDATE_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final List<JSONValue> suppressTypeValues =
         new ArrayList<>(suppressTypes.size());
    for (final SuppressType suppressType : suppressTypes)
    {
      switch (suppressType)
      {
        case LAST_ACCESS_TIME:
          suppressTypeValues.add(new JSONString(
               JSON_SUPPRESS_TYPE_LAST_ACCESS_TIME));
          break;
        case LAST_LOGIN_TIME:
          suppressTypeValues.add(new JSONString(
               JSON_SUPPRESS_TYPE_LAST_LOGIN_TIME));
          break;
        case LAST_LOGIN_IP:
          suppressTypeValues.add(new JSONString(
               JSON_SUPPRESS_TYPE_LAST_LOGIN_IP_ADDRESS));
          break;
        case LASTMOD:
          suppressTypeValues.add(new JSONString(JSON_SUPPRESS_TYPE_LASTMOD));
          break;
      }
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              SUPPRESS_OP_ATTR_UPDATE_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_SUPPRESS_OP_ATTR_UPDATE_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_SUPPRESS_TYPES,
                        new JSONArray(suppressTypeValues)))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * suppress operational attribute update request control.
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
   * @return  The suppress operational attribute update request control that was
   *          decoded from the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid suppress operational attribute update request
   *                         control.
   */
  @NotNull()
  public static SuppressOperationalAttributeUpdateRequestControl
              decodeJSONControl(@NotNull final JSONObject controlObject,
                                final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawvalue = jsonControl.getRawValue();
    if (rawvalue != null)
    {
      return new SuppressOperationalAttributeUpdateRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawvalue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final List<JSONValue> suppressTypeValues =
         valueObject.getFieldAsArray(JSON_FIELD_SUPPRESS_TYPES);
    if (suppressTypeValues == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SUPPRESS_OP_ATTR_UPDATE_REQUEST_JSON_MISSING_SUPPRESS_TYPES.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_SUPPRESS_TYPES));
    }

    if (suppressTypeValues.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SUPPRESS_OP_ATTR_UPDATE_REQUEST_JSON_EMPTY_SUPPRESS_TYPES.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_SUPPRESS_TYPES));
    }

    final Set<SuppressType> suppressTypes = EnumSet.noneOf(SuppressType.class);
    for (final JSONValue suppressTypeValue : suppressTypeValues)
    {
      if (suppressTypeValue instanceof JSONString)
      {
        final String suppressTypeString =
             ((JSONString) suppressTypeValue).stringValue();
        switch (suppressTypeString)
        {
          case JSON_SUPPRESS_TYPE_LAST_ACCESS_TIME:
            suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
            break;
          case JSON_SUPPRESS_TYPE_LAST_LOGIN_TIME:
            suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
            break;
          case JSON_SUPPRESS_TYPE_LAST_LOGIN_IP_ADDRESS:
            suppressTypes.add(SuppressType.LAST_LOGIN_IP);
            break;
          case JSON_SUPPRESS_TYPE_LASTMOD:
            suppressTypes.add(SuppressType.LASTMOD);
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SUPPRESS_OP_ATTR_UPDATE_REQUEST_JSON_UNKNOWN_SUPPRESS_TYPE.
                      get(controlObject.toSingleLineString(),
                           JSON_FIELD_SUPPRESS_TYPES,
                           JSON_SUPPRESS_TYPE_LAST_ACCESS_TIME,
                           JSON_SUPPRESS_TYPE_LAST_LOGIN_TIME,
                           JSON_SUPPRESS_TYPE_LAST_LOGIN_IP_ADDRESS,
                           JSON_SUPPRESS_TYPE_LASTMOD));
        }
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SUPPRESS_OP_ATTR_UPDATE_REQUEST_JSON_SUPPRESS_TYPE_NOT_STRING.
                  get(controlObject.toSingleLineString(),
                       JSON_FIELD_SUPPRESS_TYPES));
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_SUPPRESS_TYPES);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SUPPRESS_OP_ATTR_UPDATE_REQUEST_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new SuppressOperationalAttributeUpdateRequestControl(
         jsonControl.getCriticality(), suppressTypes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SuppressOperationalAttributeUpdateRequestControl(" +
         "isCritical=");
    buffer.append(isCritical());
    buffer.append(", suppressTypes={");

    final Iterator<SuppressType> iterator = suppressTypes.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next().name());
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
