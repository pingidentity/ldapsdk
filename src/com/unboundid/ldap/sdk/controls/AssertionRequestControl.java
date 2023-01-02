/*
 * Copyright 2007-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2023 Ping Identity Corporation
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
 * Copyright (C) 2007-2023 Ping Identity Corporation
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
import java.util.Collection;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the LDAP assertion request control
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc4528.txt">RFC 4528</A>.  It
 * may be used in conjunction with an add, compare, delete, modify, modify DN,
 * or search operation.  The assertion control includes a search filter, and the
 * associated operation should only be allowed to continue if the target entry
 * matches the provided filter.  If the filter does not match the target entry,
 * then the operation should fail with an
 * {@link ResultCode#ASSERTION_FAILED} result.
 * <BR><BR>
 * The behavior of the assertion request control makes it ideal for atomic
 * "check and set" types of operations, particularly when modifying an entry.
 * For example, it can be used to ensure that when changing the value of an
 * attribute, the current value has not been modified since it was last
 * retrieved.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the assertion request control.
 * It shows an attempt to modify an entry's "accountBalance" attribute to set
 * the value to "543.21" only if the current value is "1234.56":
 * <PRE>
 * Modification mod = new Modification(ModificationType.REPLACE,
 *      "accountBalance", "543.21");
 * ModifyRequest modifyRequest =
 *      new ModifyRequest("uid=john.doe,ou=People,dc=example,dc=com", mod);
 * modifyRequest.addControl(
 *      new AssertionRequestControl("(accountBalance=1234.56)"));
 *
 * LDAPResult modifyResult;
 * try
 * {
 *   modifyResult = connection.modify(modifyRequest);
 *   // If we've gotten here, then the modification was successful.
 * }
 * catch (LDAPException le)
 * {
 *   modifyResult = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 *   if (resultCode == ResultCode.ASSERTION_FAILED)
 *   {
 *     // The modification failed because the account balance value wasn't
 *     // what we thought it was.
 *   }
 *   else
 *   {
 *     // The modification failed for some other reason.
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AssertionRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.1.12) for the assertion request control.
   */
  @NotNull public static final String ASSERTION_REQUEST_OID = "1.3.6.1.1.12";



  /**
   * The name of the field used to represent the assertion filter in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_FILTER = "filter";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6592634203410511095L;



  // The search filter for this assertion request control.
  @NotNull private final Filter filter;



  /**
   * Creates a new assertion request control with the provided filter.  It will
   * be marked as critical.
   *
   * @param  filter  The string representation of the filter for this assertion
   *                 control.  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided filter string cannot be decoded as
   *                         a search filter.
   */
  public AssertionRequestControl(@NotNull final String filter)
         throws LDAPException
  {
    this(Filter.create(filter), true);
  }



  /**
   * Creates a new assertion request control with the provided filter.  It will
   * be marked as critical.
   *
   * @param  filter  The filter for this assertion control.  It must not be
   *                 {@code null}.
   */
  public AssertionRequestControl(@NotNull final Filter filter)
  {
    this(filter, true);
  }



  /**
   * Creates a new assertion request control with the provided filter.  It will
   * be marked as critical.
   *
   * @param  filter      The string representation of the filter for this
   *                     assertion control.  It must not be {@code null}.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   *
   * @throws  LDAPException  If the provided filter string cannot be decoded as
   *                         a search filter.
   */
  public AssertionRequestControl(@NotNull final String filter,
                                 final boolean isCritical)
         throws LDAPException
  {
    this(Filter.create(filter), isCritical);
  }



  /**
   * Creates a new assertion request control with the provided filter.  It will
   * be marked as critical.
   *
   * @param  filter      The filter for this assertion control.  It must not be
   *                     {@code null}.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public AssertionRequestControl(@NotNull final Filter filter,
                                 final boolean isCritical)
  {
    super(ASSERTION_REQUEST_OID, isCritical, encodeValue(filter));

    this.filter = filter;
  }



  /**
   * Creates a new assertion request control which is decoded from the provided
   * generic control.
   *
   * @param  control  The generic control to be decoded as an assertion request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         assertion request control.
   */
  public AssertionRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ASSERT_NO_VALUE.get());
    }


    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      filter = Filter.decode(valueElement);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ASSERT_CANNOT_DECODE.get(e), e);
    }
  }



  /**
   * Generates an assertion request control that may be used to help ensure
   * that some or all of the attributes in the specified entry have not changed
   * since it was read from the server.
   *
   * @param  sourceEntry  The entry from which to take the attributes to include
   *                      in the assertion request control.  It must not be
   *                      {@code null} and should have at least one attribute to
   *                      be included in the generated filter.
   * @param  attributes   The names of the attributes to include in the
   *                      assertion request control.  If this is empty or
   *                      {@code null}, then all attributes in the provided
   *                      entry will be used.
   *
   * @return  The generated assertion request control.
   */
  @NotNull()
  public static AssertionRequestControl generate(
                     @NotNull final Entry sourceEntry,
                     @Nullable final String... attributes)
  {
    Validator.ensureNotNull(sourceEntry);

    final ArrayList<Filter> andComponents;

    if ((attributes == null) || (attributes.length == 0))
    {
      final Collection<Attribute> entryAttrs = sourceEntry.getAttributes();
      andComponents = new ArrayList<>(entryAttrs.size());
      for (final Attribute a : entryAttrs)
      {
        for (final ASN1OctetString v : a.getRawValues())
        {
          andComponents.add(Filter.createEqualityFilter(a.getName(),
               v.getValue()));
        }
      }
    }
    else
    {
      andComponents = new ArrayList<>(attributes.length);
      for (final String name : attributes)
      {
        final Attribute a = sourceEntry.getAttribute(name);
        if (a != null)
        {
          for (final ASN1OctetString v : a.getRawValues())
          {
            andComponents.add(Filter.createEqualityFilter(name, v.getValue()));
          }
        }
      }
    }

    if (andComponents.size() == 1)
    {
      return new AssertionRequestControl(andComponents.get(0));
    }
    else
    {
      return new AssertionRequestControl(Filter.createANDFilter(andComponents));
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  filter  The filter for this assertion control.  It must not be
   *                 {@code null}.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final Filter filter)
  {
    return new ASN1OctetString(filter.encode().encode());
  }



  /**
   * Retrieves the filter for this assertion control.
   *
   * @return  The filter for this assertion control.
   */
  @NotNull()
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ASSERTION_REQUEST.get();
  }



  /**
   * Retrieves a representation of this assertion request control as a JSON
   * object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the assertion request control, the
   *     OID is "1.3.6.1.1.12".
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
   *     base64-encoded representation of the raw value for this assertion
   *     request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this assertion request
   *     control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code filter} -- A mandatory string field whose value is a string
   *         representation of the assertion filter.
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
              ASSERTION_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_ASSERTION_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_FILTER, filter.toString()))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * assertion request control.
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
   * @return  The assertion request control that was decoded from the provided
   *          JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid assertion request control.
   */
  @NotNull()
  public static AssertionRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new AssertionRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(),
           rawValue));
    }

    final JSONObject valueObject = jsonControl.getValueObject();
    final String filterString = valueObject.getFieldAsString(JSON_FIELD_FILTER);
    if (filterString == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSERT_JSON_CONTROL_MISSING_FILTER.get(
                controlObject.toSingleLineString(), JSON_FIELD_FILTER));
    }

    final Filter parsedFilter;
    try
    {
      parsedFilter = Filter.create(filterString);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSERT_JSON_CONTROL_INVALID_FILTER.get(
                controlObject.toSingleLineString(), filterString),
           e);
    }

    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_FILTER);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_ASSERT_JSON_CONTROL_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }

    return new AssertionRequestControl(parsedFilter,
         jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AssertionRequestControl(filter='");
    filter.toString(buffer);
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
