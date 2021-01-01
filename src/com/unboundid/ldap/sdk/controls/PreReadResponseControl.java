/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the LDAP pre-read response control
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc4527.txt">RFC 4527</A>.  It
 * may be used to return a copy of the target entry immediately before
 * processing a delete, modify, or modify DN operation.
 * <BR><BR>
 * If the corresponding delete, modify, or modify DN request included the
 * {@link PreReadRequestControl} and the operation was successful, then the
 * response for that operation should include the pre-read response control with
 * a read-only copy of the entry as it appeared immediately before processing
 * the request.  If the operation was not successful, then the pre-read response
 * control will not be returned.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PreReadResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.1.13.1) for the pre-read response control.
   */
  @NotNull public static final String PRE_READ_RESPONSE_OID = "1.3.6.1.1.13.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4719875382095056686L;



  // The entry returned in the response control.
  @NotNull private final ReadOnlyEntry entry;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  PreReadResponseControl()
  {
    entry = null;
  }



  /**
   * Creates a new pre-read response control including the provided entry.
   *
   * @param  entry  The entry to include in this pre-read response control.  It
   *                must not be {@code null}.
   */
  public PreReadResponseControl(@NotNull final ReadOnlyEntry entry)
  {
    super(PRE_READ_RESPONSE_OID, false, encodeValue(entry));

    this.entry = entry;
  }



  /**
   * Creates a new pre-read response control with the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         pre-read response control.
   */
  public PreReadResponseControl(@NotNull final String oid,
                                final boolean isCritical,
                                @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PRE_READ_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence entrySequence;
    try
    {
      final ASN1Element entryElement = ASN1Element.decode(value.getValue());
      entrySequence = ASN1Sequence.decodeAsSequence(entryElement);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PRE_READ_RESPONSE_VALUE_NOT_SEQUENCE.get(ae),
                              ae);
    }

    final ASN1Element[] entryElements = entrySequence.elements();
    if (entryElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PRE_READ_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   entryElements.length));
    }

    final String dn =
         ASN1OctetString.decodeAsOctetString(entryElements[0]).stringValue();

    final ASN1Sequence attrSequence;
    try
    {
      attrSequence = ASN1Sequence.decodeAsSequence(entryElements[1]);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_PRE_READ_RESPONSE_ATTRIBUTES_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] attrElements = attrSequence.elements();
    final Attribute[] attrs = new Attribute[attrElements.length];
    for (int i=0; i < attrElements.length; i++)
    {
      try
      {
        attrs[i] =
             Attribute.decode(ASN1Sequence.decodeAsSequence(attrElements[i]));
      }
      catch (final ASN1Exception ae)
      {
        Debug.debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_PRE_READ_RESPONSE_ATTR_NOT_SEQUENCE.get(ae), ae);
      }
    }

    entry = new ReadOnlyEntry(dn, attrs);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PreReadResponseControl decodeControl(@NotNull final String oid,
                                     final boolean isCritical,
                                     @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new PreReadResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a pre-read response control from the provided result.
   *
   * @param  result  The result from which to retrieve the pre-read response
   *                 control.
   *
   * @return  The pre-read response control contained in the provided result, or
   *          {@code null} if the result did not contain a pre-read response
   *          control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the pre-read response control contained in
   *                         the provided result.
   */
  @Nullable()
  public static PreReadResponseControl get(@NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PRE_READ_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PreReadResponseControl)
    {
      return (PreReadResponseControl) c;
    }
    else
    {
      return new PreReadResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  entry  The entry to include in this pre-read response control.  It
   *                must not be {@code null}.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final ReadOnlyEntry entry)
  {
    Validator.ensureNotNull(entry);

    final Collection<Attribute> attrs = entry.getAttributes();
    final ArrayList<ASN1Element> attrElements = new ArrayList<>(attrs.size());
    for (final Attribute a : attrs)
    {
      attrElements.add(a.encode());
    }

    final ASN1Element[] entryElements =
    {
      new ASN1OctetString(entry.getDN()),
      new ASN1Sequence(attrElements)
    };

    return new ASN1OctetString(new ASN1Sequence(entryElements).encode());
  }



  /**
   * Retrieves a read-only copy of the entry returned by this post-read response
   * control.
   *
   * @return  A read-only copy of the entry returned by this post-read response
   *          control.
   */
  @NotNull()
  public ReadOnlyEntry getEntry()
  {
    return entry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PRE_READ_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PreReadResponseControl(entry=");
    entry.toString(buffer);
    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
