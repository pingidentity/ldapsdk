/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import java.util.List;
import java.util.Iterator;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be used to request that
 * entries below one or more base DNs be excluded from the results returned to
 * a client while processing a search operation.  For example, this may be
 * useful in cases where you want to perform a search below "dc=example,dc=com",
 * but want to exclude all entries below "ou=private,dc=example,dc=com".
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
 * The criticality for this control may be either {@code true} or {@code false}.
 * It must have a value with the following encoding:
 * <PRE>
 *   ExcludeBranchRequest ::= SEQUENCE {
 *        baseDNs     [0] SEQUENCE OF LDAPDN,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExcludeBranchRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.17) for the exclude branch request control.
   */
  @NotNull public static final String EXCLUDE_BRANCH_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.17";



  /**
   * The BER type for the base DNs element.
   */
  private static final byte TYPE_BASE_DNS = (byte) 0xA0;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8599554860060612417L;



  // The list of base DNs to be excluded from the search results.
  @NotNull private final List<String> baseDNs;



  /**
   * Creates a new exclude branch request control with the provided set of base
   * DNs.  It will be marked critical.
   *
   * @param  baseDNs  The base DNs for entries to be excluded from search
   *                  results.  It must not be {@code null} or empty.
   */
  public ExcludeBranchRequestControl(@NotNull final Collection<String> baseDNs)
  {
    this(true, baseDNs);
  }



  /**
   * Creates a new exclude branch request control with the provided set of base
   * DNs.  It will be marked critical.
   *
   * @param  baseDNs  The base DNs for entries to be excluded from search
   *                  results.  It must not be {@code null} or empty.
   */
  public ExcludeBranchRequestControl(@NotNull final String... baseDNs)
  {
    this(true, baseDNs);
  }



  /**
   * Creates a new exclude branch request control with the provided information.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  baseDNs     The base DNs for entries to be excluded from search
   *                     results.  It must not be {@code null} or empty.
   */
  public ExcludeBranchRequestControl(final boolean isCritical,
                                     @NotNull final String... baseDNs)
  {
    super(EXCLUDE_BRANCH_REQUEST_OID, isCritical, encodeValue(baseDNs));

    this.baseDNs = Collections.unmodifiableList(Arrays.asList(baseDNs));
  }



  /**
   * Creates a new exclude branch request control with the provided information.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  baseDNs     The base DNs for entries to be excluded from search
   *                     results.  It must not be {@code null} or empty.
   */
  public ExcludeBranchRequestControl(final boolean isCritical,
                                     @NotNull final Collection<String> baseDNs)
  {
    super(EXCLUDE_BRANCH_REQUEST_OID, isCritical, encodeValue(baseDNs));

    this.baseDNs = Collections.unmodifiableList(new ArrayList<>(baseDNs));
  }



  /**
   * Creates a new exclude branch request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an exclude branch
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         exclude branch request control.
   */
  public ExcludeBranchRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXCLUDE_BRANCH_MISSING_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      valueSequence = ASN1Sequence.decodeAsSequence(value.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXCLUDE_BRANCH_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    try
    {
      final ASN1Element[] elements = valueSequence.elements();

      final ASN1Element[] dnElements =
           ASN1Sequence.decodeAsSequence(elements[0]).elements();
      final ArrayList<String> dnList = new ArrayList<>(dnElements.length);
      for (final ASN1Element e : dnElements)
      {
        dnList.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
      }
      baseDNs = Collections.unmodifiableList(dnList);

      if (baseDNs.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_EXCLUDE_BRANCH_NO_BASE_DNS.get());
      }
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
           ERR_EXCLUDE_BRANCH_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this control.
   *
   * @param  baseDNs  The base DNs for entries to be excluded from search
   *                  results.  It must not be {@code null} or empty.
   *
   * @return  The encoded value for this control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String... baseDNs)
  {
    Validator.ensureNotNull(baseDNs);
    return encodeValue(Arrays.asList(baseDNs));
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this control.
   *
   * @param  baseDNs  The base DNs for entries to be excluded from search
   *                  results.  It must not be {@code null} or empty.
   *
   * @return  The encoded value for this control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final Collection<String> baseDNs)
  {
    Validator.ensureNotNull(baseDNs);
    Validator.ensureFalse(baseDNs.isEmpty());

    final ArrayList<ASN1Element> dnElements = new ArrayList<>(baseDNs.size());
    for (final String s : baseDNs)
    {
      dnElements.add(new ASN1OctetString(s));
    }

    final ASN1Sequence baseDNSequence =
         new ASN1Sequence(TYPE_BASE_DNS, dnElements);
    final ASN1Sequence valueSequence = new ASN1Sequence(baseDNSequence);
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves a list of the base DNs for entries to exclude from the search
   * results.
   *
   * @return  A list of the base DNs for entries to exclude from the search
   *          results.
   */
  @NotNull()
  public List<String> getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_EXCLUDE_BRANCH.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ExcludeBranchRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", baseDNs={");

    final Iterator<String> iterator = baseDNs.iterator();
    while (iterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(iterator.next());
      buffer.append('\'');

      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
