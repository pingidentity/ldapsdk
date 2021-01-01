/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
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

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that may be used to provide the
 * backend set ID(s) for any relevant backend sets accessed during the course
 * of processing an operation.  It may be returned in response to a request
 * containing either the get backend set ID request control or the route to
 * backend set request control.  For add, simple bind, compare, delete,
 * modify, and modify DN operations, the LDAP result message for the operation
 * may contain zero or one get backend set ID response control.  For extended
 * operations, the extended result message may contain zero, one, or multiple
 * get backend set ID response controls.  For search operations, each search
 * result entry may contain zero or one get backend set ID response control,
 * while the search result done message will not contain any such control.  See
 * the {@link GetBackendSetIDRequestControl} class documentation for a more
 * complete description of the usage for these controls.
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
 * The get backend set ID response control has an OID of
 * "1.3.6.1.4.1.30221.2.5.34", a criticality of false, and a value with the
 * following encoding:
 * <PRE>
 *   GET_BACKEND_SET_ID_RESPONSE_VALUE ::= SEQUENCE {
 *     entryBalancingRequestProcessorID     OCTET STRING,
 *     backendSetIDs                        SET SIZE (1..MAX) OF OCTET STRING,
 *     ... }
 * </PRE>
 *
 * @see  GetBackendSetIDRequestControl
 * @see  RouteToBackendSetRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetBackendSetIDResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.34) for the get backend set ID response
   * control.
   */
  @NotNull public static final  String GET_BACKEND_SET_ID_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.34";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 117359364981309726L;



  // The backend set IDs for backend sets used during processing.
  @NotNull private final Set<String> backendSetIDs;

  // The identifier for the entry-balancing request processor with which the
  // backend set IDs are associated.
  @NotNull private final String entryBalancingRequestProcessorID;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  GetBackendSetIDResponseControl()
  {
    entryBalancingRequestProcessorID = null;
    backendSetIDs = null;
  }



  /**
   * Creates a new get backend set ID response control with the provided
   * information.
   *
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set IDs
   *                                           are associated.  It must not be
   *                                           {@code null}.
   * @param  backendSetID                      The backend set ID for the
   *                                           backend set used during
   *                                           processing.  It must not be
   *                                           {@code null}.
   */
  public GetBackendSetIDResponseControl(
              @NotNull final String entryBalancingRequestProcessorID,
              @NotNull final String backendSetID)
  {
    this(entryBalancingRequestProcessorID,
         Collections.singletonList(backendSetID));
  }



  /**
   * Creates a new get backend set ID response control with the provided
   * information.
   *
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set IDs
   *                                           are associated.  It must not be
   *                                           {@code null}.
   * @param  backendSetIDs                     The backend set IDs for backend
   *                                           sets used during processing.  It
   *                                           must not be {@code null} or
   *                                           empty.
   */
  public GetBackendSetIDResponseControl(
              @NotNull final String entryBalancingRequestProcessorID,
              @NotNull final Collection<String> backendSetIDs)
  {
    super(GET_BACKEND_SET_ID_RESPONSE_OID, false,
         encodeValue(entryBalancingRequestProcessorID, backendSetIDs));

    this.entryBalancingRequestProcessorID = entryBalancingRequestProcessorID;
    this.backendSetIDs =
         Collections.unmodifiableSet(new LinkedHashSet<>(backendSetIDs));
  }



  /**
   * Creates a new get backend set ID response control decoded from the given
   * generic control contents.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.
   *
   * @throws LDAPException  If a problem occurs while attempting to decode the
   *                        generic control as a get backend set ID response
   *                        control.
   */
  public GetBackendSetIDResponseControl(@NotNull final String oid,
                                        final boolean isCritical,
                                        @Nullable final ASN1OctetString value)
       throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_BACKEND_SET_ID_RESPONSE_MISSING_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      entryBalancingRequestProcessorID =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1Element[] backendSetIDElements =
           ASN1Set.decodeAsSet(elements[1]).elements();
      final LinkedHashSet<String> setIDs = new LinkedHashSet<>(
           StaticUtils.computeMapCapacity(backendSetIDElements.length));
      for (final ASN1Element e : backendSetIDElements)
      {
        setIDs.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
      }
      backendSetIDs = Collections.unmodifiableSet(setIDs);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_BACKEND_SET_ID_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an octet string suitable for use as
   * the value of this control.
   *
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set IDs
   *                                           are associated.  It must not be
   *                                           {@code null}.
   * @param  backendSetIDs                     The backend set IDs for backend
   *                                           sets used during processing.  It
   *                                           must not be {@code null} or
   *                                           empty.
   *
   * @return  The encoded representation of the control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final String entryBalancingRequestProcessorID,
                      @NotNull final Collection<String> backendSetIDs)
  {
    Validator.ensureNotNull(entryBalancingRequestProcessorID);
    Validator.ensureNotNull(backendSetIDs);
    Validator.ensureFalse(backendSetIDs.isEmpty());

    final ArrayList<ASN1Element> backendSetIDElements =
         new ArrayList<>(backendSetIDs.size());
    for (final String s : backendSetIDs)
    {
      backendSetIDElements.add(new ASN1OctetString(s));
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(entryBalancingRequestProcessorID),
         new ASN1Set(backendSetIDElements));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetBackendSetIDResponseControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new GetBackendSetIDResponseControl(oid, isCritical, value);
  }



  /**
   * Retrieves the identifier for the entry-balancing request processor with
   * which the backend sets IDs are associated.
   *
   * @return  The identifier for the entry-balancing request processor with
   *          which the backend set IDs are associated.
   */
  @NotNull()
  public String getEntryBalancingRequestProcessorID()
  {
    return entryBalancingRequestProcessorID;
  }



  /**
   * Retrieves the backend set IDs for the backend sets used during processing.
   *
   * @return  The backend set IDs for the backend sets used during processing.
   */
  @NotNull()
  public Set<String> getBackendSetIDs()
  {
    return backendSetIDs;
  }



  /**
   * Extracts a get backend set ID response control from the provided result.
   *
   * @param  result  The result from which to retrieve the get backend set ID
   *                 response control.
   *
   * @return  The get backend set ID response control contained in the provided
   *          result, or {@code null} if the result did not contain a get
   *          backend set ID response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get backend set ID response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static GetBackendSetIDResponseControl get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(GET_BACKEND_SET_ID_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetBackendSetIDResponseControl)
    {
      return (GetBackendSetIDResponseControl) c;
    }
    else
    {
      return new GetBackendSetIDResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Extracts a get backend set ID response control from the provided search
   * result entry.
   *
   * @param  entry  The entry from which to retrieve the get backend set ID
   *                response control.
   *
   * @return  The get backend set ID response control contained in the provided
   *          entry, or {@code null} if the entry did not contain a get backend
   *          set ID response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get backend set ID response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static GetBackendSetIDResponseControl get(
                     @NotNull final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(GET_BACKEND_SET_ID_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetBackendSetIDResponseControl)
    {
      return (GetBackendSetIDResponseControl) c;
    }
    else
    {
      return new GetBackendSetIDResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Extracts any get backend set ID response controls from the provided
   * extended result.
   *
   * @param  result  The extended result from which to retrieve the get backend
   *                 set ID response control(s).
   *
   * @return  A list of get backend set ID response controls contained in the
   *          provided extended result, or an empty list if the result did not
   *          contain a get any backend set ID response controls.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the any backend set ID response control
   *                         contained in the provided result.
   */
  @NotNull()
  public static List<GetBackendSetIDResponseControl> get(
                     @NotNull final ExtendedResult result)
         throws LDAPException
  {
    final Control[] controls = result.getResponseControls();
    if (controls.length == 0)
    {
      return Collections.emptyList();
    }

    final ArrayList<GetBackendSetIDResponseControl> decodedControls =
         new ArrayList<>(controls.length);
    for (final Control c : controls)
    {
      if (c instanceof GetBackendSetIDResponseControl)
      {
        decodedControls.add((GetBackendSetIDResponseControl) c);
      }
      else if (c.getOID().equals(GET_BACKEND_SET_ID_RESPONSE_OID))
      {
        decodedControls.add(new GetBackendSetIDResponseControl(c.getOID(),
             c.isCritical(), c.getValue()));
      }
    }

    return Collections.unmodifiableList(decodedControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_BACKEND_SET_ID_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetBackendSetIDResponseControl(" +
         "entryBalancingRequestProcessorID='");
    buffer.append(entryBalancingRequestProcessorID);
    buffer.append("', backendSetIDs={");

    final Iterator<String> iterator = backendSetIDs.iterator();
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
