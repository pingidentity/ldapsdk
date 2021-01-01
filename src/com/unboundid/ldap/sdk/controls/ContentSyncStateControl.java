/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.text.ParseException;
import java.util.ArrayList;
import java.util.UUID;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the LDAP content synchronization
 * state control as defined in
 * <a href="http://www.ietf.org/rfc/rfc4533.txt">RFC 4533</a>.  Directory
 * servers may include this control in search result entry and search result
 * reference messages returned for a search request containing the content
 * synchronization request control.  See the documentation for the
 * {@link ContentSyncRequestControl} class for more information information
 * about using the content synchronization operation.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ContentSyncStateControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.4203.1.9.1.2) for the sync state control.
   */
  @NotNull public static final String SYNC_STATE_OID =
       "1.3.6.1.4.1.4203.1.9.1.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4796325788870542241L;



  // The synchronization state cookie.
  @Nullable private final ASN1OctetString cookie;

  // The synchronization state for the associated entry.
  @NotNull private final ContentSyncState state;

  // The entryUUID value for the associated entry.
  @NotNull private final UUID entryUUID;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  ContentSyncStateControl()
  {
    state     = null;
    entryUUID = null;
    cookie    = null;
  }



  /**
   * Creates a new content synchronization state control that provides
   * information about a search result entry or referenced returned by a search
   * containing the content synchronization request control.
   *
   * @param  state      The sync state for the associated entry or reference.
   *                    It must not be {@code null}.
   * @param  entryUUID  The entryUUID for the associated entry or reference.  It
   *                    must not be {@code null}.
   * @param  cookie     A cookie with an updated synchronization state.  It may
   *                    be {@code null} if no updated state is available.
   */
  public ContentSyncStateControl(@NotNull final ContentSyncState state,
                                 @NotNull final UUID entryUUID,
                                 @Nullable final ASN1OctetString cookie)
  {
    super(SYNC_STATE_OID, false, encodeValue(state, entryUUID, cookie));

    this.state     = state;
    this.entryUUID = entryUUID;
    this.cookie    = cookie;
  }



  /**
   * Creates a new content synchronization state control which is decoded from
   * the provided information from a generic control.
   *
   * @param  oid         The OID for the control used to create this control.
   * @param  isCritical  Indicates whether the control is marked critical.
   * @param  value       The encoded value for the control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         content synchronization state control.
   */
  public ContentSyncStateControl(@NotNull final String oid,
                                 final boolean isCritical,
                                 @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_STATE_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      final ASN1Enumerated e = ASN1Enumerated.decodeAsEnumerated(elements[0]);
      state = ContentSyncState.valueOf(e.intValue());
      if (state == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SYNC_STATE_VALUE_INVALID_STATE.get(e.intValue()));
      }

      try
      {
        entryUUID = StaticUtils.decodeUUID(elements[1].getValue());
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SYNC_STATE_VALUE_MALFORMED_UUID.get(pe.getMessage()), pe);
      }

      if (elements.length == 3)
      {
        cookie = ASN1OctetString.decodeAsOctetString(elements[2]);
      }
      else
      {
        cookie = null;
      }
    }
    catch (final LDAPException le)
    {
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_STATE_VALUE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this control.
   *
   * @param  state      The sync state for the associated entry or reference.
   *                    It must not be {@code null}.
   * @param  entryUUID  The entryUUID for the associated entry or reference.  It
   *                    must not be {@code null}.
   * @param  cookie     A cookie with an updated synchronization state.  It may
   *                    be {@code null} if no updated state is available.
   *
   * @return  An ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final ContentSyncState state,
                      @NotNull final UUID entryUUID,
                      @Nullable final ASN1OctetString cookie)
  {
    Validator.ensureNotNull(state, entryUUID);

    final ArrayList<ASN1Element> elements = new ArrayList<>(3);
    elements.add(new ASN1Enumerated(state.intValue()));
    elements.add(new ASN1OctetString(StaticUtils.encodeUUID(entryUUID)));

    if (cookie != null)
    {
      elements.add(cookie);
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ContentSyncStateControl decodeControl(@NotNull final String oid,
                                      final boolean isCritical,
                                      @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new ContentSyncStateControl(oid, isCritical, value);
  }



  /**
   * Extracts a content sync state control from the provided search result
   * entry.
   *
   * @param  entry  The search result entry from which to retrieve the content
   *                sync state control.
   *
   * @return  The content sync state control contained in the provided search
   *          result entry, or {@code null} if the entry did not contain a
   *          content sync state control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the content sync state control contained in
   *                         the provided search result entry.
   */
  @Nullable()
  public static ContentSyncStateControl get(
                     @NotNull final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(SYNC_STATE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof ContentSyncStateControl)
    {
      return (ContentSyncStateControl) c;
    }
    else
    {
      return new ContentSyncStateControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Extracts a content sync state control from the provided search result
   * reference.
   *
   * @param  ref  The search result reference from which to retrieve the content
   *              sync state control.
   *
   * @return  The content sync state control contained in the provided search
   *          result reference, or {@code null} if the reference did not contain
   *          a content sync state control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the content sync state control contained in
   *                         the provided search result reference.
   */
  @Nullable()
  public static ContentSyncStateControl get(
                     @NotNull final SearchResultReference ref)
         throws LDAPException
  {
    final Control c = ref.getControl(SYNC_STATE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof ContentSyncStateControl)
    {
      return (ContentSyncStateControl) c;
    }
    else
    {
      return new ContentSyncStateControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Retrieves the synchronization state for this control, which provides
   * information about the state of the associated search result entry or
   * reference.
   *
   * @return  The state value for this content synchronization state control.
   */
  @NotNull()
  public ContentSyncState getState()
  {
    return state;
  }



  /**
   * Retrieves the entryUUID for the associated search result entry or
   * reference.
   *
   * @return  The entryUUID for the associated search result entry or
   *          reference.
   */
  @NotNull()
  public UUID getEntryUUID()
  {
    return entryUUID;
  }



  /**
   * Retrieves a cookie providing updated state information for the
   * synchronization session, if available.
   *
   * @return  A cookie providing updated state information for the
   *          synchronization session, or {@code null} if none was included in
   *          the control.
   */
  @Nullable()
  public ASN1OctetString getCookie()
  {
    return cookie;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_CONTENT_SYNC_STATE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ContentSyncStateControl(state='");
    buffer.append(state.name());
    buffer.append("', entryUUID='");
    buffer.append(entryUUID);
    buffer.append('\'');

    if (cookie != null)
    {
      buffer.append(", cookie=");
      StaticUtils.toHex(cookie.getValue(), buffer);
    }

    buffer.append(')');
  }
}
