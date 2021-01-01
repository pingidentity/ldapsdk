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



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
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
 * request control as defined in
 * <a href="http://www.ietf.org/rfc/rfc4533.txt">RFC 4533</a>.  It may be
 * included in a search request to indicate that the client wishes to stay in
 * sync with the server and/or be updated when server data changes.
 * <BR><BR>
 * Searches containing this control have the potential to take a very long time
 * to complete (and may potentially never complete if the
 * {@link ContentSyncRequestMode#REFRESH_AND_PERSIST} mode is selected), may
 * return a large number of entries, and may also return intermediate response
 * messages.  When using this control, it is important to keep the following in
 * mind:
 * <UL>
 *   <LI>The associated search request should have a
 *       {@link com.unboundid.ldap.sdk.SearchResultListener} so that entries
 *       will be made available as soon as they are returned rather than having
 *       to wait for the search to complete and/or consuming a large amount of
 *       memory by storing the entries in a list that is only made available
 *       when the search completes.  It may be desirable to use an
 *       {@link com.unboundid.ldap.sdk.AsyncSearchResultListener} to perform the
 *       search as an asynchronous operation so that the search request thread
 *       does not block while waiting for the search to complete.</LI>
 *   <LI>Entries and references returned from the search should include the
 *       {@link ContentSyncStateControl} with the associated entryUUID and
 *       potentially a cookie with an updated sync session state.  You should
 *       call {@code getControl(ContentSyncStateControl.SYNC_STATE_OID)} on the
 *       search result entries and references in order to retrieve the control
 *       with the sync state information.</LI>
 *   <LI>The search request should be configured with an unlimited server-side
 *       time limit using {@code SearchRequest.setTimeLimitSeconds(0)}, and an
 *       unlimited client-side timeout using
 *       {@code SearchRequest.setResponseTimeoutMillis(0L)}.</LI>
 *   <LI>The search request should be configured with an intermediate response
 *       listener using the
 *       {@code SearchRequest.setIntermediateResponseListener} method.</LI>
 *   <LI>If the search does complete, then the
 *       {@link com.unboundid.ldap.sdk.SearchResult} (or
 *       {@link com.unboundid.ldap.sdk.LDAPSearchException} if the search ended
 *       with a non-success response) may include a
 *       {@link ContentSyncDoneControl} with updated sync state information.
 *       You should call
 *       {@code getResponseControl(ContentSyncDoneControl.SYNC_DONE_OID)} to
 *       retrieve the control with the sync state information.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ContentSyncRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.4203.1.9.1.1) for the sync request control.
   */
  @NotNull public static final String SYNC_REQUEST_OID =
       "1.3.6.1.4.1.4203.1.9.1.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3183343423271667072L;



  // The cookie to include in the sync request.
  @Nullable private final ASN1OctetString cookie;

  // Indicates whether to request an initial content in the event that the
  // server determines that the client cannot reach convergence with the server
  // data by continuing with incremental synchronization.
  private final boolean reloadHint;

  // The request mode for this control.
  @NotNull private final ContentSyncRequestMode mode;



  /**
   * Creates a new content synchronization request control that will attempt to
   * retrieve the initial content for the synchronization using the provided
   * request mode.  It will be marked critical.
   *
   * @param  mode  The request mode which indicates whether to retrieve only
   *               the initial content or to both retrieve the initial content
   *               and be updated of changes made in the future.  It must not
   *               be {@code null}.
   */
  public ContentSyncRequestControl(@NotNull final ContentSyncRequestMode mode)
  {
    this(true, mode, null, false);
  }



  /**
   * Creates a new content synchronization request control that may be used to
   * either retrieve the initial content or an incremental update.  It will be
   * marked critical.  It will be marked critical.
   *
   * @param  mode        The request mode which indicates whether to retrieve
   *                     only the initial content or to both retrieve the
   *                     initial content and be updated of changes made in the
   *                     future.  It must not be {@code null}.
   * @param  cookie      A cookie providing state information for an existing
   *                     synchronization session.  It may be {@code null} to
   *                     perform an initial synchronization rather than an
   *                     incremental update.
   * @param  reloadHint  Indicates whether the client wishes to retrieve an
   *                     initial content during an incremental update if the
   *                     server determines that the client cannot reach
   *                     convergence with the server data.
   */
  public ContentSyncRequestControl(@NotNull final ContentSyncRequestMode mode,
                                   @Nullable final ASN1OctetString cookie,
                                   final boolean reloadHint)
  {
    this(true, mode, cookie, reloadHint);
  }



  /**
   * Creates a new content synchronization request control that may be used to
   * either retrieve the initial content or an incremental update.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  mode        The request mode which indicates whether to retrieve
   *                     only the initial content or to both retrieve the
   *                     initial content and be updated of changes made in the
   *                     future.  It must not be {@code null}.
   * @param  cookie      A cookie providing state information for an existing
   *                     synchronization session.  It may be {@code null} to
   *                     perform an initial synchronization rather than an
   *                     incremental update.
   * @param  reloadHint  Indicates whether the client wishes to retrieve an
   *                     initial content during an incremental update if the
   *                     server determines that the client cannot reach
   *                     convergence with the server data.
   */
  public ContentSyncRequestControl(final boolean isCritical,
                                   @NotNull final ContentSyncRequestMode mode,
                                   @Nullable final ASN1OctetString cookie,
                                   final boolean reloadHint)
  {
    super(SYNC_REQUEST_OID, isCritical, encodeValue(mode, cookie, reloadHint));

    this.mode       = mode;
    this.cookie     = cookie;
    this.reloadHint = reloadHint;
  }



  /**
   * Creates a new content synchronization request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a content
   *                  synchronization request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         content synchronization request control.
   */
  public ContentSyncRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_REQUEST_NO_VALUE.get());
    }

    ASN1OctetString        c = null;
    Boolean                h = null;
    ContentSyncRequestMode m = null;

    try
    {
      final ASN1Sequence s = ASN1Sequence.decodeAsSequence(value.getValue());
      for (final ASN1Element e : s.elements())
      {
        switch (e.getType())
        {
          case ASN1Constants.UNIVERSAL_ENUMERATED_TYPE:
            if (m != null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_MULTIPLE_MODES.get());
            }

            final ASN1Enumerated modeElement =
                 ASN1Enumerated.decodeAsEnumerated(e);
            m = ContentSyncRequestMode.valueOf(modeElement.intValue());
            if (m == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_INVALID_MODE.get(
                        modeElement.intValue()));
            }
            break;

          case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
            if (c == null)
            {
              c = ASN1OctetString.decodeAsOctetString(e);
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_MULTIPLE_COOKIES.get());
            }
            break;

          case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
            if (h == null)
            {
              h = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            }
            else
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SYNC_REQUEST_VALUE_MULTIPLE_HINTS.get());
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SYNC_REQUEST_VALUE_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
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
           ERR_SYNC_REQUEST_VALUE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    if (m == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_REQUEST_VALUE_NO_MODE.get());
    }
    else
    {
      mode = m;
    }

    if (h == null)
    {
      reloadHint = false;
    }
    else
    {
      reloadHint = h;
    }

    cookie = c;
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this control.
   *
   * @param  mode        The request mode which indicates whether to retrieve
   *                     only the initial content or to both retrieve the
   *                     initial content and be updated of changes made in the
   *                     future.  It must not be {@code null}.
   * @param  cookie      A cookie providing state information for an existing
   *                     synchronization session.  It may be {@code null} to
   *                     perform an initial synchronization rather than an
   *                     incremental update.
   * @param  reloadHint  Indicates whether the client wishes to retrieve an
   *                     initial content during an incremental update if the
   *                     server determines that the client cannot reach
   *                     convergence with the server data.
   *
   * @return  An ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final ContentSyncRequestMode mode,
                      @Nullable final ASN1OctetString cookie,
                      final boolean reloadHint)
  {
    Validator.ensureNotNull(mode);

    final ArrayList<ASN1Element> elements = new ArrayList<>(3);
    elements.add(new ASN1Enumerated(mode.intValue()));

    if (cookie != null)
    {
      elements.add(cookie);
    }

    if (reloadHint)
    {
      elements.add(ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT);
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the mode for this content synchronization request control, which
   * indicates whether to retrieve an initial content or an incremental update.
   *
   * @return  The mode for this content synchronization request control.
   */
  @NotNull()
  public ContentSyncRequestMode getMode()
  {
    return mode;
  }



  /**
   * Retrieves a cookie providing state information for an existing
   * synchronization session, if available.
   *
   * @return  A cookie providing state information for an existing
   *          synchronization session, or {@code null} if none is available and
   *          an initial content should be retrieved.
   */
  @Nullable()
  public ASN1OctetString getCookie()
  {
    return cookie;
  }



  /**
   * Retrieves the reload hint value for this synchronization request control.
   *
   * @return  {@code true} if the server should return an initial content rather
   *          than an incremental update if it determines that the client cannot
   *          reach convergence, or {@code false} if it should return an
   *          e-sync refresh required result in that case.
   */
  public boolean getReloadHint()
  {
    return reloadHint;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_CONTENT_SYNC_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ContentSyncRequestControl(mode='");
    buffer.append(mode.name());
    buffer.append('\'');

    if (cookie != null)
    {
      buffer.append(", cookie='");
      StaticUtils.toHex(cookie.getValue(), buffer);
      buffer.append('\'');
    }

    buffer.append(", reloadHint=");
    buffer.append(reloadHint);
    buffer.append(')');
  }
}
