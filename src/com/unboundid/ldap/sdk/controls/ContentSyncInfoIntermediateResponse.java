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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
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
 * This class provides an implementation of the sync info message, which is
 * an intermediate response message used by the content synchronization
 * operation as defined in
 * <a href="http://www.ietf.org/rfc/rfc4533.txt">RFC 4533</a>.  Directory
 * servers may return this response in the course of processing a search
 * request containing the content synchronization request control.  See the
 * documentation for the {@link ContentSyncRequestControl} class for more
 * information about using the content synchronization operation.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ContentSyncInfoIntermediateResponse
       extends IntermediateResponse
{
  /**
   * The OID (1.3.6.1.4.1.4203.1.9.1.4) for the sync info intermediate response.
   */
  @NotNull public static final String SYNC_INFO_OID =
       "1.3.6.1.4.1.4203.1.9.1.4";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4464376009337157433L;



  // An updated state cookie, if available.
  @Nullable private final ASN1OctetString cookie;

  // Indicates whether the provided set of UUIDs represent entries that have
  // been removed.
  private final boolean refreshDeletes;

  // Indicates whether the refresh phase is complete.
  private final boolean refreshDone;

  // The type of content synchronization information represented in this
  // response.
  @NotNull private final ContentSyncInfoType type;

  // A list of entryUUIDs for the set of entries associated with this message.
  @Nullable private final List<UUID> entryUUIDs;



  /**
   * Creates a new content synchronization info intermediate response with the
   * provided information.
   *
   * @param  type            The type of content synchronization information
   *                         represented in this response.
   * @param  value           The encoded value for the intermediate response, if
   *                         any.
   * @param  cookie          An updated state cookie for the synchronization
   *                         session, if available.
   * @param  refreshDone     Indicates whether the refresh phase of the
   *                         synchronization session is complete.
   * @param  refreshDeletes  Indicates whether the provided set of UUIDs
   *                         represent entries that have been removed.
   * @param  entryUUIDs      A list of entryUUIDs for the set of entries
   *                         associated with this message.
   * @param  controls        The set of controls to include in the intermediate
   *                         response, if any.
   */
  private ContentSyncInfoIntermediateResponse(
                 @NotNull final ContentSyncInfoType type,
                 @Nullable final ASN1OctetString value,
                 @Nullable final ASN1OctetString cookie,
                 final boolean refreshDone, final boolean refreshDeletes,
                 @Nullable final List<UUID> entryUUIDs,
                 @Nullable final Control... controls)
  {
    super(SYNC_INFO_OID, value, controls);

    this.type           = type;
    this.cookie         = cookie;
    this.refreshDone    = refreshDone;
    this.refreshDeletes = refreshDeletes;
    this.entryUUIDs     = entryUUIDs;
  }



  /**
   * Creates a new sync info intermediate response with a type of
   * {@link ContentSyncInfoType#NEW_COOKIE}.
   *
   * @param  cookie    The updated state cookie for the synchronization session.
   *                   It must not be {@code null}.
   * @param  controls  An optional set of controls to include in the response.
   *                   It may be {@code null} or empty if no controls should be
   *                   included.
   *
   * @return  The created sync info intermediate response.
   */
  @NotNull()
  public static ContentSyncInfoIntermediateResponse createNewCookieResponse(
                     @NotNull final ASN1OctetString cookie,
                     @Nullable final Control... controls)
  {
    Validator.ensureNotNull(cookie);

    final ContentSyncInfoType type = ContentSyncInfoType.NEW_COOKIE;

    return new ContentSyncInfoIntermediateResponse(type,
         encodeValue(type, cookie, false, null, false),
         cookie, false, false, null, controls);
  }



  /**
   * Creates a new sync info intermediate response with a type of
   * {@link ContentSyncInfoType#REFRESH_DELETE}.
   *
   * @param  cookie       The updated state cookie for the synchronization
   *                      session.  It may be {@code null} if no new cookie is
   *                      available.
   * @param  refreshDone  Indicates whether the refresh phase of the
   *                      synchronization operation has completed.
   * @param  controls     An optional set of controls to include in the
   *                      response.  It may be {@code null} or empty if no
   *                      controls should be included.
   *
   * @return  The created sync info intermediate response.
   */
  @NotNull()
  public static ContentSyncInfoIntermediateResponse createRefreshDeleteResponse(
                     @Nullable final ASN1OctetString cookie,
                     final boolean refreshDone,
                     @Nullable final Control... controls)
  {
    final ContentSyncInfoType type = ContentSyncInfoType.REFRESH_DELETE;

    return new ContentSyncInfoIntermediateResponse(type,
         encodeValue(type, cookie, refreshDone, null, false),
         cookie, refreshDone, false, null, controls);
  }



  /**
   * Creates a new sync info intermediate response with a type of
   * {@link ContentSyncInfoType#REFRESH_PRESENT}.
   *
   * @param  cookie       The updated state cookie for the synchronization
   *                      session.  It may be {@code null} if no new cookie is
   *                      available.
   * @param  refreshDone  Indicates whether the refresh phase of the
   *                      synchronization operation has completed.
   * @param  controls     An optional set of controls to include in the
   *                      response.  It may be {@code null} or empty if no
   *                      controls should be included.
   *
   * @return  The created sync info intermediate response.
   */
  @NotNull()
  public static ContentSyncInfoIntermediateResponse
                     createRefreshPresentResponse(
                          @Nullable final ASN1OctetString cookie,
                          final boolean refreshDone,
                          @Nullable final Control... controls)
  {
    final ContentSyncInfoType type = ContentSyncInfoType.REFRESH_PRESENT;

    return new ContentSyncInfoIntermediateResponse(type,
         encodeValue(type, cookie, refreshDone, null, false),
         cookie, refreshDone, false, null, controls);
  }



  /**
   * Creates a new sync info intermediate response with a type of
   * {@link ContentSyncInfoType#SYNC_ID_SET}.
   *
   * @param  cookie          The updated state cookie for the synchronization
   *                         session.  It may be {@code null} if no new cookie
   *                         is available.
   * @param  entryUUIDs      The set of entryUUIDs for the entries referenced in
   *                         this response.  It must not be {@code null}.
   * @param  refreshDeletes  Indicates whether the entryUUIDs represent entries
   *                         that have been removed rather than those that have
   *                         remained unchanged.
   * @param  controls        An optional set of controls to include in the
   *                         response.  It may be {@code null} or empty if no
   *                         controls should be included.
   *
   * @return  The created sync info intermediate response.
   */
  @NotNull()
  public static ContentSyncInfoIntermediateResponse createSyncIDSetResponse(
                     @Nullable final ASN1OctetString cookie,
                     @NotNull final List<UUID> entryUUIDs,
                     final boolean refreshDeletes,
                     @Nullable final Control... controls)
  {
    Validator.ensureNotNull(entryUUIDs);

    final ContentSyncInfoType type = ContentSyncInfoType.SYNC_ID_SET;

    return new ContentSyncInfoIntermediateResponse(type,
         encodeValue(type, cookie, false, entryUUIDs, refreshDeletes),
         cookie, false, refreshDeletes,
         Collections.unmodifiableList(entryUUIDs), controls);
  }



  /**
   * Decodes the provided generic intermediate response as a sync info
   * intermediate response.
   *
   * @param  r  The intermediate response to be decoded as a sync info
   *            intermediate response.  It must not be {@code null}.
   *
   * @return  The decoded sync info intermediate response.
   *
   * @throws  LDAPException  If a problem occurs while trying to decode the
   *                         provided intermediate response as a sync info
   *                         response.
   */
  @NotNull()
  public static ContentSyncInfoIntermediateResponse decode(
                     @NotNull final IntermediateResponse r)
         throws LDAPException
  {
    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_INFO_IR_NO_VALUE.get());
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
           ERR_SYNC_INFO_IR_VALUE_NOT_ELEMENT.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    final ContentSyncInfoType type =
         ContentSyncInfoType.valueOf(valueElement.getType());
    if (type == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SYNC_INFO_IR_VALUE_UNRECOGNIZED_TYPE.get(
                StaticUtils.toHex(valueElement.getType())));
    }

    ASN1OctetString cookie         = null;
    boolean         refreshDone    = false;
    boolean         refreshDeletes = false;
    List<UUID>      entryUUIDs     = null;

    try
    {
      switch (type)
      {
        case NEW_COOKIE:
          cookie = new ASN1OctetString(valueElement.getValue());
          break;

        case REFRESH_DELETE:
        case REFRESH_PRESENT:
          refreshDone = true;

          ASN1Sequence s = valueElement.decodeAsSequence();
          for (final ASN1Element e : s.elements())
          {
            switch (e.getType())
            {
              case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
                cookie = ASN1OctetString.decodeAsOctetString(e);
                break;
              case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
                refreshDone = ASN1Boolean.decodeAsBoolean(e).booleanValue();
                break;
              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_SYNC_INFO_IR_VALUE_INVALID_SEQUENCE_TYPE.get(
                          type.name(), StaticUtils.toHex(e.getType())));
            }
          }
          break;

        case SYNC_ID_SET:
          s = valueElement.decodeAsSequence();
          for (final ASN1Element e : s.elements())
          {
            switch (e.getType())
            {
              case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
                cookie = ASN1OctetString.decodeAsOctetString(e);
                break;
              case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
                refreshDeletes = ASN1Boolean.decodeAsBoolean(e).booleanValue();
                break;
              case ASN1Constants.UNIVERSAL_SET_TYPE:
                final ASN1Set uuidSet = ASN1Set.decodeAsSet(e);
                final ASN1Element[] uuidElements = uuidSet.elements();
                entryUUIDs = new ArrayList<>(uuidElements.length);
                for (final ASN1Element uuidElement : uuidElements)
                {
                  try
                  {
                    entryUUIDs.add(StaticUtils.decodeUUID(
                         uuidElement.getValue()));
                  }
                  catch (final ParseException pe)
                  {
                    Debug.debugException(pe);
                    throw new LDAPException(ResultCode.DECODING_ERROR,
                         ERR_SYNC_INFO_IR_INVALID_UUID.get(type.name(),
                              pe.getMessage()), pe);
                  }
                }
                break;
              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_SYNC_INFO_IR_VALUE_INVALID_SEQUENCE_TYPE.get(
                          type.name(), StaticUtils.toHex(e.getType())));
            }
          }

          if (entryUUIDs == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SYNC_INFO_IR_NO_UUID_SET.get(type.name()));
          }
          break;
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
           ERR_SYNC_INFO_IR_VALUE_DECODING_ERROR.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    return new ContentSyncInfoIntermediateResponse(type, value, cookie,
         refreshDone, refreshDeletes, entryUUIDs, r.getControls());
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this intermediate response.
   *
   * @param  type            The type for this sync info message.
   * @param  cookie          The updated sync state cookie.
   * @param  refreshDone     Indicates whether the refresh phase of the
   *                         synchronization operation is complete.
   * @param  entryUUIDs      The set of entryUUIDs for the entries referenced
   *                         in this message.
   * @param  refreshDeletes  Indicates whether the associated entryUUIDs are for
   *                         entries that have been removed.
   *
   * @return  The encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                                      @NotNull final ContentSyncInfoType type,
                                      @Nullable final ASN1OctetString cookie,
                                      final boolean refreshDone,
                                      @Nullable final List<UUID> entryUUIDs,
                                      final boolean refreshDeletes)
  {
    final ASN1Element e;
    switch (type)
    {
      case NEW_COOKIE:
        e = new ASN1OctetString(type.getType(), cookie.getValue());
        break;

      case REFRESH_DELETE:
      case REFRESH_PRESENT:
        ArrayList<ASN1Element> l = new ArrayList<>(2);
        if (cookie != null)
        {
          l.add(cookie);
        }

        if (! refreshDone)
        {
          l.add(new ASN1Boolean(refreshDone));
        }

        e = new ASN1Sequence(type.getType(), l);
        break;

      case SYNC_ID_SET:
        l = new ArrayList<>(3);

        if (cookie != null)
        {
          l.add(cookie);
        }

        if (refreshDeletes)
        {
          l.add(new ASN1Boolean(refreshDeletes));
        }

        final ArrayList<ASN1Element> uuidElements =
             new ArrayList<>(entryUUIDs.size());
        for (final UUID uuid : entryUUIDs)
        {
          uuidElements.add(new ASN1OctetString(StaticUtils.encodeUUID(uuid)));
        }
        l.add(new ASN1Set(uuidElements));

        e = new ASN1Sequence(type.getType(), l);
        break;

      default:
        // This should never happen.
        throw new AssertionError("Unexpected sync info type:  " + type.name());
    }

    return new ASN1OctetString(e.encode());
  }



  /**
   * Retrieves the type of content synchronization information represented in
   * this response.
   *
   * @return  The type of content synchronization information represented in
   *          this response.
   */
  @NotNull()
  public ContentSyncInfoType getType()
  {
    return type;
  }



  /**
   * Retrieves an updated state cookie for the synchronization session, if
   * available.  It will always be non-{@code null} for a type of
   * {@link ContentSyncInfoType#NEW_COOKIE}, and may or may not be {@code null}
   * for other types.
   *
   * @return  An updated state cookie for the synchronization session, or
   *          {@code null} if none is available.
   */
  @Nullable()
  public ASN1OctetString getCookie()
  {
    return cookie;
  }



  /**
   * Indicates whether the refresh phase of the synchronization operation has
   * completed.  This is only applicable for the
   * {@link ContentSyncInfoType#REFRESH_DELETE} and
   * {@link ContentSyncInfoType#REFRESH_PRESENT} types.
   *
   * @return  {@code true} if the refresh phase of the synchronization operation
   *          has completed, or {@code false} if not or if it is not applicable
   *          for this message type.
   */
  public boolean refreshDone()
  {
    return refreshDone;
  }



  /**
   * Retrieves a list of the entryUUID values for the entries referenced in this
   * message.  This is only applicable for the
   * {@link ContentSyncInfoType#SYNC_ID_SET} type.
   *
   * @return  A list of the entryUUID values for the entries referenced in this
   *          message, or {@code null} if it is not applicable for this message
   *          type.
   */
  @Nullable()
  public List<UUID> getEntryUUIDs()
  {
    return entryUUIDs;
  }



  /**
   * Indicates whether the provided set of UUIDs represent entries that have
   * been removed.  This is only applicable for the
   * {@link ContentSyncInfoType#SYNC_ID_SET} type.
   *
   * @return  {@code true} if the associated set of entryUUIDs represent entries
   *          that have been deleted, or {@code false} if they represent entries
   *          that remain unchanged or if it is not applicable for this message
   *          type.
   */
  public boolean refreshDeletes()
  {
    return refreshDeletes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getIntermediateResponseName()
  {
    return INFO_INTERMEDIATE_RESPONSE_NAME_SYNC_INFO.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String valueToString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("syncInfoType='");
    buffer.append(type.name());
    buffer.append('\'');

    if (cookie != null)
    {
      buffer.append(" cookie='");
      StaticUtils.toHex(cookie.getValue(), buffer);
      buffer.append('\'');
    }

    switch (type)
    {
      case REFRESH_DELETE:
      case REFRESH_PRESENT:
        buffer.append(" refreshDone='");
        buffer.append(refreshDone);
        buffer.append('\'');
        break;

      case SYNC_ID_SET:
        buffer.append(" entryUUIDs={");

        final Iterator<UUID> iterator = entryUUIDs.iterator();
        while (iterator.hasNext())
        {
          buffer.append('\'');
          buffer.append(iterator.next().toString());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(',');
          }
        }

        buffer.append('}');
        break;

      case NEW_COOKIE:
      default:
        // No additional content is needed.
        break;
    }

    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ContentSyncInfoIntermediateResponse(");

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append("messageID=");
      buffer.append(messageID);
      buffer.append(", ");
    }

    buffer.append("type='");
    buffer.append(type.name());
    buffer.append('\'');

    if (cookie != null)
    {
      buffer.append(", cookie='");
      StaticUtils.toHex(cookie.getValue(), buffer);
      buffer.append("', ");
    }

    switch (type)
    {
      case NEW_COOKIE:
        // No additional content is needed.
        break;

      case REFRESH_DELETE:
      case REFRESH_PRESENT:
        buffer.append(", refreshDone=");
        buffer.append(refreshDone);
        break;

      case SYNC_ID_SET:
        buffer.append(", entryUUIDs={");

        final Iterator<UUID> iterator = entryUUIDs.iterator();
        while (iterator.hasNext())
        {
          buffer.append('\'');
          buffer.append(iterator.next());
          buffer.append('\'');
          if (iterator.hasNext())
          {
            buffer.append(',');
          }
        }

        buffer.append("}, refreshDeletes=");
        buffer.append(refreshDeletes);
        break;
    }

    buffer.append(')');
  }
}
