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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;
import java.util.Collection;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDChangeLogEntry;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an intermediate response which
 * provides information about a changelog entry returned from a Directory
 * Server.
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
 * The changelog entry intermediate response value is encoded as follows:
 * <PRE>
 *   ChangelogEntryIntermediateResponse ::= SEQUENCE {
 *        resumeToken                  OCTET STRING,
 *        serverID                     OCTET STRING,
 *        changelogEntryDN             LDAPDN,
 *        changelogEntryAttributes     PartialAttributeList,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ChangelogEntryIntermediateResponse
       extends IntermediateResponse
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.11) for the get stream directory values
   * intermediate response.
   */
  @NotNull public static final String
       CHANGELOG_ENTRY_INTERMEDIATE_RESPONSE_OID = "1.3.6.1.4.1.30221.2.6.11";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5616371094806687752L;



  // A token that may be used to start retrieving changelog entries
  // immediately after this entry.
  @NotNull private final ASN1OctetString resumeToken;

  // The changelog entry included in this intermediate response.
  @NotNull private final UnboundIDChangeLogEntry changeLogEntry;

  // The server ID for the server from which the changelog entry was retrieved.
  @NotNull private final String serverID;



  /**
   * Creates a new changelog entry intermediate response with the provided
   * information.
   *
   * @param  changeLogEntry  The changelog entry included in this intermediate
   *                         response.  It must not be {@code null}.
   * @param  serverID        The server ID for the server from which the
   *                         changelog entry was received.  It must not be
   *                         {@code null}.
   * @param  resumeToken     A token that may be used to resume the process of
   *                         retrieving changes at the point immediately after
   *                         this change.  It must not be {@code null}.
   * @param  controls        The set of controls to include in the response.  It
   *                         may be {@code null} or empty if no controls should
   *                         be included.
   */
  public ChangelogEntryIntermediateResponse(
              @NotNull final ChangeLogEntry changeLogEntry,
              @NotNull final String serverID,
              @NotNull final ASN1OctetString resumeToken,
              @Nullable final Control... controls)
  {
    super(CHANGELOG_ENTRY_INTERMEDIATE_RESPONSE_OID,
          encodeValue(changeLogEntry, serverID, resumeToken), controls);

    if (changeLogEntry instanceof UnboundIDChangeLogEntry)
    {
      this.changeLogEntry = (UnboundIDChangeLogEntry) changeLogEntry;
    }
    else
    {
      try
      {
        this.changeLogEntry = new UnboundIDChangeLogEntry(changeLogEntry);
      }
      catch (final LDAPException le)
      {
        // This should never happen.
        Debug.debugException(le);
        throw new LDAPRuntimeException(le);
      }
    }

    this.serverID       = serverID;
    this.resumeToken    = resumeToken;
  }



  /**
   * Creates a new changelog entry intermediate response from the provided
   * generic intermediate response.
   *
   * @param  r  The generic intermediate response to be decoded.
   *
   * @throws  LDAPException  If the provided intermediate response cannot be
   *                         decoded as a changelog entry response.
   */
  public ChangelogEntryIntermediateResponse(
              @NotNull final IntermediateResponse r)
         throws LDAPException
  {
    super(r);

    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_ENTRY_IR_NO_VALUE.get());
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
           ERR_CHANGELOG_ENTRY_IR_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length != 4)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_ENTRY_IR_INVALID_VALUE_COUNT.get(
                valueElements.length));
    }

    resumeToken = ASN1OctetString.decodeAsOctetString(valueElements[0]);

    serverID =
         ASN1OctetString.decodeAsOctetString(valueElements[1]).stringValue();

    final String dn =
         ASN1OctetString.decodeAsOctetString(valueElements[2]).stringValue();

    try
    {
      final ASN1Element[] attrsElements =
           ASN1Sequence.decodeAsSequence(valueElements[3]).elements();
      final ArrayList<Attribute> attributes =
           new ArrayList<>(attrsElements.length);
      for (final ASN1Element e : attrsElements)
      {
        attributes.add(Attribute.decode(ASN1Sequence.decodeAsSequence(e)));
      }

      changeLogEntry = new UnboundIDChangeLogEntry(new Entry(dn, attributes));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_ENTRY_IR_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Encodes the provided information in a form suitable for use as the value of
   * this intermediate response.
   *
   * @param  changeLogEntry  The changelog entry included in this intermediate
   *                         response.
   * @param  serverID        The server ID for the server from which the
   *                         changelog entry was received.
   * @param  resumeToken     A token that may be used to resume the process of
   *                         retrieving changes at the point immediately after
   *                         this change.
   *
   * @return  The encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final ChangeLogEntry changeLogEntry,
               @NotNull final String serverID,
               @NotNull final ASN1OctetString resumeToken)
  {
    Validator.ensureNotNull(changeLogEntry);
    Validator.ensureNotNull(serverID);
    Validator.ensureNotNull(resumeToken);

    final Collection<Attribute> attrs = changeLogEntry.getAttributes();
    final ArrayList<ASN1Element> attrElements =
         new ArrayList<>(attrs.size());
    for (final Attribute a : attrs)
    {
      attrElements.add(a.encode());
    }

    final ASN1Sequence s = new ASN1Sequence(
         resumeToken,
         new ASN1OctetString(serverID),
         new ASN1OctetString(changeLogEntry.getDN()),
         new ASN1Sequence(attrElements));

    return new ASN1OctetString(s.encode());
  }



  /**
   * Retrieves the changelog entry contained in this intermediate response.
   *
   * @return  The changelog entry contained in this intermediate response.
   */
  @NotNull()
  public UnboundIDChangeLogEntry getChangeLogEntry()
  {
    return changeLogEntry;
  }



  /**
   * Retrieves the server ID for the server from which the changelog entry was
   * retrieved.
   *
   * @return  The server ID for the server from which the changelog entry was
   *          retrieved.
   */
  @NotNull()
  public String getServerID()
  {
    return serverID;
  }



  /**
   * Retrieves a token that may be used to resume the process of retrieving
   * changes at the point immediately after this change.
   *
   * @return  A token that may be used to resume the process of retrieving
   *          changes at the point immediately after this change.
   */
  @NotNull()
  public ASN1OctetString getResumeToken()
  {
    return resumeToken;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getIntermediateResponseName()
  {
    return INFO_CHANGELOG_ENTRY_IR_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String valueToString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("changeNumber='");
    buffer.append(changeLogEntry.getChangeNumber());
    buffer.append("' changeType='");
    buffer.append(changeLogEntry.getChangeType().getName());
    buffer.append("' targetDN='");
    buffer.append(changeLogEntry.getTargetDN());
    buffer.append("' serverID='");
    buffer.append(serverID);
    buffer.append("' resumeToken='");
    Base64.encode(resumeToken.getValue(), buffer);
    buffer.append('\'');

    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ChangelogEntryIntermediateResponse(");

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append("messageID=");
      buffer.append(messageID);
      buffer.append(", ");
    }

    buffer.append("changelogEntry=");
    changeLogEntry.toString(buffer);
    buffer.append(", serverID='");
    buffer.append(serverID);
    buffer.append("', resumeToken='");
    Base64.encode(resumeToken.getValue(), buffer);
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
