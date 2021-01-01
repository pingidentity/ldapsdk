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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of a get changelog batch change
 * selection criteria value that indicates that the server should only return
 * changes that are associated with a specified notification destination, as
 * specified by the entryUUID for the notification destination to target.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NotificationDestinationChangeSelectionCriteria
       extends ChangelogBatchChangeSelectionCriteria
{
  /**
   * The inner BER type that should be used for encoded elements that represent
   * a notification destination get changelog batch selection criteria value.
   */
  static final byte TYPE_SELECTION_CRITERIA_NOTIFICATION_DESTINATION =
       (byte) 0x84;



  // The entryUUID for the for the notification destination to target.
  @NotNull private final String destinationEntryUUID;



  /**
   * Creates a new notification destination change selection criteria value with
   * the specified destination entryUUID.
   *
   * @param  destinationEntryUUID  The entryUUID for the notification
   *                               destination to target.  It must not be
   *                               {@code null}.
   */
  public NotificationDestinationChangeSelectionCriteria(
              @NotNull final String destinationEntryUUID)
  {
    Validator.ensureNotNull(destinationEntryUUID);

    this.destinationEntryUUID = destinationEntryUUID;
  }



  /**
   * Decodes the provided ASN.1 element, which is the inner element of a
   * changelog batch change selection criteria element, as an all attributes
   * change selection criteria value.
   *
   * @param  innerElement  The inner element of a changelog batch change
   *                       selection criteria element to be decoded.
   *
   * @return  The decoded all attributes change selection criteria value.
   *
   * @throws  LDAPException  If a problem is encountered while trying to decode
   *                         the provided element as the inner element of an all
   *                         attributes change selection criteria value.
   */
  @NotNull()
  static NotificationDestinationChangeSelectionCriteria decodeInnerElement(
              @NotNull final ASN1Element innerElement)
         throws LDAPException
  {
    try
    {
      return new NotificationDestinationChangeSelectionCriteria(
           ASN1OctetString.decodeAsOctetString(innerElement).stringValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_NOT_DEST_CHANGE_SELECTION_CRITERIA_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the entryUUID for the target notification destination.
   *
   * @return  The entryUUID for the target notification destination.
   */
  @NotNull()
  public String getDestinationEntryUUID()
  {
    return destinationEntryUUID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeInnerElement()
  {
    return new ASN1OctetString(TYPE_SELECTION_CRITERIA_NOTIFICATION_DESTINATION,
         destinationEntryUUID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("NotificationDestinationChangeSelectionCriteria(" +
         "destinationEntryUUID='");
    buffer.append(destinationEntryUUID);
    buffer.append("')");
  }
}
