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
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
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

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an extended request that may be used to clear a server
 * alarm condition about missed change notifications.
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
* The request has an OID of 1.3.6.1.4.1.30221.2.6.42 and a value with the
 * following encoding:
 * <BR><BR>
 * <PRE>
 *   ClearMissedNotificationChangesAlarmRequest ::= SEQUENCE {
 *        notificationManagerID         OCTET STRING,
 *        notificationDestinationID     OCTET STRING }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ClearMissedNotificationChangesAlarmExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.42) for the clear missed notification
   * changes alarm extended request.
   */
  @NotNull public static final String
       CLEAR_MISSED_NOTIFICATION_CHANGES_ALARM_REQUEST_OID =
            "1.3.6.1.4.1.30221.2.6.42";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5245417833641929585L;



  // The notification destination ID.
  @NotNull private final String destinationID;

  // The notification manager ID.
  @NotNull private final String managerID;



  /**
   * Creates a new clear missed notification changes alarm extended request with
   * the provided information.
   *
   * @param  managerID         The notification manager ID.  It must not be
   *                           {@code null}.
   * @param  destinationID     The notification destination ID.  It must not be
   *                           {@code null}.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if no controls
   *                           are needed.
   */
  public ClearMissedNotificationChangesAlarmExtendedRequest(
       @NotNull final String managerID,
       @NotNull final String destinationID,
       @Nullable final Control... controls)
  {
    super(CLEAR_MISSED_NOTIFICATION_CHANGES_ALARM_REQUEST_OID,
         encodeValue(managerID, destinationID), controls);

    this.managerID = managerID;
    this.destinationID = destinationID;
  }



  /**
   * Creates a new clear missed notification changes alarm extended request from
   * the provided generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          clear missed notification changes alarm extended
   *                          request.
   *
   * @throws LDAPException  If a problem occurs while decoding the request.
   */
  public ClearMissedNotificationChangesAlarmExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CLEAR_MISSED_NOTIFICATION_CHANGES_ALARM_REQ_DECODE_NO_VALUE.
                get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      managerID =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      destinationID =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CLEAR_MISSED_NOTIFICATION_CHANGES_ALARM_REQ_ERROR_DECODING_VALUE.
                get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  managerID         The notification manager ID.  It must not be
   *                           {@code null}.
   * @param  destinationID     The notification destination ID.  It must not be
   *                           {@code null}.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String managerID,
                      @NotNull final String destinationID)
  {
    Validator.ensureNotNull(managerID);
    Validator.ensureNotNull(destinationID);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(managerID),
         new ASN1OctetString(destinationID));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the notification manager ID.
   *
   * @return  The notification manager ID.
   */
  @NotNull()
  public String getManagerID()
  {
    return managerID;
  }



  /**
   * Retrieves the notification destination ID.
   *
   * @return  The notification destination ID.
   */
  @NotNull()
  public String getDestinationID()
  {
    return destinationID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ClearMissedNotificationChangesAlarmExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ClearMissedNotificationChangesAlarmExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final ClearMissedNotificationChangesAlarmExtendedRequest r =
         new ClearMissedNotificationChangesAlarmExtendedRequest(managerID,
              destinationID, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_CLEAR_MISSED_NOTIFICATION_CHANGES_ALARM.
         get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ClearMissedNotificationChangesAlarmExtendedRequest(" +
         "managerID='");
    buffer.append(managerID);
    buffer.append("', destinationID='");
    buffer.append(destinationID);
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
