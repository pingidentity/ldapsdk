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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
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
 * This class provides an extended request that may be used to create or update
 * a notification destination.
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
 * The request has an OID of 1.3.6.1.4.1.30221.2.6.36 and a value with the
 * following encoding:
 * <BR><BR>
 * <PRE>
 *   SetNotificationDestinationRequest ::= SEQUENCE {
 *        notificationManagerID         OCTET STRING,
 *        notificationDestinationID     OCTET STRING,
 *        destinationDetails            SEQUENCE OF OCTET STRING,
 *        changeType                    [0] ENUMERATED {
 *             replace (0),
 *             add (1),
 *             delete (2) } DEFAULT replace }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SetNotificationDestinationExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.36) for the set notification destination
   * extended request.
   */
  @NotNull public static final String SET_NOTIFICATION_DESTINATION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.36";



  /**
   * The BER type for the value sequence element that specifies the destination
   * details change type.
   */
  private static final byte BER_TYPE_CHANGE_TYPE = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8651862605802389433L;



  // The implementation-specific details for the notification destination.
  @NotNull private final List<ASN1OctetString> destinationDetails;

  // The change type for the destination details.
  @NotNull private final SetNotificationDestinationChangeType changeType;

  // The notification destination ID.
  @NotNull private final String destinationID;

  // The notification manager ID.
  @NotNull private final String managerID;



  /**
   * Creates a new set notification destination extended request with the
   * provided information.
   *
   * @param  managerID           The notification manager ID.  It must not be
   *                             {@code null}.
   * @param  destinationID       The notification destination ID.  It must not
   *                             be {@code null}.
   * @param  destinationDetails  The implementation-specific details for the
   *                             notification destination.  At least one detail
   *                             value must be provided.
   */
  public SetNotificationDestinationExtendedRequest(
              @NotNull final String managerID,
              @NotNull final String destinationID,
              @NotNull final ASN1OctetString... destinationDetails)
  {
    this(managerID, destinationID, StaticUtils.toList(destinationDetails),
         SetNotificationDestinationChangeType.REPLACE);
  }



  /**
   * Creates a new set notification destination extended request with the
   * provided information.
   *
   * @param  managerID           The notification manager ID.  It must not be
   *                             {@code null}.
   * @param  destinationID       The notification destination ID.  It must not
   *                             be {@code null}.
   * @param  destinationDetails  The implementation-specific details for the
   *                             notification destination.  At least one detail
   *                             value must be provided.
   * @param  controls            The set of controls to include in the request.
   *                             It may be {@code null} or empty if no controls
   *                             are needed.
   */
  public SetNotificationDestinationExtendedRequest(
              @NotNull final String managerID,
              @NotNull final String destinationID,
              @NotNull final Collection<ASN1OctetString> destinationDetails,
              @Nullable final Control... controls)
  {
    this(managerID, destinationID, destinationDetails,
         SetNotificationDestinationChangeType.REPLACE, controls);
  }



  /**
   * Creates a new set notification destination extended request with the
   * provided information.
   *
   * @param  managerID           The notification manager ID.  It must not be
   *                             {@code null}.
   * @param  destinationID       The notification destination ID.  It must not
   *                             be {@code null}.
   * @param  destinationDetails  The implementation-specific details for the
   *                             notification destination.  At least one detail
   *                             value must be provided.
   * @param  changeType          The change type for the destination details.
   * @param  controls            The set of controls to include in the request.
   *                             It may be {@code null} or empty if no controls
   *                             are needed.
   */
  public SetNotificationDestinationExtendedRequest(
              @NotNull final String managerID,
              @NotNull final String destinationID,
              @NotNull final Collection<ASN1OctetString> destinationDetails,
              @Nullable final SetNotificationDestinationChangeType changeType,
              @Nullable final Control... controls)
  {
    super(SET_NOTIFICATION_DESTINATION_REQUEST_OID,
         encodeValue(managerID, destinationID, destinationDetails, changeType),
         controls);

    this.managerID = managerID;
    this.destinationID = destinationID;
    this.destinationDetails =
         Collections.unmodifiableList(new ArrayList<>(destinationDetails));

    if (changeType == null)
    {
      this.changeType = SetNotificationDestinationChangeType.REPLACE;
    }
    else
    {
      this.changeType = changeType;
    }
  }



  /**
   * Creates a new set notification destination extended request from the
   * provided generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          set notification destination extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public SetNotificationDestinationExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SET_NOTIFICATION_DEST_REQ_DECODE_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      managerID =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      destinationID =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();

      final ASN1Element[] detailElements =
           ASN1Sequence.decodeAsSequence(elements[2]).elements();
      final ArrayList<ASN1OctetString> detailList =
           new ArrayList<>(detailElements.length);
      for (final ASN1Element e : detailElements)
      {
        detailList.add(ASN1OctetString.decodeAsOctetString(e));
      }
      destinationDetails = Collections.unmodifiableList(detailList);

      SetNotificationDestinationChangeType ct =
           SetNotificationDestinationChangeType.REPLACE;
      for (int i=3; i < elements.length; i++)
      {
        final ASN1Element e = elements[i];
        switch (e.getType())
        {
          case BER_TYPE_CHANGE_TYPE:
            final int ctIntValue =
                 ASN1Enumerated.decodeAsEnumerated(e).intValue();
            ct = SetNotificationDestinationChangeType.valueOf(ctIntValue);
            if (ct == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SET_NOTIFICATION_DEST_REQ_INVALID_CT.get(ctIntValue));
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SET_NOTIFICATION_DEST_REQ_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      changeType = ct;
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
           ERR_SET_NOTIFICATION_DEST_REQ_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  managerID           The notification manager ID.  It must not be
   *                             {@code null}.
   * @param  destinationID       The notification destination ID.  It must not
   *                             be {@code null}.
   * @param  destinationDetails  The implementation-specific details for the
   *                             notification destination.  At least one detail
   *                             value must be provided.
   * @param  changeType          The change type for the destination details.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String managerID,
               @NotNull final String destinationID,
               @NotNull final Collection<ASN1OctetString> destinationDetails,
               @Nullable final SetNotificationDestinationChangeType changeType)
  {
    Validator.ensureNotNull(managerID);
    Validator.ensureNotNull(destinationID);
    Validator.ensureNotNull(destinationDetails);
    Validator.ensureFalse(destinationDetails.isEmpty());

    final ArrayList<ASN1Element> elements = new ArrayList<>(4);
    elements.add(new ASN1OctetString(managerID));
    elements.add(new ASN1OctetString(destinationID));
    elements.add(new ASN1Sequence(
         new ArrayList<ASN1Element>(destinationDetails)));

    if ((changeType != null) &&
        (changeType != SetNotificationDestinationChangeType.REPLACE))
    {
      elements.add(new ASN1Enumerated(BER_TYPE_CHANGE_TYPE,
           changeType.intValue()));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
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
   * Retrieves the implementation-specific details for the notification
   * destination.
   *
   * @return  The implementation-specific details for the notification
   *          destination.
   */
  @NotNull()
  public List<ASN1OctetString> getDestinationDetails()
  {
    return destinationDetails;
  }



  /**
   * Retrieves the change type for the destination details.
   *
   * @return  The change type for the destination details.
   */
  @NotNull()
  public SetNotificationDestinationChangeType getChangeType()
  {
    return changeType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SetNotificationDestinationExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SetNotificationDestinationExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final SetNotificationDestinationExtendedRequest r =
         new SetNotificationDestinationExtendedRequest(managerID,
              destinationID, destinationDetails, changeType, controls);
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
    return INFO_EXTENDED_REQUEST_NAME_SET_NOTIFICATION_DEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SetNotificationDestinationExtendedRequest(managerID='");
    buffer.append(managerID);
    buffer.append("', destinationID='");
    buffer.append(destinationID);
    buffer.append("', destinationDetails=ASN1OctetString[");
    buffer.append(destinationDetails.size());
    buffer.append("], changeType=");
    buffer.append(changeType.name());

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
