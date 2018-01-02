/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
  public static final String SET_NOTIFICATION_DESTINATION_REQUEST_OID =
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
  private final List<ASN1OctetString> destinationDetails;

  // The change type for the destination details.
  private final SetNotificationDestinationChangeType changeType;

  // The notification destination ID.
  private final String destinationID;

  // The notification manager ID.
  private final String managerID;



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
  public SetNotificationDestinationExtendedRequest(final String managerID,
              final String destinationID,
              final ASN1OctetString... destinationDetails)
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
  public SetNotificationDestinationExtendedRequest(final String managerID,
              final String destinationID,
              final Collection<ASN1OctetString> destinationDetails,
              final Control... controls)
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
  public SetNotificationDestinationExtendedRequest(final String managerID,
              final String destinationID,
              final Collection<ASN1OctetString> destinationDetails,
              final SetNotificationDestinationChangeType changeType,
              final Control... controls)
  {
    super(SET_NOTIFICATION_DESTINATION_REQUEST_OID,
         encodeValue(managerID, destinationID, destinationDetails, changeType),
         controls);

    this.managerID = managerID;
    this.destinationID = destinationID;
    this.destinationDetails = Collections.unmodifiableList(
         new ArrayList<ASN1OctetString>(destinationDetails));

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
              final ExtendedRequest extendedRequest)
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
           new ArrayList<ASN1OctetString>(detailElements.length);
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
  private static ASN1OctetString encodeValue(final String managerID,
                      final String destinationID,
                      final Collection<ASN1OctetString> destinationDetails,
                      final SetNotificationDestinationChangeType changeType)
  {
    Validator.ensureNotNull(managerID);
    Validator.ensureNotNull(destinationID);
    Validator.ensureNotNull(destinationDetails);
    Validator.ensureFalse(destinationDetails.isEmpty());

    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(4);
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
  public String getManagerID()
  {
    return managerID;
  }



  /**
   * Retrieves the notification destination ID.
   *
   * @return  The notification destination ID.
   */
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
  public List<ASN1OctetString> getDestinationDetails()
  {
    return destinationDetails;
  }



  /**
   * Retrieves the change type for the destination details.
   *
   * @return  The change type for the destination details.
   */
  public SetNotificationDestinationChangeType getChangeType()
  {
    return changeType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SetNotificationDestinationExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SetNotificationDestinationExtendedRequest
              duplicate(final Control[] controls)
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
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_SET_NOTIFICATION_DEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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
