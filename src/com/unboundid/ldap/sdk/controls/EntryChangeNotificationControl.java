/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
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

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the entry change notification
 * control as defined in draft-ietf-ldapext-psearch.  It will be returned in
 * search result entries that match the criteria associated with a persistent
 * search (see the {@link PersistentSearchRequestControl} class) and have been
 * changed in a way associated with the registered change types for that search.
 * <BR><BR>
 * The information that can be included in an entry change notification control
 * includes:
 * <UL>
 *   <LI>A change type, which indicates the type of operation that was performed
 *       to trigger this entry change notification control.  It will be one of
 *       the values of the {@link PersistentSearchChangeType} enum.</LI>
 *   <LI>An optional previous DN, which indicates the DN that the entry had
 *       before the associated operation was processed.  It will only be present
 *       if the associated operation was a modify DN operation.</LI>
 *   <LI>An optional change number, which may be used to retrieve additional
 *       information about the associated operation from the server.  This may
 *       not be available in all directory server implementations.</LI>
 * </UL>
 * Note that the entry change notification control should only be included in
 * search result entries that are associated with a search request that included
 * the persistent search request control, and only if that persistent search
 * request control had the {@code returnECs} flag set to {@code true} to
 * indicate that entry change notification controls should be included in
 * resulting entries.  Further, the entry change notification control will only
 * be included in entries that are returned as the result of a change in the
 * server and not any of the preliminary entries that may be returned if the
 * corresponding persistent search request had the {@code changesOnly} flag set
 * to {@code false}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EntryChangeNotificationControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (2.16.840.1.113730.3.4.7) for the entry change notification
   * control.
   */
  @NotNull public static final String ENTRY_CHANGE_NOTIFICATION_OID =
       "2.16.840.1.113730.3.4.7";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1305357948140939303L;



  // The change number for the change, if available.
  private final long changeNumber;

  // The change type for the change.
  @NotNull private final PersistentSearchChangeType changeType;

  // The previous DN of the entry, if applicable.
  @Nullable private final String previousDN;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  EntryChangeNotificationControl()
  {
    changeNumber = -1;
    changeType   = null;
    previousDN   = null;
  }



  /**
   * Creates a new entry change notification control with the provided
   * information.  It will not be critical.
   *
   * @param  changeType    The change type for the change.  It must not be
   *                       {@code null}.
   * @param  previousDN    The previous DN of the entry, if applicable.
   * @param  changeNumber  The change number to include in this control, or
   *                       -1 if there should not be a change number.
   */
  public EntryChangeNotificationControl(
              @NotNull final PersistentSearchChangeType changeType,
              @Nullable final String previousDN, final long changeNumber)
  {
    this(changeType, previousDN, changeNumber, false);
  }



  /**
   * Creates a new entry change notification control with the provided
   * information.
   *
   * @param  changeType    The change type for the change.  It must not be
   *                       {@code null}.
   * @param  previousDN    The previous DN of the entry, if applicable.
   * @param  changeNumber  The change number to include in this control, or
   *                       -1 if there should not be a change number.
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.  Response controls should generally not be
   *                       critical.
   */
  public EntryChangeNotificationControl(
              @NotNull final PersistentSearchChangeType changeType,
              @Nullable final String previousDN, final long changeNumber,
              final boolean isCritical)
  {
    super(ENTRY_CHANGE_NOTIFICATION_OID, isCritical,
          encodeValue(changeType, previousDN, changeNumber));

    this.changeType   = changeType;
    this.previousDN   = previousDN;
    this.changeNumber = changeNumber;
  }



  /**
   * Creates a new entry change notification control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         entry change notification control.
   */
  public EntryChangeNotificationControl(@NotNull final String oid,
                                        final boolean isCritical,
                                        @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_NO_VALUE.get());
    }

    final ASN1Sequence ecnSequence;
    try
    {
      final ASN1Element element = ASN1Element.decode(value.getValue());
      ecnSequence = ASN1Sequence.decodeAsSequence(element);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] ecnElements = ecnSequence.elements();
    if ((ecnElements.length < 1) || (ecnElements.length > 3))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_INVALID_ELEMENT_COUNT.get(
                                   ecnElements.length));
    }

    final ASN1Enumerated ecnEnumerated;
    try
    {
      ecnEnumerated = ASN1Enumerated.decodeAsEnumerated(ecnElements[0]);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_FIRST_NOT_ENUMERATED.get(ae), ae);
    }

    changeType = PersistentSearchChangeType.valueOf(ecnEnumerated.intValue());
    if (changeType == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ECN_INVALID_CHANGE_TYPE.get(
                                   ecnEnumerated.intValue()));
    }


    String prevDN = null;
    long   chgNum = -1;
    for (int i=1; i < ecnElements.length; i++)
    {
      switch (ecnElements[i].getType())
      {
        case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
          prevDN = ASN1OctetString.decodeAsOctetString(
                        ecnElements[i]).stringValue();
          break;

        case ASN1Constants.UNIVERSAL_INTEGER_TYPE:
          try
          {
            chgNum = ASN1Long.decodeAsLong(ecnElements[i]).longValue();
          }
          catch (final ASN1Exception ae)
          {
            Debug.debugException(ae);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ECN_CANNOT_DECODE_CHANGE_NUMBER.get(ae), ae);
          }
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_ECN_INVALID_ELEMENT_TYPE.get(
                    StaticUtils.toHex(ecnElements[i].getType())));
      }
    }

    previousDN   = prevDN;
    changeNumber = chgNum;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public EntryChangeNotificationControl
              decodeControl(@NotNull final String oid, final boolean isCritical,
                            @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new EntryChangeNotificationControl(oid, isCritical, value);
  }



  /**
   * Extracts an entry change notification control from the provided search
   * result entry.
   *
   * @param  entry  The search result entry from which to retrieve the entry
   *                change notification control.
   *
   * @return  The entry change notification control contained in the provided
   *          search result entry, or {@code null} if the entry did not contain
   *          an entry change notification control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the entry change notification control
   *                         contained in the provided entry.
   */
  @Nullable()
  public static EntryChangeNotificationControl get(
                     @NotNull final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(ENTRY_CHANGE_NOTIFICATION_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof EntryChangeNotificationControl)
    {
      return (EntryChangeNotificationControl) c;
    }
    else
    {
      return new EntryChangeNotificationControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  changeType    The change type for the change.  It must not be
   *                       {@code null}.
   * @param  previousDN    The previous DN of the entry, if applicable.
   * @param  changeNumber  The change number to include in this control, or
   *                       -1 if there should not be a change number.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final PersistentSearchChangeType changeType,
               @Nullable final String previousDN, final long changeNumber)
  {
    Validator.ensureNotNull(changeType);

    final ArrayList<ASN1Element> elementList = new ArrayList<>(3);
    elementList.add(new ASN1Enumerated(changeType.intValue()));

    if (previousDN != null)
    {
      elementList.add(new ASN1OctetString(previousDN));
    }

    if (changeNumber > 0)
    {
      elementList.add(new ASN1Long(changeNumber));
    }

    return new ASN1OctetString(new ASN1Sequence(elementList).encode());
  }



  /**
   * Retrieves the change type for this entry change notification control.
   *
   * @return  The change type for this entry change notification control.
   */
  @NotNull()
  public PersistentSearchChangeType getChangeType()
  {
    return changeType;
  }



  /**
   * Retrieves the previous DN for the entry, if applicable.
   *
   * @return  The previous DN for the entry, or {@code null} if there is none.
   */
  @Nullable()
  public String getPreviousDN()
  {
    return previousDN;
  }



  /**
   * Retrieves the change number for the associated change, if available.
   *
   * @return  The change number for the associated change, or -1 if none was
   *          provided.
   */
  public long getChangeNumber()
  {
    return changeNumber;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ENTRY_CHANGE_NOTIFICATION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("EntryChangeNotificationControl(changeType=");
    buffer.append(changeType.getName());

    if (previousDN != null)
    {
      buffer.append(", previousDN='");
      buffer.append(previousDN);
      buffer.append('\'');
    }

    if (changeNumber > 0)
    {
      buffer.append(", changeNumber=");
      buffer.append(changeNumber);
    }

    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
