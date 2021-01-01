/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
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

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be included in a search
 * request to indicate that soft-deleted entries may be included in the results,
 * or it may be included in a compare or modify request to indicate that the
 * operation should operate against the target entry even if it is a
 * soft-deleted entry.
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
 * The criticality for this control may be either {@code TRUE} or {@code FALSE},
 * but this will only impact how the delete request is to be handled by servers
 * which do not support this control.  A criticality of {@code TRUE} will cause
 * any server which does not support this control to reject the request, while
 * a criticality of {@code FALSE} should cause the request to be processed as if
 * the control had not been included.
 * <BR><BR>
 * The control may optionally have a value.  If a value is provided, then it
 * must be the encoded representation of the following ASN.1 element:
 * <PRE>
 *   SoftDeleteAccessRequestValue ::= SEQUENCE {
 *     includeNonSoftDeletedEntries     [0] BOOLEAN DEFAULT TRUE,
 *     returnEntriesInUndeletedForm     [1] BOOLEAN DEFAULT FALSE,
 *     ... }
 * </PRE>
 * See the documentation for the {@link SoftDeleteRequestControl} class for an
 * example demonstrating the use of this control.
 *
 * @see  SoftDeleteResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SoftDeletedEntryAccessRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.24) for the soft-deleted entry access
   * request control.
   */
  @NotNull public static final String SOFT_DELETED_ENTRY_ACCESS_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.24";



  /**
   * The BER type for the include non-soft-deleted entries element.
   */
  private static final byte TYPE_INCLUDE_NON_SOFT_DELETED_ENTRIES = (byte) 0x80;



  /**
   * The BER type for the return entries in undeleted form element.
   */
  private static final byte TYPE_RETURN_ENTRIES_IN_UNDELETED_FORM = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3633807543861389512L;



  // Indicates whether to include non-soft-deleted entries in search results.
  private final boolean includeNonSoftDeletedEntries;

  // Indicates whether to return soft-deleted entries in the form they appeared
  // before they were deleted.
  private final boolean returnEntriesInUndeletedForm;



  /**
   * Creates a new soft-deleted entry access request control with the default
   * settings for all elements.  It will not be marked critical.
   */
  public SoftDeletedEntryAccessRequestControl()
  {
    this(false, true, false);
  }



  /**
   * Creates a new soft delete request control with the provided information.
   *
   * @param  isCritical                    Indicates whether this control should
   *                                       be marked critical.  This will only
   *                                       have an effect on the way the
   *                                       associated delete operation is
   *                                       handled by servers which do NOT
   *                                       support the soft-deleted entry access
   *                                       request control.  For such servers, a
   *                                       control that is critical will cause
   *                                       associated request to be rejected,
   *                                       while a control that is not critical
   *                                       will be processed as if the control
   *                                       was not included in the request.
   * @param  includeNonSoftDeletedEntries  Indicates whether search results
   *                                       should include non-soft-deleted
   *                                       entries if they match the criteria
   *                                       for the associated search request.
   * @param  returnEntriesInUndeletedForm  Indicates whether soft-deleted
   *                                       entries returned in search results
   *                                       should be returned in the form in
   *                                       which they would appear if they were
   *                                       undeleted.  Note that if soft-deleted
   *                                       entries should be returned in their
   *                                       undeleted form, then it may be
   *                                       possible for multiple entries to be
   *                                       returned with the same DN (if
   *                                       multiple soft-deleted entries with
   *                                       the same original DN match the
   *                                       criteria, or if at least one
   *                                       soft-deleted entry and one normal
   *                                       entry with the same DN both match the
   *                                       search criteria).
   */
  public SoftDeletedEntryAccessRequestControl(final boolean isCritical,
              final boolean includeNonSoftDeletedEntries,
              final boolean returnEntriesInUndeletedForm)
  {
    super(SOFT_DELETED_ENTRY_ACCESS_REQUEST_OID, isCritical,
         encodeValue(includeNonSoftDeletedEntries,
              returnEntriesInUndeletedForm));

    this.includeNonSoftDeletedEntries = includeNonSoftDeletedEntries;
    this.returnEntriesInUndeletedForm = returnEntriesInUndeletedForm;
  }



  /**
   * Creates a new soft-deleted entry access request control which is decoded
   * from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a soft-deleted entry
   *                  access request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         soft-deleted entry access request control.
   */
  public SoftDeletedEntryAccessRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    boolean includeNonSoftDeleted = true;
    boolean returnAsUndeleted     = false;

    if (control.hasValue())
    {
      try
      {
        final ASN1Sequence valueSequence =
             ASN1Sequence.decodeAsSequence(control.getValue().getValue());
        for (final ASN1Element e : valueSequence.elements())
        {
          switch (e.getType())
          {
            case TYPE_INCLUDE_NON_SOFT_DELETED_ENTRIES:
              includeNonSoftDeleted =
                   ASN1Boolean.decodeAsBoolean(e).booleanValue();
              break;
            case TYPE_RETURN_ENTRIES_IN_UNDELETED_FORM:
              returnAsUndeleted = ASN1Boolean.decodeAsBoolean(e).booleanValue();
              break;
            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SOFT_DELETED_ACCESS_REQUEST_UNSUPPORTED_ELEMENT_TYPE.get(
                        StaticUtils.toHex(e.getType())));
          }
        }
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
             ERR_SOFT_DELETED_ACCESS_REQUEST_CANNOT_DECODE_VALUE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    includeNonSoftDeletedEntries = includeNonSoftDeleted;
    returnEntriesInUndeletedForm = returnAsUndeleted;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of a soft-deleted entry access request control.
   *
   * @param  includeNonSoftDeletedEntries  Indicates whether search results
   *                                       should include non-soft-deleted
   *                                       entries if they match the criteria
   *                                       for the associated search request.
   * @param  returnEntriesInUndeletedForm  Indicates whether soft-deleted
   *                                       entries returned in search results
   *                                       should be returned in the form in
   *                                       which they would appear if they were
   *                                       undeleted.  Note that if soft-deleted
   *                                       entries should be returned in their
   *                                       undeleted form, then it may be
   *                                       possible for multiple entries to be
   *                                       returned with the same DN (if
   *                                       multiple soft-deleted entries with
   *                                       the same original DN match the
   *                                       criteria, or if at least one
   *                                       soft-deleted entry and one normal
   *                                       entry with the same DN both match the
   *                                       search criteria).
   *
   * @return  An ASN.1 octet string with an encoding suitable for use as the
   *          value of a soft-deleted entry access request control, or
   *          {@code null} if no value is needed for the control.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
                      final boolean includeNonSoftDeletedEntries,
                      final boolean returnEntriesInUndeletedForm)
  {
    if (includeNonSoftDeletedEntries && (! returnEntriesInUndeletedForm))
    {
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(2);
    if (! includeNonSoftDeletedEntries)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_NON_SOFT_DELETED_ENTRIES,
           false));
    }

    if (returnEntriesInUndeletedForm)
    {
      elements.add(new ASN1Boolean(TYPE_RETURN_ENTRIES_IN_UNDELETED_FORM,
           true));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Indicates whether search results should include non-soft-deleted entries
   * if they match the criteria for the associated search request.
   *
   * @return  {@code true} if the server should return any "normal"
   *          non-soft-deleted entries that match the search criteria, or
   *          {@code false} if the server should only return soft-deleted
   *          entries that match the search criteria.
   */
  public boolean includeNonSoftDeletedEntries()
  {
    return includeNonSoftDeletedEntries;
  }



  /**
   * Indicates whether soft-deleted entries returned in search results should be
   * returned in the form in which they would appear if they were undeleted.
   * Note that if soft-deleted entries should be returned in their undeleted
   * form, then it may be possible for multiple entries to be returned with the
   * same DN (if multiple soft-deleted entries with the same original DN match
   * the criteria, or if at least one soft-deleted entry and one normal entry
   * with the same DN both match the search criteria).
   *
   * @return  {@code false} if soft-deleted entries should be returned in their
   *          current form as soft-deleted entries, or {@code true} if they
   *          should be returned in the form in which they would appear if they
   *          were undeleted (e.g., using the original DN for the entry and
   *          without all the additional meta-attributes added during the
   *          soft delete process).
   */
  public boolean returnEntriesInUndeletedForm()
  {
    return returnEntriesInUndeletedForm;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SOFT_DELETED_ACCESS_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SoftDeletedEntryAccessRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", includeNonSoftDeletedEntries=");
    buffer.append(includeNonSoftDeletedEntries);
    buffer.append(", returnEntriesInUndeletedForm=");
    buffer.append(returnEntriesInUndeletedForm);
    buffer.append(')');
  }
}
