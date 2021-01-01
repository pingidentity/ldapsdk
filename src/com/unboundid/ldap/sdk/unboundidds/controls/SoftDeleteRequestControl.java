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
import com.unboundid.ldap.sdk.DeleteRequest;
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
 * This class provides a request control which may be included in a delete
 * request to indicate that the server should perform a soft delete rather than
 * a hard delete.  A soft delete will leave the entry in the server, but will
 * mark it hidden so that it can only be retrieved with a special request
 * (e.g., one which includes the {@link SoftDeletedEntryAccessRequestControl} or
 * a filter which includes an "(objectClass=ds-soft-deleted-entry)" component).
 * A soft-deleted entry may later be undeleted (using an add request containing
 * the {@link UndeleteRequestControl}) in order to restore them with the same or
 * a different DN.
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
 * a criticality of {@code FALSE} should cause the delete request to be
 * processed as if the control had not been included (i.e., as a regular "hard"
 * delete).
 * <BR><BR>
 * The control may optionally have a value.  If a value is provided, then it
 * must be the encoded representation of the following ASN.1 element:
 * <PRE>
 *   SoftDeleteRequestValue ::= SEQUENCE {
 *     returnSoftDeleteResponse     [0] BOOLEAN DEFAULT TRUE,
 *     ... }
 * </PRE>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the soft delete request control
 * to remove the "uid=test,dc=example,dc=com" user with a soft delete operation,
 * and then to recover it with an undelete operation:
 * <PRE>
 * // Perform a search to verify that the test entry exists.
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("uid", "test"));
 * SearchResult searchResult = connection.search(searchRequest);
 * LDAPTestUtils.assertEntriesReturnedEquals(searchResult, 1);
 * String originalDN = searchResult.getSearchEntries().get(0).getDN();
 *
 * // Perform a soft delete against the entry.
 * DeleteRequest softDeleteRequest = new DeleteRequest(originalDN);
 * softDeleteRequest.addControl(new SoftDeleteRequestControl());
 * LDAPResult softDeleteResult = connection.delete(softDeleteRequest);
 *
 * // Verify that a soft delete response control was included in the result.
 * SoftDeleteResponseControl softDeleteResponseControl =
 *      SoftDeleteResponseControl.get(softDeleteResult);
 * String softDeletedDN = softDeleteResponseControl.getSoftDeletedEntryDN();
 *
 * // Verify that the original entry no longer exists.
 * LDAPTestUtils.assertEntryMissing(connection, originalDN);
 *
 * // Verify that the original search no longer returns any entries.
 * searchResult = connection.search(searchRequest);
 * LDAPTestUtils.assertNoEntriesReturned(searchResult);
 *
 * // Verify that the search will return an entry if we include the
 * // soft-deleted entry access control in the request.
 * searchRequest.addControl(new SoftDeletedEntryAccessRequestControl());
 * searchResult = connection.search(searchRequest);
 * LDAPTestUtils.assertEntriesReturnedEquals(searchResult, 1);
 *
 * // Perform an undelete operation to restore the entry.
 * AddRequest undeleteRequest = UndeleteRequestControl.createUndeleteRequest(
 *      originalDN, softDeletedDN);
 * LDAPResult undeleteResult = connection.add(undeleteRequest);
 *
 * // Verify that the original entry is back.
 * LDAPTestUtils.assertEntryExists(connection, originalDN);
 *
 * // Permanently remove the original entry with a hard delete.
 * DeleteRequest hardDeleteRequest = new DeleteRequest(originalDN);
 * hardDeleteRequest.addControl(new HardDeleteRequestControl());
 * LDAPResult hardDeleteResult = connection.delete(hardDeleteRequest);
 * </PRE>
 * Note that this class provides convenience methods that can be used to easily
 * create a delete request containing an appropriate soft delete request
 * control.  Similar methods can be found in the
 * {@link HardDeleteRequestControl} and {@link UndeleteRequestControl} classes
 * for creating appropriate hard delete and undelete requests, respectively.
 *
 * @see  HardDeleteRequestControl
 * @see  SoftDeleteResponseControl
 * @see  SoftDeletedEntryAccessRequestControl
 * @see  UndeleteRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SoftDeleteRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.20) for the soft delete request control.
   */
  @NotNull public static final String SOFT_DELETE_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.20";



  /**
   * The BER type for the return soft delete response element.
   */
  private static final byte TYPE_RETURN_SOFT_DELETE_RESPONSE = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4068029406430690545L;



  // Indicates whether to the response should include a soft delete response
  // control.
  private final boolean returnSoftDeleteResponse;



  /**
   * Creates a new soft delete request control with the default settings for
   * all elements.  It will be marked critical.
   */
  public SoftDeleteRequestControl()
  {
    this(true, true);
  }



  /**
   * Creates a new soft delete request control with the provided information.
   *
   * @param  isCritical                Indicates whether this control should be
   *                                   marked critical.  This will only have an
   *                                   effect on the way the associated delete
   *                                   operation is handled by servers which do
   *                                   NOT support the soft delete request
   *                                   control.  For such servers, a control
   *                                   that is critical will cause the soft
   *                                   delete attempt to fail, while a control
   *                                   that is not critical will be processed as
   *                                   if the control was not included in the
   *                                   request (i.e., as a normal "hard"
   *                                   delete).
   * @param  returnSoftDeleteResponse  Indicates whether to return a soft delete
   *                                   response control in the delete response
   *                                   to the client.
   */
  public SoftDeleteRequestControl(final boolean isCritical,
                                  final boolean returnSoftDeleteResponse)
  {
    super(SOFT_DELETE_REQUEST_OID, isCritical,
         encodeValue(returnSoftDeleteResponse));

    this.returnSoftDeleteResponse = returnSoftDeleteResponse;
  }



  /**
   * Creates a new soft delete request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a soft delete request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a soft
   *                         delete request control.
   */
  public SoftDeleteRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    boolean returnResponse = true;
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
            case TYPE_RETURN_SOFT_DELETE_RESPONSE:
              returnResponse = ASN1Boolean.decodeAsBoolean(e).booleanValue();
              break;
            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_SOFT_DELETE_REQUEST_UNSUPPORTED_VALUE_ELEMENT_TYPE.get(
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
             ERR_SOFT_DELETE_REQUEST_CANNOT_DECODE_VALUE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    returnSoftDeleteResponse = returnResponse;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of a soft delete request control.
   *
   * @param  returnSoftDeleteResponse  Indicates whether to return a soft delete
   *                                   response control in the delete response
   *                                   to the client.
   *
   * @return  An ASN.1 octet string with an encoding suitable for use as the
   *          value of a soft delete request control, or {@code null} if no
   *          value is needed for the control.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
                                      final boolean returnSoftDeleteResponse)
  {
    if (returnSoftDeleteResponse)
    {
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(1);
    elements.add(new ASN1Boolean(TYPE_RETURN_SOFT_DELETE_RESPONSE, false));
    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Indicates whether the delete response should include a
   * {@link SoftDeleteResponseControl}.
   *
   * @return  {@code true} if the delete response should include a soft delete
   *          response control, or {@code false} if not.
   */
  public boolean returnSoftDeleteResponse()
  {
    return returnSoftDeleteResponse;
  }



  /**
   * Creates a new delete request that may be used to soft delete the specified
   * target entry.
   *
   * @param  targetDN                  The DN of the entry to be soft deleted.
   * @param  isCritical                Indicates whether this control should be
   *                                   marked critical.  This will only have an
   *                                   effect on the way the associated delete
   *                                   operation is handled by servers which do
   *                                   NOT support the soft delete request
   *                                   control.  For such servers, a control
   *                                   that is critical will cause the soft
   *                                   delete attempt to fail, while a control
   *                                   that is not critical will be processed as
   *                                   if the control was not included in the
   *                                   request (i.e., as a normal "hard"
   *                                   delete).
   * @param  returnSoftDeleteResponse  Indicates whether to return a soft delete
   *                                   response control in the delete response
   *                                   to the client.
   *
   * @return  A delete request with the specified target DN and an appropriate
   *          soft delete request control.
   */
  @NotNull()
  public static DeleteRequest createSoftDeleteRequest(
              @NotNull final String targetDN,
              final boolean isCritical,
              final boolean returnSoftDeleteResponse)
  {
    final Control[] controls =
    {
      new SoftDeleteRequestControl(isCritical, returnSoftDeleteResponse)
    };

    return new DeleteRequest(targetDN, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SOFT_DELETE_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SoftDeleteRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", returnSoftDeleteResponse=");
    buffer.append(returnSoftDeleteResponse);
    buffer.append(')');
  }
}
