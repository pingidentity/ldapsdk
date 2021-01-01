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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be included in a delete
 * request to indicate that the server should completely remove the target
 * entry, even if it would otherwise process the operation as a soft delete and
 * merely hide the entry from most clients.
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
 * must be the encoded representation of an empty ASN.1 sequence, like:
 * <PRE>
 *   HardDeleteRequestValue ::= SEQUENCE {
 *     ... }
 * </PRE>
 * In the future, the value sequence may allow one or more elements to customize
 * the behavior of the hard delete operation, but at present no such elements
 * are defined.
 * See the documentation for the {@link SoftDeleteRequestControl} class for an
 * example demonstrating the use of this control.
 *
 * @see  SoftDeleteRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class HardDeleteRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.22) for the hard delete request control.
   */
  @NotNull public static final String HARD_DELETE_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.22";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1169625153021056712L;



  /**
   * Creates a new hard delete request control.  It will not be marked critical.
   */
  public HardDeleteRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new hard delete request control with the provided information.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.  This will only have an effect on the way the
   *                     associated delete operation is handled by servers which
   *                     do NOT support the hard delete request control.  For
   *                     such servers, a control that is critical will cause the
   *                     hard delete attempt to fail, while a control that is
   *                     not critical will be processed as if the control was
   *                     not included in the request (i.e., as a normal "hard"
   *                     delete).
   */
  public HardDeleteRequestControl(final boolean isCritical)
  {
    super(HARD_DELETE_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new hard delete request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a hard delete request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a hard
   *                         delete request control.
   */
  public HardDeleteRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      try
      {
        final ASN1Sequence valueSequence =
             ASN1Sequence.decodeAsSequence(control.getValue().getValue());
        final ASN1Element[] elements = valueSequence.elements();
        if (elements.length > 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_HARD_DELETE_REQUEST_UNSUPPORTED_VALUE_ELEMENT_TYPE.get(
                    StaticUtils.toHex(elements[0].getType())));
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
             ERR_HARD_DELETE_REQUEST_CANNOT_DECODE_VALUE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
  }



  /**
   * Creates a new delete request that may be used to hard delete the specified
   * target entry.
   *
   * @param  targetDN    The DN of the entry to be hard deleted.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.  This will only have an effect on the way the
   *                     associated delete operation is handled by servers which
   *                     do NOT support the hard delete request control.  For
   *                     such servers, a control that is critical will cause the
   *                     hard delete attempt to fail, while a control that is
   *                     not critical will be processed as if the control was
   *                     not included in the request (i.e., as a normal "hard"
   *                     delete).
   *
   * @return  A delete request with the specified target DN and an appropriate
   *          hard delete request control.
   */
  @NotNull()
  public static DeleteRequest createHardDeleteRequest(
                     @NotNull final String targetDN,
                     final boolean isCritical)
  {
    final Control[] controls =
    {
      new HardDeleteRequestControl(isCritical)
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
    return INFO_CONTROL_NAME_HARD_DELETE_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("HardDeleteRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
