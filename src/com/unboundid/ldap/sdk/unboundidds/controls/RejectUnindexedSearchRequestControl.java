/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a request control that may be
 * included in a search request to indicate that the server should reject the
 * request if the server cannot use its defined indexes to identify matching
 * entries efficiently.  This can prevent a requester with the unindexed search
 * privilege from inadvertently submitting an expensive search request that
 * could require a long time to complete and potentially consume significant
 * server resources.  This request control has an OID of
 * "1.3.6.1.4.1.30221.2.5.54", may have a criticality of either true or false,
 * and does not take a value.
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
 *
 * @see  PermitUnindexedSearchRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RejectUnindexedSearchRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.54) for the reject unindexed search request
   * control.
   */
  @NotNull public static final String REJECT_UNINDEXED_SEARCH_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.54";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6331056590003014623L;



  /**
   * Creates a new reject unindexed search request control with a criticality of
   * {@code true}.
   */
  public RejectUnindexedSearchRequestControl()
  {
    this(true);
  }



  /**
   * Creates a new reject unindexed search request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   */
  public RejectUnindexedSearchRequestControl(final boolean isCritical)
  {
    super(REJECT_UNINDEXED_SEARCH_REQUEST_OID, isCritical);
  }



  /**
   * Creates a new reject unindexed search request control that is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a reject unindexed
   *                  search request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         reject unindexed search request control.
   */
  public RejectUnindexedSearchRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_REJECT_UNINDEXED_SEARCH_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_REJECT_UNINDEXED_SEARCH_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RejectUnindexedSearchRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
