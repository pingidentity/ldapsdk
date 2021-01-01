/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
 * This class provides an implementation of a control which may be used to
 * process an add, delete, modify, or modify DN operation in the Directory
 * Server which will not be replicated to other servers.  This control is
 * primarily intended for use in manually resolving replication conflicts.
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
 * This request control has an OID of 1.3.6.1.4.1.30221.1.5.2 and a criticality
 * of true.  It does not have a value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the replication repair request
 * control:
 * <PRE>
 * ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
 *      new Modification(ModificationType.REPLACE, "attrName", "attrValue"));
 * modifyRequest.addControl(new ReplicationRepairRequestControl());
 * LDAPResult modifyResult = connection.modify(modifyRequest);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplicationRepairRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.1.5.2) for the replication repair request
   * control.
   */
  @NotNull public static final String REPLICATION_REPAIR_REQUEST_OID =
       "1.3.6.1.4.1.30221.1.5.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8036161025439278805L;



  /**
   * Creates a new replication repair request control.  It will be marked
   * critical.
   */
  public ReplicationRepairRequestControl()
  {
    super(REPLICATION_REPAIR_REQUEST_OID, true, null);
  }



  /**
   * Creates a new replication repair request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a replication repair
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         replication repair request control.
   */
  public ReplicationRepairRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_REPLICATION_REPAIR_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_REPLICATION_REPAIR_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ReplicationRepairRequestControl()");
  }
}
