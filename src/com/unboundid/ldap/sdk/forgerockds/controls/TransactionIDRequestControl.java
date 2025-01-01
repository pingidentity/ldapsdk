/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.forgerockds.controls;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.forgerockds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control that can be used to
 * specify an external identifier for a request sent to a ForgeRock Directory
 * Server that will appear in the access log message for the associated
 * operation.
 * <BR>
 * This request control has an OID of 1.3.6.1.4.1.36733.2.1.5.1, and its value
 * is the string representation of the desired transaction ID.  The control is
 * typically not marked critical.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the transaction ID request
 * control:
 * <PRE>
 * ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
 *      new Modification(ModificationType.REPLACE, "attrName", "attrValue"));
 * modifyRequest.addControl(new TransactionIDRequestControl("test-txn-id"));
 * LDAPResult modifyResult = connection.modify(modifyRequest);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TransactionIDRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.36733.2.1.5.1) for the transaction ID request control.
   */
  @NotNull public static final String TRANSACTION_ID_REQUEST_OID =
       "1.3.6.1.4.1.36733.2.1.5.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7792760251213801179L;



  // The transaction ID to use for this control.
  @NotNull private final String transactionID;



  /**
   * Creates a new transaction ID request control with the specified identifier.
   * It will not be marked critical.
   *
   * @param  transactionID  The transaction ID to use for this control.  It must
   *                        not be {@code null}.
   */
  public TransactionIDRequestControl(@NotNull final String transactionID)
  {
    this(false, transactionID);
  }



  /**
   * Creates a new transaction ID request control with the specified identifier
   * and criticality.
   *
   * @param  isCritical     Indicates whether the control should be marked
   *                        critical.
   * @param  transactionID  The transaction ID to use for this control.  It must
   *                        not be {@code null}.
   */
  public TransactionIDRequestControl(final boolean isCritical,
                                     @NotNull final String transactionID)
  {
    super(TRANSACTION_ID_REQUEST_OID, isCritical,
         new ASN1OctetString(transactionID));

    this.transactionID = transactionID;
  }



  /**
   * Creates a new transaction ID request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a transaction ID
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         transaction ID request control.
   */
  public TransactionIDRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (! control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TRANSACTION_ID_REQUEST_MISSING_VALUE.get());
    }

    transactionID = control.getValue().stringValue();
  }



  /**
   * Retrieves the transaction ID to use for this control.
   *
   * @return  The transaction ID to use for this control.
   */
  @NotNull()
  public String getTransactionID()
  {
    return transactionID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_TRANSACTION_ID_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TransactionIDRequestControl(id='");
    buffer.append(transactionID);
    buffer.append("')");
  }
}
