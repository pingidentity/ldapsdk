/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.experimental.
            DraftBeheraLDAPPasswordPolicy10RequestControl;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the transaction specification
 * request control as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc5805.txt">RFC 5805</A>.  It may be used
 * to indicate that the associated add, delete, modify, modify DN, or password
 * modify operation is part of an LDAP transaction.  The transaction should be
 * created with the start transaction extended operation, which will obtain a
 * transaction ID, and the transaction may be committed or aborted using the end
 * transaction extended operation.
 * <BR><BR>
 * Note that directory servers may limit the set of controls that are available
 * for use in requests that are part of a transaction.  RFC 5805 section 4
 * indicates that the following controls may be used in conjunction with the
 * transaction specification request control:  {@link AssertionRequestControl},
 * {@link ManageDsaITRequestControl}, {@link PreReadRequestControl}, and
 * {@link PostReadRequestControl}.  The
 * {@link ProxiedAuthorizationV1RequestControl} and
 * {@link ProxiedAuthorizationV2RequestControl} controls cannot be included in
 * requests that are part of a transaction, but you can include them in the
 * {@link StartTransactionExtendedRequest} to indicate that all operations
 * within the transaction should be processed with the specified authorization
 * identity.
 * <BR><BR>
 * The Ping Identity, UnboundID, and Nokia/Alcatel-Lucent 8661 server products
 * support the following additional UnboundID-specific controls in conjunction
 * with operations included in a transaction:  account usable request control,
 * {@link DraftBeheraLDAPPasswordPolicy10RequestControl}, hard delete request
 * control, intermediate client request control, replication repair request
 * control, soft delete request control, soft deleted entry access request
 * control, {@link SubtreeDeleteRequestControl}, and undelete request control.
 * <BR><BR>
 * See the documentation for the {@link StartTransactionExtendedRequest} class
 * for an example of processing an LDAP transaction.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TransactionSpecificationRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.1.21.2) for the transaction specification request control.
   */
  @NotNull public static final String TRANSACTION_SPECIFICATION_REQUEST_OID =
       "1.3.6.1.1.21.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6489819774149849092L;



  // The transaction ID for the associated transaction.
  @NotNull private final ASN1OctetString transactionID;



  /**
   * Creates a new transaction specification request control with the provided
   * transaction ID.
   *
   * @param  transactionID  The transaction ID for the associated transaction,
   *                        as obtained from the start transaction extended
   *                        operation.  It must not be {@code null}.
   */
  public TransactionSpecificationRequestControl(
              @NotNull final ASN1OctetString transactionID)
  {
    super(TRANSACTION_SPECIFICATION_REQUEST_OID, true,
         new ASN1OctetString(transactionID.getValue()));

    Validator.ensureNotNull(transactionID);
    this.transactionID = transactionID;
  }



  /**
   * Creates a new transaction specification request control which is decoded
   * from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a transaction
   *                  specification request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         transaction specification request control.
   */
  public TransactionSpecificationRequestControl(
              @NotNull final Control control)
         throws LDAPException
  {
    super(control);

    transactionID = control.getValue();
    if (transactionID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TXN_REQUEST_CONTROL_NO_VALUE.get());
    }
  }



  /**
   * Retrieves the transaction ID for the associated transaction.
   *
   * @return  The transaction ID for the associated transaction.
   */
  @NotNull()
  public ASN1OctetString getTransactionID()
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
    return INFO_CONTROL_NAME_TXN_SPECIFICATION_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TransactionSpecificationRequestControl(transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("')");
  }
}
