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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;
import com.unboundid.ldap.sdk.controls.PreReadRequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartBatchedTransactionExtendedRequest;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of the batched transaction
 * specification request control, which may be used to indicate that the
 * associated add, delete, modify, modify DN, or password modify operation is
 * part of a batched transaction.  The transaction should be created with the
 * start batched transaction extended operation, which will obtain a transaction
 * ID, and the transaction may be committed or aborted using the end batched
 * transaction extended operation.
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
 * Note that directory servers may limit the set of controls that are available
 * for use in requests that are part of a transaction.  RFC 5805 section 4
 * indicates that the following controls may be used in conjunction with the
 * transaction specification request control:  {@link AssertionRequestControl},
 * {@link ManageDsaITRequestControl}, {@link PreReadRequestControl}, and
 * {@link PostReadRequestControl}.  The
 * {@link ProxiedAuthorizationV1RequestControl} and
 * {@link ProxiedAuthorizationV2RequestControl} controls cannot be included in
 * requests that are part of a transaction, but you can include them in the
 * {@link StartBatchedTransactionExtendedRequest} to indicate that all
 * operations within the transaction should be processed with the specified
 * authorization identity.
 * <BR><BR>
 * The Ping Identity, UnboundID, and Nokia/Alcatel-Lucent 8661 server products
 * support the following additional UnboundID-specific controls in conjunction
 * with operations included in a transaction:
 * {@link AccountUsableRequestControl}, {@link HardDeleteRequestControl},
 * {@link IntermediateClientRequestControl},
 * {@link PasswordPolicyRequestControl},
 * {@link ReplicationRepairRequestControl}, {@link SoftDeleteRequestControl},
 * {@link SoftDeletedEntryAccessRequestControl},
 * {@link SubtreeDeleteRequestControl}, and {@link UndeleteRequestControl}.
 * <BR><BR>
 * See the documentation for the {@link StartBatchedTransactionExtendedRequest}
 * class for an example of processing a batched transaction.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BatchedTransactionSpecificationRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.1) for the batched transaction specification
   * request control.
   */
  @NotNull public static final String
       BATCHED_TRANSACTION_SPECIFICATION_REQUEST_OID =
            "1.3.6.1.4.1.30221.2.5.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6817702055586260189L;



  // The transaction ID for the associated transaction.
  @NotNull private final ASN1OctetString transactionID;



  /**
   * Creates a new batched transaction specification request control with the
   * provided transaction ID.
   *
   * @param  transactionID  The transaction ID for the associated transaction,
   *                        as obtained from the start batched transaction
   *                        extended operation.  It must not be {@code null}.
   */
  public BatchedTransactionSpecificationRequestControl(
              @NotNull final ASN1OctetString transactionID)
  {
    super(BATCHED_TRANSACTION_SPECIFICATION_REQUEST_OID, true,
         new ASN1OctetString(transactionID.getValue()));

    this.transactionID = transactionID;
  }



  /**
   * Creates a new batched transaction specification request control which is
   * decoded from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a batched transaction
   *                  specification request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         batched transaction specification request control.
   */
  public BatchedTransactionSpecificationRequestControl(
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
    return INFO_CONTROL_NAME_BATCHED_TXN_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("BatchedTransactionSpecificationRequestControl(" +
                  "transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("')");
  }
}
