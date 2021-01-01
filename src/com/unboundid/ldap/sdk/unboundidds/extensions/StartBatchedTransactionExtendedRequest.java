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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.AccountUsableRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            BatchedTransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyRequestControl;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the start batched transaction
 * extended request.  It may be used to begin a transaction that allows multiple
 * write operations to be processed as a single atomic unit.  The
 * {@link StartBatchedTransactionExtendedResult} that is returned will include a
 * a transaction ID.  For each operation that is performed as part of the
 * transaction, this transaction ID should be included in the corresponding
 * request through the {@link BatchedTransactionSpecificationRequestControl}.
 * Finally, after all requests for the transaction have been submitted to the
 * server, the {@link EndBatchedTransactionExtendedRequest} should be used to
 * commit that transaction, or it may also be used to abort the transaction if
 * it is decided that it is no longer needed.
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
 * Transactions processed using this mechanism are called "batched transactions"
 * because the associated requests are collected in the server and are only
 * processed once the {@link EndBatchedTransactionExtendedRequest} has been
 * received to indicate that the transaction should be committed.  As a result,
 * it is only possible to include write operations (in particular, add, delete,
 * modify, modify DN, and password modify operations) in a batched transaction.
 * Read operations (like search, bind, and compare) cannot be included in a
 * batched transaction.  However, it is possible to use some controls within the
 * transaction and they may prove to be sufficient in many cases.  The controls
 * that can be included in operations that are part of a batched transaction
 * include:
 * <UL>
 *   <LI>{@link AccountUsableRequestControl}</LI>
 *   <LI>{@link com.unboundid.ldap.sdk.controls.AssertionRequestControl}</LI>
 *   <LI>{@link IntermediateClientRequestControl}</LI>
 *   <LI>{@link com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl}</LI>
 *   <LI>{@link PasswordPolicyRequestControl}</LI>
 *   <LI>{@link com.unboundid.ldap.sdk.controls.PostReadRequestControl}</LI>
 *   <LI>{@link com.unboundid.ldap.sdk.controls.PreReadRequestControl}</LI>
 *   <LI>{@link SubtreeDeleteRequestControl}</LI>
 * </UL>
 * In particular, the assertion control may be used to ensure that an operation
 * is only performed if the target entry matches a given filter (which allows
 * for an atomic compare-and-swap operation), and the pre-read and post-read
 * controls may be used to retrieve a copy of an entry immediately before or
 * immediately after the operation was performed.
 * <BR><BR>
 * Note that even though the operations which are part of this transaction
 * aren't actually processed until the end batched transaction request is
 * received, the directory server will send back a response for each operation
 * that is to be performed as part of the transaction.  If the result of this
 * response is {@link ResultCode#SUCCESS}, then it means that the server has
 * accepted the operation and it will be processed when the end batched
 * transaction request is received indicating that the transaction should be
 * committed.  However, if it has some other result then it indicates that the
 * request may have been malformed or did not meet the requirements for the
 * transaction (e.g., it included a control that is not allowed for a
 * transaction).  Note that even if the server returns a non-success response
 * for an operation prior to the end batched transaction request, the
 * transaction will still be active in the server and other operations may still
 * be included in the transaction if desired.  If it is no longer desirable to
 * process the transaction, then the end batched transaction request should be
 * used to abort the transaction.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for using batched
 * transactions.  It will modify two different entries as a single atomic
 * unit.
 * <PRE>
 * // Use the start transaction extended operation to begin a transaction.
 * StartBatchedTransactionExtendedResult startTxnResult;
 * try
 * {
 *   startTxnResult = (StartBatchedTransactionExtendedResult)
 *        connection.processExtendedOperation(
 *             new StartBatchedTransactionExtendedRequest());
 *   // This doesn't necessarily mean that the operation was successful, since
 *   // some kinds of extended operations return non-success results under
 *   // normal conditions.
 * }
 * catch (LDAPException le)
 * {
 *   // For an extended operation, this generally means that a problem was
 *   // encountered while trying to send the request or read the result.
 *   startTxnResult = new StartBatchedTransactionExtendedResult(
 *        new ExtendedResult(le));
 * }
 * LDAPTestUtils.assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);
 * ASN1OctetString txnID = startTxnResult.getTransactionID();
 *
 *
 * // At this point, we have a transaction available for use.  If any problem
 * // arises, we want to ensure that the transaction is aborted, so create a
 * // try block to process the operations and a finally block to commit or
 * // abort the transaction.
 * boolean commit = false;
 * try
 * {
 *   // Create and process a modify operation to update a first entry as part
 *   // of the transaction.  Make sure to include the transaction specification
 *   // control in the request to indicate that it should be part of the
 *   // transaction.
 *   ModifyRequest firstModifyRequest = new ModifyRequest(
 *        "cn=first,dc=example,dc=com",
 *        new Modification(ModificationType.REPLACE, "description", "first"));
 *   firstModifyRequest.addControl(
 *        new BatchedTransactionSpecificationRequestControl(txnID));
 *   LDAPResult firstModifyResult;
 *   try
 *   {
 *     firstModifyResult = connection.modify(firstModifyRequest);
 *   }
 *   catch (LDAPException le)
 *   {
 *     firstModifyResult = le.toLDAPResult();
 *   }
 *   LDAPTestUtils.assertResultCodeEquals(firstModifyResult,
 *        ResultCode.SUCCESS);
 *
 *   // Perform a second modify operation as part of the transaction.
 *   ModifyRequest secondModifyRequest = new ModifyRequest(
 *        "cn=second,dc=example,dc=com",
 *        new Modification(ModificationType.REPLACE, "description", "second"));
 *   secondModifyRequest.addControl(
 *        new BatchedTransactionSpecificationRequestControl(txnID));
 *   LDAPResult secondModifyResult;
 *   try
 *   {
 *     secondModifyResult = connection.modify(secondModifyRequest);
 *   }
 *   catch (LDAPException le)
 *   {
 *     secondModifyResult = le.toLDAPResult();
 *   }
 *   LDAPTestUtils.assertResultCodeEquals(secondModifyResult,
 *        ResultCode.SUCCESS);
 *
 *   // If we've gotten here, then all writes have been processed successfully
 *   // and we can indicate that the transaction should be committed rather
 *   // than aborted.
 *   commit = true;
 * }
 * finally
 * {
 *   // Commit or abort the transaction.
 *   EndBatchedTransactionExtendedResult endTxnResult;
 *   try
 *   {
 *     endTxnResult = (EndBatchedTransactionExtendedResult)
 *          connection.processExtendedOperation(
 *               new EndBatchedTransactionExtendedRequest(txnID, commit));
 *   }
 *   catch (LDAPException le)
 *   {
 *     endTxnResult = new EndBatchedTransactionExtendedResult(
 *          new ExtendedResult(le));
 *   }
 *   LDAPTestUtils.assertResultCodeEquals(endTxnResult, ResultCode.SUCCESS);
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartBatchedTransactionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.1) for the start batched transaction
   * extended request.
   */
  @NotNull public static final String START_BATCHED_TRANSACTION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7141543268276702748L;



  /**
   * Creates a new start batched transaction extended request.
   */
  public StartBatchedTransactionExtendedRequest()
  {
    super(START_BATCHED_TRANSACTION_REQUEST_OID);
  }



  /**
   * Creates a new start batched transaction extended request.
   *
   * @param  controls  The set of controls to include in the request.
   */
  public StartBatchedTransactionExtendedRequest(
              @Nullable final Control[] controls)
  {
    super(START_BATCHED_TRANSACTION_REQUEST_OID, controls);
  }



  /**
   * Creates a new start batched transaction extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          start batched transaction extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public StartBatchedTransactionExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    if (extendedRequest.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_START_TXN_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartBatchedTransactionExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new StartBatchedTransactionExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartBatchedTransactionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartBatchedTransactionExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final StartBatchedTransactionExtendedRequest r =
         new StartBatchedTransactionExtendedRequest(controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_START_BATCHED_TXN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("StartBatchedTransactionExtendedRequest(");

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append("controls={");
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
