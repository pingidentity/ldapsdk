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
package com.unboundid.ldap.sdk.extensions;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.TransactionSpecificationRequestControl;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the start transaction extended
 * request as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc5805.txt">RFC 5805</A>.  It may be used
 * to begin a transaction that allows multiple write operations to be processed
 * as a single atomic unit.  The {@link StartTransactionExtendedResult} that is
 * returned will include a transaction ID.  For each operation that is performed
 * as part of the transaction, this transaction ID should be included in the
 * corresponding request through the
 * {@link TransactionSpecificationRequestControl}.  Finally, after all requests
 * for the transaction have been submitted to the server, the
 * {@link EndTransactionExtendedRequest} should be used to commit that
 * transaction, or it may also be used to abort the transaction if it is decided
 * that it is no longer needed.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for using LDAP  transactions.
 * It will modify two different entries as a single atomic unit.
 * <PRE>
 * // Use the start transaction extended operation to begin a transaction.
 * StartTransactionExtendedResult startTxnResult;
 * try
 * {
 *   startTxnResult = (StartTransactionExtendedResult)
 *        connection.processExtendedOperation(
 *             new StartTransactionExtendedRequest());
 *   // This doesn't necessarily mean that the operation was successful, since
 *   // some kinds of extended operations return non-success results under
 *   // normal conditions.
 * }
 * catch (LDAPException le)
 * {
 *   // For an extended operation, this generally means that a problem was
 *   // encountered while trying to send the request or read the result.
 *   startTxnResult = new StartTransactionExtendedResult(
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
 *        new TransactionSpecificationRequestControl(txnID));
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
 *        new TransactionSpecificationRequestControl(txnID));
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
 *   EndTransactionExtendedResult endTxnResult;
 *   try
 *   {
 *     endTxnResult = (EndTransactionExtendedResult)
 *          connection.processExtendedOperation(
 *               new EndTransactionExtendedRequest(txnID, commit));
 *   }
 *   catch (LDAPException le)
 *   {
 *     endTxnResult = new EndTransactionExtendedResult(new ExtendedResult(le));
 *   }
 *   LDAPTestUtils.assertResultCodeEquals(endTxnResult, ResultCode.SUCCESS);
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartTransactionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.1.21.1) for the start transaction extended request.
   */
  @NotNull public static final String START_TRANSACTION_REQUEST_OID =
       "1.3.6.1.1.21.1";


  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7382735226826929629L;



  /**
   * Creates a new start transaction extended request.
   */
  public StartTransactionExtendedRequest()
  {
    super(START_TRANSACTION_REQUEST_OID);
  }



  /**
   * Creates a new start transaction extended request.
   *
   * @param  controls  The set of controls to include in the request.
   */
  public StartTransactionExtendedRequest(@Nullable final Control[] controls)
  {
    super(START_TRANSACTION_REQUEST_OID, controls);
  }



  /**
   * Creates a new start transaction extended request from the provided generic
   * extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          start transaction extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public StartTransactionExtendedRequest(
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
  public StartTransactionExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new StartTransactionExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartTransactionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartTransactionExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final StartTransactionExtendedRequest r =
         new StartTransactionExtendedRequest(controls);
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
    return INFO_EXTENDED_REQUEST_NAME_START_TXN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("StartTransactionExtendedRequest(");

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
