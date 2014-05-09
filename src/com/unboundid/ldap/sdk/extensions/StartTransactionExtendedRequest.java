/*
 * Copyright 2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010 UnboundID Corp.
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the start transaction extended
 * request as defined in RFC 5805.  It may be used to begin a transaction that
 * allows multiple write operations to be processed as a single atomic unit.
 * The {@link StartTransactionExtendedResult} that is returned will include a
 * transaction ID.  For each operation that is performed as part of the
 * transaction, this transaction ID should be included in the corresponding
 * request through the {@link TransactionSpecificationRequestControl}.
 * Finally, after all requests for the transaction have been submitted to the
 * server, the {@link EndTransactionExtendedRequest} should be used to commit
 * that transaction, or it may also be used to abort the transaction if it is
 * decided that it is no longer needed.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for using LDAP  transactions.
 * It will modify two different entries as a single atomic unit.  In each case,
 * it will use the post-read control to retrieve a copy of the updated entry.
 * <PRE>
 *   // Send the start transaction operation and get the transaction ID.
 *   StartTransactionExtendedRequest startTxnRequest =
 *        new StartTransactionExtendedRequest();
 *   StartTransactionExtendedResult startTxnResult =
 *        (StartTransactionExtendedResult)
 *        connection.processExtendedOperation(startTxnRequest);
 *   if (startTxnResult.getResultCode() != ResultCode.SUCCESS)
 *   {
 *     throw new LDAPException(startTxnResult);
 *   }
 *   ASN1OctetString txnID = startTxnResult.getTransactionID();
 *
 *   // At this point, we have a transaction available for use.  If any error
 *   // occurs, we will want to make sure that the transaction is aborted, so
 *   // use a try/finally block to handle that.
 *   boolean shouldAbort = true;
 *   try
 *   {
 *     // Create and send the first modify request as part of the transaction.
 *     // Make sure to include the transaction specification control and the
 *     // post-read request control in the modify request.
 *     ModifyRequest modifyRequest1 = new ModifyRequest(
 *          "cn=first,dc=example,dc=com",
 *          new Modification(ModificationType.REPLACE, "description", "first");
 *     modifyRequest1.addControl(new TransactionSpecificationControl(txnID));
 *     modifyRequest1.addControl(new PostReadRequestControl());
 *     LDAPResult modifyResult1 = connection.modify(modifyRequest1);
 *
 *     // Create and send the second modify request as part of the transaction.
 *     // Again, make sure to include the appropriate controls in the request.
 *     ModifyRequest modifyRequest2 = new ModifyRequest(
 *          "cn=second,dc=example,dc=com",
 *          new Modification(ModificationType.REPLACE, "description", "second");
 *     modifyRequest2.addControl(new TransactionSpecificationControl(txnID));
 *     modifyRequest2.addControl(new PostReadRequestControl());
 *     LDAPResult modifyResult2 = connection.modify(modifyRequest1);
 *
 *     // Now we're ready to commit, which we can do with the end transaction
 *     // request with the commit flag set to true.
 *     EndTransactionExtendedRequest commitRequest =
 *          new EndTransactionExtendedRequest(txnID, true);
 *     EndTransactionExtendedResult commitResult =
 *          (EndTransactionExtendedResult)
 *          connection.processExtendedOperation(commitRequest);
 *     if (commitResult.getResultCode() == ResultCode.SUCCESS)
 *     {
 *       System.out.println("The transaction was committed successfully.");
 *
 *       // Everything was successful, so we don't need to abort anything.
 *       shouldAbort = false;
 *
 *       // Get the post-read response control for the first modify operation.
 *       // It's the same process for the second, but this example is already
 *       // long enough so we'll skip it.
 *       Control[] controls = commitResult.getOperationResponseControls(
 *            modifyResult1.getMessageID());
 *       if (controls != null)
 *       {
 *         for (Control c : controls)
 *         {
 *           if (c instanceof PostReadResponseControl)
 *           {
 *             PostReadResponseControl postReadResponse =
 *                  (PostReadResponseControl) c;
 *             System.out.println("First entry after the modification:");
 *             System.out.println(postReadResponse.getEntry().toLDIFString());
 *           }
 *         }
 *       }
 *     }
 *     else
 *     {
 *       // The transaction failed for some reason.  The response should tell us
 *       // whether it failed because of one of the operations.
 *       int failedOpMessageID = commitResult.getFailedOpMessageID();
 *       if (failedOpMessageID == modifyResult1.getMessageID())
 *       {
 *         System.err.println("The transaction failed because of a failure " +
 *              "encountered while processing the first modification.");
 *       }
 *       else if (failedOpMessageID == modifyResult2.getMessageID())
 *       {
 *         System.err.println("The transaction failed because of a failure " +
 *              "encountered while processing the second modification.");
 *       }
 *       else
 *       {
 *         System.err.println("The transaction failed for some reason other " +
 *              "than either of the modify operations.");
 *       }
 *
 *       throw new LDAPException(commitResult);
 *     }
 *   }
 *   finally
 *   {
 *     if (shouldAbort)
 *     {
 *       // Setting the commit flag to false in the end transaction request will
 *       // will cause the transaction to be aborted rather than committed.
 *       EndTransactionExtendedRequest abortRequest =
 *             new EndTransactionExtendedRequest(txnID, false);
 *       connection.processExtendedOperation(abortRequest);
 *     }
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartTransactionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID for the start transaction extended request.
   */
  public static final String START_TRANSACTION_REQUEST_OID = "1.3.6.1.1.21.1";


  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7382735226826929629L;



  // This is an ugly hack to prevent checkstyle from complaining about imports
  // for classes that are needed by javadoc @link elements but aren't otherwise
  // used in the class.  It appears that checkstyle does not recognize the use
  // of these classes in javadoc @link elements so we must ensure that they are
  // referenced elsewhere in the class to prevent checkstyle from complaining.
  static
  {
    final TransactionSpecificationRequestControl c = null;
  }



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
  public StartTransactionExtendedRequest(final Control[] controls)
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
  public StartTransactionExtendedRequest(final ExtendedRequest extendedRequest)
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
  public StartTransactionExtendedResult process(
              final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new StartTransactionExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public StartTransactionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public StartTransactionExtendedRequest duplicate(final Control[] controls)
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
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_START_TXN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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
