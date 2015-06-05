/*
 * Copyright 2007-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartBatchedTransactionExtendedRequest;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;
import static com.unboundid.util.Validator.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides an implementation of the batched transaction
 * specification request control, which may be used to indicate that the
 * associated add, delete, modify, modify DN, or password modify operation is
 * part of a batched transaction.  The transaction should be created with the
 * start batched transaction extended operation, which will obtain a transaction
 * ID, and the transaction may be committed or aborted using the end batched
 * transaction extended operation.
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
  public static final String BATCHED_TRANSACTION_SPECIFICATION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6817702055586260189L;



  // The transaction ID for the associated transaction.
  private final ASN1OctetString transactionID;



  // This is an ugly hack to prevent checkstyle from complaining about the
  // import for the StartBatchedTransactionExtendedRequest class.  It is used
  // by the @link element in the javadoc, but checkstyle apparently doesn't
  // recognize that so we just need to use it in some way in this class to
  // placate checkstyle.
  static
  {
    final StartBatchedTransactionExtendedRequest r = null;
  }



  /**
   * Creates a new batched transaction specification request control with the
   * provided transaction ID.
   *
   * @param  transactionID  The transaction ID for the associated transaction,
   *                        as obtained from the start batched transaction
   *                        extended operation.  It must not be {@code null}.
   */
  public BatchedTransactionSpecificationRequestControl(
              final ASN1OctetString transactionID)
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
  public BatchedTransactionSpecificationRequestControl(final Control control)
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
  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_BATCHED_TXN_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("BatchedTransactionSpecificationRequestControl(" +
                  "transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("')");
  }
}
