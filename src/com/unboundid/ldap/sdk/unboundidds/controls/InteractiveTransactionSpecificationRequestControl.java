/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartInteractiveTransactionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartInteractiveTransactionExtendedResult;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of the interactive transaction
 * specification request control, which may be used to indicate that the
 * associated operation is part of an interactive transaction.  It may be used
 * in conjunction with add, compare, delete, modify, modify DN, and search
 * requests, as well as some types of extended requests.  The transaction should
 * be created with the start interactive transaction extended request, and the
 * end interactive transaction extended request may be used to commit or abort
 * the associated transaction.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The elements of the interactive transaction specification request control may
 * include:
 * <UL>
 *   <LI><CODE>txnID</CODE> -- The transaction ID for the transaction, which was
 *       obtained from a previous
 *       {@link StartInteractiveTransactionExtendedResult}.</LI>
 *   <LI><CODE>abortOnFailure</CODE> -- Indicates whether the transaction should
 *       be aborted if the request associated with this control does not
 *       complete successfully.</LI>
 *   <LI><CODE>writeLock</CODE> -- Indicates whether the target entry may be
 *       altered by this or a subsequent operation which is part of the
 *       transaction.  It should generally be {@code false} only for read
 *       operations in which it is known that the target entry will not be
 *       altered by a subsequent operation.</LI>
 * </UL>
 * See the documentation for the
 * {@link StartInteractiveTransactionExtendedRequest} class for an example of
 * processing an interactive transaction.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InteractiveTransactionSpecificationRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.4) for the interactive transaction
   * specification request control.
   */
  public static final String INTERACTIVE_TRANSACTION_SPECIFICATION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.4";



  /**
   * The BER type for the {@code txnID} element of the control value.
   */
  private static final byte TYPE_TXN_ID = (byte) 0x80;



  /**
   * The BER type for the {@code abortOnFailure} element of the control value.
   */
  private static final byte TYPE_ABORT_ON_FAILURE = (byte) 0x81;



  /**
   * The BER type for the {@code writeLock} element of the control value.
   */
  private static final byte TYPE_WRITE_LOCK = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6473934815135786621L;



  // The transaction ID for the associated transaction.
  private final ASN1OctetString transactionID;

  // Indicates whether the transaction should be aborted if the associated
  // operation does not complete successfully.
  private final boolean abortOnFailure;

  // Indicates whether the server should attempt to obtain a write lock on the
  // target entry if the associated operation is a read operation.
  private final boolean writeLock;



  // This is an ugly hack to prevent checkstyle from complaining about imports
  // for classes that are needed by javadoc @link elements but aren't otherwise
  // used in the class.  It appears that checkstyle does not recognize the use
  // of these classes in javadoc @link elements so we must ensure that they are
  // referenced elsewhere in the class to prevent checkstyle from complaining.
  static
  {
    final StartInteractiveTransactionExtendedRequest r1 = null;
    final StartInteractiveTransactionExtendedResult  r2 = null;
  }



  /**
   * Creates a new interactive transaction specification request control with
   * the provided transaction ID.  The server will attempt to keep the
   * transaction active in the event of a failure and will obtain write locks on
   * targeted entries.
   *
   * @param  transactionID   The transaction ID for the associated transaction,
   *                         as obtained from the start interactive transaction
   *                         extended operation.  It must not be {@code null}.
   */
  public InteractiveTransactionSpecificationRequestControl(
              final ASN1OctetString transactionID)
  {
    this(transactionID, false, true);
  }



  /**
   * Creates a new interactive transaction specification request control with
   * the provided information.
   *
   * @param  transactionID   The transaction ID for the associated transaction,
   *                         as obtained from the start interactive transaction
   *                         extended operation.  It must not be {@code null}.
   * @param  abortOnFailure  Indicates whether the transaction should be aborted
   *                         if the associated operation does not complete
   *                         successfully.
   * @param  writeLock       Indicates whether the server should attempt to
   *                         obtain a write lock on the target entry.  This
   *                         should only be {@code false} if the associated
   *                         operation is a search or compare and it is known
   *                         that the target entry will not be updated later in
   *                         the transaction.
   */
  public InteractiveTransactionSpecificationRequestControl(
              final ASN1OctetString transactionID, final boolean abortOnFailure,
              final boolean writeLock)
  {
    super(INTERACTIVE_TRANSACTION_SPECIFICATION_REQUEST_OID, true,
          encodeValue(transactionID, abortOnFailure, writeLock));

    this.transactionID  = transactionID;
    this.abortOnFailure = abortOnFailure;
    this.writeLock      = writeLock;
  }



  /**
   * Creates a new interactive transaction specification request control which
   * is decoded from the provided generic control.
   *
   * @param  control  The generic control to be decoded as an interactive
   *                  transaction specification request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         interactive transaction specification request
   *                         control.
   */
  public InteractiveTransactionSpecificationRequestControl(
              final Control control)
         throws LDAPException
  {
    super(control);

    if (! control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_INT_TXN_REQUEST_NO_VALUE.get());
    }

    final ASN1Element[] elements;
    try
    {
      final ASN1Element e = ASN1Element.decode(control.getValue().getValue());
      elements = ASN1Sequence.decodeAsSequence(e).elements();
    }
    catch (final Exception e)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_INT_TXN_REQUEST_VALUE_NOT_SEQUENCE.get(e.getMessage()), e);
    }

    ASN1OctetString txnID = null;
    boolean shouldAbortOnFailure = false;
    boolean shouldWriteLock = true;

    for (final ASN1Element element : elements)
    {
      switch (element.getType())
      {
        case TYPE_TXN_ID:
          txnID = ASN1OctetString.decodeAsOctetString(element);
          break;
        case TYPE_ABORT_ON_FAILURE:
          try
          {
            shouldAbortOnFailure =
                 ASN1Boolean.decodeAsBoolean(element).booleanValue();
          }
          catch (final Exception e)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_INT_TXN_REQUEST_ABORT_ON_FAILURE_NOT_BOOLEAN.get(
                      e.getMessage()), e);
          }
          break;
        case TYPE_WRITE_LOCK:
          try
          {
            shouldWriteLock =
                 ASN1Boolean.decodeAsBoolean(element).booleanValue();
          }
          catch (final Exception e)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_INT_TXN_REQUEST_WRITE_LOCK_NOT_BOOLEAN.get(e.getMessage()),
                 e);
          }
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_INT_TXN_REQUEST_INVALID_ELEMENT_TYPE.get(
                    toHex(element.getType())));
      }
    }

    if (txnID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_INT_TXN_REQUEST_NO_TXN_ID.get());
    }

    transactionID  = txnID;
    abortOnFailure = shouldAbortOnFailure;
    writeLock      = shouldWriteLock;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this control.
   *
   * @param  transactionID   The transaction ID for the associated transaction,
   *                         as obtained from the start interactive transaction
   *                         extended operation.  It must not be {@code null}.
   * @param  abortOnFailure  Indicates whether the transaction should be aborted
   *                         if the associated operation does not complete
   *                         successfully.
   * @param  writeLock       Indicates whether the server should attempt to
   *                         obtain a write lock on the target entry.  This
   *                         should only be {@code false} if the associated
   *                         operation is a search or compare and it is known
   *                         that the target entry will not be updated later in
   *                         the transaction.
   *
   * @return  The ASN.1 octet string containing the encoded value for this
   *          control.
   */
  private static ASN1OctetString encodeValue(
                 final ASN1OctetString transactionID,
                 final boolean abortOnFailure, final boolean writeLock)
  {
    ensureNotNull(transactionID);

    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);
    elements.add(new ASN1OctetString(TYPE_TXN_ID, transactionID.getValue()));

    if (abortOnFailure)
    {
      elements.add(new ASN1Boolean(TYPE_ABORT_ON_FAILURE, abortOnFailure));
    }

    if (! writeLock)
    {
      elements.add(new ASN1Boolean(TYPE_WRITE_LOCK, writeLock));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
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
   * Indicates whether the transaction should be aborted if the associated
   * operation does not complete successfully.
   *
   * @return  {@code true} if the transaction should be aborted if the
   *          associated operation does not complete successfully, or
   *          {@code false} if the server should attempt to keep the transaction
   *          active if the associated operation does not complete successfully.
   */
  public boolean abortOnFailure()
  {
    return abortOnFailure;
  }



  /**
   * Indicates whether the server should attempt to obtain a write lock on
   * entries targeted by the associated operation.
   *
   * @return  {@code true} if the server should attempt to obtain a write lock
   *          on entries targeted by the associated operation, or {@code false}
   *          if a read lock is acceptable as the entries are not expected to
   *          be altered later in the transaction.
   */
  public boolean writeLock()
  {
    return writeLock;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_INTERACTIVE_TXN_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InteractiveTransactionSpecificationRequestControl(" +
                  "transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("', abortOnFailure=");
    buffer.append(abortOnFailure);
    buffer.append(", writeLock=");
    buffer.append(writeLock);
    buffer.append(')');
  }
}
