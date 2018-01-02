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
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartInteractiveTransactionExtendedRequest;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class defines an interactive transaction specification response control,
 * which will be included in the server's response to an operation that included
 * the {@link InteractiveTransactionSpecificationRequestControl}.
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
 * It provides information about the state of the transaction, which may
 * include:
 * <UL>
 *   <LI><CODE>transactionValid</CODE> -- Indicates whether the transaction is
 *       still valid in the server.  This should be checked if the associated
 *       operation did not complete successfully.</LI>
 *   <LI><CODE>baseDNs</CODE> -- This may specify the set of base DNs below
 *       which the client is allowed to request operations as part of this
 *       transaction.  It may be absent if there are no restrictions on which
 *       base DNs may be used, or if it has not changed since the last
 *       response within this transaction.</LI>
 * </UL>
 * See the documentation in the
 * {@link StartInteractiveTransactionExtendedRequest} class for an example of
 * processing interactive transactions.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InteractiveTransactionSpecificationResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.4) for the interactive transaction
   * specification response control.
   */
  public static final String
       INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.4";



  /**
   * The BER type for the {@code transactionValid} element of the control value.
   */
  private static final byte TYPE_TXN_VALID = (byte) 0x80;



  /**
   * The BER type for the {@code baseDNs} element of the control value.
   */
  private static final byte TYPE_BASE_DNS = (byte) 0xA1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4323085263241417543L;



  // The flag that indicates whether the associated transaction is still valid.
  private final boolean transactionValid;

  // The set of base DNs that may be targeted by this transaction.
  private final List<String> baseDNs;



  // This is an ugly hack to prevent checkstyle from complaining about imports
  // for classes that are needed by javadoc @link elements but aren't otherwise
  // used in the class.  It appears that checkstyle does not recognize the use
  // of these classes in javadoc @link elements so we must ensure that they are
  // referenced elsewhere in the class to prevent checkstyle from complaining.
  static
  {
    final StartInteractiveTransactionExtendedRequest r = null;
  }



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  InteractiveTransactionSpecificationResponseControl()
  {
    transactionValid = false;
    baseDNs          = null;
  }



  /**
   * Creates a new interactive transaction specification response control with
   * the provided information.  It will not be marked critical.
   *
   * @param  transactionValid  Indicates whether the associated transaction is
   *                           still valid.
   * @param  baseDNs           The set of base DNs that may be targeted over the
   *                           course of the transaction.  It may be
   *                           {@code null} if there are no restrictions or the
   *                           set of restrictions has not changed since the
   *                           last response.
   */
  public InteractiveTransactionSpecificationResponseControl(
              final boolean transactionValid, final List<String> baseDNs)
  {
    super(INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID, false,
          encodeValue(transactionValid, baseDNs));

    this.transactionValid = transactionValid;

    if (baseDNs == null)
    {
      this.baseDNs = null;
    }
    else
    {
      this.baseDNs =
           Collections.unmodifiableList(new ArrayList<String>(baseDNs));
    }
  }



  /**
   * Creates a new interactive transaction specification response control with
   * the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         interactive transaction specification response
   *                         control.
   */
  public InteractiveTransactionSpecificationResponseControl(final String oid,
              final boolean isCritical, final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_INT_TXN_RESPONSE_NO_VALUE.get());
    }

    final ASN1Element[] elements;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      elements = ASN1Sequence.decodeAsSequence(valueElement).elements();
    }
    catch (final Exception e)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_INT_TXN_RESPONSE_VALUE_NOT_SEQUENCE.get(
                                   e.getMessage()), e);
    }

    Boolean isValid = null;
    List<String> baseDNList = null;

    for (final ASN1Element element : elements)
    {
      switch (element.getType())
      {
        case TYPE_TXN_VALID:
          try
          {
            isValid = ASN1Boolean.decodeAsBoolean(element).booleanValue();
          }
          catch (final Exception e)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_INT_TXN_RESPONSE_TXN_VALID_NOT_BOOLEAN.get(e.getMessage()),
                 e);
          }
          break;
        case TYPE_BASE_DNS:
          try
          {
            final ASN1Sequence s = ASN1Sequence.decodeAsSequence(element);
            baseDNList = new ArrayList<String>(s.elements().length);
            for (final ASN1Element e : s.elements())
            {
              baseDNList.add(
                   ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
          }
          catch (final Exception e)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_INT_TXN_RESPONSE_BASE_DNS_NOT_SEQUENCE.get(e.getMessage()),
                 e);
          }
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_INT_TXN_RESPONSE_INVALID_ELEMENT_TYPE.get(
                                       toHex(element.getType())));
      }
    }

    if (isValid == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_INT_TXN_RESPONSE_NO_TXN_VALID.get());
    }

    transactionValid = isValid;

    if (baseDNList == null)
    {
      baseDNs = null;
    }
    else
    {
      baseDNs = Collections.unmodifiableList(baseDNList);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this control.
   *
   * @param  transactionValid  Indicates whether the associated transaction is
   *                           still valid.
   * @param  baseDNs           The set of base DNs that may be targeted over the
   *                           course of the transaction.  It may be
   *                           {@code null} if there are no restrictions or the
   *                           set of restrictions has not changed since the
   *                           last response.
   *
   * @return  The ASN1 octet string that may be used as the control value.
   */
  private static ASN1OctetString encodeValue(final boolean transactionValid,
                                             final List<String> baseDNs)
  {
    final ASN1Element[] elements;
    if (baseDNs == null)
    {
      elements = new ASN1Element[]
      {
        new ASN1Boolean(TYPE_TXN_VALID, transactionValid)
      };
    }
    else
    {
      final ASN1Element[] baseDNElements = new ASN1Element[baseDNs.size()];
      for (int i=0; i < baseDNElements.length; i++)
      {
        baseDNElements[i] = new ASN1OctetString(baseDNs.get(i));
      }

      elements = new ASN1Element[]
      {
        new ASN1Boolean(TYPE_TXN_VALID, transactionValid),
        new ASN1Sequence(TYPE_BASE_DNS, baseDNElements)
      };
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public InteractiveTransactionSpecificationResponseControl decodeControl(
              final String oid, final boolean isCritical,
              final ASN1OctetString value)
          throws LDAPException
  {
    return new InteractiveTransactionSpecificationResponseControl(oid,
                    isCritical, value);
  }



  /**
   * Extracts an interactive transaction specification response control from the
   * provided result.
   *
   * @param  result  The result from which to retrieve the interactive
   *                 transaction specification response control.
   *
   * @return  The interactive transaction specification response control
   *          contained in the provided result, or {@code null} if the result
   *          did not contain an interactive transaction specification response
   *          control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the interactive transaction specification
   *                         response control contained in the provided result.
   */
  public static InteractiveTransactionSpecificationResponseControl
                     get(final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(
         INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof InteractiveTransactionSpecificationResponseControl)
    {
      return (InteractiveTransactionSpecificationResponseControl) c;
    }
    else
    {
      return new InteractiveTransactionSpecificationResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Indicates whether the associated transaction is still valid on the server.
   *
   * @return  {@code true} if the associated transaction is still valid on the
   *          server and may be used for future operations, or {@code false} if
   *          the transaction has been aborted and may no longer be used.
   */
  public boolean transactionValid()
  {
    return transactionValid;
  }



  /**
   * Retrieves the set of base DNs below which operations which are part of the
   * transaction may be performed.
   *
   * @return  The set of base DNs below which operations may be performed as
   *          part of the transaction, or {@code null} if there are no
   *          restrictions or if the set of restrictions has not changed since
   *          the last response.
   */
  public List<String> getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_INTERACTIVE_TXN_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InteractiveTransactionSpecificationResponseControl(");
    buffer.append("transactionValid=");
    buffer.append(transactionValid);
    buffer.append(", baseDNs=");
    if (baseDNs == null)
    {
      buffer.append("null");
    }
    else
    {
      buffer.append('{');
      for (int i=0; i < baseDNs.size(); i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(baseDNs.get(i));
        buffer.append('\'');
      }
      buffer.append('}');
    }

    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
