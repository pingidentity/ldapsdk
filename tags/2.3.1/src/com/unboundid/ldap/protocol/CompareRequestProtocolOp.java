/*
 * Copyright 2009-2012 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2012 UnboundID Corp.
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
package com.unboundid.ldap.protocol;



import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of an LDAP compare request protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CompareRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -562642367801440060L;



  // The assertion value for this compare request.
  private final ASN1OctetString assertionValue;

  // The attribute name for this compare request.
  private final String attributeName;

  // The entry DN for this compare request.
  private final String dn;



  /**
   * Creates a new compare request protocol op with the provided information.
   *
   * @param  dn              The DN for this compare request.
   * @param  attributeName   The attribute name for this compare request.
   * @param  assertionValue  The assertion value for this compare request.
   */
  public CompareRequestProtocolOp(final String dn, final String attributeName,
                                  final ASN1OctetString assertionValue)
  {
    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = assertionValue;
  }



  /**
   * Creates a new compare request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the compare
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         compare request.
   */
  CompareRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      dn = reader.readString();

      reader.beginSequence();
      attributeName = reader.readString();
      assertionValue = new ASN1OctetString(reader.readBytes());
      ensureNotNull(dn, attributeName, assertionValue);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_COMPARE_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the DN for this compare request.
   *
   * @return  The DN for this compare request.
   */
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the attribute name for this compare request.
   *
   * @return  The attribute name for this compare request.
   */
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Retrieves the assertion value for this compare request.
   *
   * @return  The assertion value for this compare request.
   */
  public ASN1OctetString getAssertionValue()
  {
    return assertionValue;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence avaSequence = buffer.beginSequence();
    buffer.addOctetString(attributeName);
    buffer.addElement(assertionValue);
    avaSequence.end();
    opSequence.end();
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("CompareRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', attributeName='");
    buffer.append(attributeName);
    buffer.append("', assertionValue='");
    buffer.append(assertionValue.stringValue());
    buffer.append("')");
  }
}
