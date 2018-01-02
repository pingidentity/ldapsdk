/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class represents an entry that holds information about a compare
 * operation processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00CompareEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The name of the attribute used to hold the encoded attribute value
   * assertion.
   */
  public static final String ATTR_ENCODED_ASSERTION = "reqAssertion";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7968358177150902271L;



  // The assertion value for the compare operation.
  private final ASN1OctetString assertionValue;

  // The attribute name for the compare operation.
  private final String attributeName;



  /**
   * Creates a new instance of this compare access log entry from the provided
   * entry.
   *
   * @param  entry  The entry used to create this compare access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         compare access log entry as per the specification
   *                         contained in draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00CompareEntry(final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.COMPARE);


    // Decode the attribute value assertion.
    final byte[] avaBytes =
         entry.getAttributeValueBytes(ATTR_ENCODED_ASSERTION);
    if (avaBytes == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_ENCODED_ASSERTION));
    }
    else
    {
      try
      {
        final ASN1Element[] elements =
             ASN1Sequence.decodeAsSequence(avaBytes).elements();
        attributeName =
             ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
        assertionValue = ASN1OctetString.decodeAsOctetString(elements[1]);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_COMPARE_AVA_ERROR.get(entry.getDN(),
                  ATTR_ENCODED_ASSERTION),
             e);
      }
    }
  }



  /**
   * Retrieves the attribute name for the compare request described by this
   * compare access log entry.
   *
   * @return  The attribute name for the compare request described by this
   *          compare access log entry.
   */
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Retrieves the string representation of the assertion value for the compare
   * request described by this compare access log entry.
   *
   * @return  The string representation of the assertion value for the compare
   *          request described by this compare access log entry.
   */
  public String getAssertionValueString()
  {
    return assertionValue.stringValue();
  }



  /**
   * Retrieves the bytes that comprise the assertion value for the compare
   * request described by this compare access log entry.
   *
   * @return  The bytes that comprise the assertion value for the compare
   *          request described by this compare access log entry.
   */
  public byte[] getAssertionValueBytes()
  {
    return assertionValue.getValue();
  }



  /**
   * Retrieves a {@code CompareRequest} created from this compare access log
   * entry.
   *
   * @return  The {@code CompareRequest} created from this compare access log
   *          entry.
   */
  public CompareRequest toCompareRequest()
  {
    return new CompareRequest(getTargetEntryDN(), attributeName,
         assertionValue.getValue(), getRequestControlArray());
  }
}
