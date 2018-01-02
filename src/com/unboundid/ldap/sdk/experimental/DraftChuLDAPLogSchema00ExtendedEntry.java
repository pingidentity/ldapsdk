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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class represents an entry that holds information about an extended
 * operation processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00ExtendedEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The name of the attribute used to hold the extended request value.
   */
  public static final String ATTR_REQUEST_VALUE = "reqData";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3767074068423424660L;



  // The request value, if available.
  private final ASN1OctetString requestValue;

  // The request OID.
  private final String requestOID;



  /**
   * Creates a new instance of this extended operation access log entry from the
   * provided entry.
   *
   * @param  entry  The entry used to create this extended operation access log
   *                entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         extended operation access log entry as per the
   *                         specification contained in
   *                         draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00ExtendedEntry(final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.EXTENDED);


    // The request OID is encoded in the request type.
    final String requestType = entry.getAttributeValue(ATTR_OPERATION_TYPE);
    final String lowerRequestType = StaticUtils.toLowerCase(requestType);
    if (lowerRequestType.startsWith("extended") &&
        (lowerRequestType.length() > 8))
    {
      requestOID = requestType.substring(8);
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_EXTENDED_MALFORMED_REQ_TYPE.get(entry.getDN(),
                ATTR_OPERATION_TYPE, requestType));
    }


    // Get the request value, if present.
    final byte[] requestValueBytes =
         entry.getAttributeValueBytes(ATTR_REQUEST_VALUE);
    if (requestValueBytes == null)
    {
      requestValue = null;
    }
    else
    {
      requestValue = new ASN1OctetString(
           ExtendedResponseProtocolOp.TYPE_RESPONSE_VALUE, requestValueBytes);
    }
  }



  /**
   * Retrieves the request OID for the extended request described by this
   * extended operation access log entry.
   *
   * @return  The request OID for the extended request described by this
   *          extended operation access log entry.
   */
  public String getRequestOID()
  {
    return requestOID;
  }



  /**
   * Retrieves the request value for the extended request described by this
   * extended operation access log entry, if any.
   *
   * @return  The request value for the extended request described by this
   *          extended operation access log entry, or {@code null} if no request
   *          value was included in the access log entry.
   */
  public ASN1OctetString getRequestValue()
  {
    return requestValue;
  }



  /**
   * Retrieves an {@code ExtendedRequest} created from this extended operation
   * access log entry.
   *
   * @return  The {@code ExtendedRequest} created from this extended operation
   *          access log entry.
   */
  public ExtendedRequest toExtendedRequest()
  {
    return new ExtendedRequest(requestOID, requestValue,
         getRequestControlArray());
  }
}
