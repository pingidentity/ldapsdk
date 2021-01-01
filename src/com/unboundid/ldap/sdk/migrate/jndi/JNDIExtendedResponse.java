/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.jndi;



import javax.naming.NamingException;
import javax.naming.ldap.ExtendedResponse;

import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a mechanism for converting between an LDAP extended
 * response as used in JNDI and one used in the UnboundID LDAP SDK for Java.
 *
 * @see  ExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JNDIExtendedResponse
       implements ExtendedResponse
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9210853181740736844L;



  // The SDK extended result that backs this JNDI extended response.
  @NotNull private final ExtendedResult r;



  /**
   * Creates a new JNDI extended response from the provided SDK extended result.
   *
   * @param  r  The SDK extended result to use to create this JNDI extended
   *            response.
   */
  public JNDIExtendedResponse(@NotNull final ExtendedResult r)
  {
    this.r = r;
  }



  /**
   * Creates a new JNDI extended response from the provided JNDI extended
   * response.
   *
   * @param  r  The JNDI extended response to use to create this JNDI extended
   *            response.
   *
   * @throws  NamingException  If a problem occurs while trying to create this
   *                           JNDI extended response.
   */
  public JNDIExtendedResponse(@NotNull final ExtendedResponse r)
         throws NamingException
  {
    this(toSDKExtendedResult(r));
  }



  /**
   * Creates a new JNDI extended response with the provided information.
   *
   * @param  id        The object identifier for the response, or {@code null}
   *                   if there should not be a value.
   * @param  berValue  A byte array containing the encoded value (including BER
   *                   type and length), or {@code null} if the response should
   *                   not have a value.
   * @param  offset    The offset within the provided array at which the value
   *                   should begin.
   * @param  length    The number of bytes contained in the value.
   *
   * @throws  NamingException  If a problem occurs while creating the response.
   */
  JNDIExtendedResponse(@Nullable final String id,
                       @Nullable final byte[] berValue, final int offset,
                       final int length)
       throws NamingException
  {
    final ASN1OctetString value;
    if (berValue == null)
    {
      value = null;
    }
    else
    {
      try
      {
        if ((offset == 0) && (length == berValue.length))
        {
          value = ASN1OctetString.decodeAsOctetString(berValue);
        }
        else
        {
          final byte[] valueBytes = new byte[length];
          System.arraycopy(berValue, offset, valueBytes, 0, length);
          value = ASN1OctetString.decodeAsOctetString(valueBytes);
        }
      }
      catch (final ASN1Exception ae)
      {
        throw new NamingException(StaticUtils.getExceptionMessage(ae));
      }
    }

    r = new ExtendedResult(-1, ResultCode.SUCCESS, null, null, null, id, value,
                           null);
  }



  /**
   * Retrieves the object identifier for this extended response, if available.
   *
   * @return  The object identifier for this extended response, or {@code null}
   *          if there is no OID.
   */
  @Override()
  @Nullable()
  public String getID()
  {
    return r.getOID();
  }



  /**
   * Retrieves the encoded value for this extended response (including the BER
   * type and length), if available.
   *
   * @return  The encoded value for this extended response, or {@code null} if
   *          there is no value.
   */
  @Override()
  @Nullable()
  public byte[] getEncodedValue()
  {
    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      return null;
    }
    else
    {
      return value.encode();
    }
  }



  /**
   * Retrieves an LDAP SDK extended result that is the equivalent of this JNDI
   * extended response.
   *
   * @return  An LDAP SDK extended result that is the equivalent of this JNDI
   *          extended response.
   */
  @NotNull()
  public ExtendedResult toSDKExtendedResult()
  {
    return r;
  }



  /**
   * Retrieves an LDAP SDK extended result that is the equivalent of the
   * provided JNDI extended response.
   *
   * @param  r  The JNDI extended response to convert to an LDAP SDK extended
   *            result.
   *
   * @return  The LDAP SDK extended result converted from the provided JNDI
   *          extended response.
   *
   * @throws  NamingException  If a problem occurs while decoding the provided
   *                           JNDI extended response as an SDK extended result.
   */
  @Nullable()
  public static ExtendedResult toSDKExtendedResult(
                                    @Nullable final ExtendedResponse r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    final JNDIExtendedResponse response;
    final byte[] encodedValue = r.getEncodedValue();
    if (encodedValue == null)
    {
      response = new JNDIExtendedResponse(r.getID(), null, 0, 0);
    }
    else
    {
      response = new JNDIExtendedResponse(r.getID(), encodedValue, 0,
           encodedValue.length);
    }

    return response.toSDKExtendedResult();
  }



  /**
   * Retrieves a string representation of this JNDI extended response.
   *
   * @return  A string representation of this JNDI response.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return r.toString();
  }
}
