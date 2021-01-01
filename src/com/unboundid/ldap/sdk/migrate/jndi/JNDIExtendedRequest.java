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

import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a mechanism for converting between an LDAP extended
 * request as used in JNDI and one used in the UnboundID LDAP SDK for Java.
 *
 * @see  ExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JNDIExtendedRequest
       implements javax.naming.ldap.ExtendedRequest
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8502230539753937274L;



  // The SDK extended request that backs this JNDI extended request.
  @NotNull private final ExtendedRequest r;



  /**
   * Creates a new JNDI extended request from the provided SDK extended request.
   *
   * @param  r  The SDK extended request to use to create this JNDI extended
   *            request.
   */
  public JNDIExtendedRequest(@NotNull final ExtendedRequest r)
  {
    this.r = r;
  }



  /**
   * Creates a new JNDI extended request from the provided JNDI extended
   * request.
   *
   * @param  r  The JNDI extended request to use to create this JNDI extended
   *            request.
   *
   * @throws  NamingException  If a problem occurs while trying to create this
   *                           JNDI extended request.
   */
  public JNDIExtendedRequest(@NotNull final javax.naming.ldap.ExtendedRequest r)
         throws NamingException
  {
    this.r = toSDKExtendedRequest(r);
  }



  /**
   * Retrieves the object identifier for this extended request.
   *
   * @return  The object identifier for this extended request.
   */
  @Override()
  @NotNull()
  public String getID()
  {
    return r.getOID();
  }



  /**
   * Retrieves the encoded value for this extended request (including the BER
   * type and length), if available.
   *
   * @return  The encoded value for this extended request, or {@code null} if
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
   * Creates a JNDI extended response with the provided information.
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
   * @return  The created JNDI extended response.
   *
   * @throws  NamingException  If a problem occurs while creating the response.
   */
  @Override()
  @NotNull()
  public JNDIExtendedResponse createExtendedResponse(@Nullable final String id,
                                   @Nullable final byte[] berValue,
                                   final int offset, final int length)
         throws NamingException
  {
    return new JNDIExtendedResponse(id, berValue, offset, length);
  }



  /**
   * Retrieves an LDAP SDK extended request that is the equivalent of this JNDI
   * extended request.
   *
   * @return  An LDAP SDK extended request that is the equivalent of this JNDI
   *          extended request.
   */
  @NotNull()
  public ExtendedRequest toSDKExtendedRequest()
  {
    return r;
  }



  /**
   * Retrieves an LDAP SDK extended request that is the equivalent of the
   * provided JNDI extended request.
   *
   * @param  r  The JNDI extended request to convert to an LDAP SDK extended
   *            request.
   *
   * @return  The LDAP SDK extended request converted from the provided JNDI
   *          extended request.
   *
   * @throws  NamingException  If a problem occurs while decoding the provided
   *                           JNDI extended request as an SDK extended request.
   */
  @Nullable()
  public static ExtendedRequest toSDKExtendedRequest(
                     @Nullable final javax.naming.ldap.ExtendedRequest r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    final ASN1OctetString value;
    final byte[] valueBytes = r.getEncodedValue();
    if (valueBytes == null)
    {
      value = null;
    }
    else
    {
      try
      {
        value = ASN1OctetString.decodeAsOctetString(valueBytes);
      }
      catch (final ASN1Exception ae)
      {
        throw new NamingException(StaticUtils.getExceptionMessage(ae));
      }
    }

    return new ExtendedRequest(r.getID(), value);
  }



  /**
   * Retrieves a string representation of this JNDI extended request.
   *
   * @return  A string representation of this JNDI request.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return r.toString();
  }
}
