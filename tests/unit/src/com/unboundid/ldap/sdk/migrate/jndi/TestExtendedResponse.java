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



import javax.naming.ldap.ExtendedResponse;



/**
 * This class provides an implementation of a JNDI extended response that may be
 * used for testing purposes.
 */
public class TestExtendedResponse
       implements ExtendedResponse
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4537056748908120778L;



  // The encoded value for the response.
  private final byte[] value;

  // The OID for this extended response.
  private final String oid;



  /**
   * Creates a new test extended response with the provided information.
   *
   * @param  oid     The OID for the response.
   * @param  value   The array containing the encoded value for the response.
   * @param  offset  The position in the array at which the value begins.
   * @param  length  The number of bytes in the value.
   */
  public TestExtendedResponse(final String oid, final byte[] value,
                              final int offset, final int length)
  {
    this.oid = oid;

    if (value == null)
    {
      this.value = null;
    }
    else
    {
      this.value = new byte[length];
      System.arraycopy(value, 0, this.value, 0, length);
    }
  }



  /**
   * Retrieves the OID for this extended response.
   *
   * @return  The OID for this extended response.
   */
  @Override()
  public String getID()
  {
    return oid;
  }



  /**
   * Retrieves the encoded value for this extended response.
   *
   * @return  The encoded value for this extended response.
   */
  @Override()
  public byte[] getEncodedValue()
  {
    return value;
  }
}
