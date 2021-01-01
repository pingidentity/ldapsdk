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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that represents an LDAP extended
 * request.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link ExtendedRequest} class
 * should be used instead.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPExtendedOperation
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9207085503424216431L;



  // The value for this extended operation, if available.
  @Nullable private final byte[] value;

  // The OID for this extended operation.
  @NotNull private final String oid;



  /**
   * Creates a new LDAP extended operation with the provided OID and value.
   *
   * @param  id    The OID for this extended request.
   * @param  vals  The encoded value for this extended request, or {@code null}
   *               if there is none.
   */
  public LDAPExtendedOperation(@NotNull final String id,
                               @Nullable final byte[] vals)
  {
    oid   = id;
    value = vals;
  }



  /**
   * Creates a new LDAP extended operation from the provided extended request.
   *
   * @param  extendedRequest  The extended request to use to create this LDAP
   *                          extended operation.
   */
  public LDAPExtendedOperation(@NotNull final ExtendedRequest extendedRequest)
  {
    oid = extendedRequest.getOID();

    final ASN1OctetString v = extendedRequest.getValue();
    if (v == null)
    {
      value = null;
    }
    else
    {
      value = v.getValue();
    }
  }



  /**
   * Retrieves the OID for this LDAP extended operation.
   *
   * @return  The OID for this LDaP extended operation.
   */
  @NotNull()
  public String getID()
  {
    return oid;
  }



  /**
   * Retrieves the encoded value for this LDAP extended operation, if
   * available.
   *
   * @return  The encoded value for this LDAP extended operation, or
   *          {@code null} if there is none.
   */
  @Nullable()
  public byte[] getValue()
  {
    return value;
  }



  /**
   * Converts this LDAP extended operation to an {@link ExtendedRequest}.
   *
   * @return  The {@code ExtendedRequest} object that is the equivalent of this
   *          LDAP extended response.
   */
  @NotNull()
  public final ExtendedRequest toExtendedRequest()
  {
    if (value == null)
    {
      return new ExtendedRequest(oid);
    }
    else
    {
      return new ExtendedRequest(oid, new ASN1OctetString(value));
    }
  }



  /**
   * Retrieves a string representation of this extended operation.
   *
   * @return  A string representation of this extended operation.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("LDAPExtendedOperation(id=");
    buffer.append(oid);

    if (value != null)
    {
      buffer.append(", value=byte[");
      buffer.append(value.length);
      buffer.append(']');
    }

    buffer.append(')');

    return buffer.toString();
  }
}
