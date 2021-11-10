/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.Serializable;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class acts as a superclass for objects that may be used to indicate how
 * the server should handle updating trust information for a new listener
 * certificate chain.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ReplaceCertificateTrustBehavior
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2978084206955241218L;



  /**
   * Encodes this trust behavior object to an ASN.1 element suitable for
   * inclusion in a replace listener certificate request.
   *
   * @return  The ASN.1 element containing an encoded representation of this
   *          trust behavior object.
   */
  @NotNull()
  public abstract ASN1Element encode();



  /**
   * Decodes the provided ASN.1 element as a trust behavior object.
   *
   * @param  element  An ASN.1 element that contains an encoded representation
   *                  of a trust behavior element.  It must not be {@code null}.
   *
   * @return  The decoded trust behavior object.
   *
   * @throws  LDAPException  If the provided element cannot be decoded as a
   *                         trust behavior object.
   */
  @NotNull()
  public static ReplaceCertificateTrustBehavior decode(
              @NotNull final ASN1Element element)
         throws LDAPException
  {
    switch (element.getType())
    {
      case TrustManagerProviderReplaceCertificateTrustBehavior.
           TYPE_TRUST_BEHAVIOR:
        return new TrustManagerProviderReplaceCertificateTrustBehavior(
             element.decodeAsOctetString().stringValue());
      case JVMDefaultReplaceCertificateTrustBehavior.TYPE_TRUST_BEHAVIOR:
        return JVMDefaultReplaceCertificateTrustBehavior.getInstance();
      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_TB_DECODE_UNRECOGNIZED_TYPE.get(
                  StaticUtils.toHex(element.getType())));
    }
  }



  /**
   * Retrieves a string representation of this trust behavior object.
   *
   * @return  A string representation of this trust behavior object.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this trust behavior object to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the encoded representation should be
   *                 appended.  It must not be {@code null}.
   */
  public abstract void toString(@NotNull final StringBuilder buffer);
}
