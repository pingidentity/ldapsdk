/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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



import java.io.Serializable;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that should be implemented by all
 * types of LDAP protocol ops.
 */
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ProtocolOp
       extends Serializable
{
  /**
   * Retrieves the BER type for this protocol op.
   *
   * @return  The BER type for this protocol op.
   */
  byte getProtocolOpType();



  /**
   * Encodes this protocol op to an ASN.1 element suitable for inclusion in an
   * encoded LDAP message.
   *
   * @return  The ASN.1 element containing the encoded protocol op.
   */
  ASN1Element encodeProtocolOp();



  /**
   * Writes an ASN.1-encoded representation of this LDAP protocol op to the
   * provided ASN.1 buffer.  This method is intended for internal use only and
   * should not be used by third-party code.
   *
   * @param  buffer  The ASN.1 buffer to which the encoded representation should
   *                 be written.
   */
  void writeTo(ASN1Buffer buffer);



  /**
   * Appends a string representation of this LDAP protocol op to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  void toString(StringBuilder buffer);
}
