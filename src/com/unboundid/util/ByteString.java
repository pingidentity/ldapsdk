/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.Serializable;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This interface defines a set of methods for treating a value as either a
 * string or byte array.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface ByteString
       extends Serializable
{
  /**
   * Retrieves a byte array containing the binary value for this byte string.
   *
   * @return  A byte array containing the binary value for this byte string.
   */
  byte[] getValue();



  /**
   * Retrieves the value for this byte string as a {@code String}.
   *
   * @return  The value for this byte string as a {@code String}.
   */
  String stringValue();



  /**
   * Appends the value of this byte string to the provided buffer.  It must not
   * use the {@link ByteStringBuffer#append(ByteString)} method, since that
   * method relies on this method.
   *
   * @param  buffer  The buffer to which the value should be appended.
   */
  void appendValueTo(ByteStringBuffer buffer);



  /**
   * Converts this byte string to an ASN.1 octet string.
   *
   * @return  An ASN.1 octet string with the value of this byte string.
   */
  ASN1OctetString toASN1OctetString();
}
