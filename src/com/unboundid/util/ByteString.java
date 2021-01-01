/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
  @NotNull()
  byte[] getValue();



  /**
   * Retrieves the value for this byte string as a {@code String}.
   *
   * @return  The value for this byte string as a {@code String}.
   */
  @NotNull()
  String stringValue();



  /**
   * Appends the value of this byte string to the provided buffer.  It must not
   * use the {@link ByteStringBuffer#append(ByteString)} method, since that
   * method relies on this method.
   *
   * @param  buffer  The buffer to which the value should be appended.
   */
  void appendValueTo(@NotNull ByteStringBuffer buffer);



  /**
   * Converts this byte string to an ASN.1 octet string.
   *
   * @return  An ASN.1 octet string with the value of this byte string.
   */
  @NotNull()
  ASN1OctetString toASN1OctetString();
}
