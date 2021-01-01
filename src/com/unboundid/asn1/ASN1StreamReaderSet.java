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
package com.unboundid.asn1;



import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Messages.*;



/**
 * This class provides a data structure which is used in the course of reading
 * an ASN.1 set from an ASN.1 stream reader.  It provides access to the BER type
 * and the total number of bytes in the encoded representations of all of the
 * embedded values, and provides a method to determine when the end of the set
 * has been reached.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ASN1StreamReaderSet
{
  // The ASN.1 stream reader associated with this object.
  @NotNull private final ASN1StreamReader reader;

  // The BER type for this ASN.1 set.
  private final byte type;

  // The number of bytes contained in the encoded representations of all of the
  // embedded values.
  private final int length;

  // The value for the total number of bytes read from the associated reader at
  // which the end of the set should be encountered.
  private final long endBytesRead;



  /**
   * Creates a new instance of this class with the provided information.
   *
   * @param  reader  The ASN.1 stream reader with which this object will be
   *                 associated.
   * @param  type    The BER type for this ASN.1 set.
   * @param  length  The number of bytes contained in the encoded
   *                 representations of all the embedded values.
   */
  ASN1StreamReaderSet(@NotNull final ASN1StreamReader reader, final byte type,
                      final int length)
  {
    this.reader = reader;
    this.type   = type;
    this.length = length;

    endBytesRead = reader.getTotalBytesRead() + length;
  }



  /**
   * Retrieves the BER type for this ASN.1 set.
   *
   * @return  The BER type for this ASN.1 set.
   */
  public byte getType()
  {
    return type;
  }



  /**
   * Retrieves the number of bytes contained in the encoded representations of
   * all the embedded values.
   *
   * @return  The number of bytes contained in the encoded representations of
   *          all the embedded values.
   */
  public int getLength()
  {
    return length;
  }



  /**
   * Indicates whether there are more elements in this set to be read from the
   * associated ASN.1 stream reader.
   *
   * @return  {@code true} if there are more elements in this set to be read
   *          from the associated ASN.1 stream reader or false if the end of the
   *          set has been reached.
   *
   * @throws  ASN1Exception  If the associated ASN.1 stream reader has already
   *                         read beyond the end of the set.
   */
  public boolean hasMoreElements()
         throws ASN1Exception
  {
    final long currentBytesRead = reader.getTotalBytesRead();
    if (currentBytesRead == endBytesRead)
    {
      return false;
    }
    else if (currentBytesRead < endBytesRead)
    {
      return true;
    }

    throw new ASN1Exception(ERR_STREAM_READER_SET_READ_PAST_END.get(
         length, endBytesRead, currentBytesRead));
  }
}
