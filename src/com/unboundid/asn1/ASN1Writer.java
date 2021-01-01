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
package com.unboundid.asn1;



import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an efficient mechanism for writing ASN.1 elements to
 * output streams.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1Writer
{
  /**
   * The thread-local buffers that will be used for encoding the elements.
   */
  @NotNull private static final ThreadLocal<ByteStringBuffer> BUFFERS =
       new ThreadLocal<>();



  /**
   * The maximum amount of memory that will be used for a thread-local buffer.
   */
  private static final int MAX_BUFFER_LENGTH = 524_288;



  /**
   * Prevent this class from being instantiated.
   */
  private ASN1Writer()
  {
    // No implementation is required.
  }



  /**
   * Writes an encoded representation of the provided ASN.1 element to the
   * given output stream.
   *
   * @param  element       The ASN.1 element to be written.
   * @param  outputStream  The output stream to which the encoded representation
   *                       of the element should be written.
   *
   * @throws  IOException  If a problem occurs while writing the element.
   */
  public static void writeElement(@NotNull final ASN1Element element,
                                  @NotNull final OutputStream outputStream)
         throws IOException
  {
    Debug.debugASN1Write(element);

    ByteStringBuffer buffer = BUFFERS.get();
    if (buffer == null)
    {
      buffer = new ByteStringBuffer();
      BUFFERS.set(buffer);
    }

    element.encodeTo(buffer);

    try
    {
      buffer.write(outputStream);
    }
    finally
    {
      if (buffer.capacity() > MAX_BUFFER_LENGTH)
      {
        buffer.setCapacity(MAX_BUFFER_LENGTH);
      }
      buffer.clear();
    }
  }



  /**
   * Appends an encoded representation of the provided ASN.1 element to the
   * given byte buffer.  When this method completes, the position will be at the
   * beginning of the written element, and the limit will be at the end.
   *
   * @param  element  The ASN.1 element to be written.
   * @param  buffer   The buffer to which the element should be added.
   *
   * @throws  BufferOverflowException  If the provided buffer does not have
   *                                   enough space between the position and
   *                                   the limit to hold the encoded element.
   */
  public static void writeElement(@NotNull final ASN1Element element,
                                  @NotNull final ByteBuffer buffer)
         throws BufferOverflowException
  {
    Debug.debugASN1Write(element);

    ByteStringBuffer b = BUFFERS.get();
    if (b == null)
    {
      b = new ByteStringBuffer();
      BUFFERS.set(b);
    }

    element.encodeTo(b);

    try
    {
      if (buffer.remaining() < b.length())
      {
        throw new BufferOverflowException();
      }

      final int pos = buffer.position();
      buffer.put(b.getBackingArray(), 0, b.length());
      buffer.limit(buffer.position());
      buffer.position(pos);
    }
    finally
    {
      if (b.capacity() > MAX_BUFFER_LENGTH)
      {
        b.setCapacity(MAX_BUFFER_LENGTH);
      }
      b.clear();
    }
  }
}
