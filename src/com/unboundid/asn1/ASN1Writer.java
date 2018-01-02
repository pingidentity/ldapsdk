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
package com.unboundid.asn1;



import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;



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
  private static final ThreadLocal<ByteStringBuffer> buffers =
       new ThreadLocal<ByteStringBuffer>();



  /**
   * The maximum amount of memory that will be used for a thread-local buffer.
   */
  private static final int MAX_BUFFER_LENGTH = 524288;



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
  public static void writeElement(final ASN1Element element,
                                  final OutputStream outputStream)
         throws IOException
  {
    debugASN1Write(element);

    ByteStringBuffer buffer = buffers.get();
    if (buffer == null)
    {
      buffer = new ByteStringBuffer();
      buffers.set(buffer);
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
  public static void writeElement(final ASN1Element element,
                                  final ByteBuffer buffer)
         throws BufferOverflowException
  {
    debugASN1Write(element);

    ByteStringBuffer b = buffers.get();
    if (b == null)
    {
      b = new ByteStringBuffer();
      buffers.set(b);
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
