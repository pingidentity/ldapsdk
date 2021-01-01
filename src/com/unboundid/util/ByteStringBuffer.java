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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Arrays;

import com.unboundid.asn1.ASN1OctetString;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a growable byte array to which data can be appended.
 * Methods in this class are not synchronized.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ByteStringBuffer
       implements Serializable, Appendable
{
  /**
   * The default initial capacity for this buffer.
   */
  private static final int DEFAULT_INITIAL_CAPACITY = 20;



  /**
   * The pre-allocated array that will be used for a boolean value of "false".
   */
  @NotNull private static final byte[] FALSE_VALUE_BYTES =
       StaticUtils.getBytes("false");



  /**
   * The pre-allocated array that will be used for a boolean value of "true".
   */
  @NotNull private static final byte[] TRUE_VALUE_BYTES =
       StaticUtils.getBytes("true");



  /**
   * A thread-local byte array that will be used for holding numeric values
   * to append to the buffer.
   */
  @NotNull private static final ThreadLocal<byte[]> TEMP_NUMBER_BUFFER =
       new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2899392249591230998L;



  // The backing array for this buffer.
  @NotNull private byte[] array;

  // The length of the backing array.
  private int capacity;

  // The position at which to append the next data.
  private int endPos;



  /**
   * Creates a new empty byte string buffer with a default initial capacity.
   */
  public ByteStringBuffer()
  {
    this(DEFAULT_INITIAL_CAPACITY);
  }



  /**
   * Creates a new byte string buffer with the specified capacity.
   *
   * @param  initialCapacity  The initial capacity to use for the buffer.  It
   *                          must be greater than or equal to zero.
   */
  public ByteStringBuffer(final int initialCapacity)
  {
    array    = new byte[initialCapacity];
    capacity = initialCapacity;
    endPos   = 0;
  }



  /**
   * Appends the provided boolean value to this buffer.
   *
   * @param  b  The boolean value to be appended to this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer append(final boolean b)
  {
    if (b)
    {
      return append(TRUE_VALUE_BYTES, 0, 4);
    }
    else
    {
      return append(FALSE_VALUE_BYTES, 0, 5);
    }
  }



  /**
   * Appends the provided byte to this buffer.
   *
   * @param  b  The byte to be appended to this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer append(final byte b)
  {
    ensureCapacity(endPos + 1);
    array[endPos++] = b;
    return this;
  }



  /**
   * Appends the contents of the provided byte array to this buffer.
   *
   * @param  b  The array whose contents should be appended to this buffer.  It
   *            must not be {@code null}.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   */
  @NotNull()
  public ByteStringBuffer append(@NotNull final byte[] b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return append(b, 0, b.length);
  }



  /**
   * Appends the specified portion of the provided byte array to this buffer.
   *
   * @param  b    The array whose contents should be appended to this buffer.
   * @param  off  The offset within the array at which to begin copying data.
   * @param  len  The number of bytes to copy.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the offset or length are negative,
   *                                     if the offset plus the length is beyond
   *                                     the end of the provided array.
   */
  @NotNull()
  public ByteStringBuffer append(@NotNull final byte[] b, final int off,
                                 final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > b.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 b.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }

    if (len > 0)
    {
      ensureCapacity(endPos + len);
      System.arraycopy(b, off, array, endPos, len);
      endPos += len;
    }

    return this;
  }



  /**
   * Appends the provided byte string to this buffer.
   *
   * @param  b  The byte string to be appended to this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided byte string is {@code null}.
   */
  @NotNull()
  public ByteStringBuffer append(@NotNull final ByteString b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    b.appendValueTo(this);
    return this;
  }



  /**
   * Appends the provided byte string buffer to this buffer.
   *
   * @param  buffer  The buffer whose contents should be appended to this
   *                 buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided buffer is {@code null}.
   */
  @NotNull()
  public ByteStringBuffer append(@NotNull final ByteStringBuffer buffer)
         throws NullPointerException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return append(buffer.array, 0, buffer.endPos);
  }



  /**
   * Appends the provided character to this buffer.
   *
   * @param  c  The character to be appended to this buffer.
   *
   * @return  A reference to this buffer.
   */
  @Override()
  @NotNull()
  public ByteStringBuffer append(final char c)
  {
    final byte b = (byte) (c & 0x7F);
    if (b == c)
    {
      ensureCapacity(endPos + 1);
      array[endPos++] = b;
    }
    else
    {
      append(String.valueOf(c));
    }

    return this;
  }



  /**
   * Appends the contents of the provided character array to this buffer.
   *
   * @param  c  The array whose contents should be appended to this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   */
  @NotNull()
  public ByteStringBuffer append(@NotNull final char[] c)
         throws NullPointerException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return append(c, 0, c.length);
  }



  /**
   * Appends the specified portion of the provided character array to this
   * buffer.
   *
   * @param  c    The array whose contents should be appended to this buffer.
   * @param  off  The offset within the array at which to begin copying data.
   * @param  len  The number of characters to copy.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the offset or length are negative,
   *                                     if the offset plus the length is beyond
   *                                     the end of the provided array.
   */
  @NotNull()
  public ByteStringBuffer append(@NotNull final char[] c, final int off,
                                 final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > c.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 c.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }

    if (len > 0)
    {
      ensureCapacity(endPos + len);

      int pos = off;
      for (int i=0; i < len; i++, pos++)
      {
        final byte b = (byte) (c[pos] & 0x7F);
        if (b == c[pos])
        {
          array[endPos++] = b;
        }
        else
        {
          final String remainingString =
               String.valueOf(c, pos, (off + len - pos));
          final byte[] remainingBytes = StaticUtils.getBytes(remainingString);
          return append(remainingBytes);
        }
      }
    }

    return this;
  }



  /**
   * Appends the provided character sequence to this buffer.
   *
   * @param  s  The character sequence to append to this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided character sequence is
   *                                {@code null}.
   */
  @Override()
  @NotNull()
  public ByteStringBuffer append(@NotNull final CharSequence s)
         throws NullPointerException
  {
    final String str = s.toString();
    return append(str, 0, str.length());
  }



  /**
   * Appends the provided character sequence to this buffer.
   *
   * @param  s      The character sequence to append to this buffer.
   * @param  start  The position in the sequence of the first character in the
   *                sequence to be appended to this buffer.
   * @param  end    The position in the sequence immediately after the position
   *                of the last character to be appended.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided character sequence is
   *                                {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the provided start or end positions
   *                                     are outside the bounds of the given
   *                                     character sequence.
   */
  @Override()
  @NotNull()
  public ByteStringBuffer append(@NotNull final CharSequence s, final int start,
                                 final int end)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    final String string = s.toString();
    final int stringLength = string.length();
    if (start < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_START_NEGATIVE.get(start));
    }
    else if (start > end)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_START_BEYOND_END.get(start, end));
    }
    else if (start > stringLength)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_START_BEYOND_LENGTH.get(start, stringLength));
    }
    else if (end > stringLength)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_END_BEYOND_LENGTH.get(start, stringLength));
    }
    else if (start < end)
    {
      ensureCapacity(endPos + (end - start));
      for (int pos=start; pos < end; pos++)
      {
        final char c = string.charAt(pos);
        if (c <= 0x7F)
        {
          array[endPos++] = (byte) (c & 0x7F);
        }
        else
        {
          final String remainingString = string.substring(pos, end);
          final byte[] remainingBytes = StaticUtils.getBytes(remainingString);
          return append(remainingBytes);
        }
      }
    }

    return this;
  }



  /**
   * Appends the provided integer value to this buffer.
   *
   * @param  i  The integer value to be appended to this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer append(final int i)
  {
    final int length = getBytes(i);
    return append(TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  /**
   * Appends the provided long value to this buffer.
   *
   * @param  l  The long value to be appended to this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer append(final long l)
  {
    final int length = getBytes(l);
    return append(TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  /**
   * Inserts the provided boolean value to this buffer.
   *
   * @param  pos  The position at which the value is to be inserted.
   * @param  b    The boolean value to be inserted into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, final boolean b)
         throws  IndexOutOfBoundsException
  {
    if (b)
    {
      return insert(pos, TRUE_VALUE_BYTES, 0, 4);
    }
    else
    {
      return insert(pos, FALSE_VALUE_BYTES, 0, 5);
    }
  }



  /**
   * Inserts the provided byte at the specified position in this buffer.
   *
   * @param  pos  The position at which the byte is to be inserted.
   * @param  b    The byte to be inserted into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull ()
  public ByteStringBuffer insert(final int pos, final byte b)
         throws IndexOutOfBoundsException
  {
    if ((pos < 0) || (pos > endPos))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }
    else if (pos == endPos)
    {
      return append(b);
    }

    ensureCapacity(endPos + 1);
    System.arraycopy(array, pos, array, pos+1, (endPos-pos));
    array[pos] = b;
    endPos++;
    return this;
  }



  /**
   * Inserts the contents of the provided byte array at the specified position
   * in this buffer.
   *
   * @param  pos  The position at which the data is to be inserted.
   * @param  b    The array whose contents should be inserted into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, @NotNull final byte[] b)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return insert(pos, b, 0, b.length);
  }



  /**
   * Inserts a portion of the data in the provided array at the specified
   * position in this buffer.
   *
   * Appends the specified portion of the provided byte array to this buffer.
   *
   * @param  pos  The position at which the data is to be inserted.
   * @param  b    The array whose contents should be inserted into this buffer.
   * @param  off  The offset within the array at which to begin copying data.
   * @param  len  The number of bytes to copy.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length, if
   *                                     the offset or length are negative, if
   *                                     the offset plus the length is beyond
   *                                     the end of the provided array.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, @NotNull final byte[] b,
                                 final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    if ((pos < 0) || (pos > endPos) || (off < 0) || (len < 0) ||
        (off+len > b.length))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else if (pos > endPos)
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }
      else if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 b.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }
    else if (len == 0)
    {
      return this;
    }
    else if (pos == endPos)
    {
      return append(b, off, len);
    }

    ensureCapacity(endPos + len);
    System.arraycopy(array, pos, array, pos+len, (endPos-pos));
    System.arraycopy(b, off, array, pos, len);
    endPos += len;
    return this;
  }



  /**
   * Inserts the provided byte string into this buffer at the specified
   * position.
   *
   * @param  pos  The position at which the data is to be inserted.
   * @param  b    The byte string to insert into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided byte string is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, @NotNull final ByteString b)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return insert(pos, b.getValue());
  }



  /**
   * Inserts the provided byte string buffer into this buffer at the specified
   * position.
   *
   * @param  pos     The position at which the data is to be inserted.
   * @param  buffer  The buffer whose contents should be inserted into this
   *                 buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided buffer is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos,
                                 @NotNull final ByteStringBuffer buffer)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return insert(pos, buffer.array, 0, buffer.endPos);
  }



  /**
   * Inserts the provided character into this buffer at the provided position.
   *
   * @param  pos  The position at which the character is to be inserted.
   * @param  c    The character to be inserted into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, final char c)
         throws IndexOutOfBoundsException
  {
    if ((pos < 0) || (pos > endPos))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }
    else if (pos == endPos)
    {
      return append(c);
    }

    final byte b = (byte) (c & 0x7F);
    if (b == c)
    {
      ensureCapacity(endPos + 1);
      System.arraycopy(array, pos, array, pos+1, (endPos-pos));
      array[pos] = b;
      endPos++;
    }
    else
    {
      insert(pos, String.valueOf(c));
    }

    return this;
  }



  /**
   * Inserts the contents of the provided character array into this buffer at
   * the specified position.
   *
   * @param  pos  The position at which the data is to be inserted.
   * @param  c    The array whose contents should be inserted into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, @NotNull final char[] c)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return insert(pos, new String(c, 0, c.length));
  }



  /**
   * Inserts the specified portion of the provided character array to this
   * buffer at the specified position.
   *
   * @param  pos  The position at which the data is to be inserted.
   * @param  c    The array whose contents should be inserted into this buffer.
   * @param  off  The offset within the array at which to begin copying data.
   * @param  len  The number of characters to copy.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length, if
   *                                     the offset or length are negative, if
   *                                     the offset plus the length is beyond
   *                                     the end of the provided array.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, @NotNull final char[] c,
                                 final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    return insert(pos, new String(c, off, len));
  }



  /**
   * Inserts the provided character sequence to this buffer at the specified
   * position.
   *
   * @param  pos  The position at which the data is to be inserted.
   * @param  s    The character sequence to insert into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided character sequence is
   *                                {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, @NotNull final CharSequence s)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    if ((pos < 0) || (pos > endPos))
    {
      final String message;
      if (pos < 0)
      {
        message = ERR_BS_BUFFER_POS_NEGATIVE.get(pos);
      }
      else
      {
        message = ERR_BS_BUFFER_POS_TOO_LARGE.get(pos, endPos);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }
    else if (pos == endPos)
    {
      return append(s);
    }
    else
    {
      return insert(pos, StaticUtils.getBytes(s.toString()));
    }
  }



  /**
   * Inserts the provided integer value to this buffer.
   *
   * @param  pos  The position at which the value is to be inserted.
   * @param  i    The integer value to be inserted into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, final int i)
         throws IndexOutOfBoundsException
  {
    final int length = getBytes(i);
    return insert(pos, TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  /**
   * Inserts the provided long value to this buffer.
   *
   * @param  pos  The position at which the value is to be inserted.
   * @param  l    The long value to be inserted into this buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  @NotNull()
  public ByteStringBuffer insert(final int pos, final long l)
         throws IndexOutOfBoundsException
  {
    final int length = getBytes(l);
    return insert(pos, TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  /**
   * Deletes the specified number of bytes from the beginning of the buffer.
   *
   * @param  len  The number of bytes to delete.
   *
   * @return  A reference to this buffer.
   *
   * @throws  IndexOutOfBoundsException  If the specified length is negative,
   *                                     or if it is greater than the number of
   *                                     bytes currently contained in this
   *                                     buffer.
   */
  @NotNull()
  public ByteStringBuffer delete(final int len)
         throws IndexOutOfBoundsException
  {
    return delete(0, len);
  }



  /**
   * Deletes the indicated number of bytes from the specified location in the
   * buffer.
   *
   * @param  off  The position in the buffer at which the content to delete
   *              begins.
   * @param  len  The number of bytes to remove from the buffer.
   *
   * @return  A reference to this buffer.
   *
   * @throws  IndexOutOfBoundsException  If the offset or length is negative, or
   *                                     if the combination of the offset and
   *                                     length is greater than the end of the
   *                                     content in the buffer.
   */
  @NotNull()
  public ByteStringBuffer delete(final int off, final int len)
         throws IndexOutOfBoundsException
  {
    if (off < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off));
    }
    else if (len < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len));
    }
    else if ((off + len) > endPos)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len, endPos));
    }
    else if (len == 0)
    {
      return this;
    }
    else if (off == 0)
    {
      if (len == endPos)
      {
        endPos = 0;
        return this;
      }
      else
      {
        final int newEndPos = endPos - len;
        System.arraycopy(array, len, array, 0, newEndPos);
        endPos = newEndPos;
        return this;
      }
    }
    else
    {
      if ((off + len) == endPos)
      {
        endPos = off;
        return this;
      }
      else
      {
        final int bytesToCopy = endPos - (off+len);
        System.arraycopy(array, (off+len), array, off, bytesToCopy);
        endPos -= len;
        return this;
      }
    }
  }



  /**
   * Sets the contents of this buffer to include only the provided boolean
   * value.
   *
   * @param  b  The boolean value to use as the content for this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(final boolean b)
  {
    if (b)
    {
      return set(TRUE_VALUE_BYTES, 0, 4);
    }
    else
    {
      return set(FALSE_VALUE_BYTES, 0, 5);
    }
  }



  /**
   * Sets the contents of this buffer to include only the provided byte.
   *
   * @param  b  The byte to use as the content for this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(final byte b)
  {
    endPos = 0;
    return append(b);
  }



  /**
   * Sets the contents of this buffer to the contents of the provided byte
   * array.
   *
   * @param  b  The byte array containing the content to use for this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(@NotNull final byte[] b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(b, 0, b.length);
  }



  /**
   * Sets the contents of this buffer to the specified portion of the provided
   * byte array.
   *
   * @param  b    The byte array containing the content to use for this buffer.
   * @param  off  The offset within the array at which to begin copying data.
   * @param  len  The number of bytes to copy.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the offset or length are negative,
   *                                     if the offset plus the length is beyond
   *                                     the end of the provided array.
   */
  @NotNull()
  public ByteStringBuffer set(@NotNull final byte[] b, final int off,
                              final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > b.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 b.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(b, off, len);
  }



  /**
   * Sets the contents of this buffer to the contents of the provided byte
   * string.
   *
   * @param  b  The byte string that should be used as the content for this
   *            buffer.
   *
   * @throws  NullPointerException  If the provided byte string is {@code null}.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(@NotNull final ByteString b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    endPos = 0;
    b.appendValueTo(this);
    return this;
  }



  /**
   * Sets the contents of this buffer to the contents of the provided byte
   * string buffer.
   *
   * @param  buffer  The buffer whose contents should be used as the content for
   *                 this buffer.
   *
   * @throws  NullPointerException  If the provided buffer is {@code null}.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(@NotNull final ByteStringBuffer buffer)
         throws NullPointerException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(buffer.array, 0, buffer.endPos);
  }



  /**
   * Sets the contents of this buffer to include only the provided character.
   *
   * @param  c  The character use as the content for this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(final char c)
  {
    endPos = 0;
    return append(c);
  }



  /**
   * Sets the contents of this buffer to the contents of the provided character
   * array.
   *
   * @param  c  The character array containing the content to use for this
   *            buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(@NotNull final char[] c)
         throws NullPointerException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(c, 0, c.length);
  }



  /**
   * Sets the contents of this buffer to the specified portion of the provided
   * character array.
   *
   * @param  c    The character array containing the content to use for this
   *              buffer.
   * @param  off  The offset within the array at which to begin copying data.
   * @param  len  The number of characters to copy.
   *
   * @return  A reference to this buffer.
   *
   * @throws  NullPointerException  If the provided array is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the offset or length are negative,
   *                                     if the offset plus the length is beyond
   *                                     the end of the provided array.
   */
  @NotNull()
  public ByteStringBuffer set(@NotNull final char[] c, final int off,
                              final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    if ((off < 0) || (len < 0) || (off+len > c.length))
    {
      final String message;
      if (off < 0)
      {
        message = ERR_BS_BUFFER_OFFSET_NEGATIVE.get(off);
      }
      else if (len < 0)
      {
        message = ERR_BS_BUFFER_LENGTH_NEGATIVE.get(len);
      }
      else
      {
        message = ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(off, len,
                                                                 c.length);
      }

      final IndexOutOfBoundsException e =
           new IndexOutOfBoundsException(message);
      Debug.debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(c, off, len);
  }



  /**
   * Sets the contents of this buffer to the specified portion of the provided
   * character sequence.
   *
   * @param  s  The character sequence to use as the content for this buffer.
   *
   * @throws  NullPointerException  If the provided character sequence is
   *                                {@code null}.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(@NotNull final CharSequence s)
         throws NullPointerException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      Debug.debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(s);
  }



  /**
   * Sets the contents of this buffer to include only the provided integer
   * value.
   *
   * @param  i  The integer value to use as the content for this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(final int i)
  {
    final int length = getBytes(i);
    return set(TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  /**
   * Sets the contents of this buffer to include only the provided long value.
   *
   * @param  l  The long value to use as the content for this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer set(final long l)
  {
    final int length = getBytes(l);
    return set(TEMP_NUMBER_BUFFER.get(), 0, length);
  }



  /**
   * Clears the contents of this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer clear()
  {
    endPos = 0;
    return this;
  }



  /**
   * Clears the contents of this buffer.
   *
   * @param  zero  Indicates whether to overwrite the content of the backing
   *               array with all zeros in order to wipe out any sensitive data
   *               it may contain.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer clear(final boolean zero)
  {
    endPos = 0;

    if (zero)
    {
      Arrays.fill(array, (byte) 0x00);
    }

    return this;
  }



  /**
   * Retrieves the current backing array for this buffer.  The data will begin
   * at position 0 and will contain {@link ByteStringBuffer#length} bytes.
   *
   * @return  The current backing array for this buffer.
   */
  @NotNull()
  public byte[] getBackingArray()
  {
    return array;
  }



  /**
   * Indicates whether this buffer is currently empty.
   *
   * @return  {@code true} if this buffer is currently empty, or {@code false}
   *          if not.
   */
  public boolean isEmpty()
  {
    return (endPos == 0);
  }



  /**
   * Retrieves the number of bytes contained in this buffer.
   *
   * @return  The number of bytes contained in this buffer.
   */
  public int length()
  {
    return endPos;
  }



  /**
   * Sets the length of this buffer to the specified value.  If the new length
   * is greater than the current length, the value will be padded with zeroes.
   *
   * @param  length  The new length to use for the buffer.  It must be greater
   *                 than or equal to zero.
   *
   * @throws  IndexOutOfBoundsException  If the provided length is negative.
   */
  public void setLength(final int length)
         throws IndexOutOfBoundsException
  {
    if (length < 0)
    {
      final IndexOutOfBoundsException e = new IndexOutOfBoundsException(
           ERR_BS_BUFFER_LENGTH_NEGATIVE.get(length));
      Debug.debugCodingError(e);
      throw e;
    }

    if (length > endPos)
    {
      ensureCapacity(length);
      Arrays.fill(array, endPos, length, (byte) 0x00);
      endPos = length;
    }
    else
    {
      endPos = length;
    }
  }



  /**
   * Returns the current capacity for this buffer.
   *
   * @return  The current capacity for this buffer.
   */
  public int capacity()
  {
    return capacity;
  }



  /**
   * Ensures that the total capacity of this buffer is at least equal to the
   * specified size.
   *
   * @param  minimumCapacity  The minimum capacity for this buffer.
   */
  public void ensureCapacity(final int minimumCapacity)
  {
    if (capacity < minimumCapacity)
    {
      final int newCapacity = Math.max(minimumCapacity, (2 * capacity) + 2);
      final byte[] newArray = new byte[newCapacity];
      System.arraycopy(array, 0, newArray, 0, capacity);
      array = newArray;
      capacity = newCapacity;
    }
  }



  /**
   * Sets the capacity equal to the specified value.  If the provided capacity
   * is less than the current length, then the length will be reduced to the
   * new capacity.
   *
   * @param  capacity  The new capacity for this buffer.  It must be greater
   *                   than or equal to zero.
   *
   * @throws  IndexOutOfBoundsException  If the provided capacity is negative.
   */
  public void setCapacity(final int capacity)
         throws IndexOutOfBoundsException
  {
    if (capacity < 0)
    {
      final IndexOutOfBoundsException e = new IndexOutOfBoundsException(
           ERR_BS_BUFFER_CAPACITY_NEGATIVE.get(capacity));
      Debug.debugCodingError(e);
      throw e;
    }

    if (this.capacity == capacity)
    {
      return;
    }
    else if (this.capacity < capacity)
    {
      final byte[] newArray = new byte[capacity];
      System.arraycopy(array, 0, newArray, 0, this.capacity);
      array = newArray;
      this.capacity = capacity;
    }
    else
    {
      final byte[] newArray = new byte[capacity];
      System.arraycopy(array, 0, newArray, 0, capacity);
      array = newArray;
      endPos = Math.min(endPos, capacity);
      this.capacity = capacity;
    }
  }



  /**
   * Trims the backing array to the minimal size required for this buffer.
   *
   * @return  A reference to this buffer.
   */
  @NotNull()
  public ByteStringBuffer trimToSize()
  {
    if (endPos != capacity)
    {
      final byte[] newArray = new byte[endPos];
      System.arraycopy(array, 0, newArray, 0, endPos);
      array = newArray;
      capacity = endPos;
    }

    return this;
  }



  /**
   * Retrieves the byte at the specified offset in the buffer.
   *
   * @param  offset  The offset of the byte to read.  It must be between greater
   *                 than or equal to zero and less than {@link #length}.
   *
   * @return  The byte at the specified offset in the buffer.
   *
   * @throws  IndexOutOfBoundsException  If the provided offset is negative or
   *                                     greater than or equal to the length of
   *                                     the buffer.
   */
  public byte byteAt(final int offset)
         throws IndexOutOfBoundsException
  {
    if (offset < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_NEGATIVE.get(offset));
    }
    else if (offset >= endPos)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_TOO_LARGE.get(offset, endPos));
    }
    else
    {
      return array[offset];
    }
  }



  /**
   * Retrieves the specified subset of bytes from the buffer.
   *
   * @param  offset  The offset of the first byte to retrieve.  It must be
   *                 greater than or equal to zero and less than
   *                 {@link #length}.
   * @param  length  The number of bytes to retrieve.  It must be greater than
   *                 or equal to zero, and the sum of {@code offset} and
   *                 {@code length} must be less than or equal to
   *                 {@link #length}.
   *
   * @return  A byte array containing the specified subset of bytes from the
   *          buffer.
   *
   * @throws  IndexOutOfBoundsException  If either the offset or the length is
   *                                     negative, or if the offsset plus the
   *                                     length is greater than or equal to the
   *                                     length of the buffer.
   */
  @NotNull()
  public byte[] bytesAt(final int offset, final int length)
         throws IndexOutOfBoundsException
  {
    if (offset < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_NEGATIVE.get(offset));
    }

    if (length < 0)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_LENGTH_NEGATIVE.get(length));
    }

    if ((offset + length) > endPos)
    {
      throw new IndexOutOfBoundsException(
           ERR_BS_BUFFER_OFFSET_PLUS_LENGTH_TOO_LARGE.get(offset, length,
                endPos));
    }

    final byte[] returnArray = new byte[length];
    System.arraycopy(array, offset, returnArray, 0, length);
    return returnArray;
  }



  /**
   * Indicates whether this buffer starts with the specified set of bytes.
   *
   * @param  bytes  The bytes for which to make the determination.
   *
   * @return  {@code true} if this buffer starts with the specified set of
   *          bytes, or {@code false} if not.
   */
  public boolean startsWith(@NotNull final byte[] bytes)
  {
    if (bytes.length > endPos)
    {
      return false;
    }

    for (int i=0; i < bytes.length; i++)
    {
      if (array[i] != bytes[i])
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Indicates whether this buffer ends with the specified set of bytes.
   *
   * @param  bytes  The bytes for which to make the determination.
   *
   * @return  {@code true} if this buffer ends with the specified set of bytes,
   *          or {@code false} if not.
   */
  public boolean endsWith(@NotNull final byte[] bytes)
  {
    if (bytes.length > endPos)
    {
      return false;
    }

    for (int i=0; i < bytes.length; i++)
    {
      if (array[endPos - bytes.length + i] != bytes[i])
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Returns a new byte array with the content from this buffer.
   *
   * @return  A byte array containing the content from this buffer.
   */
  @NotNull()
  public byte[] toByteArray()
  {
    final byte[] newArray = new byte[endPos];
    System.arraycopy(array, 0, newArray, 0, endPos);
    return newArray;
  }



  /**
   * Returns a new byte string with the content from this buffer.
   *
   * @return  A byte string with the content from this buffer.
   */
  @NotNull()
  public ByteString toByteString()
  {
    return new ASN1OctetString(toByteArray());
  }



  /**
   * Creates an input stream that may be used to read content from this buffer.
   * This buffer should not be altered while the input stream is being used.
   *
   * @return  An input stream that may be used to read content from this buffer.
   */
  @NotNull()
  public InputStream asInputStream()
  {
    return new ByteArrayInputStream(array, 0, endPos);
  }



  /**
   * Reads the contents of the specified file into this buffer, appending it to
   * the end of the buffer.
   *
   * @param  file  The file to be read.
   *
   * @throws  IOException  If an unexpected problem occurs.
   */
  public void readFrom(@NotNull final File file)
         throws IOException
  {
    try (FileInputStream inputStream = new FileInputStream(file))
    {
      readFrom(inputStream);
    }
  }



  /**
   * Reads data from the provided input stream into this buffer, appending it to
   * the end of the buffer.  The entire content of the input stream will be
   * read, but the input stream will not be closed.
   *
   * @param  inputStream  The input stream from which data is to be read.
   *
   * @throws  IOException  If an unexpected problem occurs.
   */
  public void readFrom(@NotNull final InputStream inputStream)
         throws IOException
  {
    final int initialEndPos = endPos;

    try
    {
      while (true)
      {
        int remainingCapacity = capacity - endPos;
        if (remainingCapacity <= 100)
        {
          ensureCapacity(Math.max(100, (2*capacity)));
          remainingCapacity = capacity - endPos;
        }

        final int bytesRead =
             inputStream.read(array, endPos, remainingCapacity);
        if (bytesRead < 0)
        {
          return;
        }

        endPos += bytesRead;
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      endPos = initialEndPos;
      throw e;
    }
  }



  /**
   * Writes the contents of this byte string buffer to the provided output
   * stream.
   *
   * @param  outputStream  The output stream to which the data should be
   *                       written.
   *
   * @throws  IOException  If a problem occurs while writing to the provided
   *                       output stream.
   */
  public void write(@NotNull final OutputStream outputStream)
         throws IOException
  {
    outputStream.write(array, 0, endPos);
  }



  /**
   * Adds the bytes comprising the string representation of the provided long
   * value to the temporary number buffer.
   *
   * @param  l  The long value to be appended.
   *
   * @return  The number of bytes in the string representation of the value.
   */
  private static int getBytes(final long l)
  {
    // NOTE:  This method is probably not as efficient as it could be, but it is
    // more important to avoid the need for memory allocation.
    byte[] b = TEMP_NUMBER_BUFFER.get();
    if (b == null)
    {
      b = new byte[20];
      TEMP_NUMBER_BUFFER.set(b);
    }

    if (l == Long.MIN_VALUE)
    {
      b[0]  = '-';
      b[1]  = '9';
      b[2]  = '2';
      b[3]  = '2';
      b[4]  = '3';
      b[5]  = '3';
      b[6]  = '7';
      b[7]  = '2';
      b[8]  = '0';
      b[9]  = '3';
      b[10] = '6';
      b[11] = '8';
      b[12] = '5';
      b[13] = '4';
      b[14] = '7';
      b[15] = '7';
      b[16] = '5';
      b[17] = '8';
      b[18] = '0';
      b[19] = '8';
      return 20;
    }
    else if (l == 0L)
    {
      b[0] = '0';
      return 1;
    }

    int pos = 0;
    long v = l;
    if (l < 0)
    {
      b[0] = '-';
      pos = 1;
      v = Math.abs(l);
    }

    long divisor;
    if (v <= 9L)
    {
      divisor = 1L;
    }
    else if (v <= 99L)
    {
      divisor = 10L;
    }
    else if (v <= 999L)
    {
      divisor = 100L;
    }
    else if (v <= 9999L)
    {
      divisor = 1000L;
    }
    else if (v <= 99_999L)
    {
      divisor = 10_000L;
    }
    else if (v <= 999_999L)
    {
      divisor = 100_000L;
    }
    else if (v <= 9_999_999L)
    {
      divisor = 1_000_000L;
    }
    else if (v <= 99_999_999L)
    {
      divisor = 10_000_000L;
    }
    else if (v <= 999_999_999L)
    {
      divisor = 100_000_000L;
    }
    else if (v <= 9_999_999_999L)
    {
      divisor = 1_000_000_000L;
    }
    else if (v <= 99_999_999_999L)
    {
      divisor = 10_000_000_000L;
    }
    else if (v <= 999_999_999_999L)
    {
      divisor = 100_000_000_000L;
    }
    else if (v <= 9_999_999_999_999L)
    {
      divisor = 1_000_000_000_000L;
    }
    else if (v <= 99_999_999_999_999L)
    {
      divisor = 10_000_000_000_000L;
    }
    else if (v <= 999_999_999_999_999L)
    {
      divisor = 100_000_000_000_000L;
    }
    else if (v <= 9_999_999_999_999_999L)
    {
      divisor = 1_000_000_000_000_000L;
    }
    else if (v <= 99_999_999_999_999_999L)
    {
      divisor = 10_000_000_000_000_000L;
    }
    else if (v <= 999_999_999_999_999_999L)
    {
      divisor = 100_000_000_000_000_000L;
    }
    else
    {
      divisor = 1_000_000_000_000_000_000L;
    }

    while (true)
    {
      final long digit = v / divisor;
      switch ((int) digit)
      {
        case 0:
          b[pos++] = '0';
          break;
        case 1:
          b[pos++] = '1';
          break;
        case 2:
          b[pos++] = '2';
          break;
        case 3:
          b[pos++] = '3';
          break;
        case 4:
          b[pos++] = '4';
          break;
        case 5:
          b[pos++] = '5';
          break;
        case 6:
          b[pos++] = '6';
          break;
        case 7:
          b[pos++] = '7';
          break;
        case 8:
          b[pos++] = '8';
          break;
        case 9:
          b[pos++] = '9';
          break;
      }

      if (divisor == 1L)
      {
        break;
      }
      else
      {
        v -= (divisor * digit);
        if (v == 0)
        {
          while (divisor > 1L)
          {
            b[pos++] = '0';
            divisor /= 10L;
          }

          break;
        }

        divisor /= 10L;
      }
    }

    return pos;
  }



  /**
   * Retrieves a hash code for this byte array.
   *
   * @return  A hash code for this byte array.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = 0;

    for (int i=0; i < endPos; i++)
    {
      hashCode += array[i];
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is a byte string buffer with contents
   * that are identical to that of this buffer.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          buffer, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof ByteStringBuffer))
    {
      return false;
    }

    final ByteStringBuffer b = (ByteStringBuffer) o;
    if (endPos != b.endPos)
    {
      return false;
    }

    for (int i=0; i < endPos; i++)
    {
      if (array[i] != b.array[i])
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Creates a duplicate of this byte string buffer.  It will have identical
   * content but with a different backing array.  Changes to this byte string
   * buffer will not impact the duplicate, and vice-versa.
   *
   * @return  A duplicate of this byte string buffer.
   */
  @NotNull()
  public ByteStringBuffer duplicate()
  {
    final ByteStringBuffer newBuffer = new ByteStringBuffer(endPos);
    return newBuffer.append(this);
  }



  /**
   * Retrieves a string representation of the contents for this buffer.
   *
   * @return  A string representation of the contents for this buffer.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return StaticUtils.toUTF8String(array, 0, endPos);
  }
}
