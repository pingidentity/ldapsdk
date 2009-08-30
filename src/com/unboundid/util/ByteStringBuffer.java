/*
 * Copyright 2008-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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



import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Arrays;

import com.unboundid.asn1.ASN1OctetString;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a growable byte array to which data can be appended.
 * Methods in this class are not synchronized.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ByteStringBuffer
       implements Serializable
{
  /**
   * The default initial capacity for this buffer.
   */
  private static final int DEFAULT_INITIAL_CAPACITY = 20;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2899392249591230998L;



  // The backing array for this buffer.
  private byte[] array;

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
   * Appends the provided byte to this buffer.
   *
   * @param  b  The byte to be appended to this buffer.
   *
   * @return  A reference to this buffer.
   */
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
  public ByteStringBuffer append(final byte[] b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer append(final byte[] b, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
      debugCodingError(e);
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
  public ByteStringBuffer append(final ByteString b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer append(final ByteStringBuffer buffer)
         throws NullPointerException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer append(final char[] c)
         throws NullPointerException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer append(final char[] c, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
      debugCodingError(e);
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
          append(String.valueOf(c, pos, (off + len - pos)));
          break;
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
  public ByteStringBuffer append(final CharSequence s)
         throws NullPointerException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      debugCodingError(e);
      throw e;
    }

    final int length = s.length();
    ensureCapacity(endPos + length);
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      final byte b = (byte) (c & 0x7F);
      if (b == c)
      {
        array[endPos++] = b;
      }
      else
      {
        append(StaticUtils.getBytes(s.subSequence(i, length).toString()));
        break;
      }
    }

    return this;
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
      debugCodingError(e);
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
  public ByteStringBuffer insert(final int pos, final byte[] b)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer insert(final int pos, final byte[] b, final int off,
                                 final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
      debugCodingError(e);
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
   * @throws  NullPointerException  If the provided buffer is {@code null}.
   *
   * @throws  IndexOutOfBoundsException  If the specified position is negative
   *                                     or greater than the current length.
   */
  public ByteStringBuffer insert(final int pos, final ByteString b)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer insert(final int pos, final ByteStringBuffer buffer)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      debugCodingError(e);
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
      debugCodingError(e);
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
  public ByteStringBuffer insert(final int pos, final char[] c)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer insert(final int pos, final char[] c, final int off,
                                 final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer insert(final int pos, final CharSequence s)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      debugCodingError(e);
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
      debugCodingError(e);
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
   * Sets the contents of this buffer to include only the provided byte.
   *
   * @param  b  The byte to use as the content for this buffer.
   *
   * @return  A reference to this buffer.
   */
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
  public ByteStringBuffer set(final byte[] b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer set(final byte[] b, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
      debugCodingError(e);
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
  public ByteStringBuffer set(final ByteString b)
         throws NullPointerException
  {
    if (b == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BYTE_STRING_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer set(final ByteStringBuffer buffer)
         throws NullPointerException
  {
    if (buffer == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_BUFFER_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer set(final char[] c)
         throws NullPointerException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
  public ByteStringBuffer set(final char[] c, final int off, final int len)
         throws NullPointerException, IndexOutOfBoundsException
  {
    if (c == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_ARRAY_NULL.get());
      debugCodingError(e);
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
      debugCodingError(e);
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
  public ByteStringBuffer set(final CharSequence s)
         throws NullPointerException
  {
    if (s == null)
    {
      final NullPointerException e =
           new NullPointerException(ERR_BS_BUFFER_CHAR_SEQUENCE_NULL.get());
      debugCodingError(e);
      throw e;
    }

    endPos = 0;
    return append(s);
  }



  /**
   * Clears the contents of this buffer.
   *
   * @return  A reference to this buffer.
   */
  public ByteStringBuffer clear()
  {
    endPos = 0;
    return this;
  }



  /**
   * Retrieves the current backing array for this buffer.  The data will begin
   * at position 0 and will contain {@link ByteStringBuffer#length} bytes.
   *
   * @return  The current backing array for this buffer.
   */
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
      debugCodingError(e);
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
      debugCodingError(e);
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
   * Returns a new byte array with the content form this buffer.
   *
   * @return  A byte array containing the content from this buffer.
   */
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
  public ByteString toByteString()
  {
    return new ASN1OctetString(array, 0, endPos);
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
  public void write(final OutputStream outputStream)
         throws IOException
  {
    outputStream.write(array, 0, endPos);
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
  public boolean equals(final Object o)
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
  public String toString()
  {
    return StaticUtils.toUTF8String(array, 0, endPos);
  }
}
