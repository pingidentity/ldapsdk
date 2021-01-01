/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.LinkedList;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a mechanism for constructing the string representation of
 * one or more JSON objects by appending elements of those objects into a byte
 * string buffer.  {@code JSONBuffer} instances may be cleared and reused any
 * number of times.  They are not threadsafe and should not be accessed
 * concurrently by multiple threads.
 * <BR><BR>
 * Note that the caller is responsible for proper usage to ensure that the
 * buffer results in a valid JSON encoding.  This includes ensuring that the
 * object begins with the appropriate opening curly brace,  that all objects
 * and arrays are properly closed, that raw values are not used outside of
 * arrays, that named fields are not added into arrays, etc.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class JSONBuffer
       implements Serializable
{
  /**
   * The default maximum buffer size.
   */
  private static final int DEFAULT_MAX_BUFFER_SIZE = 1_048_576;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5946166401452532693L;



  // Indicates whether to format the JSON object across multiple lines rather
  // than putting it all on a single line.
  private final boolean multiLine;

  // Indicates whether we need to add a comma before adding the next element.
  private boolean needComma = false;

  // The buffer to which all data will be written.
  @NotNull private ByteStringBuffer buffer;

  // The maximum buffer size that should be retained.
  private final int maxBufferSize;

  // A list of the indents that we need to use when formatting multi-line
  // objects.
  @NotNull private final LinkedList<String> indents;



  /**
   * Creates a new instance of this JSON buffer with the default maximum buffer
   * size.
   */
  public JSONBuffer()
  {
    this(DEFAULT_MAX_BUFFER_SIZE);
  }



  /**
   * Creates a new instance of this JSON buffer with an optional maximum
   * retained size.  If a maximum size is defined, then this buffer may be used
   * to hold elements larger than that, but when the buffer is cleared it will
   * be shrunk to the maximum size.
   *
   * @param  maxBufferSize  The maximum buffer size that will be retained by
   *                        this JSON buffer.  A value less than or equal to
   *                        zero indicates that no maximum size should be
   *                        enforced.
   */
  public JSONBuffer(final int maxBufferSize)
  {
    this(null, maxBufferSize, false);
  }



  /**
   * Creates a new instance of this JSON buffer that wraps the provided byte
   * string buffer (if provided) and that has an optional maximum retained size.
   * If a maximum size is defined, then this buffer may be used to hold elements
   * larger than that, but when the buffer is cleared it will be shrunk to the
   * maximum size.
   *
   * @param  buffer         The buffer to wrap.  It may be {@code null} if a new
   *                        buffer should be created.
   * @param  maxBufferSize  The maximum buffer size that will be retained by
   *                        this JSON buffer.  A value less than or equal to
   *                        zero indicates that no maximum size should be
   *                        enforced.
   * @param  multiLine      Indicates whether to format JSON objects using a
   *                        user-friendly, formatted, multi-line representation
   *                        rather than constructing the entire element without
   *                        any line breaks.  Note that regardless of the value
   *                        of this argument, there will not be an end-of-line
   *                        marker at the very end of the object.
   */
  public JSONBuffer(@Nullable final ByteStringBuffer buffer,
                    final int maxBufferSize, final boolean multiLine)
  {
    this.multiLine = multiLine;
    this.maxBufferSize = maxBufferSize;

    indents = new LinkedList<>();
    needComma = false;

    if (buffer == null)
    {
      this.buffer = new ByteStringBuffer();
    }
    else
    {
      this.buffer = buffer;
    }
  }



  /**
   * Clears the contents of this buffer.
   */
  public void clear()
  {
    buffer.clear();

    if ((maxBufferSize > 0) && (buffer.capacity() > maxBufferSize))
    {
      buffer.setCapacity(maxBufferSize);
    }

    needComma = false;
    indents.clear();
  }



  /**
   * Replaces the underlying buffer to which the JSON object data will be
   * written.
   *
   * @param  buffer  The underlying buffer to which the JSON object data will be
   *                 written.
   */
  public void setBuffer(@Nullable final ByteStringBuffer buffer)
  {
    if (buffer == null)
    {
      this.buffer = new ByteStringBuffer();
    }
    else
    {
      this.buffer = buffer;
    }

    needComma = false;
    indents.clear();
  }



  /**
   * Retrieves the current length of this buffer in bytes.
   *
   * @return  The current length of this buffer in bytes.
   */
  public int length()
  {
    return buffer.length();
  }



  /**
   * Appends the open curly brace needed to signify the beginning of a JSON
   * object.  This will not include a field name, so it should only be used to
   * start the outermost JSON object, or to start a JSON object contained in an
   * array.
   */
  public void beginObject()
  {
    addComma();
    buffer.append("{ ");
    needComma = false;
    addIndent(2);
  }



  /**
   * Begins a new JSON object that will be used as the value of the specified
   * field.
   *
   * @param  fieldName  The name of the field
   */
  public void beginObject(@NotNull final String fieldName)
  {
    addComma();

    final int startPos = buffer.length();
    JSONString.encodeString(fieldName, buffer);
    final int fieldNameLength = buffer.length() - startPos;

    buffer.append(":{ ");
    needComma = false;
    addIndent(fieldNameLength + 3);
  }



  /**
   * Appends the close curly brace needed to signify the end of a JSON object.
   */
  public void endObject()
  {
    if (needComma)
    {
      buffer.append(' ');
    }

    buffer.append('}');
    needComma = true;
    removeIndent();
  }



  /**
   * Appends the open curly brace needed to signify the beginning of a JSON
   * array.  This will not include a field name, so it should only be used to
   * start a JSON array contained in an array.
   */
  public void beginArray()
  {
    addComma();
    buffer.append("[ ");
    needComma = false;
    addIndent(2);
  }



  /**
   * Begins a new JSON array that will be used as the value of the specified
   * field.
   *
   * @param  fieldName  The name of the field
   */
  public void beginArray(@NotNull final String fieldName)
  {
    addComma();

    final int startPos = buffer.length();
    JSONString.encodeString(fieldName, buffer);
    final int fieldNameLength = buffer.length() - startPos;

    buffer.append(":[ ");
    needComma = false;
    addIndent(fieldNameLength + 3);
  }



  /**
   * Appends the close square bracket needed to signify the end of a JSON array.
   */
  public void endArray()
  {
    if (needComma)
    {
      buffer.append(' ');
    }

    buffer.append(']');
    needComma = true;
    removeIndent();
  }



  /**
   * Appends the provided Boolean value.  This will not include a field name, so
   * it should only be used for Boolean value elements in an array.
   *
   * @param  value  The Boolean value to append.
   */
  public void appendBoolean(final boolean value)
  {
    addComma();
    if (value)
    {
      buffer.append("true");
    }
    else
    {
      buffer.append("false");
    }
    needComma = true;
  }



  /**
   * Appends a JSON field with the specified name and the provided Boolean
   * value.
   *
   * @param  fieldName  The name of the field.
   * @param  value      The Boolean value.
   */
  public void appendBoolean(@NotNull final String fieldName,
                            final boolean value)
  {
    addComma();
    JSONString.encodeString(fieldName, buffer);
    if (value)
    {
      buffer.append(":true");
    }
    else
    {
      buffer.append(":false");
    }

    needComma = true;
  }



  /**
   * Appends the provided JSON null value.  This will not include a field name,
   * so it should only be used for null value elements in an array.
   */
  public void appendNull()
  {
    addComma();
    buffer.append("null");
    needComma = true;
  }



  /**
   * Appends a JSON field with the specified name and a null value.
   *
   * @param  fieldName  The name of the field.
   */
  public void appendNull(@NotNull final String fieldName)
  {
    addComma();
    JSONString.encodeString(fieldName, buffer);
    buffer.append(":null");
    needComma = true;
  }



  /**
   * Appends the provided JSON number value.  This will not include a field
   * name, so it should only be used for number elements in an array.
   *
   * @param  value  The number to add.
   */
  public void appendNumber(@NotNull final BigDecimal value)
  {
    addComma();
    buffer.append(value.toPlainString());
    needComma = true;
  }



  /**
   * Appends the provided JSON number value.  This will not include a field
   * name, so it should only be used for number elements in an array.
   *
   * @param  value  The number to add.
   */
  public void appendNumber(final int value)
  {
    addComma();
    buffer.append(value);
    needComma = true;
  }



  /**
   * Appends the provided JSON number value.  This will not include a field
   * name, so it should only be used for number elements in an array.
   *
   * @param  value  The number to add.
   */
  public void appendNumber(final long value)
  {
    addComma();
    buffer.append(value);
    needComma = true;
  }



  /**
   * Appends the provided JSON number value.  This will not include a field
   * name, so it should only be used for number elements in an array.
   *
   * @param  value  The string representation of the number to add.  It must be
   *                properly formed.
   */
  public void appendNumber(@NotNull final String value)
  {
    addComma();
    buffer.append(value);
    needComma = true;
  }



  /**
   * Appends a JSON field with the specified name and a number value.
   *
   * @param  fieldName  The name of the field.
   * @param  value      The number value.
   */
  public void appendNumber(@NotNull final String fieldName,
                           @NotNull final BigDecimal value)
  {
    addComma();
    JSONString.encodeString(fieldName, buffer);
    buffer.append(':');
    buffer.append(value.toPlainString());
    needComma = true;
  }



  /**
   * Appends a JSON field with the specified name and a number value.
   *
   * @param  fieldName  The name of the field.
   * @param  value      The number value.
   */
  public void appendNumber(@NotNull final String fieldName, final int value)
  {
    addComma();
    JSONString.encodeString(fieldName, buffer);
    buffer.append(':');
    buffer.append(value);
    needComma = true;
  }



  /**
   * Appends a JSON field with the specified name and a number value.
   *
   * @param  fieldName  The name of the field.
   * @param  value      The number value.
   */
  public void appendNumber(@NotNull final String fieldName, final long value)
  {
    addComma();
    JSONString.encodeString(fieldName, buffer);
    buffer.append(':');
    buffer.append(value);
    needComma = true;
  }



  /**
   * Appends a JSON field with the specified name and a number value.
   *
   * @param  fieldName  The name of the field.
   * @param  value      The string representation of the number ot add.  It must
   *                    be properly formed.
   */
  public void appendNumber(@NotNull final String fieldName,
                           @NotNull final String value)
  {
    addComma();
    JSONString.encodeString(fieldName, buffer);
    buffer.append(':');
    buffer.append(value);
    needComma = true;
  }



  /**
   * Appends the provided JSON string value.  This will not include a field
   * name, so it should only be used for string elements in an array.
   *
   * @param  value  The value to add.
   */
  public void appendString(@NotNull final String value)
  {
    addComma();
    JSONString.encodeString(value, buffer);
    needComma = true;
  }



  /**
   * Appends a JSON field with the specified name and a null value.
   *
   * @param  fieldName  The name of the field.
   * @param  value      The value to add.
   */
  public void appendString(@NotNull final String fieldName,
                           @NotNull final String value)
  {
    addComma();
    JSONString.encodeString(fieldName, buffer);
    buffer.append(':');
    JSONString.encodeString(value, buffer);
    needComma = true;
  }



  /**
   * Appends the provided JSON value.  This will not include a field name, so it
   * should only be used for elements in an array.
   *
   * @param  value  The value to append.
   */
  public void appendValue(@NotNull final JSONValue value)
  {
    value.appendToJSONBuffer(this);
  }



  /**
   * Appends the provided JSON value.  This will not include a field name, so it
   * should only be used for elements in an array.
   *
   * @param  fieldName  The name of the field.
   * @param  value      The value to append.
   */
  public void appendValue(@NotNull final String fieldName,
                          @NotNull final JSONValue value)
  {
    value.appendToJSONBuffer(fieldName, this);
  }



  /**
   * Retrieves the byte string buffer that backs this JSON buffer.
   *
   * @return  The byte string buffer that backs this JSON buffer.
   */
  @NotNull()
  public ByteStringBuffer getBuffer()
  {
    return buffer;
  }



  /**
   * Writes the current contents of this JSON buffer to the provided output
   * stream.  Note that based on the current contents of this buffer and the way
   * it has been used so far, it may not represent a valid JSON object.
   *
   * @param  outputStream  The output stream to which the current contents of
   *                       this JSON buffer should be written.
   *
   * @throws  IOException  If a problem is encountered while writing to the
   *                       provided output stream.
   */
  public void writeTo(@NotNull final OutputStream outputStream)
         throws IOException
  {
    buffer.write(outputStream);
  }



  /**
   * Retrieves a string representation of the current contents of this JSON
   * buffer.  Note that based on the current contents of this buffer and the way
   * it has been used so far, it may not represent a valid JSON object.
   *
   * @return  A string representation of the current contents of this JSON
   *          buffer.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return buffer.toString();
  }



  /**
   * Retrieves the current contents of this JSON buffer as a JSON object.
   *
   * @return  The JSON object decoded from the contents of this JSON buffer.
   *
   * @throws  JSONException  If the buffer does not currently contain exactly
   *                         one valid JSON object.
   */
  @NotNull()
  public JSONObject toJSONObject()
         throws JSONException
  {
    return new JSONObject(buffer.toString());
  }



  /**
   * Adds a comma and line break to the buffer if appropriate.
   */
  private void addComma()
  {
    if (needComma)
    {
      buffer.append(',');
      if (multiLine)
      {
        buffer.append(StaticUtils.EOL_BYTES);
        buffer.append(indents.getLast());
      }
      else
      {
        buffer.append(' ');
      }
    }
  }



  /**
   * Adds an indent to the set of indents of appropriate.
   *
   * @param  size  The number of spaces to indent.
   */
  private void addIndent(final int size)
  {
    if (multiLine)
    {
      final char[] spaces = new char[size];
      Arrays.fill(spaces, ' ');
      final String indentStr = new String(spaces);

      if (indents.isEmpty())
      {
        indents.add(indentStr);
      }
      else
      {
        indents.add(indents.getLast() + indentStr);
      }
    }
  }



  /**
   * Removes an indent from the set of indents of appropriate.
   */
  private void removeIndent()
  {
    if (multiLine && (! indents.isEmpty()))
    {
      indents.removeLast();
    }
  }
}
