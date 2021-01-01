/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collection;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Messages.*;



/**
 * This class provides an ASN.1 set element, which is used to hold a set of
 * zero or more other elements (potentially including additional "envelope"
 * element types like other sequences and/or sets) in which the order of those
 * elements should not be considered significant.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1Set
       extends ASN1Element
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -523497075310394409L;



  /*
   * NOTE:  This class uses lazy initialization for the encoded value.  The
   * encoded value should only be needed by the getValue() method, which is used
   * by ASN1Element.encode().  Even though this class is externally immutable,
   * that does not by itself make it completely threadsafe, because weirdness in
   * the Java memory model could allow the assignment to be performed out of
   * order.  By passing the value through a volatile variable any time the value
   * is set other than in the constructor (which will always be safe) we ensure
   * that this reordering cannot happen.
   *
   * In the majority of cases, passing the value through assignments to
   * valueBytes through a volatile variable is much faster than declaring
   * valueBytes itself to be volatile because a volatile variable cannot be held
   * in CPU caches or registers and must only be accessed from memory visible to
   * all threads.  Since the value may be read much more often than it is
   * written, passing it through a volatile variable rather than making it
   * volatile directly can help avoid that penalty when possible.
   */



  // The set of ASN.1 elements contained in this set.
  @NotNull private final ASN1Element[] elements;

  // The encoded representation of the value, if available.
  @Nullable private byte[] encodedValue;

  // A volatile variable used to guard publishing the encodedValue array.  See
  // the note above to explain why this is needed.
  @Nullable private volatile byte[] encodedValueGuard;



  /**
   * Creates a new ASN.1 set with the default BER type and no encapsulated
   * elements.
   */
  public ASN1Set()
  {
    super(ASN1Constants.UNIVERSAL_SET_TYPE);

    elements     = ASN1Constants.NO_ELEMENTS;
    encodedValue = ASN1Constants.NO_VALUE;
  }



  /**
   * Creates a new ASN.1 set with the specified BER type and no encapsulated
   * elements.
   *
   * @param  type  The BER type to use for this element.
   */
  public ASN1Set(final byte type)
  {
    super(type);

    elements     = ASN1Constants.NO_ELEMENTS;
    encodedValue = ASN1Constants.NO_VALUE;
  }



  /**
   * Creates a new ASN.1 set with the default BER type and the provided set of
   * elements.
   *
   * @param  elements  The set of elements to include in this set.
   */
  public ASN1Set(@Nullable final ASN1Element... elements)
  {
    super(ASN1Constants.UNIVERSAL_SET_TYPE);

    if (elements == null)
    {
      this.elements = ASN1Constants.NO_ELEMENTS;
    }
    else
    {
      this.elements = elements;
    }

    encodedValue = null;
  }



  /**
   * Creates a new ASN.1 set with the default BER type and the provided set of
   * elements.
   *
   * @param  elements  The set of elements to include in this set.
   */
  public ASN1Set(@Nullable final Collection<? extends ASN1Element> elements)
  {
    super(ASN1Constants.UNIVERSAL_SET_TYPE);

    if ((elements == null) || elements.isEmpty())
    {
      this.elements = ASN1Constants.NO_ELEMENTS;
    }
    else
    {
      this.elements = new ASN1Element[elements.size()];
      elements.toArray(this.elements);
    }

    encodedValue = null;
  }



  /**
   * Creates a new ASN.1 set with the specified BER type and the provided set of
   * elements.
   *
   * @param  type      The BER type to use for this element.
   * @param  elements  The set of elements to include in this set.
   */
  public ASN1Set(final byte type, @Nullable final ASN1Element... elements)
  {
    super(type);

    if (elements == null)
    {
      this.elements = ASN1Constants.NO_ELEMENTS;
    }
    else
    {
      this.elements = elements;
    }

    encodedValue = null;
  }



  /**
   * Creates a new ASN.1 set with the specified BER type and the provided set of
   * elements.
   *
   * @param  type      The BER type to use for this element.
   * @param  elements  The set of elements to include in this set.
   */
  public ASN1Set(final byte type,
                 @Nullable final Collection<? extends ASN1Element> elements)
  {
    super(type);

    if ((elements == null) || elements.isEmpty())
    {
      this.elements = ASN1Constants.NO_ELEMENTS;
    }
    else
    {
      this.elements = new ASN1Element[elements.size()];
      elements.toArray(this.elements);
    }

    encodedValue = null;
  }



  /**
   * Creates a new ASN.1 set with the specified type, set of elements, and
   * encoded value.
   *
   * @param  type      The BER type to use for this element.
   * @param  elements  The set of elements to include in this set.
   * @param  value     The pre-encoded value for this element.
   */
  private ASN1Set(final byte type,
                  @NotNull final ASN1Element[] elements,
                  @NotNull final byte[] value)
  {
    super(type);

    this.elements = elements;
    encodedValue  = value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  byte[] getValueArray()
  {
    return getValue();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  int getValueOffset()
  {
    return 0;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getValueLength()
  {
    return getValue().length;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public byte[] getValue()
  {
    if (encodedValue == null)
    {
      encodedValueGuard = ASN1Sequence.encodeElements(elements);
      encodedValue      = encodedValueGuard;
    }

    return encodedValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void encodeTo(@NotNull final ByteStringBuffer buffer)
  {
    buffer.append(getType());

    if (elements.length == 0)
    {
      buffer.append((byte) 0x00);
      return;
    }

    // In this case, it will likely be faster to just go ahead and append
    // encoded representations of all of the elements and insert the length
    // later once we know it.
    final int originalLength = buffer.length();
    for (final ASN1Element e : elements)
    {
      e.encodeTo(buffer);
    }

    buffer.insert(originalLength,
                  encodeLength(buffer.length() - originalLength));
  }



  /**
   * Retrieves the set of encapsulated elements held in this set.
   *
   * @return  The set of encapsulated elements held in this set.
   */
  @NotNull()
  public ASN1Element[] elements()
  {
    return elements;
  }



  /**
   * Decodes the contents of the provided byte array as a set element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 set element.
   *
   * @return  The decoded ASN.1 set element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a set
   *                         element.
   */
  @NotNull()
  public static ASN1Set decodeAsSet(@NotNull final byte[] elementBytes)
         throws ASN1Exception
  {
    try
    {
      int valueStartPos = 2;
      int length = (elementBytes[1] & 0x7F);
      if (length != elementBytes[1])
      {
        final int numLengthBytes = length;

        length = 0;
        for (int i=0; i < numLengthBytes; i++)
        {
          length <<= 8;
          length |= (elementBytes[valueStartPos++] & 0xFF);
        }
      }

      if ((elementBytes.length - valueStartPos) != length)
      {
        throw new ASN1Exception(ERR_ELEMENT_LENGTH_MISMATCH.get(length,
                                     (elementBytes.length - valueStartPos)));
      }

      final byte[] value = new byte[length];
      System.arraycopy(elementBytes, valueStartPos, value, 0, length);

      int numElements = 0;
      final ArrayList<ASN1Element> elementList = new ArrayList<>(5);
      try
      {
        int pos = 0;
        while (pos < value.length)
        {
          final byte type = value[pos++];

          final byte firstLengthByte = value[pos++];
          int l = (firstLengthByte & 0x7F);
          if (l != firstLengthByte)
          {
            final int numLengthBytes = l;
            l = 0;
            for (int i=0; i < numLengthBytes; i++)
            {
              l <<= 8;
              l |= (value[pos++] & 0xFF);
            }
          }

          final int posPlusLength = pos + l;
          if ((l < 0) || (posPlusLength < 0) || (posPlusLength > value.length))
          {
            throw new ASN1Exception(
                 ERR_SET_BYTES_DECODE_LENGTH_EXCEEDS_AVAILABLE.get());
          }

          elementList.add(new ASN1Element(type, value, pos, l));
          pos += l;
          numElements++;
        }
      }
      catch (final ASN1Exception ae)
      {
        throw ae;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ASN1Exception(ERR_SET_BYTES_DECODE_EXCEPTION.get(e), e);
      }

      int i = 0;
      final ASN1Element[] elements = new ASN1Element[numElements];
      for (final ASN1Element e : elementList)
      {
        elements[i++] = e;
      }

      return new ASN1Set(elementBytes[0], elements, value);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw ae;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ASN1Exception(ERR_ELEMENT_DECODE_EXCEPTION.get(e), e);
    }
  }



  /**
   * Decodes the provided ASN.1 element as a set element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 set element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a set
   *                         element.
   */
  @NotNull()
  public static ASN1Set decodeAsSet(@NotNull final ASN1Element element)
         throws ASN1Exception
  {
    int numElements = 0;
    final ArrayList<ASN1Element> elementList = new ArrayList<>(5);
    final byte[] value = element.getValue();

    try
    {
      int pos = 0;
      while (pos < value.length)
      {
        final byte type = value[pos++];

        final byte firstLengthByte = value[pos++];
        int length = (firstLengthByte & 0x7F);
        if (length != firstLengthByte)
        {
          final int numLengthBytes = length;
          length = 0;
          for (int i=0; i < numLengthBytes; i++)
          {
            length <<= 8;
            length |= (value[pos++] & 0xFF);
          }
        }

        final int posPlusLength = pos + length;
        if ((length < 0) || (posPlusLength < 0) ||
            (posPlusLength > value.length))
        {
          throw new ASN1Exception(
               ERR_SET_DECODE_LENGTH_EXCEEDS_AVAILABLE.get(
                    String.valueOf(element)));
        }

        elementList.add(new ASN1Element(type, value, pos, length));
        pos += length;
        numElements++;
      }
    }
    catch (final ASN1Exception ae)
    {
      throw ae;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ASN1Exception(
           ERR_SET_DECODE_EXCEPTION.get(String.valueOf(element), e), e);
    }

    int i = 0;
    final ASN1Element[] elements = new ASN1Element[numElements];
    for (final ASN1Element e : elementList)
    {
      elements[i++] = e;
    }

    return new ASN1Set(element.getType(), elements, value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append('[');
    for (int i=0; i < elements.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }
      elements[i].toString(buffer);
    }
    buffer.append(']');
  }
}
