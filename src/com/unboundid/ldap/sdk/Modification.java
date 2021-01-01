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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1BufferSet;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSet;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for holding information about an LDAP
 * modification, which describes a change to apply to an attribute.  A
 * modification includes the following elements:
 * <UL>
 *   <LI>A modification type, which describes the type of change to apply.</LI>
 *   <LI>An attribute name, which specifies which attribute should be
 *       updated.</LI>
 *   <LI>An optional set of values to use for the modification.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Modification
       implements Serializable
{
  /**
   * The value array that will be used when the modification should not have any
   * values.
   */
  @NotNull private static final ASN1OctetString[] NO_VALUES =
       new ASN1OctetString[0];



  /**
   * The byte array value array that will be used when the modification does not
   * have any values.
   */
  @NotNull private static final byte[][] NO_BYTE_VALUES = new byte[0][];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5170107037390858876L;



  // The set of values for this modification.
  @NotNull private final ASN1OctetString[] values;

  // The modification type for this modification.
  @NotNull private final ModificationType modificationType;

  // The name of the attribute to target with this modification.
  @NotNull private final String attributeName;



  /**
   * Creates a new LDAP modification with the provided modification type and
   * attribute name.  It will not have any values.
   *
   * @param  modificationType  The modification type for this modification.
   * @param  attributeName     The name of the attribute to target with this
   *                           modification.  It must not be {@code null}.
   */
  public Modification(@NotNull final ModificationType modificationType,
                      @NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = NO_VALUES;
  }



  /**
   * Creates a new LDAP modification with the provided information.
   *
   * @param  modificationType  The modification type for this modification.
   * @param  attributeName     The name of the attribute to target with this
   *                           modification.  It must not be {@code null}.
   * @param  attributeValue    The attribute value for this modification.  It
   *                           must not be {@code null}.
   */
  public Modification(@NotNull final ModificationType modificationType,
                      @NotNull final String attributeName,
                      @NotNull final String attributeValue)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[] { new ASN1OctetString(attributeValue) };
  }



  /**
   * Creates a new LDAP modification with the provided information.
   *
   * @param  modificationType  The modification type for this modification.
   * @param  attributeName     The name of the attribute to target with this
   *                           modification.  It must not be {@code null}.
   * @param  attributeValue    The attribute value for this modification.  It
   *                           must not be {@code null}.
   */
  public Modification(@NotNull final ModificationType modificationType,
                      @NotNull final String attributeName,
                      @NotNull final byte[] attributeValue)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[] { new ASN1OctetString(attributeValue) };
  }



  /**
   * Creates a new LDAP modification with the provided information.
   *
   * @param  modificationType  The modification type for this modification.
   * @param  attributeName     The name of the attribute to target with this
   *                           modification.  It must not be {@code null}.
   * @param  attributeValues   The set of attribute value for this modification.
   *                           It must not be {@code null}.
   */
  public Modification(@NotNull final ModificationType modificationType,
                      @NotNull final String attributeName,
                      @NotNull final String... attributeValues)
  {
    Validator.ensureNotNull(attributeName, attributeValues);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = new ASN1OctetString(attributeValues[i]);
    }
  }



  /**
   * Creates a new LDAP modification with the provided information.
   *
   * @param  modificationType  The modification type for this modification.
   * @param  attributeName     The name of the attribute to target with this
   *                           modification.  It must not be {@code null}.
   * @param  attributeValues   The set of attribute value for this modification.
   *                           It must not be {@code null}.
   */
  public Modification(@NotNull final ModificationType modificationType,
                      @NotNull final String attributeName,
                      @NotNull final byte[]... attributeValues)
  {
    Validator.ensureNotNull(attributeName, attributeValues);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = new ASN1OctetString(attributeValues[i]);
    }
  }



  /**
   * Creates a new LDAP modification with the provided information.
   *
   * @param  modificationType  The modification type for this modification.
   * @param  attributeName     The name of the attribute to target with this
   *                           modification.  It must not be {@code null}.
   * @param  attributeValues   The set of attribute value for this modification.
   *                           It must not be {@code null}.
   */
  public Modification(@NotNull final ModificationType modificationType,
                      @NotNull final String attributeName,
                      @NotNull final ASN1OctetString[] attributeValues)
  {
    this.modificationType = modificationType;
    this.attributeName    = attributeName;
    values                = attributeValues;
  }



  /**
   * Retrieves the modification type for this modification.
   *
   * @return  The modification type for this modification.
   */
  @NotNull()
  public ModificationType getModificationType()
  {
    return modificationType;
  }



  /**
   * Retrieves the attribute for this modification.
   *
   * @return  The attribute for this modification.
   */
  @NotNull()
  public Attribute getAttribute()
  {
    return new Attribute(attributeName,
                         CaseIgnoreStringMatchingRule.getInstance(), values);
  }



  /**
   * Retrieves the name of the attribute to target with this modification.
   *
   * @return  The name of the attribute to target with this modification.
   */
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Indicates whether this modification has at least one value.
   *
   * @return  {@code true} if this modification has one or more values, or
   *          {@code false} if not.
   */
  public boolean hasValue()
  {
    return (values.length > 0);
  }



  /**
   * Retrieves the set of values for this modification as an array of strings.
   *
   * @return  The set of values for this modification as an array of strings.
   */
  @NotNull()
  public String[] getValues()
  {
    if (values.length == 0)
    {
      return StaticUtils.NO_STRINGS;
    }
    else
    {
      final String[] stringValues = new String[values.length];
      for (int i=0; i < values.length; i++)
      {
        stringValues[i] = values[i].stringValue();
      }

      return stringValues;
    }
  }



  /**
   * Retrieves the set of values for this modification as an array of byte
   * arrays.
   *
   * @return  The set of values for this modification as an array of byte
   *          arrays.
   */
  @NotNull()
  public byte[][] getValueByteArrays()
  {
    if (values.length == 0)
    {
      return NO_BYTE_VALUES;
    }
    else
    {
      final byte[][] byteValues = new byte[values.length][];
      for (int i=0; i < values.length; i++)
      {
        byteValues[i] = values[i].getValue();
      }

      return byteValues;
    }
  }



  /**
   * Retrieves the set of values for this modification as an array of ASN.1
   * octet strings.
   *
   * @return  The set of values for this modification as an array of ASN.1 octet
   *          strings.
   */
  @NotNull()
  public ASN1OctetString[] getRawValues()
  {
    return values;
  }



  /**
   * Writes an ASN.1-encoded representation of this modification to the provided
   * ASN.1 buffer.
   *
   * @param  buffer  The ASN.1 buffer to which the encoded representation should
   *                 be written.
   */
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence modSequence = buffer.beginSequence();
    buffer.addEnumerated(modificationType.intValue());

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    buffer.addOctetString(attributeName);

    final ASN1BufferSet valueSet = buffer.beginSet();
    for (final ASN1OctetString v : values)
    {
      buffer.addElement(v);
    }
    valueSet.end();
    attrSequence.end();
    modSequence.end();
  }



  /**
   * Encodes this modification to an ASN.1 sequence suitable for use in the LDAP
   * protocol.
   *
   * @return  An ASN.1 sequence containing the encoded value.
   */
  @NotNull()
  public ASN1Sequence encode()
  {
    final ASN1Element[] attrElements =
    {
      new ASN1OctetString(attributeName),
      new ASN1Set(values)
    };

    final ASN1Element[] modificationElements =
    {
      new ASN1Enumerated(modificationType.intValue()),
      new ASN1Sequence(attrElements)
    };

    return new ASN1Sequence(modificationElements);
  }



  /**
   * Reads and decodes an LDAP modification from the provided ASN.1 stream
   * reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the
   *                 modification.
   *
   * @return  The decoded modification.
   *
   * @throws  LDAPException  If a problem occurs while trying to read or decode
   *                         the modification.
   */
  @NotNull()
  public static Modification readFrom(@NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      Validator.ensureNotNull(reader.beginSequence());
      final ModificationType modType =
           ModificationType.valueOf(reader.readEnumerated());

      Validator.ensureNotNull(reader.beginSequence());
      final String attrName = reader.readString();

      final ArrayList<ASN1OctetString> valueList = new ArrayList<>(5);
      final ASN1StreamReaderSet valueSet = reader.beginSet();
      while (valueSet.hasMoreElements())
      {
        valueList.add(new ASN1OctetString(reader.readBytes()));
      }

      final ASN1OctetString[] values = new ASN1OctetString[valueList.size()];
      valueList.toArray(values);

      return new Modification(modType, attrName, values);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Decodes the provided ASN.1 sequence as an LDAP modification.
   *
   * @param  modificationSequence  The ASN.1 sequence to decode as an LDAP
   *                               modification.  It must not be {@code null}.
   *
   * @return  The decoded LDAP modification.
   *
   * @throws  LDAPException  If a problem occurs while trying to decode the
   *                         provided ASN.1 sequence as an LDAP modification.
   */
  @NotNull()
  public static Modification decode(
                     @NotNull final ASN1Sequence modificationSequence)
         throws LDAPException
  {
    Validator.ensureNotNull(modificationSequence);

    final ASN1Element[] modificationElements = modificationSequence.elements();
    if (modificationElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MOD_DECODE_INVALID_ELEMENT_COUNT.get(
                                   modificationElements.length));
    }

    final int modType;
    try
    {
      final ASN1Enumerated typeEnumerated =
           ASN1Enumerated.decodeAsEnumerated(modificationElements[0]);
      modType = typeEnumerated.intValue();
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_DECODE_CANNOT_PARSE_MOD_TYPE.get(
                StaticUtils.getExceptionMessage(ae)),
           ae);
    }

    final ASN1Sequence attrSequence;
    try
    {
      attrSequence = ASN1Sequence.decodeAsSequence(modificationElements[1]);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_DECODE_CANNOT_PARSE_ATTR.get(
                StaticUtils.getExceptionMessage(ae)),
           ae);
    }

    final ASN1Element[] attrElements = attrSequence.elements();
    if (attrElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_DECODE_INVALID_ATTR_ELEMENT_COUNT.get(attrElements.length));
    }

    final String attrName =
         ASN1OctetString.decodeAsOctetString(attrElements[0]).stringValue();

    final ASN1Set valueSet;
    try
    {
      valueSet = ASN1Set.decodeAsSet(attrElements[1]);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_DECODE_CANNOT_PARSE_ATTR_VALUE_SET.get(
                StaticUtils.getExceptionMessage(ae)), ae);
    }

    final ASN1Element[] valueElements = valueSet.elements();
    final ASN1OctetString[] values = new ASN1OctetString[valueElements.length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = ASN1OctetString.decodeAsOctetString(valueElements[i]);
    }

    return new Modification(ModificationType.valueOf(modType), attrName,
                            values);
  }



  /**
   * Calculates a hash code for this LDAP modification.
   *
   * @return  The generated hash code for this LDAP modification.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = modificationType.intValue() +
         StaticUtils.toLowerCase(attributeName).hashCode();

    for (final ASN1OctetString value : values)
    {
      hashCode += value.hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this LDAP modification.
   * The provided object will only be considered equal if it is an LDAP
   * modification with the same modification type, attribute name, and set of
   * values as this LDAP modification.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this modification,
   *          or {@code false} if not.
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

    if (! (o instanceof Modification))
    {
      return false;
    }

    final Modification mod = (Modification) o;
    if (modificationType != mod.modificationType)
    {
      return false;
    }

    if (! attributeName.equalsIgnoreCase(mod.attributeName))
    {
      return false;
    }

    if (values.length != mod.values.length)
    {
      return false;
    }

    // Look at the values using a byte-for-byte matching.
    for (final ASN1OctetString value : values)
    {
      boolean found = false;
      for (int j = 0; j < mod.values.length; j++)
      {
        if (value.equalsIgnoreType(mod.values[j]))
        {
          found = true;
          break;
        }
      }

      if (!found)
      {
        return false;
      }
    }

    // If we've gotten here, then we can consider the object equal to this LDAP
    // modification.
    return true;
  }



  /**
   * Retrieves a string representation of this LDAP modification.
   *
   * @return  A string representation of this LDAP modification.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this LDAP modification to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this LDAP modification.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPModification(type=");

    switch (modificationType.intValue())
    {
      case 0:
        buffer.append("add");
        break;
      case 1:
        buffer.append("delete");
        break;
      case 2:
        buffer.append("replace");
        break;
      case 3:
        buffer.append("increment");
        break;
      default:
        buffer.append(modificationType);
        break;
    }

    buffer.append(", attr=");
    buffer.append(attributeName);

    if (values.length == 0)
    {
      buffer.append(", values={");
    }
    else if (needsBase64Encoding())
    {
      buffer.append(", base64Values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(Base64.encode(values[i].getValue()));
      }

      buffer.append('\'');
    }
    else
    {
      buffer.append(", values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(values[i].stringValue());
      }

      buffer.append('\'');
    }

    buffer.append("})");
  }



  /**
   * Indicates whether this modification needs to be base64-encoded when
   * represented as LDIF.
   *
   * @return  {@code true} if this modification needs to be base64-encoded when
   *          represented as LDIF, or {@code false} if not.
   */
  private boolean needsBase64Encoding()
  {
    for (final ASN1OctetString s : values)
    {
      if (Attribute.needsBase64Encoding(s.getValue()))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Appends a number of lines comprising the Java source code that can be used
   * to recreate this modification to the given list.  Note that unless a first
   * line prefix and/or last line suffix are provided, this will just include
   * the code for the constructor, starting with "new Modification(" and ending
   * with the closing parenthesis for that constructor.
   *
   * @param  lineList         The list to which the source code lines should be
   *                          added.
   * @param  indentSpaces     The number of spaces that should be used to indent
   *                          the generated code.  It must not be negative.
   * @param  firstLinePrefix  An optional string that should precede
   *                          "new Modification(" on the first line of the
   *                          generated code (e.g., it could be used for an
   *                          attribute assignment, like "Modification m = ").
   *                          It may be {@code null} or empty if there should be
   *                          no first line prefix.
   * @param  lastLineSuffix   An optional suffix that should follow the closing
   *                          parenthesis of the constructor (e.g., it could be
   *                          a semicolon to represent the end of a Java
   *                          statement or a comma to separate it from another
   *                          element in an array).  It may be {@code null} or
   *                          empty if there should be no last line suffix.
   */
  public void toCode(@NotNull final List<String> lineList,
                     final int indentSpaces,
                     @Nullable final String firstLinePrefix,
                     @Nullable final String lastLineSuffix)
  {
    // Generate a string with the appropriate indent.
    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < indentSpaces; i++)
    {
      buffer.append(' ');
    }
    final String indent = buffer.toString();


    // Start the constructor.
    buffer.setLength(0);
    buffer.append(indent);
    if (firstLinePrefix != null)
    {
      buffer.append(firstLinePrefix);
    }
    buffer.append("new Modification(");
    lineList.add(buffer.toString());

    // There will always be a modification type.
    buffer.setLength(0);
    buffer.append(indent);
    buffer.append("     \"ModificationType.");
    buffer.append(modificationType.getName());
    buffer.append(',');
    lineList.add(buffer.toString());


    // There will always be an attribute name.
    buffer.setLength(0);
    buffer.append(indent);
    buffer.append("     \"");
    buffer.append(attributeName);
    buffer.append('"');


    // If the attribute has any values, then include each on its own line.
    // If possible, represent the values as strings, but fall back to using
    // byte arrays if necessary.  But if this is something we might consider a
    // sensitive attribute (like a password), then use fake values in the form
    // "---redacted-value-N---" to indicate that the actual value has been
    // hidden but to still show the correct number of values.
    if (values.length > 0)
    {
      boolean allPrintable = true;

      final ASN1OctetString[] attrValues;
      if (StaticUtils.isSensitiveToCodeAttribute(attributeName))
      {
        attrValues = new ASN1OctetString[values.length];
        for (int i=0; i < values.length; i++)
        {
          attrValues[i] =
               new ASN1OctetString("---redacted-value-" + (i+1) + "---");
        }
      }
      else
      {
        attrValues = values;
        for (final ASN1OctetString v : values)
        {
          if (! StaticUtils.isPrintableString(v.getValue()))
          {
            allPrintable = false;
            break;
          }
        }
      }

      for (final ASN1OctetString v : attrValues)
      {
        buffer.append(',');
        lineList.add(buffer.toString());

        buffer.setLength(0);
        buffer.append(indent);
        buffer.append("     ");
        if (allPrintable)
        {
          buffer.append('"');
          buffer.append(v.stringValue());
          buffer.append('"');
        }
        else
        {
          StaticUtils.byteArrayToCode(v.getValue(), buffer);
        }
      }
    }


    // Append the closing parenthesis and any last line suffix.
    buffer.append(')');
    if (lastLineSuffix != null)
    {
      buffer.append(lastLineSuffix);
    }
    lineList.add(buffer.toString());
  }
}
