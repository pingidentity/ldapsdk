/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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


import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used to represent an
 * argument provided to a method or constructor.  It may also be used to
 * represent an element in an array.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ToCodeArgHelper
{
  // The lines that comprise the string representations to use for the
  // argument, with all appropriate formatting applied.  The first line will
  // not be indented.  If there are multiple lines, then subsequent lines may be
  // indented relative to the first line.
  @NotNull private final List<String> argStrings;

  // An optional comment that may help clarify the argument.
  @Nullable private final String comment;



  /**
   * Creates a new argument with the provided information.
   *
   * @param  argString  The string representation to use for the argument, with
   *                    all appropriate formatting applied.  It must not be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   */
  private ToCodeArgHelper(@NotNull final String argString,
                          @Nullable final String comment)
  {
    argStrings = Collections.singletonList(argString);
    this.comment = comment;
  }



  /**
   * Creates a new argument with the provided information.
   *
   * @param  argStrings  The list of strings to use for the argument, with
   *                     all appropriate formatting applied.  It must not be
   *                     {@code null} or empty.
   * @param  comment     A comment that may help clarify the argument.  It may
   *                     be {@code null} if there should be no comment.
   */
  private ToCodeArgHelper(@NotNull final List<String> argStrings,
                          @Nullable final String comment)
  {
    this.argStrings = argStrings;
    this.comment = comment;
  }



  /**
   * Creates an argument for a byte literal value.  It will be represented as
   * a hexadecimal literal (starting with "0x"), and will be prefixed by
   * "(byte)" if necessary.
   *
   * @param  b               The byte value for the argument.
   * @param  includeComment  Indicates whether to attempt to generate a comment
   *                         for the byte.  If this is {@code true} and the byte
   *                         represents a printable ASCII character, then the
   *                         generated comment will consist of that character
   *                         enclosed in quotation marks.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createByte(final byte b,
                                           final boolean includeComment)
  {
    String s = "0x" + StaticUtils.toHex(b);
    if ((b & 0x80) != 0x00)
    {
      s = "(byte) " + s;
    }

    final String comment;
    if (includeComment && StaticUtils.isPrintableString(new byte[] { b }))
    {
      comment = "\"" + ((char) b) + '"';
    }
    else
    {
      comment = null;
    }

    return new ToCodeArgHelper(s, comment);
  }



  /**
   * Creates an argument for a byte array.  If the array is non-empty, then it
   * will be represented with multiple lines, with the first line being
   * "new byte[]", the second "{", then the hexadecimal literal representation
   * of each byte on its own line, and then a last line of "}".
   *
   * @param  b                The byte array value for the argument.  It may be
   *                          {@code null}.
   * @param  includeComments  Indicates whether to attempt to generate a comment
   *                          for each byte in the array.  If this is
   *                          {@code true}, then all bytes that represent
   *                          printable characters will have a generated comment
   *                          consisting of that character enclosed in quotation
   *                          marks.
   * @param  comment          A comment to use for the overall array.  It may be
   *                          {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createByteArray(@Nullable final byte[] b,
                                                final boolean includeComments,
                                                @Nullable final String comment)
  {
    return new ToCodeArgHelper(getByteArrayLines(b, includeComments), comment);
  }



  /**
   * Retrieves the lines that comprise the string representation of the provided
   * byte array.  If the array is non-empty, then it will be represented with
   * multiple lines, with the first line being "new byte[]", the second "{",
   * then the hexadecimal literal representation of each byte on its own line,
   * and then a last line of "}".
   *
   * @param  b                The byte array value for the argument.  It may be
   *                          {@code null}.
   * @param  includeComments  Indicates whether to attempt to generate a comment
   *                          for each byte in the array.  If this is
   *                          {@code true}, then all bytes that represent
   *                          printable characters will have a generated comment
   *                          consisting of that character enclosed in quotation
   *                          marks.
   *
   * @return  The list of lines that comprise the string representation of the
   *          provided byte array.
   */
  @NotNull()
  private static List<String> getByteArrayLines(@Nullable final byte[] b,
                                                final boolean includeComments)
  {
    if (b == null)
    {
      return Collections.singletonList("(byte[]) null");
    }

    if (b.length == 0)
    {
      return Collections.singletonList("new byte[0]");
    }

    final ArrayList<String> lines = new ArrayList<>(3 + b.length);
    lines.add("new byte[]");
    lines.add("{");

    final byte[] oneByteString = new byte[1];
    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < b.length; i++)
    {
      buffer.setLength(0);
      buffer.append("  ");

      if ((b[i] & 0x80) != 0x00)
      {
        buffer.append("(byte) 0x");
        StaticUtils.toHex(b[i], buffer);
        if (i < (b.length-1))
        {
          buffer.append(',');
        }
      }
      else
      {
        buffer.append("0x");
        StaticUtils.toHex(b[i], buffer);
        if (i < (b.length-1))
        {
          buffer.append(',');
        }

        oneByteString[0] = b[i];
        if (includeComments && StaticUtils.isPrintableString(oneByteString))
        {
          buffer.append(" // \"");
          buffer.append((char) b[i]);
          buffer.append('"');
        }
      }
      lines.add(buffer.toString());
    }

    lines.add("}");
    return lines;
  }



  /**
   * Creates an argument for a boolean literal value.
   *
   * @param  b          The boolean value for the argument.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createBoolean(final boolean b,
                                              @Nullable final String comment)
  {
    return new ToCodeArgHelper((b ? "true" : "false"), comment);
  }



  /**
   * Creates an argument for a literal value of any integer data type.
   *
   * @param  i          The integer value for the argument.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createInteger(final long i,
                                              @Nullable final String comment)
  {
    String valueString = String.valueOf(i);
    if ((i > Integer.MAX_VALUE) || (i < Integer.MIN_VALUE))
    {
      valueString += 'L';
    }

    return new ToCodeArgHelper(valueString, comment);
  }



  /**
   * Creates an argument for a String literal value.  If it is {@code null},
   * then it will be represented as "(String) null" without the quotation marks.
   * If it is non-{@code null}, then it will be surrounded by quotation marks
   * and any embedded quotes will be escaped.
   *
   * @param  s          The string value for the argument.  It may be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createString(@Nullable final String s,
                                             @Nullable final String comment)
  {
    if (s == null)
    {
      return new ToCodeArgHelper("(String) null", comment);
    }
    else
    {
      return new ToCodeArgHelper('"' + s.replace("\"", "\\\"") + '"', comment);
    }
  }



  /**
   * Creates an argument for an ASN.1 octet string value.
   *
   * @param  s          The ASN.1 octet string value for the argument.  It may
   *                    be {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createASN1OctetString(
                                     @Nullable final ASN1OctetString s,
                                     @Nullable final String comment)
  {
    if (s == null)
    {
      return new ToCodeArgHelper("(ASN1OctetString) null", comment);
    }
    else
    {
      final ArrayList<String> lines = new ArrayList<>(10);

      final boolean universalType =
           (s.getType() == ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE);

      final byte[] valueBytes = s.getValue();
      if (valueBytes.length == 0)
      {
        if (universalType)
        {
          lines.add("new ASN1OctetString()");
        }
        else
        {
          lines.add("new ASN1OctetString(");
          lines.add("     (byte) 0x" + StaticUtils.toHex(s.getType()) + ')');
        }
      }
      else
      {
        lines.add("new ASN1OctetString(");
        if (! universalType)
        {
          lines.add("     (byte) 0x" + StaticUtils.toHex(s.getType()) + ',');
        }

        final boolean isPrintable = StaticUtils.isPrintableString(valueBytes);
        if (isPrintable)
        {
          lines.add("     \"" + s.stringValue() + "\")");
        }
        else
        {
          final StringBuilder line = new StringBuilder();
          final Iterator<String> iterator =
               getByteArrayLines(valueBytes, true).iterator();
          while (iterator.hasNext())
          {
            line.setLength(0);
            line.append("     ");
            line.append(iterator.next());

            if (! iterator.hasNext())
            {
              line.append(')');
            }

            lines.add(line.toString());
          }
        }
      }

      return new ToCodeArgHelper(lines, comment);
    }
  }



  /**
   * Creates an argument for a modification type value.
   *
   * @param  t          The modification type value for the argument.  It may
   *                    be {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createModificationType(
                                     @Nullable final ModificationType t,
                                     @Nullable final String comment)
  {
    if (t == null)
    {
      return new ToCodeArgHelper("(ModificationType) null", comment);
    }

    final ModificationType definedType =
         ModificationType.definedValueOf(t.intValue());
    if (definedType == null)
    {
      return new ToCodeArgHelper(
           "ModificationType.valueOf(" + t.intValue() + ')', comment);
    }
    else
    {
      return new ToCodeArgHelper("ModificationType." + definedType.getName(),
           comment);
    }
  }



  /**
   * Creates an argument for a search scope value.
   *
   * @param  s          The search scope value for the argument.  It may be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createScope(@Nullable final SearchScope s,
                                            @Nullable final String comment)
  {
    if (s == null)
    {
      return new ToCodeArgHelper("(SearchScope) null", comment);
    }

    final SearchScope definedScope = SearchScope.definedValueOf(s.intValue());
    if (definedScope == null)
    {
      return new ToCodeArgHelper("SearchScope.valueOf(" + s.intValue() + ')',
           comment);
    }
    else
    {
      return new ToCodeArgHelper("SearchScope." + definedScope.getName(),
           comment);
    }
  }



  /**
   * Creates an argument for a dereference policy value.
   *
   * @param  p          The dereference policy value for the argument.  It may
   *                    be {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createDerefPolicy(
              @Nullable final DereferencePolicy p,
              @Nullable final String comment)
  {
    if (p == null)
    {
      return new ToCodeArgHelper("(DereferencePolicy) null", comment);
    }

    final DereferencePolicy definedPolicy =
         DereferencePolicy.definedValueOf(p.intValue());
    if (definedPolicy == null)
    {
      return new ToCodeArgHelper(
           "DereferencePolicy.valueOf(" + p.intValue() + ')', comment);
    }
    else
    {
      return new ToCodeArgHelper("DereferencePolicy." + definedPolicy.getName(),
           comment);
    }
  }



  /**
   * Creates an argument for an attribute.
   *
   * @param  a          The attribute value for the argument.  It may be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createAttribute(@Nullable final Attribute a,
                                                @Nullable final String comment)
  {
    if (a == null)
    {
      return new ToCodeArgHelper("(Attribute) null", comment);
    }

    if (! a.hasValue())
    {
      return new ToCodeArgHelper(
           "new Attribute(\"" + a.getName() + "\")",
           comment);
    }

    final ASN1OctetString[] rawValues = a.getRawValues();
    final ArrayList<String> lines = new ArrayList<>(2 + rawValues.length);
    lines.add("new Attribute(");
    lines.add("     \"" + a.getName() + "\",");

    // FIXME -- Should we make any attempt to use a matching rule here?

    if (StaticUtils.isSensitiveToCodeAttribute(a.getName()))
    {
      if (rawValues.length == 1)
      {
        lines.add("     \"---redacted-value---\")");
      }
      else
      {
        for (int i=1; i <= rawValues.length; i++)
        {
          final String suffix;
          if (i == rawValues.length)
          {
            suffix = ")";
          }
          else
          {
            suffix = ",";
          }

          lines.add("     \"---redacted-value-" + i + "---\"" + suffix);
        }
      }
    }
    else
    {
      if (allPrintable(rawValues))
      {
        for (int i=0; i < rawValues.length; i++)
        {
          final String suffix;
          if (i == (rawValues.length-1))
          {
            suffix = ")";
          }
          else
          {
            suffix = ",";
          }

          lines.add("     \"" +
               rawValues[i].stringValue().replace("\"", "\\\"") + '"' + suffix);
        }
      }
      else
      {
        for (int i=0; i < rawValues.length; i++)
        {
          final String suffix;
          if (i < (rawValues.length-1))
          {
            suffix = ",";
          }
          else
          {
            suffix = ")";
          }

          final Iterator<String> byteArrayLineIterator =
               getByteArrayLines(rawValues[i].getValue(), true).iterator();
          while (byteArrayLineIterator.hasNext())
          {
            final String s = byteArrayLineIterator.next();
            if (byteArrayLineIterator.hasNext())
            {
              lines.add("     " + s);
            }
            else
            {
              lines.add("     " + s + suffix);
            }
          }
        }
      }
    }

    return new ToCodeArgHelper(lines, comment);
  }



  /**
   * Creates an argument for a modification.
   *
   * @param  m          The modification value for the argument.  It may be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createModification(
                                     @Nullable final Modification m,
                                     @Nullable final String comment)
  {
    if (m == null)
    {
      return new ToCodeArgHelper("(Modification) null", comment);
    }

    final ASN1OctetString[] rawValues = m.getRawValues();
    final ArrayList<String> lines = new ArrayList<>(3 + rawValues.length);

    lines.add("new Modification(");
    lines.add("     " +  createModificationType(m.getModificationType(),
         null).getLines().get(0) + ',');

    if (rawValues.length == 0)
    {
      lines.add("     \"" + m.getAttributeName() + "\")");
    }
    else
    {
      lines.add("     \"" + m.getAttributeName() + "\",");

      if (StaticUtils.isSensitiveToCodeAttribute(m.getAttributeName()))
      {
        if (rawValues.length == 1)
        {
          lines.add("     \"---redacted-value---\")");
        }
        else
        {
          for (int i=1; i <= rawValues.length; i++)
          {
            final String suffix;
            if (i == rawValues.length)
            {
              suffix = ")";
            }
            else
            {
              suffix = ",";
            }

            lines.add("     \"---redacted-value-" + i + "---\"" + suffix);
          }
        }
      }
      else if (allPrintable(rawValues))
      {
        for (int i=0; i < rawValues.length; i++)
        {
          final String suffix;
          if (i == (rawValues.length-1))
          {
            suffix = ")";
          }
          else
          {
            suffix = ",";
          }

          lines.add("     \"" +
               rawValues[i].stringValue().replace("\"", "\\\"") + '"' + suffix);
        }
      }
      else
      {
        for (int i=0; i < rawValues.length; i++)
        {
          final String suffix;
          if (i == (rawValues.length-1))
          {
            suffix = ")";
          }
          else
          {
            suffix = ",";
          }

          final Iterator<String> byteArrayLineIterator =
               getByteArrayLines(rawValues[i].getValue(), true).iterator();
          while (byteArrayLineIterator.hasNext())
          {
            final String s = byteArrayLineIterator.next();
            if (byteArrayLineIterator.hasNext())
            {
              lines.add("     " + s);
            }
            else
            {
              lines.add("     " + s + suffix);
            }
          }
        }
      }
    }

    return new ToCodeArgHelper(lines, comment);
  }



  /**
   * Creates an argument for a search filter.
   *
   * @param  f          The filter value for the argument.  It may be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createFilter(@Nullable final Filter f,
                                             @Nullable final String comment)
  {
    if (f == null)
    {
      return new ToCodeArgHelper("(Filter) null", comment);
    }

    final ArrayList<String> lines = new ArrayList<>(10);
    addFilterLines(lines, f, "", "");

    return new ToCodeArgHelper(lines, comment);
  }



  /**
   * Updates the provided list with the appropriate lines for the provided
   * filter.
   *
   * @param  lines   The list to be updated.  It must not be {@code null}.
   * @param  f       The filter whose lines should be added to the list.
   * @param  indent  The indent that should be used at the beginning of each
   *                 line.  It must not be {@code null} but may be empty.
   * @param  suffix  The suffix to append to the last line.  It must not be
   *                 {@code null} but may be empty.
   */
  private static void addFilterLines(@NotNull final List<String> lines,
                                     @NotNull final Filter f,
                                     @NotNull final String indent,
                                     @NotNull final String suffix)
  {
    final String nestedIndent = indent + "     ";

    switch (f.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
      case Filter.FILTER_TYPE_OR:
        final Filter[] components = f.getComponents();
        if (f.getFilterType() == Filter.FILTER_TYPE_AND)
        {
          if (components.length == 0)
          {
            lines.add(indent + "Filter.createANDFilter()" + suffix);
            return;
          }
          else
          {
            lines.add(indent + "Filter.createANDFilter(");
          }
        }
        else
        {
          if (components.length == 0)
          {
            lines.add(indent + "Filter.createORFilter()" + suffix);
            return;
          }
          else
          {
            lines.add(indent + "Filter.createORFilter(");
          }
        }

        for (int i = 0; i < components.length; i++)
        {
          if (i == (components.length - 1))
          {
            addFilterLines(lines, components[i], nestedIndent, ')' + suffix);
          }
          else
          {
            addFilterLines(lines, components[i], nestedIndent, ",");
          }
        }
        break;


      case Filter.FILTER_TYPE_NOT:
        lines.add(indent + "Filter.createNOTFilter(");
        addFilterLines(lines, f.getNOTComponent(), nestedIndent, ')' + suffix);
        break;


      case Filter.FILTER_TYPE_PRESENCE:
        lines.add(indent + "Filter.createPresenceFilter(");
        lines.add(nestedIndent + '"' + f.getAttributeName() + "\")" + suffix);
        break;


      case Filter.FILTER_TYPE_EQUALITY:
      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        switch (f.getFilterType())
        {
          case Filter.FILTER_TYPE_EQUALITY:
            lines.add(indent + "Filter.createEqualityFilter(");
            break;
          case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
            lines.add(indent + "Filter.createGreaterOrEqualFilter(");
            break;
          case Filter.FILTER_TYPE_LESS_OR_EQUAL:
            lines.add(indent + "Filter.createLessOrEqualFilter(");
            break;
          case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
            lines.add(indent + "Filter.createApproximateMatchFilter(");
            break;
        }

        lines.add(nestedIndent + '"' + f.getAttributeName() + "\",");
        if (StaticUtils.isSensitiveToCodeAttribute(f.getAttributeName()))
        {
          lines.add(nestedIndent + "\"---redacted-value---\")" + suffix);
        }
        else if (StaticUtils.isPrintableString(f.getAssertionValueBytes()))
        {
          lines.add(nestedIndent + '"' + f.getAssertionValue() + "\")" +
               suffix);
        }
        else
        {
          final Iterator<String> iterator =
               getByteArrayLines(f.getAssertionValueBytes(), true).iterator();
          while (iterator.hasNext())
          {
            final String line = iterator.next();
            if (iterator.hasNext())
            {
              lines.add(nestedIndent + line);
            }
            else
            {
              lines.add(nestedIndent + line + ')' + suffix);
            }
          }
        }
        break;


      case Filter.FILTER_TYPE_SUBSTRING:
        lines.add(indent + "Filter.createSubstringFilter(");
        lines.add(nestedIndent + '"' + f.getAttributeName() + "\",");

        if (StaticUtils.isSensitiveToCodeAttribute(f.getAttributeName()))
        {
          if (f.getRawSubInitialValue() == null)
          {
            lines.add(nestedIndent + "null,");
          }
          else
          {
            lines.add(nestedIndent + "\"---redacted-subInitial---\",");
          }

          if (f.getRawSubAnyValues().length == 0)
          {
            lines.add(nestedIndent + "null,");
          }
          else if (f.getRawSubAnyValues().length == 1)
          {
            lines.add(nestedIndent + "new String[]");
            lines.add(nestedIndent + '{');
            lines.add(nestedIndent + "  \"---redacted-subAny---\"");
            lines.add(nestedIndent + "},");
          }
          else
          {
            lines.add(nestedIndent + "new String[]");
            lines.add(nestedIndent + '{');
            for (int i=1; i <= f.getRawSubAnyValues().length; i++)
            {
              final String comma =
                   (i == f.getRawSubAnyValues().length) ? "" : ",";
              lines.add(nestedIndent + "  \"---redacted-subAny-" + i +
                   "---\"" + comma);
            }
            lines.add(nestedIndent + "},");
          }

          if (f.getRawSubFinalValue() == null)
          {
            lines.add(nestedIndent + "null)" + suffix);
          }
          else
          {
            lines.add(nestedIndent + "\"---redacted-subFinal---\")" + suffix);
          }
        }
        else
        {
          boolean allPrintable =
               ((f.getRawSubInitialValue() == null) ||
                StaticUtils.isPrintableString(f.getSubInitialBytes())) &&
               ((f.getRawSubFinalValue() == null) ||
                StaticUtils.isPrintableString(f.getSubFinalBytes()));
          if (allPrintable && (f.getRawSubAnyValues().length > 0))
          {
            for (final byte[] b : f.getSubAnyBytes())
            {
              if (! StaticUtils.isPrintableString(b))
              {
                allPrintable = false;
                break;
              }
            }
          }

          if (f.getRawSubInitialValue() == null)
          {
            lines.add(nestedIndent + "null,");
          }
          else if (allPrintable)
          {
            lines.add(nestedIndent + '"' +
                 f.getSubInitialString().replace("\"", "\\\"") + "\",");
          }
          else
          {
            final Iterator<String> iterator =
                 getByteArrayLines(f.getSubInitialBytes(), true).iterator();
            while (iterator.hasNext())
            {
              final String line = iterator.next();
              if (iterator.hasNext())
              {
                lines.add(nestedIndent + line);
              }
              else
              {
                lines.add(nestedIndent + line + ',');
              }
            }
          }

          if (f.getRawSubAnyValues().length == 0)
          {
            lines.add(nestedIndent + "null,");
          }
          else if (allPrintable)
          {
            lines.add(nestedIndent + "new String[]");
            lines.add(nestedIndent + '{');

            final String[] subAnyStrings = f.getSubAnyStrings();
            for (int i=0; i < subAnyStrings.length; i++)
            {
              final String comma;
              if (i == (subAnyStrings.length-1))
              {
                comma = "";
              }
              else
              {
                comma = ",";
              }
              lines.add(nestedIndent + "  \"" + subAnyStrings[i] + '"' + comma);
            }

            lines.add(nestedIndent + "},");
          }
          else
          {
            lines.add(nestedIndent + "new byte[][]");
            lines.add(nestedIndent + '{');

            final byte[][] subAnyBytes = f.getSubAnyBytes();
            for (int i=0; i < subAnyBytes.length; i++)
            {
              final String comma;
              if (i == (subAnyBytes.length-1))
              {
                comma = "";
              }
              else
              {
                comma = ",";
              }

              final Iterator<String> iterator =
                   getByteArrayLines(subAnyBytes[i], true).iterator();
              while (iterator.hasNext())
              {
                final String line = iterator.next();
                if (iterator.hasNext())
                {
                  lines.add(nestedIndent + "  " + line);
                }
                else
                {
                  lines.add(nestedIndent + "  " + line + comma);
                }
              }
            }

            lines.add(nestedIndent + "},");
          }

          if (f.getRawSubFinalValue() == null)
          {
            lines.add(nestedIndent + "null)" + suffix);
          }
          else if (allPrintable)
          {
            lines.add(nestedIndent + '"' +
                 f.getSubFinalString().replace("\"", "\\\"") + "\")" + suffix);
          }
          else
          {
            final Iterator<String> iterator =
                 getByteArrayLines(f.getSubFinalBytes(), true).iterator();
            while (iterator.hasNext())
            {
              final String line = iterator.next();
              if (iterator.hasNext())
              {
                lines.add(nestedIndent + line);
              }
              else
              {
                lines.add(nestedIndent + line + ')' + suffix);
              }
            }
          }
        }
        break;


      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        lines.add(indent + "Filter.createExtensibleMatchFilter(");

        if (f.getAttributeName() == null)
        {
          lines.add(nestedIndent + "null,");
        }
        else
        {
          lines.add(nestedIndent + '"' + f.getAttributeName() + "\",");
        }

        if (f.getMatchingRuleID() == null)
        {
          lines.add(nestedIndent + "null,");
        }
        else
        {
          lines.add(nestedIndent + '"' + f.getMatchingRuleID() + "\",");
        }

        lines.add(nestedIndent + f.getDNAttributes() + ',');

        if ((f.getAttributeName() != null) &&
            StaticUtils.isSensitiveToCodeAttribute(f.getAttributeName()))
        {
          lines.add(nestedIndent + "\"---redacted-value---\")" + suffix);
        }
        else if (StaticUtils.isPrintableString(f.getAssertionValueBytes()))
        {
          lines.add(nestedIndent + '"' +
               f.getAssertionValue().replace("\"", "\\\"") + "\")" + suffix);
        }
        else
        {
          final Iterator<String> iterator =
               getByteArrayLines(f.getAssertionValueBytes(), true).iterator();
          while (iterator.hasNext())
          {
            final String line = iterator.next();
            if (iterator.hasNext())
            {
              lines.add(nestedIndent + line);
            }
            else
            {
              lines.add(nestedIndent + line + ')' + suffix);
            }
          }
        }
        break;
    }
  }



  /**
   * Creates an argument for a control.
   *
   * @param  c          The control value for the argument.  It may be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createControl(@Nullable final Control c,
                                              @Nullable final String comment)
  {
    if (c == null)
    {
      return new ToCodeArgHelper("(Control) null", comment);
    }

    // NYI -- Figure out what type of control it is and create more specific
    // code for that type of control if possible.  If not, then use the
    // following generic code:

    final ArrayList<String> lines = new ArrayList<>(10);
    lines.add("new Control(");
    lines.add("     \"" + c.getOID() + "\",");

    if (c.hasValue())
    {
      lines.add("     " + c.isCritical() + ',');

      final List<String> valueLines =
           createASN1OctetString(c.getValue(), null).argStrings;
      final Iterator<String> valueLineIterator = valueLines.iterator();
      while (valueLineIterator.hasNext())
      {
        final String s = valueLineIterator.next();
        if (valueLineIterator.hasNext())
        {
          lines.add("     " + s);
        }
        else
        {
          lines.add("     " + s + ')');
        }
      }
    }
    else
    {
      lines.add("     " + c.isCritical() + ')');
    }

    return new ToCodeArgHelper(lines, comment);
  }



  /**
   * Creates an argument for an array of controls.
   *
   * @param  c          The control value for the argument.  It may be
   *                    {@code null}.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createControlArray(@Nullable final Control[] c,
                                     @Nullable final String comment)
  {
    if (c == null)
    {
      return new ToCodeArgHelper("(Control[]) null", comment);
    }

    if (c.length == 0)
    {
      return new ToCodeArgHelper("new Control[0]", comment);
    }

    final ArrayList<String> lines = new ArrayList<>(10);
    lines.add("new Control[]");
    lines.add("{");

    for (int i=0; i < c.length; i++)
    {
      final ToCodeArgHelper h = createControl(c[i], null);
      final List<String> hLines = h.argStrings;

      final Iterator<String> iterator = hLines.iterator();
      while (iterator.hasNext())
      {
        final String line = iterator.next();
        if ((! iterator.hasNext()) && (i < (c.length-1)))
        {

          lines.add("  " + line + ',');
        }
        else
        {
          lines.add("  " + line);
        }
      }
    }

    lines.add("}");

    return new ToCodeArgHelper(lines, comment);
  }



  /**
   * Creates an argument that will use exactly the provided representation.
   *
   * @param  s          The raw string representation for the argument.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createRaw(@NotNull final String s,
                                          @Nullable final String comment)
  {
    return new ToCodeArgHelper(s, comment);
  }



  /**
   * Creates an argument that will use exactly the provided representation.
   *
   * @param  s          The list of lines comprising the raw string
   *                    representation for the argument.  If any indent is
   *                    needed for subsequent lines, it should be included in
   *                    the raw values.
   * @param  comment    A comment that may help clarify the argument.  It may
   *                    be {@code null} if there should be no comment.
   *
   * @return  The argument that was created.
   */
  @NotNull()
  public static ToCodeArgHelper createRaw(@NotNull final List<String> s,
                                          @Nullable final String comment)
  {
    return new ToCodeArgHelper(s, comment);
  }



  /**
   * Indicates whether all of the provided values represent printable strings.
   *
   * @param  values  The values for which to make the determination.
   *
   * @return  {@code true} if all of the values represent printable strings, or
   *          {@code false} if not.
   */
  private static boolean allPrintable(@NotNull final ASN1OctetString... values)
  {
    for (final ASN1OctetString s : values)
    {
      if (! StaticUtils.isPrintableString(s.getValue()))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves the list of lines comprising the string representation for this
   * argument.  All appropriate formatting will be applied.  There will not be
   * any indent used for the first line.  If there are multiple lines, then
   * subsequent lines may be indented relative to the first line, and any
   * necessary separator will be used at the end of all lines except the last.
   *
   * @return  The list of lines comprising the string representation for this
   *          argument.  At least one line will be included.
   */
  @NotNull()
  public List<String> getLines()
  {
    return argStrings;
  }



  /**
   * Retrieves the comment for this argument, if any.
   *
   * @return  The comment for this argument, or {@code null} if there is none.
   */
  @Nullable()
  public String getComment()
  {
    return comment;
  }
}
