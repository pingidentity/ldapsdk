/*
 * Copyright 2007-2018 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.UUID;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Version;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.UtilityMessages.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a number of static utility functions.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StaticUtils
{
  /**
   * A pre-allocated byte array containing zero bytes.
   */
  public static final byte[] NO_BYTES = new byte[0];



  /**
   * A pre-allocated empty control array.
   */
  public static final Control[] NO_CONTROLS = new Control[0];



  /**
   * A pre-allocated empty string array.
   */
  public static final String[] NO_STRINGS = new String[0];



  /**
   * The end-of-line marker for this platform.
   */
  public static final String EOL = System.getProperty("line.separator");



  /**
   * A byte array containing the end-of-line marker for this platform.
   */
  public static final byte[] EOL_BYTES = getBytes(EOL);



  /**
   * The width of the terminal window, in columns.
   */
  public static final int TERMINAL_WIDTH_COLUMNS;
  static
  {
    // Try to dynamically determine the size of the terminal window using the
    // COLUMNS environment variable.
    int terminalWidth = 80;
    final String columnsEnvVar = System.getenv("COLUMNS");
    if (columnsEnvVar != null)
    {
      try
      {
        terminalWidth = Integer.parseInt(columnsEnvVar);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    TERMINAL_WIDTH_COLUMNS = terminalWidth;
  }



  /**
   * The thread-local date formatter used to encode generalized time values.
   */
  private static final ThreadLocal<SimpleDateFormat> DATE_FORMATTERS =
       new ThreadLocal<SimpleDateFormat>();



  /**
   * The {@code TimeZone} object that represents the UTC (universal coordinated
   * time) time zone.
   */
  private static TimeZone UTC_TIME_ZONE = TimeZone.getTimeZone("UTC");



  /**
   * A set containing the names of attributes that will be considered sensitive
   * by the {@code toCode} methods of various request and data structure types.
   */
  private static volatile Set<String> TO_CODE_SENSITIVE_ATTRIBUTE_NAMES;
  static
  {
    final LinkedHashSet<String> nameSet = new LinkedHashSet<String>(4);

    // Add userPassword by name and OID.
    nameSet.add("userpassword");
    nameSet.add("2.5.4.35");

    // add authPassword by name and OID.
    nameSet.add("authpassword");
    nameSet.add("1.3.6.1.4.1.4203.1.3.4");

    TO_CODE_SENSITIVE_ATTRIBUTE_NAMES = Collections.unmodifiableSet(nameSet);
  }



  /**
   * Prevent this class from being instantiated.
   */
  private StaticUtils()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a UTF-8 byte representation of the provided string.
   *
   * @param  s  The string for which to retrieve the UTF-8 byte representation.
   *
   * @return  The UTF-8 byte representation for the provided string.
   */
  public static byte[] getBytes(final String s)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      return NO_BYTES;
    }

    final byte[] b = new byte[length];
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (c <= 0x7F)
      {
        b[i] = (byte) (c & 0x7F);
      }
      else
      {
        try
        {
          return s.getBytes("UTF-8");
        }
        catch (final Exception e)
        {
          // This should never happen.
          debugException(e);
          return s.getBytes();
        }
      }
    }

    return b;
  }



  /**
   * Indicates whether the contents of the provided byte array represent an
   * ASCII string, which is also known in LDAP terminology as an IA5 string.
   * An ASCII string is one that contains only bytes in which the most
   * significant bit is zero.
   *
   * @param  b  The byte array for which to make the determination.  It must
   *            not be {@code null}.
   *
   * @return  {@code true} if the contents of the provided array represent an
   *          ASCII string, or {@code false} if not.
   */
  public static boolean isASCIIString(final byte[] b)
  {
    for (final byte by : b)
    {
      if ((by & 0x80) == 0x80)
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Indicates whether the provided character is a printable ASCII character, as
   * per RFC 4517 section 3.2.  The only printable characters are:
   * <UL>
   *   <LI>All uppercase and lowercase ASCII alphabetic letters</LI>
   *   <LI>All ASCII numeric digits</LI>
   *   <LI>The following additional ASCII characters:  single quote, left
   *       parenthesis, right parenthesis, plus, comma, hyphen, period, equals,
   *       forward slash, colon, question mark, space.</LI>
   * </UL>
   *
   * @param  c  The character for which to make the determination.
   *
   * @return  {@code true} if the provided character is a printable ASCII
   *          character, or {@code false} if not.
   */
  public static boolean isPrintable(final char c)
  {
    if (((c >= 'a') && (c <= 'z')) ||
        ((c >= 'A') && (c <= 'Z')) ||
        ((c >= '0') && (c <= '9')))
    {
      return true;
    }

    switch (c)
    {
      case '\'':
      case '(':
      case ')':
      case '+':
      case ',':
      case '-':
      case '.':
      case '=':
      case '/':
      case ':':
      case '?':
      case ' ':
        return true;
      default:
        return false;
    }
  }



  /**
   * Indicates whether the contents of the provided byte array represent a
   * printable LDAP string, as per RFC 4517 section 3.2.  The only characters
   * allowed in a printable string are:
   * <UL>
   *   <LI>All uppercase and lowercase ASCII alphabetic letters</LI>
   *   <LI>All ASCII numeric digits</LI>
   *   <LI>The following additional ASCII characters:  single quote, left
   *       parenthesis, right parenthesis, plus, comma, hyphen, period, equals,
   *       forward slash, colon, question mark, space.</LI>
   * </UL>
   * If the provided array contains anything other than the above characters
   * (i.e., if the byte array contains any non-ASCII characters, or any ASCII
   * control characters, or if it contains excluded ASCII characters like
   * the exclamation point, double quote, octothorpe, dollar sign, etc.), then
   * it will not be considered printable.
   *
   * @param  b  The byte array for which to make the determination.  It must
   *            not be {@code null}.
   *
   * @return  {@code true} if the contents of the provided byte array represent
   *          a printable LDAP string, or {@code false} if not.
   */
  public static boolean isPrintableString(final byte[] b)
  {
    for (final byte by : b)
    {
      if ((by & 0x80) == 0x80)
      {
        return false;
      }

      if (((by >= 'a') && (by <= 'z')) ||
          ((by >= 'A') && (by <= 'Z')) ||
          ((by >= '0') && (by <= '9')))
      {
        continue;
      }

      switch (by)
      {
        case '\'':
        case '(':
        case ')':
        case '+':
        case ',':
        case '-':
        case '.':
        case '=':
        case '/':
        case ':':
        case '?':
        case ' ':
          continue;
        default:
          return false;
      }
    }

    return true;
  }



  /**
   * Indicates whether the contents of the provided array are valid UTF-8.
   *
   * @param  b  The byte array to examine.  It must not be {@code null}.
   *
   * @return  {@code true} if the byte array can be parsed as a valid UTF-8
   *          string, or {@code false} if not.
   */
  public static boolean isValidUTF8(final byte[] b)
  {
    int i = 0;
    while (i < b.length)
    {
      final byte currentByte = b[i++];

      // If the most significant bit is not set, then this represents a valid
      // single-byte character.
      if ((currentByte & 0b1000_0000) == 0b0000_0000)
      {
        continue;
      }

      // If the first byte starts with 0b110, then it must be followed by
      // another byte that starts with 0b10.
      if ((currentByte & 0b1110_0000) == 0b1100_0000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 1))
        {
          return false;
        }

        i++;
        continue;
      }

      // If the first byte starts with 0b1110, then it must be followed by two
      // more bytes that start with 0b10.
      if ((currentByte & 0b1111_0000) == 0b1110_0000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 2))
        {
          return false;
        }

        i += 2;
        continue;
      }

      // If the first byte starts with 0b11110, then it must be followed by
      // three more bytes that start with 0b10.
      if ((currentByte & 0b1111_1000) == 0b1111_0000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 3))
        {
          return false;
        }

        i += 3;
        continue;
      }

      // If the first byte starts with 0b111110, then it must be followed by
      // four more bytes that start with 0b10.
      if ((currentByte & 0b1111_1100) == 0b1111_1000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 4))
        {
          return false;
        }

        i += 4;
        continue;
      }

      // If the first byte starts with 0b1111110, then it must be followed by
      // five more bytes that start with 0b10.
      if ((currentByte & 0b1111_1110) == 0b1111_1100)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 5))
        {
          return false;
        }

        i += 5;
        continue;
      }

      // This is not a valid first byte for a UTF-8 character.
      return false;
    }


    // If we've gotten here, then the provided array represents a valid UTF-8
    // string.
    return true;
  }



  /**
   * Ensures that the provided array has the expected number of bytes that start
   * with 0b10 starting at the specified position in the array.
   *
   * @param  b  The byte array to examine.
   * @param  p  The position in the byte array at which to start looking.
   * @param  n  The number of bytes to examine.
   *
   * @return  {@code true} if the provided byte array has the expected number of
   *          bytes that start with 0b10, or {@code false} if not.
   */
  private static boolean hasExpectedSubsequentUTF8Bytes(final byte[] b,
                                                        final int p,
                                                        final int n)
  {
    if (b.length < (p + n))
    {
      return false;
    }

    for (int i=0; i < n; i++)
    {
      if ((b[p+i] & 0b1100_0000) != 0b1000_0000)
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves a string generated from the provided byte array using the UTF-8
   * encoding.
   *
   * @param  b  The byte array for which to return the associated string.
   *
   * @return  The string generated from the provided byte array using the UTF-8
   *          encoding.
   */
  public static String toUTF8String(final byte[] b)
  {
    try
    {
      return new String(b, "UTF-8");
    }
    catch (final Exception e)
    {
      // This should never happen.
      debugException(e);
      return new String(b);
    }
  }



  /**
   * Retrieves a string generated from the specified portion of the provided
   * byte array using the UTF-8 encoding.
   *
   * @param  b       The byte array for which to return the associated string.
   * @param  offset  The offset in the array at which the value begins.
   * @param  length  The number of bytes in the value to convert to a string.
   *
   * @return  The string generated from the specified portion of the provided
   *          byte array using the UTF-8 encoding.
   */
  public static String toUTF8String(final byte[] b, final int offset,
                                    final int length)
  {
    try
    {
      return new String(b, offset, length, "UTF-8");
    }
    catch (final Exception e)
    {
      // This should never happen.
      debugException(e);
      return new String(b, offset, length);
    }
  }



  /**
   * Retrieves a version of the provided string with the first character
   * converted to lowercase but all other characters retaining their original
   * capitalization.
   *
   * @param  s  The string to be processed.
   *
   * @return  A version of the provided string with the first character
   *          converted to lowercase but all other characters retaining their
   *          original capitalization.
   */
  public static String toInitialLowerCase(final String s)
  {
    if ((s == null) || (s.length() == 0))
    {
      return s;
    }
    else if (s.length() == 1)
    {
      return toLowerCase(s);
    }
    else
    {
      final char c = s.charAt(0);
      if (((c >= 'A') && (c <= 'Z')) || (c < ' ') || (c > '~'))
      {
        final StringBuilder b = new StringBuilder(s);
        b.setCharAt(0, Character.toLowerCase(c));
        return b.toString();
      }
      else
      {
        return s;
      }
    }
  }



  /**
   * Retrieves an all-lowercase version of the provided string.
   *
   * @param  s  The string for which to retrieve the lowercase version.
   *
   * @return  An all-lowercase version of the provided string.
   */
  public static String toLowerCase(final String s)
  {
    if (s == null)
    {
      return null;
    }

    final int length = s.length();
    final char[] charArray = s.toCharArray();
    for (int i=0; i < length; i++)
    {
      switch (charArray[i])
      {
        case 'A':
          charArray[i] = 'a';
          break;
        case 'B':
          charArray[i] = 'b';
          break;
        case 'C':
          charArray[i] = 'c';
          break;
        case 'D':
          charArray[i] = 'd';
          break;
        case 'E':
          charArray[i] = 'e';
          break;
        case 'F':
          charArray[i] = 'f';
          break;
        case 'G':
          charArray[i] = 'g';
          break;
        case 'H':
          charArray[i] = 'h';
          break;
        case 'I':
          charArray[i] = 'i';
          break;
        case 'J':
          charArray[i] = 'j';
          break;
        case 'K':
          charArray[i] = 'k';
          break;
        case 'L':
          charArray[i] = 'l';
          break;
        case 'M':
          charArray[i] = 'm';
          break;
        case 'N':
          charArray[i] = 'n';
          break;
        case 'O':
          charArray[i] = 'o';
          break;
        case 'P':
          charArray[i] = 'p';
          break;
        case 'Q':
          charArray[i] = 'q';
          break;
        case 'R':
          charArray[i] = 'r';
          break;
        case 'S':
          charArray[i] = 's';
          break;
        case 'T':
          charArray[i] = 't';
          break;
        case 'U':
          charArray[i] = 'u';
          break;
        case 'V':
          charArray[i] = 'v';
          break;
        case 'W':
          charArray[i] = 'w';
          break;
        case 'X':
          charArray[i] = 'x';
          break;
        case 'Y':
          charArray[i] = 'y';
          break;
        case 'Z':
          charArray[i] = 'z';
          break;
        default:
          if (charArray[i] > 0x7F)
          {
            return s.toLowerCase();
          }
          break;
      }
    }

    return new String(charArray);
  }



  /**
   * Indicates whether the provided character is a valid hexadecimal digit.
   *
   * @param  c  The character for which to make the determination.
   *
   * @return  {@code true} if the provided character does represent a valid
   *          hexadecimal digit, or {@code false} if not.
   */
  public static boolean isHex(final char c)
  {
    switch (c)
    {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
      case 'a':
      case 'A':
      case 'b':
      case 'B':
      case 'c':
      case 'C':
      case 'd':
      case 'D':
      case 'e':
      case 'E':
      case 'f':
      case 'F':
        return true;

      default:
        return false;
    }
  }



  /**
   * Retrieves a hexadecimal representation of the provided byte.
   *
   * @param  b  The byte to encode as hexadecimal.
   *
   * @return  A string containing the hexadecimal representation of the provided
   *          byte.
   */
  public static String toHex(final byte b)
  {
    final StringBuilder buffer = new StringBuilder(2);
    toHex(b, buffer);
    return buffer.toString();
  }



  /**
   * Appends a hexadecimal representation of the provided byte to the given
   * buffer.
   *
   * @param  b       The byte to encode as hexadecimal.
   * @param  buffer  The buffer to which the hexadecimal representation is to be
   *                 appended.
   */
  public static void toHex(final byte b, final StringBuilder buffer)
  {
    switch (b & 0xF0)
    {
      case 0x00:
        buffer.append('0');
        break;
      case 0x10:
        buffer.append('1');
        break;
      case 0x20:
        buffer.append('2');
        break;
      case 0x30:
        buffer.append('3');
        break;
      case 0x40:
        buffer.append('4');
        break;
      case 0x50:
        buffer.append('5');
        break;
      case 0x60:
        buffer.append('6');
        break;
      case 0x70:
        buffer.append('7');
        break;
      case 0x80:
        buffer.append('8');
        break;
      case 0x90:
        buffer.append('9');
        break;
      case 0xA0:
        buffer.append('a');
        break;
      case 0xB0:
        buffer.append('b');
        break;
      case 0xC0:
        buffer.append('c');
        break;
      case 0xD0:
        buffer.append('d');
        break;
      case 0xE0:
        buffer.append('e');
        break;
      case 0xF0:
        buffer.append('f');
        break;
    }

    switch (b & 0x0F)
    {
      case 0x00:
        buffer.append('0');
        break;
      case 0x01:
        buffer.append('1');
        break;
      case 0x02:
        buffer.append('2');
        break;
      case 0x03:
        buffer.append('3');
        break;
      case 0x04:
        buffer.append('4');
        break;
      case 0x05:
        buffer.append('5');
        break;
      case 0x06:
        buffer.append('6');
        break;
      case 0x07:
        buffer.append('7');
        break;
      case 0x08:
        buffer.append('8');
        break;
      case 0x09:
        buffer.append('9');
        break;
      case 0x0A:
        buffer.append('a');
        break;
      case 0x0B:
        buffer.append('b');
        break;
      case 0x0C:
        buffer.append('c');
        break;
      case 0x0D:
        buffer.append('d');
        break;
      case 0x0E:
        buffer.append('e');
        break;
      case 0x0F:
        buffer.append('f');
        break;
    }
  }



  /**
   * Retrieves a hexadecimal representation of the contents of the provided byte
   * array.  No delimiter character will be inserted between the hexadecimal
   * digits for each byte.
   *
   * @param  b  The byte array to be represented as a hexadecimal string.  It
   *            must not be {@code null}.
   *
   * @return  A string containing a hexadecimal representation of the contents
   *          of the provided byte array.
   */
  public static String toHex(final byte[] b)
  {
    ensureNotNull(b);

    final StringBuilder buffer = new StringBuilder(2 * b.length);
    toHex(b, buffer);
    return buffer.toString();
  }



  /**
   * Retrieves a hexadecimal representation of the contents of the provided byte
   * array.  No delimiter character will be inserted between the hexadecimal
   * digits for each byte.
   *
   * @param  b       The byte array to be represented as a hexadecimal string.
   *                 It must not be {@code null}.
   * @param  buffer  A buffer to which the hexadecimal representation of the
   *                 contents of the provided byte array should be appended.
   */
  public static void toHex(final byte[] b, final StringBuilder buffer)
  {
    toHex(b, null, buffer);
  }



  /**
   * Retrieves a hexadecimal representation of the contents of the provided byte
   * array.  No delimiter character will be inserted between the hexadecimal
   * digits for each byte.
   *
   * @param  b          The byte array to be represented as a hexadecimal
   *                    string.  It must not be {@code null}.
   * @param  delimiter  A delimiter to be inserted between bytes.  It may be
   *                    {@code null} if no delimiter should be used.
   * @param  buffer     A buffer to which the hexadecimal representation of the
   *                    contents of the provided byte array should be appended.
   */
  public static void toHex(final byte[] b, final String delimiter,
                           final StringBuilder buffer)
  {
    boolean first = true;
    for (final byte bt : b)
    {
      if (first)
      {
        first = false;
      }
      else if (delimiter != null)
      {
        buffer.append(delimiter);
      }

      toHex(bt, buffer);
    }
  }



  /**
   * Retrieves a hex-encoded representation of the contents of the provided
   * array, along with an ASCII representation of its contents next to it.  The
   * output will be split across multiple lines, with up to sixteen bytes per
   * line.  For each of those sixteen bytes, the two-digit hex representation
   * will be appended followed by a space.  Then, the ASCII representation of
   * those sixteen bytes will follow that, with a space used in place of any
   * byte that does not have an ASCII representation.
   *
   * @param  array   The array whose contents should be processed.
   * @param  indent  The number of spaces to insert on each line prior to the
   *                 first hex byte.
   *
   * @return  A hex-encoded representation of the contents of the provided
   *          array, along with an ASCII representation of its contents next to
   *          it.
   */
  public static String toHexPlusASCII(final byte[] array, final int indent)
  {
    final StringBuilder buffer = new StringBuilder();
    toHexPlusASCII(array, indent, buffer);
    return buffer.toString();
  }



  /**
   * Appends a hex-encoded representation of the contents of the provided array
   * to the given buffer, along with an ASCII representation of its contents
   * next to it.  The output will be split across multiple lines, with up to
   * sixteen bytes per line.  For each of those sixteen bytes, the two-digit hex
   * representation will be appended followed by a space.  Then, the ASCII
   * representation of those sixteen bytes will follow that, with a space used
   * in place of any byte that does not have an ASCII representation.
   *
   * @param  array   The array whose contents should be processed.
   * @param  indent  The number of spaces to insert on each line prior to the
   *                 first hex byte.
   * @param  buffer  The buffer to which the encoded data should be appended.
   */
  public static void toHexPlusASCII(final byte[] array, final int indent,
                                    final StringBuilder buffer)
  {
    if ((array == null) || (array.length == 0))
    {
      return;
    }

    for (int i=0; i < indent; i++)
    {
      buffer.append(' ');
    }

    int pos = 0;
    int startPos = 0;
    while (pos < array.length)
    {
      toHex(array[pos++], buffer);
      buffer.append(' ');

      if ((pos % 16) == 0)
      {
        buffer.append("  ");
        for (int i=startPos; i < pos; i++)
        {
          if ((array[i] < ' ') || (array[i] > '~'))
          {
            buffer.append(' ');
          }
          else
          {
            buffer.append((char) array[i]);
          }
        }
        buffer.append(EOL);
        startPos = pos;

        if (pos < array.length)
        {
          for (int i=0; i < indent; i++)
          {
            buffer.append(' ');
          }
        }
      }
    }

    // If the last line isn't complete yet, then finish it off.
    if ((array.length % 16) != 0)
    {
      final int missingBytes = (16 - (array.length % 16));
      if (missingBytes > 0)
      {
        for (int i=0; i < missingBytes; i++)
        {
          buffer.append("   ");
        }
        buffer.append("  ");
        for (int i=startPos; i < array.length; i++)
        {
          if ((array[i] < ' ') || (array[i] > '~'))
          {
            buffer.append(' ');
          }
          else
          {
            buffer.append((char) array[i]);
          }
        }
        buffer.append(EOL);
      }
    }
  }



  /**
   * Retrieves the bytes that correspond to the provided hexadecimal string.
   *
   * @param  hexString  The hexadecimal string for which to retrieve the bytes.
   *                    It must not be {@code null}, and there must not be any
   *                    delimiter between bytes.
   *
   * @return  The bytes that correspond to the provided hexadecimal string.
   *
   * @throws  ParseException  If the provided string does not represent valid
   *                          hexadecimal data, or if the provided string does
   *                          not contain an even number of characters.
   */
  public static byte[] fromHex(final String hexString)
         throws ParseException
  {
    if ((hexString.length() % 2) != 0)
    {
      throw new ParseException(
           ERR_FROM_HEX_ODD_NUMBER_OF_CHARACTERS.get(hexString.length()),
           hexString.length());
    }

    final byte[] decodedBytes = new byte[hexString.length() / 2];
    for (int i=0, j=0; i < decodedBytes.length; i++, j+= 2)
    {
      switch (hexString.charAt(j))
      {
        case '0':
          // No action is required.
          break;
        case '1':
          decodedBytes[i] = 0x10;
          break;
        case '2':
          decodedBytes[i] = 0x20;
          break;
        case '3':
          decodedBytes[i] = 0x30;
          break;
        case '4':
          decodedBytes[i] = 0x40;
          break;
        case '5':
          decodedBytes[i] = 0x50;
          break;
        case '6':
          decodedBytes[i] = 0x60;
          break;
        case '7':
          decodedBytes[i] = 0x70;
          break;
        case '8':
          decodedBytes[i] = (byte) 0x80;
          break;
        case '9':
          decodedBytes[i] = (byte) 0x90;
          break;
        case 'a':
        case 'A':
          decodedBytes[i] = (byte) 0xA0;
          break;
        case 'b':
        case 'B':
          decodedBytes[i] = (byte) 0xB0;
          break;
        case 'c':
        case 'C':
          decodedBytes[i] = (byte) 0xC0;
          break;
        case 'd':
        case 'D':
          decodedBytes[i] = (byte) 0xD0;
          break;
        case 'e':
        case 'E':
          decodedBytes[i] = (byte) 0xE0;
          break;
        case 'f':
        case 'F':
          decodedBytes[i] = (byte) 0xF0;
          break;
        default:
          throw new ParseException(ERR_FROM_HEX_NON_HEX_CHARACTER.get(j), j);
      }

      switch (hexString.charAt(j+1))
      {
        case '0':
          // No action is required.
          break;
        case '1':
          decodedBytes[i] |= 0x01;
          break;
        case '2':
          decodedBytes[i] |= 0x02;
          break;
        case '3':
          decodedBytes[i] |= 0x03;
          break;
        case '4':
          decodedBytes[i] |= 0x04;
          break;
        case '5':
          decodedBytes[i] |= 0x05;
          break;
        case '6':
          decodedBytes[i] |= 0x06;
          break;
        case '7':
          decodedBytes[i] |= 0x07;
          break;
        case '8':
          decodedBytes[i] |= 0x08;
          break;
        case '9':
          decodedBytes[i] |= 0x09;
          break;
        case 'a':
        case 'A':
          decodedBytes[i] |= 0x0A;
          break;
        case 'b':
        case 'B':
          decodedBytes[i] |= 0x0B;
          break;
        case 'c':
        case 'C':
          decodedBytes[i] |= 0x0C;
          break;
        case 'd':
        case 'D':
          decodedBytes[i] |= 0x0D;
          break;
        case 'e':
        case 'E':
          decodedBytes[i] |= 0x0E;
          break;
        case 'f':
        case 'F':
          decodedBytes[i] |= 0x0F;
          break;
        default:
          throw new ParseException(ERR_FROM_HEX_NON_HEX_CHARACTER.get(j+1),
               j+1);
      }
    }

    return decodedBytes;
  }



  /**
   * Appends a hex-encoded representation of the provided character to the given
   * buffer.  Each byte of the hex-encoded representation will be prefixed with
   * a backslash.
   *
   * @param  c       The character to be encoded.
   * @param  buffer  The buffer to which the hex-encoded representation should
   *                 be appended.
   */
  public static void hexEncode(final char c, final StringBuilder buffer)
  {
    final byte[] charBytes;
    if (c <= 0x7F)
    {
      charBytes = new byte[] { (byte) (c & 0x7F) };
    }
    else
    {
      charBytes = getBytes(String.valueOf(c));
    }

    for (final byte b : charBytes)
    {
      buffer.append('\\');
      toHex(b, buffer);
    }
  }



  /**
   * Appends the Java code that may be used to create the provided byte
   * array to the given buffer.
   *
   * @param  array   The byte array containing the data to represent.  It must
   *                 not be {@code null}.
   * @param  buffer  The buffer to which the code should be appended.
   */
  public static void byteArrayToCode(final byte[] array,
                                     final StringBuilder buffer)
  {
    buffer.append("new byte[] {");
    for (int i=0; i < array.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      buffer.append(" (byte) 0x");
      toHex(array[i], buffer);
    }
    buffer.append(" }");
  }



  /**
   * Retrieves a single-line string representation of the stack trace for the
   * provided {@code Throwable}.  It will include the unqualified name of the
   * {@code Throwable} class, a list of source files and line numbers (if
   * available) for the stack trace, and will also include the stack trace for
   * the cause (if present).
   *
   * @param  t  The {@code Throwable} for which to retrieve the stack trace.
   *
   * @return  A single-line string representation of the stack trace for the
   *          provided {@code Throwable}.
   */
  public static String getStackTrace(final Throwable t)
  {
    final StringBuilder buffer = new StringBuilder();
    getStackTrace(t, buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of the stack trace for the
   * provided {@code Throwable} to the given buffer.  It will include the
   * unqualified name of the {@code Throwable} class, a list of source files and
   * line numbers (if available) for the stack trace, and will also include the
   * stack trace for the cause (if present).
   *
   * @param  t       The {@code Throwable} for which to retrieve the stack
   *                 trace.
   * @param  buffer  The buffer to which the information should be appended.
   */
  public static void getStackTrace(final Throwable t,
                                   final StringBuilder buffer)
  {
    buffer.append(getUnqualifiedClassName(t.getClass()));
    buffer.append('(');

    final String message = t.getMessage();
    if (message != null)
    {
      buffer.append("message='");
      buffer.append(message);
      buffer.append("', ");
    }

    buffer.append("trace='");
    getStackTrace(t.getStackTrace(), buffer);
    buffer.append('\'');

    final Throwable cause = t.getCause();
    if (cause != null)
    {
      buffer.append(", cause=");
      getStackTrace(cause, buffer);
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    buffer.append(')');
  }



  /**
   * Returns a single-line string representation of the stack trace.  It will
   * include a list of source files and line numbers (if available) for the
   * stack trace.
   *
   * @param  elements  The stack trace.
   *
   * @return  A single-line string representation of the stack trace.
   */
  public static String getStackTrace(final StackTraceElement[] elements)
  {
    final StringBuilder buffer = new StringBuilder();
    getStackTrace(elements, buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of the stack trace to the given
   * buffer.  It will include a list of source files and line numbers
   * (if available) for the stack trace.
   *
   * @param  elements  The stack trace.
   * @param  buffer  The buffer to which the information should be appended.
   */
  public static void getStackTrace(final StackTraceElement[] elements,
                                   final StringBuilder buffer)
  {
    for (int i=0; i < elements.length; i++)
    {
      if (i > 0)
      {
        buffer.append(" / ");
      }

      buffer.append(elements[i].getMethodName());
      buffer.append('(');
      buffer.append(elements[i].getFileName());

      final int lineNumber = elements[i].getLineNumber();
      if (lineNumber > 0)
      {
        buffer.append(':');
        buffer.append(lineNumber);
      }
      else if (elements[i].isNativeMethod())
      {
        buffer.append(":native");
      }
      else
      {
        buffer.append(":unknown");
      }
      buffer.append(')');
    }
  }



  /**
   * Retrieves a string representation of the provided {@code Throwable} object
   * suitable for use in a message.  For runtime exceptions and errors, then a
   * full stack trace for the exception will be provided.  For exception types
   * defined in the LDAP SDK, then its {@code getExceptionMessage} method will
   * be used to get the string representation.  For all other types of
   * exceptions, then the standard string representation will be used.
   * <BR><BR>
   * For all types of exceptions, the message will also include the cause if one
   * exists.
   *
   * @param  t  The {@code Throwable} for which to generate the exception
   *            message.
   *
   * @return  A string representation of the provided {@code Throwable} object
   *          suitable for use in a message.
   */
  public static String getExceptionMessage(final Throwable t)
  {
    final boolean includeCause =
         Boolean.getBoolean(Debug.PROPERTY_INCLUDE_CAUSE_IN_EXCEPTION_MESSAGES);
    final boolean includeStackTrace = Boolean.getBoolean(
         Debug.PROPERTY_INCLUDE_STACK_TRACE_IN_EXCEPTION_MESSAGES);

    return getExceptionMessage(t, includeCause, includeStackTrace);
  }



  /**
   * Retrieves a string representation of the provided {@code Throwable} object
   * suitable for use in a message.  For runtime exceptions and errors, then a
   * full stack trace for the exception will be provided.  For exception types
   * defined in the LDAP SDK, then its {@code getExceptionMessage} method will
   * be used to get the string representation.  For all other types of
   * exceptions, then the standard string representation will be used.
   * <BR><BR>
   * For all types of exceptions, the message will also include the cause if one
   * exists.
   *
   * @param  t                  The {@code Throwable} for which to generate the
   *                            exception message.
   * @param  includeCause       Indicates whether to include information about
   *                            the cause (if any) in the exception message.
   * @param  includeStackTrace  Indicates whether to include a condensed
   *                            representation of the stack trace in the
   *                            exception message.
   *
   * @return  A string representation of the provided {@code Throwable} object
   *          suitable for use in a message.
   */
  public static String getExceptionMessage(final Throwable t,
                                           final boolean includeCause,
                                           final boolean includeStackTrace)
  {
    if (t == null)
    {
      return ERR_NO_EXCEPTION.get();
    }

    final StringBuilder buffer = new StringBuilder();
    if (t instanceof LDAPSDKException)
    {
      buffer.append(((LDAPSDKException) t).getExceptionMessage());
    }
    else if (t instanceof LDAPSDKRuntimeException)
    {
      buffer.append(((LDAPSDKRuntimeException) t).getExceptionMessage());
    }
    else if (t instanceof NullPointerException)
    {
      buffer.append("NullPointerException(");

      final StackTraceElement[] stackTraceElements = t.getStackTrace();
      for (int i=0; i < stackTraceElements.length; i++)
      {
        final StackTraceElement e = stackTraceElements[i];
        if (i > 0)
        {
          buffer.append(" / ");
        }

        buffer.append(e.getFileName());

        final int lineNumber = e.getLineNumber();
        if (lineNumber > 0)
        {
          buffer.append(':');
          buffer.append(lineNumber);
        }
        else if (e.isNativeMethod())
        {
          buffer.append(":native");
        }
        else
        {
          buffer.append(":unknown");
        }

        if (e.getClassName().contains("unboundid"))
        {
          if (i < (stackTraceElements.length - 1))
          {
            buffer.append(" ...");
          }

          break;
        }
      }

      buffer.append(')');
    }
    else if ((t.getMessage() == null) || t.getMessage().isEmpty() ||
         t.getMessage().equalsIgnoreCase("null"))
    {
      getStackTrace(t, buffer);
    }
    else
    {
      buffer.append(t.getClass().getSimpleName());
      buffer.append('(');
      buffer.append(t.getMessage());
      buffer.append(')');

      if (includeStackTrace)
      {
        buffer.append(" trace=");
        getStackTrace(t, buffer);
      }
      else if (includeCause)
      {
        final Throwable cause = t.getCause();
        if (cause != null)
        {
          buffer.append(" caused by ");
          buffer.append(getExceptionMessage(cause));
        }
      }
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    return buffer.toString();
  }



  /**
   * Retrieves the unqualified name (i.e., the name without package information)
   * for the provided class.
   *
   * @param  c  The class for which to retrieve the unqualified name.
   *
   * @return  The unqualified name for the provided class.
   */
  public static String getUnqualifiedClassName(final Class<?> c)
  {
    final String className     = c.getName();
    final int    lastPeriodPos = className.lastIndexOf('.');

    if (lastPeriodPos > 0)
    {
      return className.substring(lastPeriodPos+1);
    }
    else
    {
      return className;
    }
  }



  /**
   * Retrieves a {@code TimeZone} object that represents the UTC (universal
   * coordinated time) time zone.
   *
   * @return  A {@code TimeZone} object that represents the UTC time zone.
   */
  public static TimeZone getUTCTimeZone()
  {
    return UTC_TIME_ZONE;
  }



  /**
   * Encodes the provided timestamp in generalized time format.
   *
   * @param  timestamp  The timestamp to be encoded in generalized time format.
   *                    It should use the same format as the
   *                    {@code System.currentTimeMillis()} method (i.e., the
   *                    number of milliseconds since 12:00am UTC on January 1,
   *                    1970).
   *
   * @return  The generalized time representation of the provided date.
   */
  public static String encodeGeneralizedTime(final long timestamp)
  {
    return encodeGeneralizedTime(new Date(timestamp));
  }



  /**
   * Encodes the provided date in generalized time format.
   *
   * @param  d  The date to be encoded in generalized time format.
   *
   * @return  The generalized time representation of the provided date.
   */
  public static String encodeGeneralizedTime(final Date d)
  {
    SimpleDateFormat dateFormat = DATE_FORMATTERS.get();
    if (dateFormat == null)
    {
      dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
      dateFormat.setTimeZone(UTC_TIME_ZONE);
      DATE_FORMATTERS.set(dateFormat);
    }

    return dateFormat.format(d);
  }



  /**
   * Decodes the provided string as a timestamp in generalized time format.
   *
   * @param  t  The timestamp to be decoded.  It must not be {@code null}.
   *
   * @return  The {@code Date} object decoded from the provided timestamp.
   *
   * @throws  ParseException  If the provided string could not be decoded as a
   *                          timestamp in generalized time format.
   */
  public static Date decodeGeneralizedTime(final String t)
         throws ParseException
  {
    ensureNotNull(t);

    // Extract the time zone information from the end of the value.
    int tzPos;
    final TimeZone tz;
    if (t.endsWith("Z"))
    {
      tz = TimeZone.getTimeZone("UTC");
      tzPos = t.length() - 1;
    }
    else
    {
      tzPos = t.lastIndexOf('-');
      if (tzPos < 0)
      {
        tzPos = t.lastIndexOf('+');
        if (tzPos < 0)
        {
          throw new ParseException(ERR_GENTIME_DECODE_CANNOT_PARSE_TZ.get(t),
                                   0);
        }
      }

      tz = TimeZone.getTimeZone("GMT" + t.substring(tzPos));
      if (tz.getRawOffset() == 0)
      {
        // This is the default time zone that will be returned if the value
        // cannot be parsed.  If it's valid, then it will end in "+0000" or
        // "-0000".  Otherwise, it's invalid and GMT was just a fallback.
        if (! (t.endsWith("+0000") || t.endsWith("-0000")))
        {
          throw new ParseException(ERR_GENTIME_DECODE_CANNOT_PARSE_TZ.get(t),
                                   tzPos);
        }
      }
    }


    // See if the timestamp has a sub-second portion.  Note that if there is a
    // sub-second portion, then we may need to massage the value so that there
    // are exactly three sub-second characters so that it can be interpreted as
    // milliseconds.
    final String subSecFormatStr;
    final String trimmedTimestamp;
    int periodPos = t.lastIndexOf('.', tzPos);
    if (periodPos > 0)
    {
      final int subSecondLength = tzPos - periodPos - 1;
      switch (subSecondLength)
      {
        case 0:
          subSecFormatStr  = "";
          trimmedTimestamp = t.substring(0, periodPos);
          break;
        case 1:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, (periodPos+2)) + "00";
          break;
        case 2:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, (periodPos+3)) + '0';
          break;
        default:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, periodPos+4);
          break;
      }
    }
    else
    {
      subSecFormatStr  = "";
      periodPos        = tzPos;
      trimmedTimestamp = t.substring(0, tzPos);
    }


    // Look at where the period is (or would be if it existed) to see how many
    // characters are in the integer portion.  This will give us what we need
    // for the rest of the format string.
    final String formatStr;
    switch (periodPos)
    {
      case 10:
        formatStr = "yyyyMMddHH" + subSecFormatStr;
        break;
      case 12:
        formatStr = "yyyyMMddHHmm" + subSecFormatStr;
        break;
      case 14:
        formatStr = "yyyyMMddHHmmss" + subSecFormatStr;
        break;
      default:
        throw new ParseException(ERR_GENTIME_CANNOT_PARSE_INVALID_LENGTH.get(t),
                                 periodPos);
    }


    // We should finally be able to create an appropriate date format object
    // to parse the trimmed version of the timestamp.
    final SimpleDateFormat dateFormat = new SimpleDateFormat(formatStr);
    dateFormat.setTimeZone(tz);
    dateFormat.setLenient(false);
    return dateFormat.parse(trimmedTimestamp);
  }



  /**
   * Trims only leading spaces from the provided string, leaving any trailing
   * spaces intact.
   *
   * @param  s  The string to be processed.  It must not be {@code null}.
   *
   * @return  The original string if no trimming was required, or a new string
   *          without leading spaces if the provided string had one or more.  It
   *          may be an empty string if the provided string was an empty string
   *          or contained only spaces.
   */
  public static String trimLeading(final String s)
  {
    ensureNotNull(s);

    int nonSpacePos = 0;
    final int length = s.length();
    while ((nonSpacePos < length) && (s.charAt(nonSpacePos) == ' '))
    {
      nonSpacePos++;
    }

    if (nonSpacePos == 0)
    {
      // There were no leading spaces.
      return s;
    }
    else if (nonSpacePos >= length)
    {
      // There were no non-space characters.
      return "";
    }
    else
    {
      // There were leading spaces, so return the string without them.
      return s.substring(nonSpacePos, length);
    }
  }



  /**
   * Trims only trailing spaces from the provided string, leaving any leading
   * spaces intact.
   *
   * @param  s  The string to be processed.  It must not be {@code null}.
   *
   * @return  The original string if no trimming was required, or a new string
   *          without trailing spaces if the provided string had one or more.
   *          It may be an empty string if the provided string was an empty
   *          string or contained only spaces.
   */
  public static String trimTrailing(final String s)
  {
    ensureNotNull(s);

    final int lastPos = s.length() - 1;
    int nonSpacePos = lastPos;
    while ((nonSpacePos >= 0) && (s.charAt(nonSpacePos) == ' '))
    {
      nonSpacePos--;
    }

    if (nonSpacePos < 0)
    {
      // There were no non-space characters.
      return "";
    }
    else if (nonSpacePos == lastPos)
    {
      // There were no trailing spaces.
      return s;
    }
    else
    {
      // There were trailing spaces, so return the string without them.
      return s.substring(0, (nonSpacePos+1));
    }
  }



  /**
   * Wraps the contents of the specified line using the given width.  It will
   * attempt to wrap at spaces to preserve words, but if that is not possible
   * (because a single "word" is longer than the maximum width), then it will
   * wrap in the middle of the word at the specified maximum width.
   *
   * @param  line      The line to be wrapped.  It must not be {@code null}.
   * @param  maxWidth  The maximum width for lines in the resulting list.  A
   *                   value less than or equal to zero will cause no wrapping
   *                   to be performed.
   *
   * @return  A list of the wrapped lines.  It may be empty if the provided line
   *          contained only spaces.
   */
  public static List<String> wrapLine(final String line, final int maxWidth)
  {
    return wrapLine(line, maxWidth, maxWidth);
  }



  /**
   * Wraps the contents of the specified line using the given width.  It will
   * attempt to wrap at spaces to preserve words, but if that is not possible
   * (because a single "word" is longer than the maximum width), then it will
   * wrap in the middle of the word at the specified maximum width.
   *
   * @param  line                    The line to be wrapped.  It must not be
   *                                 {@code null}.
   * @param  maxFirstLineWidth       The maximum length for the first line in
   *                                 the resulting list.  A value less than or
   *                                 equal to zero will cause no wrapping to be
   *                                 performed.
   * @param  maxSubsequentLineWidth  The maximum length for all lines except the
   *                                 first line.  This must be greater than zero
   *                                 unless {@code maxFirstLineWidth} is less
   *                                 than or equal to zero.
   *
   * @return  A list of the wrapped lines.  It may be empty if the provided line
   *          contained only spaces.
   */
  public static List<String> wrapLine(final String line,
                                      final int maxFirstLineWidth,
                                      final int maxSubsequentLineWidth)
  {
    if (maxFirstLineWidth > 0)
    {
      Validator.ensureTrue(maxSubsequentLineWidth > 0);
    }

    // See if the provided string already contains line breaks.  If so, then
    // treat it as multiple lines rather than a single line.
    final int breakPos = line.indexOf('\n');
    if (breakPos >= 0)
    {
      final ArrayList<String> lineList = new ArrayList<String>(10);
      final StringTokenizer tokenizer = new StringTokenizer(line, "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        lineList.addAll(wrapLine(tokenizer.nextToken(), maxFirstLineWidth,
             maxSubsequentLineWidth));
      }

      return lineList;
    }

    final int length = line.length();
    if ((maxFirstLineWidth <= 0) || (length < maxFirstLineWidth))
    {
      return Arrays.asList(line);
    }


    int wrapPos = maxFirstLineWidth;
    int lastWrapPos = 0;
    final ArrayList<String> lineList = new ArrayList<String>(5);
    while (true)
    {
      final int spacePos = line.lastIndexOf(' ', wrapPos);
      if (spacePos > lastWrapPos)
      {
        // We found a space in an acceptable location, so use it after trimming
        // any trailing spaces.
        final String s = trimTrailing(line.substring(lastWrapPos, spacePos));

        // Don't bother adding the line if it contained only spaces.
        if (s.length() > 0)
        {
          lineList.add(s);
        }

        wrapPos = spacePos;
      }
      else
      {
        // We didn't find any spaces, so we'll have to insert a hard break at
        // the specified wrap column.
        lineList.add(line.substring(lastWrapPos, wrapPos));
      }

      // Skip over any spaces before the next non-space character.
      while ((wrapPos < length) && (line.charAt(wrapPos) == ' '))
      {
        wrapPos++;
      }

      lastWrapPos = wrapPos;
      wrapPos += maxSubsequentLineWidth;
      if (wrapPos >= length)
      {
        // The last fragment can fit on the line, so we can handle that now and
        // break.
        if (lastWrapPos >= length)
        {
          break;
        }
        else
        {
          final String s = line.substring(lastWrapPos);
          if (s.length() > 0)
          {
            lineList.add(s);
          }
          break;
        }
      }
    }

    return lineList;
  }



  /**
   * This method returns a form of the provided argument that is safe to
   * use on the command line for the local platform. This method is provided as
   * a convenience wrapper around {@link ExampleCommandLineArgument}.  Calling
   * this method is equivalent to:
   *
   * <PRE>
   *  return ExampleCommandLineArgument.getCleanArgument(s).getLocalForm();
   * </PRE>
   *
   * For getting direct access to command line arguments that are safe to
   * use on other platforms, call
   * {@link ExampleCommandLineArgument#getCleanArgument}.
   *
   * @param  s  The string to be processed.  It must not be {@code null}.
   *
   * @return  A cleaned version of the provided string in a form that will allow
   *          it to be displayed as the value of a command-line argument on.
   */
  public static String cleanExampleCommandLineArgument(final String s)
  {
    return ExampleCommandLineArgument.getCleanArgument(s).getLocalForm();
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  a  The array of strings to concatenate.  It must not be
   *            {@code null}.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided array.
   */
  public static String concatenateStrings(final String... a)
  {
    return concatenateStrings(null, null, "  ", null, null, a);
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  l  The list of strings to concatenate.  It must not be
   *            {@code null}.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided list.
   */
  public static String concatenateStrings(final List<String> l)
  {
    return concatenateStrings(null, null, "  ", null, null, l);
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  beforeList       A string that should be placed at the beginning of
   *                          the list.  It may be {@code null} or empty if
   *                          nothing should be placed at the beginning of the
   *                          list.
   * @param  beforeElement    A string that should be placed before each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed before each element.
   * @param  betweenElements  The separator that should be placed between
   *                          elements in the list.  It may be {@code null} or
   *                          empty if no separator should be placed between
   *                          elements.
   * @param  afterElement     A string that should be placed after each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed after each element.
   * @param  afterList        A string that should be placed at the end of the
   *                          list.  It may be {@code null} or empty if nothing
   *                          should be placed at the end of the list.
   * @param  a                The array of strings to concatenate.  It must not
   *                          be {@code null}.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided list.
   */
  public static String concatenateStrings(final String beforeList,
                                          final String beforeElement,
                                          final String betweenElements,
                                          final String afterElement,
                                          final String afterList,
                                          final String... a)
  {
    return concatenateStrings(beforeList, beforeElement, betweenElements,
         afterElement, afterList, Arrays.asList(a));
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  beforeList       A string that should be placed at the beginning of
   *                          the list.  It may be {@code null} or empty if
   *                          nothing should be placed at the beginning of the
   *                          list.
   * @param  beforeElement    A string that should be placed before each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed before each element.
   * @param  betweenElements  The separator that should be placed between
   *                          elements in the list.  It may be {@code null} or
   *                          empty if no separator should be placed between
   *                          elements.
   * @param  afterElement     A string that should be placed after each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed after each element.
   * @param  afterList        A string that should be placed at the end of the
   *                          list.  It may be {@code null} or empty if nothing
   *                          should be placed at the end of the list.
   * @param  l                The list of strings to concatenate.  It must not
   *                          be {@code null}.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided list.
   */
  public static String concatenateStrings(final String beforeList,
                                          final String beforeElement,
                                          final String betweenElements,
                                          final String afterElement,
                                          final String afterList,
                                          final List<String> l)
  {
    ensureNotNull(l);

    final StringBuilder buffer = new StringBuilder();

    if (beforeList != null)
    {
      buffer.append(beforeList);
    }

    final Iterator<String> iterator = l.iterator();
    while (iterator.hasNext())
    {
      if (beforeElement != null)
      {
        buffer.append(beforeElement);
      }

      buffer.append(iterator.next());

      if (afterElement != null)
      {
        buffer.append(afterElement);
      }

      if ((betweenElements != null) && iterator.hasNext())
      {
        buffer.append(betweenElements);
      }
    }

    if (afterList != null)
    {
      buffer.append(afterList);
    }

    return buffer.toString();
  }



  /**
   * Converts a duration in seconds to a string with a human-readable duration
   * which may include days, hours, minutes, and seconds, to the extent that
   * they are needed.
   *
   * @param  s  The number of seconds to be represented.
   *
   * @return  A string containing a human-readable representation of the
   *          provided time.
   */
  public static String secondsToHumanReadableDuration(final long s)
  {
    return millisToHumanReadableDuration(s * 1000L);
  }



  /**
   * Converts a duration in seconds to a string with a human-readable duration
   * which may include days, hours, minutes, and seconds, to the extent that
   * they are needed.
   *
   * @param  m  The number of milliseconds to be represented.
   *
   * @return  A string containing a human-readable representation of the
   *          provided time.
   */
  public static String millisToHumanReadableDuration(final long m)
  {
    final StringBuilder buffer = new StringBuilder();
    long numMillis = m;

    final long numDays = numMillis / 86400000L;
    if (numDays > 0)
    {
      numMillis -= (numDays * 86400000L);
      if (numDays == 1)
      {
        buffer.append(INFO_NUM_DAYS_SINGULAR.get(numDays));
      }
      else
      {
        buffer.append(INFO_NUM_DAYS_PLURAL.get(numDays));
      }
    }

    final long numHours = numMillis / 3600000L;
    if (numHours > 0)
    {
      numMillis -= (numHours * 3600000L);
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      if (numHours == 1)
      {
        buffer.append(INFO_NUM_HOURS_SINGULAR.get(numHours));
      }
      else
      {
        buffer.append(INFO_NUM_HOURS_PLURAL.get(numHours));
      }
    }

    final long numMinutes = numMillis / 60000L;
    if (numMinutes > 0)
    {
      numMillis -= (numMinutes * 60000L);
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      if (numMinutes == 1)
      {
        buffer.append(INFO_NUM_MINUTES_SINGULAR.get(numMinutes));
      }
      else
      {
        buffer.append(INFO_NUM_MINUTES_PLURAL.get(numMinutes));
      }
    }

    if (numMillis == 1000)
    {
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      buffer.append(INFO_NUM_SECONDS_SINGULAR.get(1));
    }
    else if ((numMillis > 0) || (buffer.length() == 0))
    {
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      final long numSeconds = numMillis / 1000L;
      numMillis -= (numSeconds * 1000L);
      if ((numMillis % 1000L) != 0L)
      {
        final double numSecondsDouble = numSeconds + (numMillis / 1000.0);
        final DecimalFormat decimalFormat = new DecimalFormat("0.000");
        buffer.append(INFO_NUM_SECONDS_WITH_DECIMAL.get(
             decimalFormat.format(numSecondsDouble)));
      }
      else
      {
        buffer.append(INFO_NUM_SECONDS_PLURAL.get(numSeconds));
      }
    }

    return buffer.toString();
  }



  /**
   * Converts the provided number of nanoseconds to milliseconds.
   *
   * @param  nanos  The number of nanoseconds to convert to milliseconds.
   *
   * @return  The number of milliseconds that most closely corresponds to the
   *          specified number of nanoseconds.
   */
  public static long nanosToMillis(final long nanos)
  {
    return Math.max(0L, Math.round(nanos / 1000000.0d));
  }



  /**
   * Converts the provided number of milliseconds to nanoseconds.
   *
   * @param  millis  The number of milliseconds to convert to nanoseconds.
   *
   * @return  The number of nanoseconds that most closely corresponds to the
   *          specified number of milliseconds.
   */
  public static long millisToNanos(final long millis)
  {
    return Math.max(0L, (millis * 1000000L));
  }



  /**
   * Indicates whether the provided string is a valid numeric OID.  A numeric
   * OID must start and end with a digit, must have at least on period, must
   * contain only digits and periods, and must not have two consecutive periods.
   *
   * @param  s  The string to examine.  It must not be {@code null}.
   *
   * @return  {@code true} if the provided string is a valid numeric OID, or
   *          {@code false} if not.
   */
  public static boolean isNumericOID(final String s)
  {
    boolean digitRequired = true;
    boolean periodFound   = false;
    for (final char c : s.toCharArray())
    {
      switch (c)
      {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          digitRequired = false;
          break;

        case '.':
          if (digitRequired)
          {
            return false;
          }
          else
          {
            digitRequired = true;
          }
          periodFound = true;
          break;

        default:
          return false;
      }

    }

    return (periodFound && (! digitRequired));
  }



  /**
   * Capitalizes the provided string.  The first character will be converted to
   * uppercase, and the rest of the string will be left unaltered.
   *
   * @param  s  The string to be capitalized.
   *
   * @return  A capitalized version of the provided string.
   */
  public static String capitalize(final String s)
  {
    return capitalize(s, false);
  }



  /**
   * Capitalizes the provided string.  The first character of the string (or
   * optionally the first character of each word in the string)
   *
   * @param  s         The string to be capitalized.
   * @param  allWords  Indicates whether to capitalize all words in the string,
   *                   or only the first word.
   *
   * @return  A capitalized version of the provided string.
   */
  public static String capitalize(final String s, final boolean allWords)
  {
    if (s == null)
    {
      return null;
    }

    switch (s.length())
    {
      case 0:
        return s;

      case 1:
        return s.toUpperCase();

      default:
        boolean capitalize = true;
        final char[] chars = s.toCharArray();
        final StringBuilder buffer = new StringBuilder(chars.length);
        for (final char c : chars)
        {
          // Whitespace and punctuation will be considered word breaks.
          if (Character.isWhitespace(c) ||
              (((c >= '!') && (c <= '.')) ||
               ((c >= ':') && (c <= '@')) ||
               ((c >= '[') && (c <= '`')) ||
               ((c >= '{') && (c <= '~'))))
          {
            buffer.append(c);
            capitalize |= allWords;
          }
          else if (capitalize)
          {
            buffer.append(Character.toUpperCase(c));
            capitalize = false;
          }
          else
          {
            buffer.append(c);
          }
        }
        return buffer.toString();
    }
  }



  /**
   * Encodes the provided UUID to a byte array containing its 128-bit
   * representation.
   *
   * @param  uuid  The UUID to be encoded.  It must not be {@code null}.
   *
   * @return  The byte array containing the 128-bit encoded UUID.
   */
  public static byte[] encodeUUID(final UUID uuid)
  {
    final byte[] b = new byte[16];

    final long mostSignificantBits  = uuid.getMostSignificantBits();
    b[0]  = (byte) ((mostSignificantBits >> 56) & 0xFF);
    b[1]  = (byte) ((mostSignificantBits >> 48) & 0xFF);
    b[2]  = (byte) ((mostSignificantBits >> 40) & 0xFF);
    b[3]  = (byte) ((mostSignificantBits >> 32) & 0xFF);
    b[4]  = (byte) ((mostSignificantBits >> 24) & 0xFF);
    b[5]  = (byte) ((mostSignificantBits >> 16) & 0xFF);
    b[6]  = (byte) ((mostSignificantBits >> 8) & 0xFF);
    b[7]  = (byte) (mostSignificantBits & 0xFF);

    final long leastSignificantBits = uuid.getLeastSignificantBits();
    b[8]  = (byte) ((leastSignificantBits >> 56) & 0xFF);
    b[9]  = (byte) ((leastSignificantBits >> 48) & 0xFF);
    b[10] = (byte) ((leastSignificantBits >> 40) & 0xFF);
    b[11] = (byte) ((leastSignificantBits >> 32) & 0xFF);
    b[12] = (byte) ((leastSignificantBits >> 24) & 0xFF);
    b[13] = (byte) ((leastSignificantBits >> 16) & 0xFF);
    b[14] = (byte) ((leastSignificantBits >> 8) & 0xFF);
    b[15] = (byte) (leastSignificantBits & 0xFF);

    return b;
  }



  /**
   * Decodes the value of the provided byte array as a Java UUID.
   *
   * @param  b  The byte array to be decoded as a UUID.  It must not be
   *            {@code null}.
   *
   * @return  The decoded UUID.
   *
   * @throws  ParseException  If the provided byte array cannot be parsed as a
   *                         UUID.
   */
  public static UUID decodeUUID(final byte[] b)
         throws ParseException
  {
    if (b.length != 16)
    {
      throw new ParseException(ERR_DECODE_UUID_INVALID_LENGTH.get(toHex(b)), 0);
    }

    long mostSignificantBits = 0L;
    for (int i=0; i < 8; i++)
    {
      mostSignificantBits = (mostSignificantBits << 8) | (b[i] & 0xFF);
    }

    long leastSignificantBits = 0L;
    for (int i=8; i < 16; i++)
    {
      leastSignificantBits = (leastSignificantBits << 8) | (b[i] & 0xFF);
    }

    return new UUID(mostSignificantBits, leastSignificantBits);
  }



  /**
   * Returns {@code true} if and only if the current process is running on
   * a Windows-based operating system.
   *
   * @return  {@code true} if the current process is running on a Windows-based
   *          operating system and {@code false} otherwise.
   */
  public static boolean isWindows()
  {
    final String osName = toLowerCase(System.getProperty("os.name"));
    return ((osName != null) && osName.contains("windows"));
  }



  /**
   * Attempts to parse the contents of the provided string to an argument list
   * (e.g., converts something like "--arg1 arg1value --arg2 --arg3 arg3value"
   * to a list of "--arg1", "arg1value", "--arg2", "--arg3", "arg3value").
   *
   * @param  s  The string to be converted to an argument list.
   *
   * @return  The parsed argument list.
   *
   * @throws  ParseException  If a problem is encountered while attempting to
   *                          parse the given string to an argument list.
   */
  public static List<String> toArgumentList(final String s)
         throws ParseException
  {
    if ((s == null) || (s.length() == 0))
    {
      return Collections.emptyList();
    }

    int quoteStartPos = -1;
    boolean inEscape = false;
    final ArrayList<String> argList = new ArrayList<String>();
    final StringBuilder currentArg = new StringBuilder();
    for (int i=0; i < s.length(); i++)
    {
      final char c = s.charAt(i);
      if (inEscape)
      {
        currentArg.append(c);
        inEscape = false;
        continue;
      }

      if (c == '\\')
      {
        inEscape = true;
      }
      else if (c == '"')
      {
        if (quoteStartPos >= 0)
        {
          quoteStartPos = -1;
        }
        else
        {
          quoteStartPos = i;
        }
      }
      else if (c == ' ')
      {
        if (quoteStartPos >= 0)
        {
          currentArg.append(c);
        }
        else if (currentArg.length() > 0)
        {
          argList.add(currentArg.toString());
          currentArg.setLength(0);
        }
      }
      else
      {
        currentArg.append(c);
      }
    }

    if (s.endsWith("\\") && (! s.endsWith("\\\\")))
    {
      throw new ParseException(ERR_ARG_STRING_DANGLING_BACKSLASH.get(),
           (s.length() - 1));
    }

    if (quoteStartPos >= 0)
    {
      throw new ParseException(ERR_ARG_STRING_UNMATCHED_QUOTE.get(
           quoteStartPos), quoteStartPos);
    }

    if (currentArg.length() > 0)
    {
      argList.add(currentArg.toString());
    }

    return Collections.unmodifiableList(argList);
  }



  /**
   * Creates a modifiable list with all of the items of the provided array in
   * the same order.  This method behaves much like {@code Arrays.asList},
   * except that if the provided array is {@code null}, then it will return a
   * {@code null} list rather than throwing an exception.
   *
   * @param  <T>  The type of item contained in the provided array.
   *
   * @param  array  The array of items to include in the list.
   *
   * @return  The list that was created, or {@code null} if the provided array
   *          was {@code null}.
   */
  public static <T> List<T> toList(final T[] array)
  {
    if (array == null)
    {
      return null;
    }

    final ArrayList<T> l = new ArrayList<T>(array.length);
    l.addAll(Arrays.asList(array));
    return l;
  }



  /**
   * Creates a modifiable list with all of the items of the provided array in
   * the same order.  This method behaves much like {@code Arrays.asList},
   * except that if the provided array is {@code null}, then it will return an
   * empty list rather than throwing an exception.
   *
   * @param  <T>  The type of item contained in the provided array.
   *
   * @param  array  The array of items to include in the list.
   *
   * @return  The list that was created, or an empty list if the provided array
   *          was {@code null}.
   */
  public static <T> List<T> toNonNullList(final T[] array)
  {
    if (array == null)
    {
      return new ArrayList<T>(0);
    }

    final ArrayList<T> l = new ArrayList<T>(array.length);
    l.addAll(Arrays.asList(array));
    return l;
  }



  /**
   * Indicates whether both of the provided objects are {@code null} or both
   * are logically equal (using the {@code equals} method).
   *
   * @param  o1  The first object for which to make the determination.
   * @param  o2  The second object for which to make the determination.
   *
   * @return  {@code true} if both objects are {@code null} or both are
   *          logically equal, or {@code false} if only one of the objects is
   *          {@code null} or they are not logically equal.
   */
  public static boolean bothNullOrEqual(final Object o1, final Object o2)
  {
    if (o1 == null)
    {
      return (o2 == null);
    }
    else if (o2 == null)
    {
      return false;
    }

    return o1.equals(o2);
  }



  /**
   * Indicates whether both of the provided strings are {@code null} or both
   * are logically equal ignoring differences in capitalization (using the
   * {@code equalsIgnoreCase} method).
   *
   * @param  s1  The first string for which to make the determination.
   * @param  s2  The second string for which to make the determination.
   *
   * @return  {@code true} if both strings are {@code null} or both are
   *          logically equal ignoring differences in capitalization, or
   *          {@code false} if only one of the objects is {@code null} or they
   *          are not logically equal ignoring capitalization.
   */
  public static boolean bothNullOrEqualIgnoreCase(final String s1,
                                                  final String s2)
  {
    if (s1 == null)
    {
      return (s2 == null);
    }
    else if (s2 == null)
    {
      return false;
    }

    return s1.equalsIgnoreCase(s2);
  }



  /**
   * Indicates whether the provided string arrays have the same elements,
   * ignoring the order in which they appear and differences in capitalization.
   * It is assumed that neither array contains {@code null} strings, and that
   * no string appears more than once in each array.
   *
   * @param  a1  The first array for which to make the determination.
   * @param  a2  The second array for which to make the determination.
   *
   * @return  {@code true} if both arrays have the same set of strings, or
   *          {@code false} if not.
   */
  public static boolean stringsEqualIgnoreCaseOrderIndependent(
                             final String[] a1, final String[] a2)
  {
    if (a1 == null)
    {
      return (a2 == null);
    }
    else if (a2 == null)
    {
      return false;
    }

    if (a1.length != a2.length)
    {
      return false;
    }

    if (a1.length == 1)
    {
      return (a1[0].equalsIgnoreCase(a2[0]));
    }

    final HashSet<String> s1 = new HashSet<String>(a1.length);
    for (final String s : a1)
    {
      s1.add(toLowerCase(s));
    }

    final HashSet<String> s2 = new HashSet<String>(a2.length);
    for (final String s : a2)
    {
      s2.add(toLowerCase(s));
    }

    return s1.equals(s2);
  }



  /**
   * Indicates whether the provided arrays have the same elements, ignoring the
   * order in which they appear.  It is assumed that neither array contains
   * {@code null} elements, and that no element appears more than once in each
   * array.
   *
   * @param  <T>  The type of element contained in the arrays.
   *
   * @param  a1  The first array for which to make the determination.
   * @param  a2  The second array for which to make the determination.
   *
   * @return  {@code true} if both arrays have the same set of elements, or
   *          {@code false} if not.
   */
  public static <T> boolean arraysEqualOrderIndependent(final T[] a1,
                                                        final T[] a2)
  {
    if (a1 == null)
    {
      return (a2 == null);
    }
    else if (a2 == null)
    {
      return false;
    }

    if (a1.length != a2.length)
    {
      return false;
    }

    if (a1.length == 1)
    {
      return (a1[0].equals(a2[0]));
    }

    final HashSet<T> s1 = new HashSet<T>(Arrays.asList(a1));
    final HashSet<T> s2 = new HashSet<T>(Arrays.asList(a2));
    return s1.equals(s2);
  }



  /**
   * Determines the number of bytes in a UTF-8 character that starts with the
   * given byte.
   *
   * @param  b  The byte for which to make the determination.
   *
   * @return  The number of bytes in a UTF-8 character that starts with the
   *          given byte, or -1 if it does not appear to be a valid first byte
   *          for a UTF-8 character.
   */
  public static int numBytesInUTF8CharacterWithFirstByte(final byte b)
  {
    if ((b & 0x7F) == b)
    {
      return 1;
    }
    else if ((b & 0xE0) == 0xC0)
    {
      return 2;
    }
    else if ((b & 0xF0) == 0xE0)
    {
      return 3;
    }
    else if ((b & 0xF8) == 0xF0)
    {
      return 4;
    }
    else
    {
      return -1;
    }
  }



  /**
   * Indicates whether the provided attribute name should be considered a
   * sensitive attribute for the purposes of {@code toCode} methods.  If an
   * attribute is considered sensitive, then its values will be redacted in the
   * output of the {@code toCode} methods.
   *
   * @param  name  The name for which to make the determination.  It may or may
   *               not include attribute options.  It must not be {@code null}.
   *
   * @return  {@code true} if the specified attribute is one that should be
   *          considered sensitive for the
   */
  public static boolean isSensitiveToCodeAttribute(final String name)
  {
    final String lowerBaseName = Attribute.getBaseName(name).toLowerCase();
    return TO_CODE_SENSITIVE_ATTRIBUTE_NAMES.contains(lowerBaseName);
  }



  /**
   * Retrieves a set containing the base names (in all lowercase characters) of
   * any attributes that should be considered sensitive for the purposes of the
   * {@code toCode} methods.  By default, only the userPassword and
   * authPassword attributes and their respective OIDs will be included.
   *
   * @return  A set containing the base names (in all lowercase characters) of
   *          any attributes that should be considered sensitive for the
   *          purposes of the {@code toCode} methods.
   */
  public static Set<String> getSensitiveToCodeAttributeBaseNames()
  {
    return TO_CODE_SENSITIVE_ATTRIBUTE_NAMES;
  }



  /**
   * Specifies the names of any attributes that should be considered sensitive
   * for the purposes of the {@code toCode} methods.
   *
   * @param  names  The names of any attributes that should be considered
   *                sensitive for the purposes of the {@code toCode} methods.
   *                It may be {@code null} or empty if no attributes should be
   *                considered sensitive.
   */
  public static void setSensitiveToCodeAttributes(final String... names)
  {
    setSensitiveToCodeAttributes(toList(names));
  }



  /**
   * Specifies the names of any attributes that should be considered sensitive
   * for the purposes of the {@code toCode} methods.
   *
   * @param  names  The names of any attributes that should be considered
   *                sensitive for the purposes of the {@code toCode} methods.
   *                It may be {@code null} or empty if no attributes should be
   *                considered sensitive.
   */
  public static void setSensitiveToCodeAttributes(
                          final Collection<String> names)
  {
    if ((names == null) || names.isEmpty())
    {
      TO_CODE_SENSITIVE_ATTRIBUTE_NAMES = Collections.emptySet();
    }
    else
    {
      final LinkedHashSet<String> nameSet =
           new LinkedHashSet<String>(names.size());
      for (final String s : names)
      {
        nameSet.add(Attribute.getBaseName(s).toLowerCase());
      }

      TO_CODE_SENSITIVE_ATTRIBUTE_NAMES = Collections.unmodifiableSet(nameSet);
    }
  }



  /**
   * Creates a new {@code IOException} with a cause.  The constructor needed to
   * do this wasn't available until Java SE 6, so reflection is used to invoke
   * this constructor in versions of Java that provide it.  In Java SE 5, the
   * provided message will be augmented with information about the cause.
   *
   * @param  message  The message to use for the exception.  This may be
   *                  {@code null} if the message should be generated from the
   *                  provided cause.
   * @param  cause    The underlying cause for the exception.  It may be
   *                  {@code null} if the exception should have only a message.
   *
   * @return  The {@code IOException} object that was created.
   */
  public static IOException createIOExceptionWithCause(final String message,
                                                       final Throwable cause)
  {
    if (cause == null)
    {
      return new IOException(message);
    }
    else if (message == null)
    {
      return new IOException(cause);
    }
    else
    {
      return new IOException(message, cause);
    }
  }



  /**
   * Converts the provided string (which may include line breaks) into a list
   * containing the lines without the line breaks.
   *
   * @param  s  The string to convert into a list of its representative lines.
   *
   * @return  A list containing the lines that comprise the given string.
   */
  public static List<String> stringToLines(final String s)
  {
    final ArrayList<String> l = new ArrayList<String>(10);

    if (s == null)
    {
      return l;
    }

    final BufferedReader reader = new BufferedReader(new StringReader(s));

    try
    {
      while (true)
      {
        try
        {
          final String line = reader.readLine();
          if (line == null)
          {
            return l;
          }
          else
          {
            l.add(line);
          }
        }
        catch (final Exception e)
        {
          debugException(e);

          // This should never happen.  If it does, just return a list
          // containing a single item that is the original string.
          l.clear();
          l.add(s);
          return l;
        }
      }
    }
    finally
    {
      try
      {
        // This is technically not necessary in this case, but it's good form.
        reader.close();
      }
      catch (final Exception e)
      {
        debugException(e);
        // This should never happen, and there's nothing we need to do even if
        // it does.
      }
    }
  }



  /**
   * Constructs a {@code File} object from the provided path.
   *
   * @param  baseDirectory  The base directory to use as the starting point.
   *                        It must not be {@code null} and is expected to
   *                        represent a directory.
   * @param  pathElements   An array of the elements that make up the remainder
   *                        of the path to the specified file, in order from
   *                        paths closest to the root of the filesystem to
   *                        furthest away (that is, the first element should
   *                        represent a file or directory immediately below the
   *                        base directory, the second is one level below that,
   *                        and so on).  It may be {@code null} or empty if the
   *                        base directory should be used.
   *
   * @return  The constructed {@code File} object.
   */
  public static File constructPath(final File baseDirectory,
                                   final String... pathElements)
  {
    Validator.ensureNotNull(baseDirectory);

    File f = baseDirectory;
    if (pathElements != null)
    {
      for (final String pathElement : pathElements)
      {
        f = new File(f, pathElement);
      }
    }

    return f;
  }



  /**
   * Creates a byte array from the provided integer values.  All of the integer
   * values must be between 0x00 and 0xFF (0 and 255), inclusive.  Any bits
   * set outside of that range will be ignored.
   *
   * @param  bytes  The values to include in the byte array.
   *
   * @return  A byte array with the provided set of values.
   */
  public static byte[] byteArray(final int... bytes)
  {
    if ((bytes == null) || (bytes.length == 0))
    {
      return NO_BYTES;
    }

    final byte[] byteArray = new byte[bytes.length];
    for (int i=0; i < bytes.length; i++)
    {
      byteArray[i] = (byte) (bytes[i] & 0xFF);
    }

    return byteArray;
  }
}
