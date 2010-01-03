/*
 * Copyright 2007-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2010 UnboundID Corp.
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



import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;

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
   * The end-of-line marker for this platform.
   */
  public static final String EOL = System.getProperty("line.separator");



  /**
   * A byte array containing the end-of-line marker for this platform.
   */
  public static final byte[] EOL_BYTES = getBytes(EOL);



  /**
   * The thread-local date formatter used to encode generalized time values.
   */
  private static final ThreadLocal<SimpleDateFormat> dateFormatters =
       new ThreadLocal<SimpleDateFormat>();



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
        catch (Exception e)
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
    catch (Exception e)
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
    catch (Exception e)
    {
      // This should never happen.
      debugException(e);
      return new String(b, offset, length);
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
    for (final byte bt : b)
    {
      toHex(bt, buffer);
    }
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
    buffer.append(", revision=");
    buffer.append(Version.REVISION_NUMBER);
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
    if ((t instanceof RuntimeException) || (t instanceof Error))
    {
      return getStackTrace(t);
    }
    else
    {
      buffer.append(String.valueOf(t));
    }

    final Throwable cause = t.getCause();
    if (cause != null)
    {
      buffer.append(" caused by ");
      buffer.append(getExceptionMessage(cause));
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
   * Encodes the provided date in generalized time format.
   *
   * @param  d  The date to be encoded in generalized time format.
   *
   * @return  The generalized time representation of the provided date.
   */
  public static String encodeGeneralizedTime(final Date d)
  {
    SimpleDateFormat dateFormat = dateFormatters.get();
    if (dateFormat == null)
    {
      dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
      dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      dateFormatters.set(dateFormat);
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
    final int length = line.length();
    if ((maxWidth <= 0) || (length < maxWidth))
    {
      return Arrays.asList(line);
    }


    int wrapPos = maxWidth;
    int lastWrapPos = 0;
    final LinkedList<String> lineList = new LinkedList<String>();
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
      wrapPos += maxWidth;
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
          final String s = trimTrailing(line.substring(lastWrapPos));
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
   * Formats the provided string in a manner that will allow it to be properly
   * displayed as the value of a command-line argument in an example.  The
   * processing that will be performed includes:
   * <UL>
   *   <LI>If the provided string has a length of zero characters, then the
   *       value returned will be two consecutive double quotes (i.e., "").</LI>
   *   <LI>All instances of the following characters will be escaped by
   *       prefixing them with backslash characters:  backslash (\\), double
   *       quote ("), percent (%), vertical pipe (|), dollar sign ($),
   *       exclamation point (!), and backwards single quote (`).</LI>
   *   <LI>The string resulting from the above escaping will be surrounded by
   *       double quote (") characters if it contains any characters other than
   *       the following characters:  uppercase or lowercase ASCII letters,
   *       numeric digits, dash (-), underscore (_), colon (:), period (.),
   *       backslash (\\), and forward slash (/).</LI>
   * </UL>
   *
   * @param  s  The string to be processed.  It must not be {@code null}.
   *
   * @return  A cleaned version of the provided string in a form that will allow
   *          it to be displayed as the value of a command-line argument.
   */
  public static String cleanExampleCommandLineArgument(final String s)
  {
    ensureNotNull(s);

    if (s.length() == 0)
    {
      return "\"\"";
    }

    boolean needsQuotes = false;
    final StringBuilder buffer = new StringBuilder(2 * s.length() + 2);

    for (int i=0; i < s.length(); i++)
    {
      final char c = s.charAt(i);
      switch (c)
      {
        case '\\':
          // This needs to be escaped, but the value does not necessarily need
          // to be quoted.
          buffer.append("\\\\");
          break;

        case '"':
        case '%':
        case '|':
        case '$':
        case '!':
        case '`':
          // This needs to be escaped and the value needs to be quoted.
          needsQuotes = true;
          buffer.append('\\');
          buffer.append(c);
          break;

        case '-':
        case '_':
        case ':':
        case '.':
        case '/':
          // This does not need to be escaped and does not indicate that the
          // string needs to be quoted.
          buffer.append(c);
          break;

        default:
          if (((c >= 'a') && (c <= 'z')) ||
              ((c >= 'A') && (c <= 'Z')) ||
              ((c >= '0') && (c <= '9')))
          {
            buffer.append(c);
          }
          else
          {
            needsQuotes = true;
            buffer.append(c);
          }
      }
    }

    if (needsQuotes)
    {
      buffer.insert(0, '"');
      buffer.append('"');
    }

    return buffer.toString();
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
    ensureNotNull(l);

    final StringBuilder buffer = new StringBuilder();

    final Iterator<String> iterator = l.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());
      if (iterator.hasNext())
      {
        buffer.append("  ");
      }
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
}
