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
package com.unboundid.util;



import java.io.IOException;
import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a method for generating a string value comprised of zero
 * or more components.  The components may be any combination of zero or more
 * strings, sequential numeric ranges, and random numeric ranges.  These
 * components should be formatted as follows:
 * <UL>
 *   <LI>Strings are simply any kind of static text that will be used as-is
 *       without any modification, except that double opening or closing square
 *       brackets (i.e., "<CODE>[[</CODE>" or "<CODE>]]</CODE>") will be
 *       replaced with single opening or closing square brackets to distinguish
 *       them from the square brackets used in numeric ranges or URL
 *       references.</LI>
 *   <LI>Sequential numeric ranges consist of an opening square bracket, a
 *       numeric value to be used as the lower bound for the range, a colon, a
 *       second numeric value to be used as the upper bound for the range, an
 *       optional '<CODE>x</CODE>' character followed by a numeric value to be
 *       used as the increment, an optional '<CODE>%</CODE>' character followed
 *       by a format string as allowed by the {@link java.text.DecimalFormat}
 *       class to define how the resulting value should be formatted, and a
 *       closing square bracket to indicate the end of the range.</LI>
 *   <LI>Random numeric ranges consist of an opening square bracket, a
 *       numeric value to be used as the lower bound for the range, a dash, a
 *       second numeric value to be used as the upper bound for the range, an
 *       optional '<CODE>%</CODE>' character followed by a format string as
 *       allowed by the {@link java.text.DecimalFormat} class to define how the
 *       resulting value should be formatted, and a closing square bracket to
 *       indicate the end of the range.</LI>
 *   <LI>Strings read from a file specified by a given URL.  That file may be
 *       contained on the local filesystem (using a URL like
 *       "file:///tmp/mydata.txt") or read from a remote server via HTTP (using
 *       a URL like "http://server.example.com/mydata.txt").  In either case,
 *       the provided URL must not contain a closing square bracket character.
 *       If this option is used, then that file must contain one value per line,
 *       and its contents will be read into memory and values from the file will
 *       be selected in a random order and used in place of the bracketed
 *       URL.</LI>
 *   <LI>Back-references that will be replaced with the same value as the
 *       bracketed token in the specified position in the string.  For example,
 *       a component of "[ref:1]" will be replaced with the same value as used
 *       in the first bracketed component of the value pattern.  Back-references
 *       must only reference components that have been previously defined in the
 *       value pattern, and not those which appear after the reference.</LI>
 * </UL>
 * <BR>
 * It must be possible to represent all of the numeric values used in sequential
 * or random numeric ranges as {@code long} values.  In a sequential numeric
 * range, if the first value is larger than the second value, then values will
 * be chosen in descending rather than ascending order (and if an increment is
 * given, then it should be positive).  In addition, once the end of a
 * sequential range has been reached, then the value will wrap around to the
 * beginning of that range.
 * <BR>
 * Examples of value pattern components include:
 * <UL>
 *   <LI><CODE>Hello</CODE> -- The static text "<CODE>Hello</CODE>".</LI>
 *   <LI><CODE>[[Hello]]</CODE> -- The static text "<CODE>[Hello]</CODE>" (note
 *       that the double square brackets were replaced with single square
 *       brackets).</LI>
 *   <LI><CODE>[0:1000]</CODE> -- A sequential numeric range that will iterate
 *      in ascending sequential order from 0 to 1000.  The 1002nd value that is
 *      requested will cause the value to be wrapped around to 0 again.</LI>
 *   <LI><CODE>[1000:0]</CODE> -- A sequential numeric range that will iterate
 *      in descending sequential order from 1000 to 0.  The 1002nd value that is
 *      requested will cause the value to be wrapped around to 1000 again.</LI>
 *   <LI><CODE>[0:1000x5%0000]</CODE> -- A sequential numeric range that will
 *      iterate in ascending sequential order from 0 to 1000 in increments of
 *      five with all values represented as four-digit numbers padded with
 *      leading zeroes.  For example, the first four values generated by this
 *      component will be "0000", "0005", "0010", and "0015".</LI>
 *   <LI><CODE>[0-1000]</CODE> -- A random numeric range that will choose values
 *       at random between 0 and 1000, inclusive.</LI>
 *   <LI><CODE>[0-1000%0000]</CODE> -- A random numeric range that will choose
 *       values at random between 0 and 1000, inclusive, and values will be
 *       padded with leading zeroes as necessary so that they are represented
 *       using four digits.</LI>
 *   <LI><CODE>[file:///tmp/mydata.txt]</CODE> -- A URL reference that will
 *       cause randomly-selected lines from the specified local file to be used
 *       in place of the bracketed range.  To make it clear that the file
 *       contents are randomly accessed, you may use {@code randomfile} in place
 *       of {@code file}.</LI>
 *   <LI><CODE>[sequentialfile:///tmp/mydata.txt]</CODE> -- A URL reference that
 *       will cause lines from the specified local file, selected in sequential
 *       order, to be used in place of the bracketed range.</LI>
 *   <LI><CODE>[http://server.example.com/tmp/mydata.txt]</CODE> -- A URL
 *       reference that will cause randomly-selected lines from the specified
 *       remote HTTP-accessible file to be used in place of the bracketed
 *       range.</LI>
 * </UL>
 * <BR>
 * Examples of full value pattern strings include:
 * <UL>
 *   <LI><CODE>dc=example,dc=com</CODE> -- A value pattern containing only
 *       static text and no numeric components.</LI>
 *   <LI><CODE>[1000:9999]</CODE> -- A value pattern containing only a numeric
 *       component that will choose numbers in sequential order from 1000 to
 *       9999.</LI>
 *   <LI><CODE>(uid=user.[1-1000000])</CODE> -- A value pattern that combines
 *       the static text "<CODE>(uid=user.</CODE>" with a value chosen randomly
 *       between one and one million, and another static text string of
 *       "<CODE>)</CODE>".</LI>
 *   <LI><CODE>uid=user.[1-1000000],ou=org[1-10],dc=example,dc=com</CODE> -- A
 *       value pattern containing two numeric components interspersed between
 *       three static text components.</LI>
 *   <LI><CODE>uid=user.[1-1000000],ou=org[ref:1],dc=example,dc=com</CODE> -- A
 *       value pattern in which the organization number will be the same as the
 *       randomly-selected user number.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ValuePattern
       implements Serializable
{
  /**
   * The URL to the publicly-accessible javadoc for this class, which provides
   * a detailed overview of the supported value pattern syntax.
   */
  public static final String PUBLIC_JAVADOC_URL =
       "https://docs.ldap.com/ldap-sdk/docs/javadoc/index.html?" +
            "com/unboundid/util/ValuePattern.html";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4502778464751705304L;



  // Indicates whether the provided value pattern includes one or more
  // back-references.
  private final boolean hasBackReference;

  // The string that was originally used to create this value pattern.
  private final String pattern;

  // The thread-local array list that will be used to hold values for
  // back-references.
  private final ThreadLocal<ArrayList<String>> refLists;

  // The thread-local string builder that will be used to build values.
  private final ThreadLocal<StringBuilder> buffers;

  // The value pattern components that will be used to generate values.
  private final ValuePatternComponent[] components;



  /**
   * Creates a new value pattern from the provided string.
   *
   * @param  s  The string representation of the value pattern to create.  It
   *            must not be {@code null}.
   *
   * @throws  ParseException  If the provided string cannot be parsed as a valid
   *                          value pattern string.
   */
  public ValuePattern(final String s)
         throws ParseException
  {
    this(s, null);
  }



  /**
   * Creates a new value pattern from the provided string.
   *
   * @param  s  The string representation of the value pattern to create.  It
   *            must not be {@code null}.
   * @param  r  The seed to use for the random number generator.  It may be
   *            {@code null} if no seed is required.
   *
   * @throws  ParseException  If the provided string cannot be parsed as a valid
   *                          value pattern string.
   */
  public ValuePattern(final String s, final Long r)
         throws ParseException
  {
    Validator.ensureNotNull(s);

    pattern  = s;
    refLists = new ThreadLocal<ArrayList<String>>();
    buffers  = new ThreadLocal<StringBuilder>();

    final AtomicBoolean hasRef = new AtomicBoolean(false);

    final Random random;
    if (r == null)
    {
      random = new Random();
    }
    else
    {
      random = new Random(r);
    }

    final ArrayList<ValuePatternComponent> l =
         new ArrayList<ValuePatternComponent>(3);
    parse(s, 0, l, random, hasRef);

    hasBackReference = hasRef.get();
    if (hasBackReference)
    {
      int availableReferences = 0;
      for (final ValuePatternComponent c : l)
      {
        if (c instanceof BackReferenceValuePatternComponent)
        {
          final BackReferenceValuePatternComponent brvpc =
               (BackReferenceValuePatternComponent) c;
          if (brvpc.getIndex() > availableReferences)
          {
            throw new ParseException(
                 ERR_REF_VALUE_PATTERN_INVALID_INDEX.get(brvpc.getIndex()), 0);
          }
        }

        if (c.supportsBackReference())
        {
          availableReferences++;
        }
      }
    }

    components = new ValuePatternComponent[l.size()];
    l.toArray(components);
  }



  /**
   * Recursively parses the provided string into a list of value pattern
   * components.
   *
   * @param  s    The string representation of the value pattern to create.  It
   *              may be a portion of the entire value pattern string.
   * @param  o    The offset of the first character of the provided string in
   *              the full value pattern string.
   * @param  l    The list into which the parsed components should be added.
   * @param  r    The random number generator to use to seed random number
   *              generators used by components.
   * @param  ref  A value that may be updated if the pattern contains any
   *              back-references.
   *
   * @throws  ParseException  If the provided string cannot be parsed as a valid
   *                          value pattern string.
   */
  private static void parse(final String s, final int o,
                            final ArrayList<ValuePatternComponent> l,
                            final Random r, final AtomicBoolean ref)
          throws ParseException
  {
    // Find the first occurrence of "[[".  Parse the portion of the string
    // before it, into the list, then add a string value pattern containing "[",
    // then parse the portion of the string after it.
    // First, parse out any occurrences of "[[" and replace them with string
    // value pattern components containing only "[".
    int pos = s.indexOf("[[");
    if (pos >= 0)
    {
      if (pos > 0)
      {
        parse(s.substring(0, pos), o, l, r, ref);
      }

      l.add(new StringValuePatternComponent("["));

      if (pos < (s.length() - 2))
      {
        parse(s.substring(pos+2), (o+pos+2), l, r, ref);
      }
      return;
    }

    // Find the first occurrence of "]]".  Parse the portion of the string
    // before it, into the list, then add a string value pattern containing "]",
    // then parse the portion of the string after it.
    pos = s.indexOf("]]");
    if (pos >= 0)
    {
      if (pos > 0)
      {
        parse(s.substring(0, pos), o, l, r, ref);
      }

      l.add(new StringValuePatternComponent("]"));

      if (pos < (s.length() - 2))
      {
        parse(s.substring(pos+2), (o+pos+2), l, r, ref);
      }
      return;
    }

    // Find the first occurrence of "[" and the corresponding "]".  The part
    // before that will be a string.  Then parse out the numeric or URL
    // component, and parse the rest of the string after the "]".
    pos = s.indexOf('[');
    if (pos >= 0)
    {
      final int closePos = s.indexOf(']');
      if (closePos < 0)
      {
        throw new ParseException(
             ERR_VALUE_PATTERN_UNMATCHED_OPEN.get(o+pos), (o+pos));
      }
      else if (closePos < pos)
      {
        throw new ParseException(
             ERR_VALUE_PATTERN_UNMATCHED_CLOSE.get(o+closePos), (o+closePos));
      }

      if (pos > 0)
      {
        l.add(new StringValuePatternComponent(s.substring(0, pos)));
      }

      final String bracketedToken = s.substring(pos+1, closePos);
      if (bracketedToken.startsWith("file:"))
      {
        final String path = bracketedToken.substring(5);
        try
        {
          l.add(new FileValuePatternComponent(path, r.nextLong(), false));
        }
        catch (final IOException ioe)
        {
          debugException(ioe);
          throw new ParseException(ERR_FILE_VALUE_PATTERN_NOT_USABLE.get(
               path, getExceptionMessage(ioe)), o+pos);
        }
      }
      else if (bracketedToken.startsWith("randomfile:"))
      {
        final String path = bracketedToken.substring(11);
        try
        {
          l.add(new FileValuePatternComponent(path, r.nextLong(), false));
        }
        catch (final IOException ioe)
        {
          debugException(ioe);
          throw new ParseException(ERR_FILE_VALUE_PATTERN_NOT_USABLE.get(
               path, getExceptionMessage(ioe)), o+pos);
        }
      }
      else if (bracketedToken.startsWith("sequentialfile:"))
      {
        final String path = bracketedToken.substring(15);
        try
        {
          l.add(new FileValuePatternComponent(path, r.nextLong(), true));
        }
        catch (final IOException ioe)
        {
          debugException(ioe);
          throw new ParseException(ERR_FILE_VALUE_PATTERN_NOT_USABLE.get(
               path, getExceptionMessage(ioe)), o+pos);
        }
      }
      else if (bracketedToken.startsWith("http://"))
      {
        try
        {
          l.add(new HTTPValuePatternComponent(bracketedToken, r.nextLong()));
        }
        catch (final IOException ioe)
        {
          debugException(ioe);
          throw new ParseException(ERR_HTTP_VALUE_PATTERN_NOT_USABLE.get(
               bracketedToken, getExceptionMessage(ioe)), o+pos);
        }
      }
      else if (bracketedToken.startsWith("ref:"))
      {
        ref.set(true);

        final String valueStr = bracketedToken.substring(4);
        try
        {
          final int index = Integer.parseInt(valueStr);
          if (index == 0)
          {
            throw new ParseException(ERR_REF_VALUE_PATTERN_ZERO_INDEX.get(),
                 (o+pos+4));
          }
          else if (index < 0)
          {
            throw new ParseException(
                 ERR_REF_VALUE_PATTERN_NOT_VALID.get(valueStr), (o+pos+4));
          }
          else
          {
            l.add(new BackReferenceValuePatternComponent(index));
          }
        }
        catch (final NumberFormatException nfe)
        {
          debugException(nfe);
          throw new ParseException(
               ERR_REF_VALUE_PATTERN_NOT_VALID.get(valueStr),  (o+pos+4));
        }
      }
      else
      {
        l.add(parseNumericComponent(s.substring(pos+1, closePos), (o+pos+1),
                                    r));
      }

      if (closePos < (s.length() - 1))
      {
        parse(s.substring(closePos+1), (o+closePos+1), l, r, ref);
      }

      return;
    }


    // If there are any occurrences of "]" without a corresponding open, then
    // that's invalid.
    pos = s.indexOf(']');
    if (pos >= 0)
    {
      throw new ParseException(
           ERR_VALUE_PATTERN_UNMATCHED_CLOSE.get(o+pos), (o+pos));
    }

    // There are no brackets, so it's just a static string.
    l.add(new StringValuePatternComponent(s));
  }



  /**
   * Parses the specified portion of the provided string as either a
   * sequential or random numeric value pattern component.
   *
   * @param  s  The string to parse, not including the square brackets.
   * @param  o  The offset in the overall value pattern string at which the
   *            provided substring begins.
   * @param  r  The random number generator to use to seed random number
   *            generators used by components.
   *
   * @return  The parsed numeric value pattern component.
   *
   * @throws  ParseException  If the specified substring cannot be parsed as a
   *
   */
  private static ValuePatternComponent parseNumericComponent(final String s,
                                                             final int o,
                                                             final Random r)
          throws ParseException
  {
    boolean delimiterFound = false;
    boolean sequential     = false;
    int     pos            = 0;
    long   lowerBound      = 0L;

lowerBoundLoop:
    for ( ; pos < s.length(); pos++)
    {
      switch (s.charAt(pos))
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
          // These are all acceptable.
          break;

        case '-':
          if (pos == 0)
          {
            // This indicates that the value is negative.
            break;
          }
          else
          {
            // This indicates the end of the lower bound.
            delimiterFound = true;
            sequential     = false;

            try
            {
              lowerBound = Long.parseLong(s.substring(0, pos));
            }
            catch (final NumberFormatException nfe)
            {
              Debug.debugException(nfe);
              throw new ParseException(
                   ERR_VALUE_PATTERN_VALUE_NOT_LONG.get((o-1), Long.MIN_VALUE,
                                                        Long.MAX_VALUE),
                   (o-1));
            }
            pos++;
            break lowerBoundLoop;
          }

        case ':':
          delimiterFound = true;
          sequential     = true;

          if (pos == 0)
          {
            throw new ParseException(
                 ERR_VALUE_PATTERN_EMPTY_LOWER_BOUND.get(o-1), (o-1));
          }
          else
          {
            try
            {
              lowerBound = Long.parseLong(s.substring(0, pos));
            }
            catch (final NumberFormatException nfe)
            {
              Debug.debugException(nfe);
              throw new ParseException(
                   ERR_VALUE_PATTERN_VALUE_NOT_LONG.get((o-1), Long.MIN_VALUE,
                                                        Long.MAX_VALUE),
                   (o-1));
            }
          }
          pos++;
          break lowerBoundLoop;

        default:
          throw new ParseException(
               ERR_VALUE_PATTERN_INVALID_CHARACTER.get(s.charAt(pos), (o+pos)),
               (o+pos));
      }
    }

    if (! delimiterFound)
    {
      throw new ParseException(ERR_VALUE_PATTERN_NO_DELIMITER.get(o-1), (o-1));
    }

    boolean hasIncrement = false;
    int     startPos     = pos;
    long    upperBound   = lowerBound;
    long    increment    = 1L;
    String  formatString = null;

    delimiterFound = false;

upperBoundLoop:
    for ( ; pos < s.length(); pos++)
    {
      switch (s.charAt(pos))
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
          // These are all acceptable.
          break;

        case '-':
          if (pos == startPos)
          {
            // This indicates that the value is negative.
            break;
          }
          else
          {
            throw new ParseException(
                 ERR_VALUE_PATTERN_INVALID_CHARACTER.get('-', (o+pos)),
                 (o+pos));
          }

        case 'x':
          delimiterFound = true;
          hasIncrement   = true;

          if (pos == startPos)
          {
            throw new ParseException(
                 ERR_VALUE_PATTERN_EMPTY_UPPER_BOUND.get(o-1), (o-1));
          }
          else
          {
            try
            {
              upperBound = Long.parseLong(s.substring(startPos, pos));
            }
            catch (final NumberFormatException nfe)
            {
              Debug.debugException(nfe);
              throw new ParseException(
                   ERR_VALUE_PATTERN_VALUE_NOT_LONG.get((o-1), Long.MIN_VALUE,
                                                        Long.MAX_VALUE),
                   (o-1));
            }
          }
          pos++;
          break upperBoundLoop;

        case '%':
          delimiterFound = true;
          hasIncrement   = false;

          if (pos == startPos)
          {
            throw new ParseException(
                 ERR_VALUE_PATTERN_EMPTY_UPPER_BOUND.get(o-1), (o-1));
          }
          else
          {
            try
            {
              upperBound = Long.parseLong(s.substring(startPos, pos));
            }
            catch (final NumberFormatException nfe)
            {
              Debug.debugException(nfe);
              throw new ParseException(
                   ERR_VALUE_PATTERN_VALUE_NOT_LONG.get((o-1), Long.MIN_VALUE,
                                                        Long.MAX_VALUE),
                   (o-1));
            }
          }
          pos++;
          break upperBoundLoop;

        default:
          throw new ParseException(
               ERR_VALUE_PATTERN_INVALID_CHARACTER.get(s.charAt(pos), (o+pos)),
               (o+pos));
      }
    }

    if (! delimiterFound)
    {
      if (pos == startPos)
      {
        throw new ParseException(
             ERR_VALUE_PATTERN_EMPTY_UPPER_BOUND.get(o-1), (o-1));
      }

      try
      {
        upperBound = Long.parseLong(s.substring(startPos, pos));
      }
      catch (final NumberFormatException nfe)
      {
        Debug.debugException(nfe);
        throw new ParseException(
             ERR_VALUE_PATTERN_VALUE_NOT_LONG.get((o-1), Long.MIN_VALUE,
                                                  Long.MAX_VALUE),
             (o-1));
      }

      if (sequential)
      {
        return new SequentialValuePatternComponent(lowerBound, upperBound, 1,
                                                   null);
      }
      else
      {
        return new RandomValuePatternComponent(lowerBound, upperBound,
                                               r.nextLong(), null);
      }
    }

    if (hasIncrement)
    {
      delimiterFound = false;
      startPos       = pos;

incrementLoop:
      for ( ; pos < s.length(); pos++)
      {
        switch (s.charAt(pos))
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
            // These are all acceptable.
            break;

          case '-':
            if (pos == startPos)
            {
              // This indicates that the value is negative.
              break;
            }
            else
            {
              throw new ParseException(
                   ERR_VALUE_PATTERN_INVALID_CHARACTER.get('-', (o+pos)),
                   (o+pos));
            }

          case '%':
            delimiterFound = true;
            if (pos == startPos)
            {
              throw new ParseException(
                   ERR_VALUE_PATTERN_EMPTY_INCREMENT.get(o-1), (o-1));
            }
            else if (pos == (s.length() - 1))
            {
              throw new ParseException(
                   ERR_VALUE_PATTERN_EMPTY_FORMAT.get(o-1), (o-1));
            }
            else
            {
              try
              {
                increment = Long.parseLong(s.substring(startPos, pos));
              }
              catch (final NumberFormatException nfe)
              {
                Debug.debugException(nfe);
                throw new ParseException(
                     ERR_VALUE_PATTERN_VALUE_NOT_LONG.get((o-1), Long.MIN_VALUE,
                                                          Long.MAX_VALUE),
                     (o-1));
              }

              formatString = s.substring(pos+1);
            }
            break incrementLoop;

          default:
            throw new ParseException(
                 ERR_VALUE_PATTERN_INVALID_CHARACTER.get(s.charAt(pos),
                                                         (o+pos)),
                 (o+pos));
        }
      }

      if (! delimiterFound)
      {
        if (pos == startPos)
        {
          throw new ParseException(
               ERR_VALUE_PATTERN_EMPTY_INCREMENT.get(o-1), (o-1));
        }

        try
        {
          increment = Long.parseLong(s.substring(startPos, pos));
        }
        catch (final NumberFormatException nfe)
        {
          Debug.debugException(nfe);
          throw new ParseException(
               ERR_VALUE_PATTERN_VALUE_NOT_LONG.get((o-1), Long.MIN_VALUE,
                                                    Long.MAX_VALUE),
               (o-1));
        }
      }
    }
    else
    {
      formatString = s.substring(pos);
      if (formatString.length() == 0)
      {
        throw new ParseException(
             ERR_VALUE_PATTERN_EMPTY_FORMAT.get(o-1), (o-1));
      }
    }

    if (sequential)
    {
      return new SequentialValuePatternComponent(lowerBound, upperBound,
                                                 increment, formatString);
    }
    else
    {
      return new RandomValuePatternComponent(lowerBound, upperBound,
                                             r.nextLong(), formatString);
    }
  }



  /**
   * Retrieves the next value generated from the value pattern.
   *
   * @return  The next value generated from the value pattern.
   */
  public String nextValue()
  {
    StringBuilder buffer = buffers.get();
    if (buffer == null)
    {
      buffer = new StringBuilder();
      buffers.set(buffer);
    }
    else
    {
      buffer.setLength(0);
    }

    ArrayList<String> refList = refLists.get();
    if (hasBackReference)
    {
      if (refList == null)
      {
        refList = new ArrayList<String>(10);
        refLists.set(refList);
      }
      else
      {
        refList.clear();
      }
    }

    for (final ValuePatternComponent c : components)
    {
      if (hasBackReference)
      {
        if (c instanceof BackReferenceValuePatternComponent)
        {
          final BackReferenceValuePatternComponent brvpc =
               (BackReferenceValuePatternComponent) c;
          final String value = refList.get(brvpc.getIndex() - 1);
          buffer.append(value);
          refList.add(value);
        }
        else if (c.supportsBackReference())
        {
          final int startPos = buffer.length();
          c.append(buffer);
          refList.add(buffer.substring(startPos));
        }
        else
        {
          c.append(buffer);
        }
      }
      else
      {
        c.append(buffer);
      }
    }

    return buffer.toString();
  }



  /**
   * Retrieves a string representation of this value pattern, which will be the
   * original pattern string used to create it.
   *
   * @return  A string representation of this value pattern.
   */
  @Override()
  public String toString()
  {
    return pattern;
  }
}
