/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a data structure that may be used for representing object
 * identifiers.  Since some directory servers support using strings that aren't
 * valid object identifiers where OIDs are required, this implementation
 * supports arbitrary strings, but some methods may only be available for valid
 * OIDs.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OID
       implements Serializable, Comparable<OID>
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4542498394670806081L;



  // The numeric components that comprise this OID.
  @Nullable private final List<Integer> components;

  // The string representation for this OID.
  @NotNull private final String oidString;



  /**
   * Creates a new OID object from the provided string representation.
   *
   * @param  oidString  The string to use to create this OID.
   */
  public OID(@Nullable final String oidString)
  {
    if (oidString == null)
    {
      this.oidString = "";
    }
    else
    {
      this.oidString = oidString;
    }

    components = parseComponents(oidString);
  }



  /**
   * Creates a new OID object from the provided set of numeric components.  At
   * least one component must be provided for a valid OID.
   *
   * @param  components  The numeric components to include in the OID.
   */
  public OID(@Nullable final int... components)
  {
    this(toList(components));
  }



  /**
   * Creates a new OID object from the provided set of numeric components.  At
   * least one component must be provided for a valid OID.
   *
   * @param  components  The numeric components to include in the OID.
   */
  public OID(@Nullable final List<Integer> components)
  {
    if ((components == null) || components.isEmpty())
    {
      this.components = null;
      oidString = "";
    }
    else
    {
      this.components =
           Collections.unmodifiableList(new ArrayList<>(components));

      final StringBuilder buffer = new StringBuilder();
      for (final Integer i : components)
      {
        if (buffer.length() > 0)
        {
          buffer.append('.');
        }
        buffer.append(i);
      }
      oidString = buffer.toString();
    }
  }



  /**
   * Creates a new OID that is a child of the provided parent OID.
   *
   * @param  parentOID       The parent OID below which the child should be
   *                         created.  It must not be {@code null}, and it must
   *                         be a valid numeric OID.
   * @param  childComponent  The integer value for the child component.
   *
   * @throws  ParseException  If the provided parent OID is not a valid numeric
   *                          OID.
   */
  public OID(@NotNull final OID parentOID, final int childComponent)
         throws ParseException
  {
    if (parentOID.components == null)
    {
      throw new ParseException(
           ERR_OID_INIT_PARENT_NOT_VALID.get(String.valueOf(parentOID)), 0);
    }

    components = new ArrayList<>(parentOID.components.size() + 1);
    components.addAll(parentOID.components);
    components.add(childComponent);

    oidString = parentOID.oidString + '.' + childComponent;
  }



  /**
   * Creates a new OID object with the provided string representation and set
   * of components.
   *
   * @param  oidString   The string representation of this OID.
   * @param  components  The numeric components for this OID.
   */
  private OID(@NotNull final String oidString,
              @NotNull final List<Integer> components)
  {
    this.oidString = oidString;
    this.components = Collections.unmodifiableList(components);
  }



  /**
   * Retrieves a list corresponding to the elements in the provided array.
   *
   * @param  components  The array to convert to a list.
   *
   * @return  The list of elements.
   */
  @Nullable()
  private static List<Integer> toList(@Nullable final int... components)
  {
    if (components == null)
    {
      return null;
    }

    final ArrayList<Integer> compList = new ArrayList<>(components.length);
    for (final int i : components)
    {
      compList.add(i);
    }
    return compList;
  }



  /**
   * Parses the provided string as a numeric OID and extracts the numeric
   * components from it.
   *
   * @param  oidString  The string to parse as a numeric OID.
   *
   * @return  The numeric components extracted from the provided string, or
   *          {@code null} if the provided string does not represent a valid
   *          numeric OID.
   */
  @Nullable()
  public static List<Integer> parseComponents(@Nullable final String oidString)
  {
    if ((oidString == null) || oidString.isEmpty() ||
        oidString.startsWith(".") || oidString.endsWith(".") ||
        (oidString.indexOf("..") > 0))
    {
      return null;
    }

    final StringTokenizer tokenizer = new StringTokenizer(oidString, ".");
    final ArrayList<Integer> compList = new ArrayList<>(10);
    while (tokenizer.hasMoreTokens())
    {
      final String token = tokenizer.nextToken();
      try
      {
        compList.add(Integer.parseInt(token));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return null;
      }
    }

    return Collections.unmodifiableList(compList);
  }



  /**
   * Parses the provided string as a numeric OID, optionally using additional
   * strict validation.
   *
   * @param  oidString  The string to be parsed as a numeric OID.  It must not
   *                    be {@code null}.
   * @param  strict     Indicates whether to use strict validation.  If this is
   *                    {@code false}, then the method will verify that the
   *                    provided string is made up of a dotted list of numbers
   *                    that does not start or end with a period and does not
   *                    contain consecutive periods.  If this is {@code true},
   *                    then it will additional verify that the OID contains at
   *                    least two components, that the value of the first
   *                    component is not greater than two, and that the value of
   *                    the second component is not greater than 39 if the value
   *                    of the first component is zero or one.
   *
   * @return  The OID that was parsed from the provided string.
   *
   * @throws  ParseException  If the provided string cannot be parsed as a valid
   *                          numeric OID.
   */
  @NotNull()
  public static OID parseNumericOID(@Nullable final String oidString,
                                    final boolean strict)
         throws ParseException
  {
    if ((oidString == null) || oidString.isEmpty())
    {
      throw new ParseException(ERR_OID_EMPTY.get(), 0);
    }

    int componentStartPos = 0;
    final List<Integer> components = new ArrayList<>(oidString.length());
    final StringBuilder buffer = new StringBuilder(oidString.length());
    for (int i=0; i < oidString.length(); i++)
    {
      final char c = oidString.charAt(i);
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
          buffer.append(c);
          break;

        case '.':
          if (buffer.length() == 0)
          {
            if (i == 0)
            {
              throw new ParseException(
                   ERR_OID_STARTS_WITH_PERIOD.get(oidString), i);
            }
            else
            {
              throw new ParseException(
                   ERR_OID_CONSECUTIVE_PERIODS.get(oidString, i), i);
            }
          }

          if ((buffer.length() > 1) && (buffer.charAt(0) == '0'))
          {
            throw new ParseException(
                 ERR_OID_LEADING_ZERO.get(oidString, buffer.toString()),
                 componentStartPos);
          }

          try
          {
            components.add(Integer.parseInt(buffer.toString()));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new ParseException(
                 ERR_OID_CANNOT_PARSE_AS_INT.get( oidString, buffer.toString(),
                      componentStartPos),
                 componentStartPos);
          }
          buffer.setLength(0);
          componentStartPos = (i + 1);
          break;

        default:
          throw new ParseException(
               ERR_OID_ILLEGAL_CHARACTER.get(oidString, c, i), i);
      }
    }

    if (buffer.length() == 0)
    {
      throw new ParseException(
           ERR_OID_ENDS_WITH_PERIOD.get(oidString), (oidString.length() - 1));
    }

    if ((buffer.length() > 1) && (buffer.charAt(0) == '0'))
    {
      throw new ParseException(
           ERR_OID_LEADING_ZERO.get(oidString, buffer.toString()),
           componentStartPos);
    }

    try
    {
      components.add(Integer.parseInt(buffer.toString()));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ParseException(
           ERR_OID_CANNOT_PARSE_AS_INT.get( oidString, buffer.toString(),
                componentStartPos),
           componentStartPos);
    }


    if (strict)
    {
      if (components.size() < 2)
      {
        throw new ParseException(
             ERR_OID_NOT_ENOUGH_COMPONENTS.get(oidString), 0);
      }

      final int firstComponent = components.get(0);
      final int secondComponent = components.get(1);
      switch (firstComponent)
      {
        case 0:
        case 1:
          if (secondComponent > 39)
          {
            throw new ParseException(
                 ERR_OID_ILLEGAL_SECOND_COMPONENT.get(oidString,
                      secondComponent, firstComponent),
                 0);
          }
          break;

        case 2:
          // We don't need to do any more validation.
          break;

        default:
          // Invalid value for the first component.
          throw new ParseException(
               ERR_OID_ILLEGAL_FIRST_COMPONENT.get(oidString, firstComponent),
               0);
      }
    }

    return new OID(oidString, components);
  }



  /**
   * Indicates whether the provided string represents a valid numeric OID.  Note
   * this this method only ensures that the value is made up of a dotted list of
   * numbers that does not start or end with a period and does not contain two
   * consecutive periods.  The {@link #isStrictlyValidNumericOID(String)} method
   * performs additional validation, including ensuring that the OID contains
   * at least two components, that the value of the first component is not
   * greater than two, and that the value of the second component is not greater
   * than 39 if the value of the first component is zero or one.
   *
   * @param  s  The string for which to make the determination.
   *
   * @return  {@code true} if the provided string represents a valid numeric
   *          OID, or {@code false} if not.
   */
  public static boolean isValidNumericOID(@Nullable final String s)
  {
    return new OID(s).isValidNumericOID();
  }



  /**
   * Indicates whether the provided string represents a valid numeric OID.  Note
   * this this method only ensures that the value is made up of a dotted list of
   * numbers that does not start or end with a period and does not contain two
   * consecutive periods.  The {@link #isStrictlyValidNumericOID()} method
   * performs additional validation, including ensuring that the OID contains
   * at least two components, that the value of the first component is not
   * greater than two, and that the value of the second component is not greater
   * than 39 if the value of the first component is zero or one.
   *
   * @return  {@code true} if this object represents a valid numeric OID, or
   *          {@code false} if not.
   */
  public boolean isValidNumericOID()
  {
    return (components != null);
  }



  /**
   * Indicates whether this object represents a strictly valid numeric OID.
   * In addition to ensuring that the value is made up of a dotted list of
   * numbers that does not start or end with a period or contain two consecutive
   * periods, this method also ensures that the OID contains at least two
   * components, that the value of the first component is not greater than two,
   * and that the value of the second component is not greater than 39 if the
   * value of the first component is zero or one.
   *
   * @param  s  The string for which to make the determination.
   *
   * @return  {@code true} if this object represents a strictly valid numeric
   *          OID, or {@code false} if not.
   */
  public static boolean isStrictlyValidNumericOID(@Nullable final String s)
  {
    return new OID(s).isStrictlyValidNumericOID();
  }



  /**
   * Indicates whether this object represents a strictly valid numeric OID.
   * In addition to ensuring that the value is made up of a dotted list of
   * numbers that does not start or end with a period or contain two consecutive
   * periods, this method also ensures that the OID contains at least two
   * components, that the value of the first component is not greater than two,
   * and that the value of the second component is not greater than 39 if the
   * value of the first component is zero or one.
   *
   * @return  {@code true} if this object represents a strictly valid numeric
   *          OID, or {@code false} if not.
   */
  public boolean isStrictlyValidNumericOID()
  {
    if ((components == null) || (components.size() < 2))
    {
      return false;
    }

    final int firstComponent = components.get(0);
    final int secondComponent = components.get(1);
    switch (firstComponent)
    {
      case 0:
      case 1:
        // The value of the second component must not be greater than 39.
        return (secondComponent <= 39);

      case 2:
        // We don't need to do any more validation.
        return true;

      default:
        // Invalid value for the first component.
        return false;
    }
  }



  /**
   * Retrieves the numeric components that comprise this OID.  This will only
   * return a non-{@code null} value if {@link #isValidNumericOID} returns
   * {@code true}.
   *
   * @return  The numeric components that comprise this OID, or {@code null} if
   *          this object does not represent a valid numeric OID.
   */
  @Nullable()
  public List<Integer> getComponents()
  {
    return components;
  }



  /**
   * Retrieves the OID that is the parent for this OID.  This OID must represent
   * a valid numeric OID.
   *
   * @return  The OID that is the parent for this OID, or {@code null} if this
   *          OID doesn't have a parent.  Note that the returned OID may not
   *          necessarily be strictly valid in some cases (for example, if this
   *          OID only contains two components, as all strictly valid OIDs must
   *          contain at least two components).
   *
   * @throws  ParseException  If this OID does not represent a valid numeric
   *                          OID.
   */
  @Nullable()
  public OID getParent()
         throws ParseException
  {
    if (components == null)
    {
      throw new ParseException(ERR_OID_GET_PARENT_NOT_VALID.get(oidString), 0);
    }

    if (components.size() <= 1)
    {
      // This OID cannot have a parent.
      return null;
    }

    final List<Integer> childComponents = new ArrayList<>(components);
    childComponents.remove(components.size() - 1);
    return new OID(childComponents);
  }



  /**
   * Indicates whether this OID is an ancestor of the provided OID.  This OID
   * will be considered an ancestor of the provided OID if the provided OID has
   * more components than this OID, and if the components that comprise this
   * OID make up the initial set of components for the provided OID.
   *
   * @param  oid  The OID for which to make the determination.  It must not be
   *              {@code null}, and it must represent a valid numeric OID.
   *
   * @return  {@code true} if this OID is an ancestor of the provided OID, or
   *          {@code false} if not.
   *
   * @throws  ParseException  If either this OID or the provided OID does not
   *                          represent a valid numeric OID.
   */
  public boolean isAncestorOf(@NotNull final OID oid)
         throws ParseException
  {
    if (components == null)
    {
      throw new ParseException(
           ERR_OID_IS_ANCESTOR_OF_THIS_NOT_VALID.get(oidString,
                oid.oidString),
           0);
    }

    if (oid.components == null)
    {
      throw new ParseException(
           ERR_OID_IS_ANCESTOR_OF_PROVIDED_NOT_VALID.get(oid.oidString,
                oid.oidString),
           0);
    }

    if (oid.components.size() <= components.size())
    {
      return false;
    }

    for (int i=0; i < components.size(); i++)
    {
      if (! components.get(i).equals(oid.components.get(i)))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Indicates whether this OID is a descendant of the provided OID.  This OID
   * will be considered a descendant of the provided OID if this OID has more
   * components than the provided OID, and if the components that comprise the
   * provided OID make up the initial set of components for this OID.
   *
   * @param  oid  The OID for which to make the determination.  It must not be
   *              {@code null}, and it must represent a valid numeric OID.
   *
   * @return  {@code true} if this OID is a descendant of the provided OID, or
   *          {@code false} if not.
   *
   * @throws  ParseException  If either this OID or the provided OID does not
   *                          represent a valid numeric OID.
   */
  public boolean isDescendantOf(@NotNull final OID oid)
         throws ParseException
  {
    if (components == null)
    {
      throw new ParseException(
           ERR_OID_IS_DESCENDANT_OF_THIS_NOT_VALID.get(oidString,
                oid.oidString),
           0);
    }

    if (oid.components == null)
    {
      throw new ParseException(
           ERR_OID_IS_DESCENDANT_OF_PROVIDED_NOT_VALID.get(oid.oidString,
                oid.oidString),
           0);
    }

    if (components.size() <= oid.components.size())
    {
      return false;
    }

    for (int i=0; i < oid.components.size(); i++)
    {
      if (! components.get(i).equals(oid.components.get(i)))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves a hash code for this OID.
   *
   * @return  A hash code for this OID.
   */
  @Override()
  public int hashCode()
  {
    if (components == null)
    {
      return oidString.hashCode();
    }
    else
    {
      int hashCode = 0;
      for (final int i : components)
      {
        hashCode += i;
      }
      return hashCode;
    }
  }



  /**
   * Indicates whether the provided object is equal to this OID.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this OID, or
   *          {@code false} if not.
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

    if (o instanceof OID)
    {
      final OID oid = (OID) o;
      if (components == null)
      {
        return oidString.equals(oid.oidString);
      }
      else
      {
        return components.equals(oid.components);
      }
    }

    return false;
  }



  /**
   * Indicates the position of the provided object relative to this OID in a
   * sorted list.
   *
   * @param  oid  The OID to compare against this OID.
   *
   * @return  A negative value if this OID should come before the provided OID
   *          in a sorted list, a positive value if this OID should come after
   *          the provided OID in a sorted list, or zero if the two OIDs
   *          represent equivalent values.
   */
  @Override()
  public int compareTo(@NotNull final OID oid)
  {
    if (components == null)
    {
      if (oid.components == null)
      {
        // Neither is a valid numeric OID, so we'll just compare the string
        // representations.
        return oidString.compareTo(oid.oidString);
      }
      else
      {
        // A valid numeric OID will always come before a non-valid one.
        return 1;
      }
    }

    if (oid.components == null)
    {
      // A valid numeric OID will always come before a non-valid one.
      return -1;
    }

    for (int i=0; i < Math.min(components.size(), oid.components.size()); i++)
    {
      final int thisValue = components.get(i);
      final int thatValue = oid.components.get(i);

      if (thisValue < thatValue)
      {
        // This OID has a lower number in the first non-equal slot than the
        // provided OID.
        return -1;
      }
      else if (thisValue > thatValue)
      {
        // This OID has a higher number in the first non-equal slot than the
        // provided OID.
        return 1;
      }
    }

    // Where the values overlap, they are equivalent.  Make the determination
    // based on which is longer.
    if (components.size() < oid.components.size())
    {
      // The provided OID is longer than this OID.
      return -1;
    }
    else if (components.size() > oid.components.size())
    {
      // The provided OID is shorter than this OID.
      return 1;
    }
    else
    {
      // They represent equivalent OIDs.
      return 0;
    }
  }



  /**
   * Retrieves a string representation of this OID.
   *
   * @return  A string representation of this OID.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return oidString;
  }
}
