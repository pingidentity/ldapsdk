/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;



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
  private final List<Integer> components;

  // The string representation for this OID.
  private final String oidString;



  /**
   * Creates a new OID object from the provided string representation.
   *
   * @param  oidString  The string to use to create this OID.
   */
  public OID(final String oidString)
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
  public OID(final int... components)
  {
    this(toList(components));
  }



  /**
   * Creates a new OID object from the provided set of numeric components.  At
   * least one component must be provided for a valid OID.
   *
   * @param  components  The numeric components to include in the OID.
   */
  public OID(final List<Integer> components)
  {
    if ((components == null) || components.isEmpty())
    {
      this.components = null;
      oidString = "";
    }
    else
    {
      this.components =
           Collections.unmodifiableList(new ArrayList<Integer>(components));

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
   * Retrieves a list corresponding to the elements in the provided array.
   *
   * @param  components  The array to convert to a list.
   *
   * @return  The list of elements.
   */
  private static List<Integer> toList(final int... components)
  {
    if (components == null)
    {
      return null;
    }

    final ArrayList<Integer> compList =
         new ArrayList<Integer>(components.length);
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
  public static List<Integer> parseComponents(final String oidString)
  {
    if ((oidString == null) || (oidString.length() == 0) ||
        oidString.startsWith(".") || oidString.endsWith(".") ||
        (oidString.indexOf("..") > 0))
    {
      return null;
    }

    final StringTokenizer tokenizer = new StringTokenizer(oidString, ".");
    final ArrayList<Integer> compList = new ArrayList<Integer>(10);
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
  public static boolean isValidNumericOID(final String s)
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
  public static boolean isStrictlyValidNumericOID(final String s)
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
  public List<Integer> getComponents()
  {
    return components;
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
  public int compareTo(final OID oid)
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
  public String toString()
  {
    return oidString;
  }
}
