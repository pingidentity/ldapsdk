/*
 * Copyright 2015-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



/**
 * This enum defines a set of change type values that may be used in conjunction
 * with the set notification destination extended request.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 */
public enum SetNotificationDestinationChangeType
{
  /**
   * Indicates that the complete set of destination details should be replaced.
   */
  REPLACE(0),



  /**
   * Indicates that the provided destination details should be added to the
   * existing set.
   */
  ADD(1),



  /**
   * Indicates tht the specified destination details should be removed from the
   * notification destination.
   */
  DELETE(2);



  // The integer value for this change type.
  private final int intValue;



  /**
   * Creates a new set notification destination change type with the provided
   * information.
   *
   * @param  intValue  The integer value for this change type.
   */
  private SetNotificationDestinationChangeType(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this set notification destination change
   * type.
   *
   * @return  The integer value for this set notification destination change
   *          type.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the set notification destination change type with the specified
   * integer value.
   *
   * @param  intValue  The integer value for the change type to retrieve.
   *
   * @return  The requested change type, or {@code null} if there is no change
   *          type with the specified integer value.
   */
  public static SetNotificationDestinationChangeType valueOf(final int intValue)
  {
    for (final SetNotificationDestinationChangeType t : values())
    {
      if (t.intValue == intValue)
      {
        return t;
      }
    }

    return null;
  }
}
