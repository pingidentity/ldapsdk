/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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
package com.unboundid.ldap.sdk.persist;



import java.util.UUID;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides a set of utilities that may be used in the course of
 * persistence processing.
 */
final class PersistUtils
{
  /**
   * Prevent this utility class from being instantiated.
   */
  private PersistUtils()
  {
    // No implementation required.
  }



  /**
   * Indicates whether the provided string could be used as a valid attribute or
   * object class name.
   *
   * @param  s  The string for which to make the determination.
   * @param  r  A buffer to which the unacceptable reason may be appended.
   *
   * @return  {@code true} if the provided string is acceptable for use as an
   *          LDAP attribute or object class name, or {@code false} if not.
   */
  static boolean isValidLDAPName(final String s, final StringBuilder r)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      r.append(ERR_LDAP_NAME_VALIDATOR_EMPTY.get());
      return false;
    }

    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')))
      {
        // This will always be acceptable.
      }
      else if (((c >= '0') && (c <= '9')) || (c == '-'))
      {
        // This will be acceptable for all but the first character.
        if (i == 0)
        {
          r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_FIRST_CHAR.get(s));
          return false;
        }
      }
      else
      {
        r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_CHAR.get(s, c, i));
        return false;
      }
    }

    return true;
  }



  /**
   * Transforms the provided string if necessary so that it may be used as a
   * valid Java identifier.  If the provided string is already a valid Java
   * identifier, then it will be returned as-is.  Otherwise, it will be
   * transformed to make it more suitable.
   *
   * @param  s  The attribute or object class name to be converted to a Java
   *            identifier.
   *
   * @return  A string that may be used as a valid Java identifier.
   */
  static String toJavaIdentifier(final String s)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      // This will be ugly, but safe.
      return toJavaIdentifier(UUID.randomUUID().toString());
    }

    boolean nextUpper = false;
    final StringBuilder b = new StringBuilder(length);
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')))
      {
        if (nextUpper)
        {
          b.append(Character.toUpperCase(c));
        }
        else
        {
          b.append(c);
        }

        nextUpper = false;
      }
      else if ((c >= '0') && (c <= '9'))
      {
        if (i == 0)
        {
          // Java identifiers can't begin with a digit, but they can begin with
          // an underscore followed by a digit, so we'll use that instead.
          b.append('_');
        }

        b.append(c);
        nextUpper = false;
      }
      else
      {
        // If the provided string was a valid LDAP attribute or object class
        // name, then this should be a dash, but we'll be safe and take the same
        // action for any remaining character.
        nextUpper = true;
      }
    }

    if (b.length() == 0)
    {
      // This should only happen if the provided string wasn't a valid LDAP
      // attribute or object class name to start with.
      return toJavaIdentifier(UUID.randomUUID().toString());
    }

    return b.toString();
  }
}
