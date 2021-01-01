/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DNEntrySource;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides a set of utilities that may be used in the course of
 * persistence processing.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PersistUtils
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
   * object class name.  Numeric OIDs will also be considered acceptable.
   *
   * @param  s  The string for which to make the determination.
   * @param  r  A buffer to which the unacceptable reason may be appended.  It
   *            must not be {@code null}.
   *
   * @return  {@code true} if the provided string is acceptable for use as an
   *          LDAP attribute or object class name, or {@code false} if not.
   */
  public static boolean isValidLDAPName(@NotNull final String s,
                                        @NotNull final StringBuilder r)
  {
    return isValidLDAPName(s, false, r);
  }



  /**
   * Indicates whether the provided string could be used as a valid attribute or
   * object class name.  Numeric OIDs will also be considered acceptable.
   *
   * @param  s  The string for which to make the determination.
   * @param  o  Indicates whether the name should be allowed to contain
   *            attribute options (e.g., a semicolon with one or more valid
   *            characters after it).
   * @param  r  A buffer to which the unacceptable reason may be appended.  It
   *            must not be {@code null}.
   *
   * @return  {@code true} if the provided string is acceptable for use as an
   *          LDAP attribute or object class name, or {@code false} if not.
   */
  public static boolean isValidLDAPName(@NotNull final String s,
                                        final boolean o,
                                        @NotNull final StringBuilder r)
  {
    int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      r.append(ERR_LDAP_NAME_VALIDATOR_EMPTY.get());
      return false;
    }

    final String baseName;
    final int semicolonPos = s.indexOf(';');
    if (semicolonPos > 0)
    {
      if (! o)
      {
        r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_CHAR.get(s, ';',
             semicolonPos));
        return false;
      }

      baseName = s.substring(0, semicolonPos);
      length = baseName.length();

      final String optionsStr = s.substring(semicolonPos+1);
      if (! isValidOptionSet(baseName, optionsStr, r))
      {
        return false;
      }
    }
    else
    {
      baseName = s;
    }

    if (StaticUtils.isNumericOID(baseName))
    {
      return true;
    }

    for (int i=0; i < length; i++)
    {
      final char c = baseName.charAt(i);
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
   * Indicates whether the provided string represents a valid set of attribute
   * options.  It should not contain the initial semicolon.
   *
   * @param  b  The base name for the attribute, without the option string or
   *            the semicolon used to delimit the option string from the base
   *            name.
   * @param  o  The option string to examine.  It must not be {@code null}, and
   *            must not contain the initial semicolon.
   * @param  r  A buffer to which the unacceptable reason may be appended.  It
   *            must not be {@code null}.
   *
   * @return  {@code true} if the provided string represents a valid set of
   *          options, or {@code false} if not.
   */
  private static boolean isValidOptionSet(@NotNull final String b,
                                          @NotNull final String o,
                                          @NotNull final StringBuilder r)
  {
    boolean lastWasSemicolon = true;

    for (int i=0; i < o.length(); i++)
    {
      final char c = o.charAt(i);
      if (c == ';')
      {
        if (lastWasSemicolon)
        {
          r.append(
               ERR_LDAP_NAME_VALIDATOR_OPTION_WITH_CONSECUTIVE_SEMICOLONS.get(
                    b + ';' + o));
          return false;
        }
        else
        {
          lastWasSemicolon = true;
        }
      }
      else
      {
        lastWasSemicolon = false;
        if (((c >= 'a') && (c <= 'z')) ||
            ((c >= 'A') && (c <= 'Z')) ||
            ((c >= '0') && (c <= '9')) ||
            (c == '-'))
        {
          // This will always be acceptable.
        }
        else
        {
          r.append(ERR_LDAP_NAME_VALIDATOR_INVALID_OPTION_CHAR.get(
               (b + ';' + o), c, (b.length() + 1 + i)));
          return false;
        }
      }
    }

    if (lastWasSemicolon)
    {
      r.append(ERR_LDAP_NAME_VALIDATOR_ENDS_WITH_SEMICOLON.get(b + ';' + o));
      return false;
    }

    return true;
  }



  /**
   * Indicates whether the provided string could be used as a valid Java
   * identifier.  The identifier must begin with an ASCII letter or underscore,
   * and must contain only ASCII letters, ASCII digits, and the underscore
   * character.  Even though a dollar sign is technically allowed, it will not
   * be considered valid for the purpose of this method.  Similarly, even though
   * Java keywords are not allowed, they will not be rejected by this method.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   * @param  r  A buffer to which the unacceptable reason may be appended.  It
   *            must not be {@code null}.
   *
   * @return  {@code true} if the provided string is acceptable for use as a
   *          Java identifier, or {@code false} if not.
   */
  public static boolean isValidJavaIdentifier(@NotNull final String s,
                                              @NotNull final StringBuilder r)
  {
    final int length = s.length();
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')) ||
          (c == '_'))
      {
        // This will always be acceptable.
      }
      else if ((c >= '0') && (c <= '9'))
      {
        if (i == 0)
        {
          r.append(ERR_JAVA_NAME_VALIDATOR_INVALID_FIRST_CHAR_DIGIT.get(s));
          return false;
        }
      }
      else
      {
        r.append(ERR_JAVA_NAME_VALIDATOR_INVALID_CHAR.get(s, c, i));
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
  @NotNull()
  public static String toJavaIdentifier(@NotNull final String s)
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



  /**
   * Retrieves the entry with the specified DN and decodes it as an object of
   * the specified type.
   *
   * @param  <T>  The type of object as which to decode the entry.
   *
   * @param  dn    The DN of the entry to retrieve.  It must not be
   *               {@code null}.
   * @param  type  The type of object as which the entry should be decoded.  It
   *               must not be {@code null}, and the class must be marked with
   *               the {@link LDAPObject} annotation type.
   * @param  conn  The connection that should be used to retrieve the entry.  It
   *               must not be {@code null}.
   *
   * @return  The object decoded from the specified entry, or {@code null} if
   *          the entry cannot be retrieved (e.g., because it does not exist or
   *          is not readable by the authenticated user).
   *
   * @throws  LDAPException  If a problem occurs while trying to retrieve the
   *                         entry or decode it as the specified type of object.
   */
  @Nullable()
  public static <T> T getEntryAsObject(@NotNull final DN dn,
                                       @NotNull final Class<T> type,
                                       @NotNull final LDAPInterface conn)
         throws LDAPException
  {
    Validator.ensureNotNull(dn, type, conn);

    final LDAPPersister<T> p = LDAPPersister.getInstance(type);

    final Entry e = conn.getEntry(dn.toString(),
         p.getObjectHandler().getAttributesToRequest());
    if (e == null)
    {
      return null;
    }

    return p.decode(e);
  }



  /**
   * Retrieves and decodes the indicated entries as objects of the specified
   * type.
   *
   * @param  <T>  The type of object as which to decode the entries.
   *
   * @param  dns   The DNs of the entries to retrieve.  It must not be
   *               {@code null}.
   * @param  type  The type of object as which the entries should be decoded.
   *               It must not be {@code null}, and the class must be marked
   *               with the {@link LDAPObject} annotation type.
   * @param  conn  The connection that should be used to retrieve the entries.
   *               It must not be {@code null}.
   *
   * @return  A {@code PersistedObjects} result that may be used to access the
   *          objects decoded from the provided set of DNs.
   *
   * @throws  LDAPPersistException  If the requested type cannot be used with
   *                                the LDAP SDK persistence framework.
   */
  @NotNull()
  public static <T> PersistedObjects<T> getEntriesAsObjects(
                                             @NotNull final DN[] dns,
                                             @NotNull final Class<T> type,
                                             @NotNull final LDAPInterface conn)
         throws LDAPPersistException
  {
    Validator.ensureNotNull(dns, type, conn);

    final LDAPPersister<T> p = LDAPPersister.getInstance(type);

    final DNEntrySource entrySource = new DNEntrySource(conn, dns,
         p.getObjectHandler().getAttributesToRequest());
    return new PersistedObjects<>(p, entrySource);
  }
}
