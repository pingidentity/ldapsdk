/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.Serializable;
import java.util.StringTokenizer;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides a data structure for holding information read from a
 * value of the ds-changelog-attr-exceeded-max-values-count attribute.  Values
 * should be in the form "attr=X,beforeCount=Y,afterCount=Z", where "X" is the
 * name of the attribute which had too many values before and/or after the
 * change, "Y" is the number of values the attribute had before the change, and
 * "Z" is the number of values the attribute had after the change.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ChangeLogEntryAttributeExceededMaxValuesCount
       implements Serializable
{
  /**
   * The name of the token used to provide the name of the associated attribute.
   */
  @NotNull private static final String TOKEN_NAME_ATTR = "attr";



  /**
   * The name of the token used to provide the number of values before the
   * change.
   */
  @NotNull private static final String TOKEN_NAME_BEFORE_COUNT =
       StaticUtils.toLowerCase("beforeCount");



  /**
   * The name of the token used to provide the number of values after the
   * change.
   */
  @NotNull private static final String TOKEN_NAME_AFTER_COUNT =
       StaticUtils.toLowerCase("afterCount");


  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4689107630879614032L;



  // The number of values the associated attribute had after the change.
  private final long afterCount;

  // The number of values the associated attribute had before the change.
  private final long beforeCount;

  // The name of the updated attribute for which the number of values exceeded
  // the maximum display count before and/or after the change.
  @NotNull private final String attributeName;

  // The string representation for this element.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new instance of this object from the provided string value from
   * the ds-changelog-attr-exceeded-max-values-count.
   *
   * @param  s  The value to be parsed.
   *
   * @throws  LDAPException  If an error occurred while attempting to parse the
   *                         value.
   */
  public ChangeLogEntryAttributeExceededMaxValuesCount(@NotNull final String s)
         throws LDAPException
  {
    stringRepresentation = s;

    String name   = null;
    Long   before = null;
    Long   after  = null;

    final StringTokenizer tokenizer = new StringTokenizer(s, ",");
    while (tokenizer.hasMoreTokens())
    {
      final String token = tokenizer.nextToken();
      final int equalPos = token.indexOf('=');
      if (equalPos < 0)
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_MALFORMED_TOKEN.get(s, token));
      }

      final String tokenName =
           StaticUtils.toLowerCase(token.substring(0, equalPos).trim());
      final String value = token.substring(equalPos+1).trim();

      if (tokenName.equals(TOKEN_NAME_ATTR))
      {
        if (name == null)
        {
          name = value;
        }
        else
        {
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_REPEATED_TOKEN.get(s,
                    tokenName));
        }
      }
      else if (tokenName.equals(TOKEN_NAME_BEFORE_COUNT))
      {
        if (before == null)
        {
          try
          {
            before = Long.parseLong(value);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                 ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_MALFORMED_COUNT.get(s,
                      tokenName),
                 e);
          }
        }
        else
        {
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_REPEATED_TOKEN.get(s,
                    tokenName));
        }
      }
      else if (tokenName.equals(TOKEN_NAME_AFTER_COUNT))
      {
        if (after == null)
        {
          try
          {
            after = Long.parseLong(value);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                 ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_REPEATED_TOKEN.get(s,
                      tokenName),
                 e);
          }
        }
        else
        {
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_REPEATED_TOKEN.get(s,
                    tokenName));
        }
      }
    }

    if (name == null)
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_MISSING_TOKEN.get(s,
                TOKEN_NAME_ATTR));
    }

    if (before == null)
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_MISSING_TOKEN.get(s,
                TOKEN_NAME_BEFORE_COUNT));
    }

    if (after == null)
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_CHANGELOG_EXCEEDED_VALUE_COUNT_MISSING_TOKEN.get(s,
                TOKEN_NAME_AFTER_COUNT));
    }

    attributeName = name;
    beforeCount   = before;
    afterCount    = after;
  }



  /**
   * Retrieves the name of the attribute that exceeded the maximum number of
   * values for inclusion in the ds-changelog-before-values and/or
   * ds-changelog-after-values attribute of the changelog entry.
   *
   * @return  The name of the attribute that exceeded the maximum number of
   *          values for inclusion in the ds-changelog-before-values and/or
   *          ds-changelog-after-values attribute of the changelog entry.
   */
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Retrieves the number of values the specified attribute had in the
   * target entry before the associated change was processed.
   *
   * @return  The number of values the specified attribute had in the target
   *          entry before the associated change was processed, or zero if the
   *          attribute was not present in the entry before the change.
   */
  public long getBeforeCount()
  {
    return beforeCount;
  }



  /**
   * Retrieves the number of values the specified attribute had in the
   * target entry after the associated change was processed.
   *
   * @return  The number of values the specified attribute had in the target
   *          entry after the associated change was processed, or zero if the
   *          attribute was not present in the entry after the change.
   */
  public long getAfterCount()
  {
    return afterCount;
  }



  /**
   * Generates a hash code for this changelog attribute exceeded max values
   * count object.
   *
   * @return  The generated hash code for this changelog attribute exceeded max
   *          values count object.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = StaticUtils.toLowerCase(attributeName).hashCode();

    hashCode = (int) ((hashCode * 31) + beforeCount);
    hashCode = (int) ((hashCode * 31) + afterCount);

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this changelog attribute
   * exceeded max values count object.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object may be considered equal to
   *          this changelog attribute exceeded max values count object, or
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

    if (! (o instanceof ChangeLogEntryAttributeExceededMaxValuesCount))
    {
      return false;
    }

    final ChangeLogEntryAttributeExceededMaxValuesCount c =
         (ChangeLogEntryAttributeExceededMaxValuesCount) o;
    return ((beforeCount == c.beforeCount) && (afterCount == c.afterCount) &&
         attributeName.equalsIgnoreCase(c.attributeName));
  }



  /**
   * Retrieves a string representation of this changelog entry attribute
   * exceeded max values count.
   *
   * @return  A string representation of this changelog entry attribute exceeded
   *          max values count.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stringRepresentation;
  }
}
