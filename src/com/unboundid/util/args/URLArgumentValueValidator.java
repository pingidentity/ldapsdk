/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.util.args;



import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that is
 * expected to be used with a string argument and ensures that all values for
 * the argument are valid URLs.  It can optionally restrict the URLs to a
 * specified set of schemes.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class URLArgumentValueValidator
       extends ArgumentValueValidator
{
  // The set of schemes allowed to be used in URLs.
  private final Set<String> allowedSchemes;



  /**
   * Creates a new instance of this URL argument value validator that will
   * accept values that are URLs with any of the specified schemes.
   *
   * @param  allowedSchemes  The names of the schemes for the URLs that will be
   *                         accepted.  It may be {@code null} or empty if any
   *                         scheme will be accepted.
   */
  public URLArgumentValueValidator(final String... allowedSchemes)
  {
    this(StaticUtils.toList(allowedSchemes));
  }



  /**
   * Creates a new instance of this URL argument value validator that will
   * accept values that are URLs with any of the specified schemes.
   *
   * @param  allowedSchemes  The names of the schemes for the URLs that will be
   *                         accepted.  It may be {@code null} or empty if any
   *                         scheme will be accepted.
   */
  public URLArgumentValueValidator(final Collection<String> allowedSchemes)
  {
    if (allowedSchemes == null)
    {
      this.allowedSchemes = Collections.emptySet();
    }
    else
    {
      this.allowedSchemes = Collections.unmodifiableSet(
           new LinkedHashSet<String>(allowedSchemes));
    }
  }



  /**
   * Retrieves the names of the schemes for the URLs that will be accepted.
   *
   * @return  The names of the schemes for the URLs that will be accepted, or
   *          an empty set if URLs will be allowed to have any scheme.
   */
  public Set<String> getAllowedSchemes()
  {
    return allowedSchemes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(final Argument argument,
                                    final String valueString)
         throws ArgumentException
  {
    final URI uri;
    try
    {
      uri = new URI(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_URL_VALIDATOR_VALUE_NOT_URL.get(valueString,
                argument.getIdentifierString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (uri.getScheme() == null)
    {
      throw new ArgumentException(ERR_URL_VALIDATOR_MISSING_SCHEME.get(
           valueString, argument.getIdentifierString()));
    }

    if ((! allowedSchemes.isEmpty()) &&
         (! allowedSchemes.contains(uri.getScheme())))
    {
      throw new ArgumentException(
           ERR_URL_VALIDATOR_UNACCEPTABLE_SCHEME.get(valueString,
                argument.getIdentifierString(), uri.getScheme()));
    }
  }



  /**
   * Retrieves a string representation of this argument value validator.
   *
   * @return  A string representation of this argument value validator.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this argument value validator to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("URLArgumentValueValidator(");

    if (allowedSchemes != null)
    {
      buffer.append("allowedSchemes={");

      final Iterator<String> iterator = allowedSchemes.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
