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



import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.persist.PersistUtils;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that is
 * expected to be used with a string argument and ensures that all values for
 * the argument are valid attribute type names (or numeric OIDs) or attribute
 * descriptions (a name or OID with attribute options).  It can optionally use a
 * provided schema to verify that the specified attribute type is defined.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AttributeNameArgumentValueValidator
       extends ArgumentValueValidator
{
  // Indicates whether to allow values to include attribute options.
  private final boolean allowOptions;

  // An optional schema to use to verify that the specified attribute type is
  // defined.
  private final Schema schema;



  /**
   * Creates a new instance of this attribute name argument value validator that
   * will not permit attribute options and will not attempt to verify that the
   * specified attribute type is defined in a schema.
   */
  public AttributeNameArgumentValueValidator()
  {
    this(false, null);
  }



  /**
   * Creates a new instance of this attribute name argument value validator with
   * the provided information.
   *
   * @param  allowOptions  Indicates whether to allow values that include one or
   *                       more attribute options.
   * @param  schema        An optional schema that can be used to verify that
   *                       the specified attribute type is defined.
   */
  public AttributeNameArgumentValueValidator(final boolean allowOptions,
                                             final Schema schema)
  {
    this.allowOptions = allowOptions;
    this.schema       = schema;
  }



  /**
   * Indicates whether to allow values that include one or more attribute
   * options.
   *
   * @return  {@code true} if values will be allowed to include attribute
   *          options, or {@code false} if not.
   */
  public boolean allowOptions()
  {
    return allowOptions;
  }



  /**
   * Retrieves the schema that will be used to verify that attribute types
   * specified in argument values are defined, if any.
   *
   * @return  The schema that will be used to verify that attribute types
   *          specified in argument values are defined, or {@code null} if no
   *          such validation will be performed.
   */
  public Schema getSchema()
  {
    return schema;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(final Argument argument,
                                    final String valueString)
         throws ArgumentException
  {
    final StringBuilder errorMessage = new StringBuilder();
    if (! PersistUtils.isValidLDAPName(valueString, allowOptions, errorMessage))
    {
      throw new ArgumentException(ERR_ATTR_NAME_VALIDATOR_INVALID_VALUE.get(
           valueString, argument.getIdentifierString(),
           String.valueOf(errorMessage)));
    }

    if (schema != null)
    {
      final String baseName = Attribute.getBaseName(valueString);
      if (schema.getAttributeType(baseName) == null)
      {
        throw new ArgumentException(
             ERR_ATTR_NAME_VALIDATOR_TYPE_NOT_DEFINED.get(valueString,
                  argument.getIdentifierString(), baseName));
      }
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
    buffer.append("AttributeNameArgumentValueValidator(allowOptions=");
    buffer.append(allowOptions);
    buffer.append(", hasSchema=");
    buffer.append(schema != null);
    buffer.append(')');
  }
}
