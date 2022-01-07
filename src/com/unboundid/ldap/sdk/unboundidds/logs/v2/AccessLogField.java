/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2;



import java.io.Serializable;

import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines a data structure that represents a field that may appear
 * in a Directory Server access log message.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AccessLogField
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6689083040240574632L;



  // The expected syntax for this field.
  @NotNull private final AccessLogFieldSyntax<?> expectedSyntax;

  // The name for this field.
  @NotNull private final String fieldName;




  /**
   * Creates an access log field with whe provided information.
   *
   * @param  fieldName       The name for this field.  It must not be
   *                         {@code null}.
   * @param  expectedSyntax  The expected syntax for this field.  It must not be
   *                         {@code null}.
   */
  public AccessLogField(@NotNull final String fieldName,
                        @NotNull final AccessLogFieldSyntax<?> expectedSyntax)
  {
    Validator.ensureNotNullOrEmpty(fieldName,
         "AccessLogField.fieldName must not be null or empty.");
    Validator.ensureNotNullWithMessage(expectedSyntax,
         "AccessLogField.fieldName must not be null or empty.");

    this.fieldName = fieldName;
    this.expectedSyntax = expectedSyntax;
  }



  /**
   * Retrieves the name for this field.
   *
   * @return  The name for this field.
   */
  @NotNull()
  public String getFieldName()
  {
    return fieldName;
  }



  /**
   * Retrieves the expected syntax for this field.  Note that this may be a
   * generic instance of the associated syntax, which may or may not reflect the
   * settings used to actually generate the log message.
   *
   * @return  The expected syntax for this field.
   */
  @NotNull()
  public AccessLogFieldSyntax<?> getExpectedSyntax()
  {
    return expectedSyntax;
  }



  /**
   * Retrieves a string representation of this access log field.
   *
   * @return  A string representation of this access log field.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this access log field to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AccessLogField(fieldName='");
    buffer.append(fieldName);
    buffer.append("', expectedSyntax='");
    buffer.append(expectedSyntax.getSyntaxName());
    buffer.append("')");
  }
}
