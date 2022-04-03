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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines options for the behaviors that should be used when trying
 * to decode JSON objects embedded in a {@link JSONFormattedRequestControl} or
 * {@link JSONFormattedResponseControl} as
 * {@link com.unboundid.ldap.sdk.Control} objects.
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
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class JSONFormattedControlDecodeBehavior
       implements Serializable
{
  /**
   * The serial verison UID for this serizlizable class.
   */
  private static final long serialVersionUID = -1035196310465374381L;



  // Indicates whether to allow embedded JSON-formatted request or response
  // controls.
  private boolean allowEmbeddedJSONFormattedControl;

  // Indicates whether to use strict mode when decoding controls.
  private boolean strict;

  // Indicates whether to throw an exception when encountering an object that
  // has the proper basic formatting for a JSON control with a criticality of
  // true, but that cannot actually be decoded as a valid control.
  private boolean throwOnInvalidCriticalControl;

  // Indicates whether to throw an exception when encountering an object that
  // has the proper basic formatting for a JSON control with a criticality of
  // false, but that cannot actually be decoded as a valid control.
  private boolean throwOnInvalidNonCriticalControl;

  // Indicates whether to throw an exception when encountering an object that
  // does not meet the basic requirements for a JSON-formatted control.
  private boolean throwOnUnparsableObject;



  /**
   * Creates a new instance of this behavior with the default configuration.
   * The default configuration is as follows:
   * <UL>
   *   <LI>{@code throwOnUnparsableObject} is set to {@code true}</LI>
   *   <LI>{@code throwOnInvalidCriticalControl} is set to {@code true}</LI>
   *   <LI>{@code throwOnInvalidNonCriticalControl} is set to {@code true}</LI>
   *   <LI>{@code allowEmbeddedJSONFormattedControl} is set to
   *       {@code false}</LI>
   *   <LI>{@code strict} is set to {@code false}</LI>
   * </UL>
   */
  public JSONFormattedControlDecodeBehavior()
  {
    throwOnUnparsableObject = true;
    throwOnInvalidCriticalControl = true;
    throwOnInvalidNonCriticalControl = true;
    allowEmbeddedJSONFormattedControl = false;
    strict = false;
  }



  /**
   * Indicates whether to throw an exception if the JSON-formatted request or
   * response control includes a JSON object that does not meet the basic
   * requirements for representing a valid JSON-formatted control, including
   * controls without the required {@code oid} and {@code criticality} fields,
   * and controls with both {@code value-base64} and {@code value-json} fields.
   * If strict mode is enabled, then this also includes unrecognized top-level
   * fields.
   *
   * @return  {@code true} if an exception should be thrown if a JSON-formatted
   *          request or response control includes a JSON object that does not
   *          meet the basic requirements for representing a valid
   *          JSON-formatted control, or {@code false} if any such JSON objects
   *          should simply be ignored.
   */
  public boolean throwOnUnparsableObject()
  {
    return throwOnUnparsableObject;
  }



  /**
   * Specifies whether to throw an exception if the JSON-formatted request or
   * response control includes a JSON object that does not meet the basic
   * requirements for representing a valid JSON-formatted control, including
   * controls without the required {@code oid} and {@code criticality} fields,
   * and controls with both {@code value-base64} and {@code value-json} fields.
   * If strict mode is enabled, then this also includes unrecognized top-level
   * fields.
   *
   * @param  throwOnUnparsableObject  Indicates whether to throw an exception
   *                                  for any JSON object that does not meet
   *                                  the basic requirements for a
   *                                  JSON-formatted control.  If this is
   *                                  {@code true}, then an exception will be
   *                                  thrown if any such JSON object is
   *                                  encountered.  If this is {@code false},
   *                                  any such JSON objects will be ignored.
   */
  public void setThrowOnUnparsableObject(final boolean throwOnUnparsableObject)
  {
    this.throwOnUnparsableObject = throwOnUnparsableObject;
  }



  /**
   * Indicates whether to throw an exception if the JSON-formatted request or
   * response control includes a JSON object that at least meets the basic
   * requirements for a JSON-formatted control with a criticality of
   * {@code true}, but that cannot be parsed as a valid {@code Control} instance
   * for some reason.  This may include a control with an OID for which
   * specific decoding support has been implemented but a problem is encountered
   * while trying to decode the JSON object as a control of that type, or a
   * control with an OID for which no specific decoding has been implemented but
   * includes a value specified using the {@code value-json} format.
   *
   * @return  {@code true} if an exception should be thrown if a critical
   *          control cannot be decoded as a valid control instance, or
   *          {@code false} if any such controls should be ignored.
   */
  public boolean throwOnInvalidCriticalControl()
  {
    return throwOnInvalidCriticalControl;
  }



  /**
   * Specifies whether to throw an exception if the JSON-formatted request or
   * response control includes a JSON object that at least meets the basic
   * requirements for a JSON-formatted control with a criticality of
   * {@code true}, but that cannot be parsed as a valid {@code Control} instance
   * for some reason.  This may include a control with an OID for which
   * specific decoding support has been implemented but a problem is encountered
   * while trying to decode the JSON object as a control of that type, or a
   * control with an OID for which no specific decoding has been implemented but
   * includes a value specified using the {@code value-json} format.
   *
   * @param  throwOnInvalidCriticalControl  Indicates whether to throw an
   *                                        exception for any well-formed JSON
   *                                        object with a criticality of
   *                                        {@code true} that cannot be parsed
   *                                        as a {@code Control}.  If this is
   *                                        {@code true}, then an exception will
   *                                        be thrown if any such object is
   *                                        encountered.  If this is
   *                                        {@code false}, then any such JSON
   *                                        objects will be ignored.
   */
  public void setThrowOnInvalidCriticalControl(
                   final boolean throwOnInvalidCriticalControl)
  {
    this.throwOnInvalidCriticalControl = throwOnInvalidCriticalControl;
  }



  /**
   * Indicates whether to throw an exception if the JSON-formatted request or
   * response control includes a JSON object that at least meets the basic
   * requirements for a JSON-formatted control with a criticality of
   * {@code false}, but that cannot be parsed as a valid {@code Control}
   * instance for some reason.  This may include a control with an OID for which
   * specific decoding support has been implemented but a problem is encountered
   * while trying to decode the JSON object as a control of that type, or a
   * control with an OID for which no specific decoding has been implemented but
   * includes a value specified using the {@code value-json} format.
   *
   * @return  {@code true} if an exception should be thrown if a non-critical
   *          control cannot be decoded as a valid control instance, or
   *          {@code false} if any such controls should be ignored.
   */
  public boolean throwOnInvalidNonCriticalControl()
  {
    return throwOnInvalidNonCriticalControl;
  }



  /**
   * Specifies whether to throw an exception if the JSON-formatted request or
   * response control includes a JSON object that at least meets the basic
   * requirements for a JSON-formatted control with a criticality of
   * {@code false}, but that cannot be parsed as a valid {@code Control}
   * instance for some reason.  This may include a control with an OID for which
   * specific decoding support has been implemented but a problem is encountered
   * while trying to decode the JSON object as a control of that type, or a
   * control with an OID for which no specific decoding has been implemented but
   * includes a value specified using the {@code value-json} format.
   *
   * @param  throwOnInvalidNonCriticalControl  Indicates whether to throw an
   *                                           exception for any well-formed
   *                                           JSON object with a criticality of
   *                                           {@code false} that cannot be
   *                                           parsed as a {@code Control}.  If
   *                                           this is {@code true}, then an
   *                                           exception will be thrown if any
   *                                           such object is encountered.  If
   *                                           this is {@code false}, then any
   *                                           such JSON objects will be
   *                                           ignored.
   */
  public void setThrowOnInvalidNonCriticalControl(
                   final boolean throwOnInvalidNonCriticalControl)
  {
    this.throwOnInvalidNonCriticalControl = throwOnInvalidNonCriticalControl;
  }



  /**
   * Indicates whether to allow a JSON-formatted request or response control to
   * include another JSON-formatted request or response control in the set of
   * embedded controls.  If embedded JSON-formatted controls are not allowed,
   * then the attempt to decode will throw an exception if the control is
   * critical, or it will be ignored with a non-fatal error message if the
   * control is non-critical.
   *
   * @return  {@code true} if embedded JSON-formatted request or response
   *          controls should be allowed, or {@code false} if not.
   */
  public boolean allowEmbeddedJSONFormattedControl()
  {
    return allowEmbeddedJSONFormattedControl;
  }



  /**
   * Specifies whether to allow a JSON-formatted request or response control to
   * include another JSON-formatted request or response control in the set of
   * embedded controls.  If embedded JSON-formatted controls are not allowed,
   * then the attempt to decode will throw an exception if the control is
   * critical, or it will be ignored with a non-fatal error message if the
   * control is non-critical.
   *
   * @param  allowEmbeddedJSONFormattedControl  Indicates whether to allow a
   *                                            JSON-formatted request or
   *                                            response control.  If this is
   *                                            {@code true], then an embedded
   *                                            JSON-formatted control will
   *                                            either result in an exception
   *                                            (if the embedded control is
   *                                            critical) or cause it to be
   *                                            ignored with a non-fatal error
   *                                            message (if it is not critical).
   *                                            If this is {@code false}, then
   *                                            the JSON-formatted control will
   *                                            be included directly in the list
   *                                            of decoded controls that is
   *                                            returned without attempting to
   *                                            extract its embedded controls.
   */
  public void setAllowEmbeddedJSONFormattedControl(
                   final boolean allowEmbeddedJSONFormattedControl)
  {
    this.allowEmbeddedJSONFormattedControl = allowEmbeddedJSONFormattedControl;
  }



  /**
   * Indicates whether to use strict mode when parsing JSON objects as controls.
   * This may include throwing an exception if a JSON object contains any
   * unrecognized fields, or if the object violates any other control-specific
   * constraints.
   *
   * @return  {@code true} if strict mode should be used when parsing JSON
   *          objects as controls, or {@code false} if a lenient mode should be
   *          used.
   */
  public boolean strict()
  {
    return strict;
  }



  /**
   * Specifies whether to use strict mode when parsing JSON objects as controls.
   * This may include throwing an exception if a JSON object contains any
   * unrecognized fields, or if the object violates any other control-specific
   * constraints.
   *
   * @param  strict  Indicates whether to use strict mode when parsing JSON
   *                 objects as controls.  If this is {@code true}, then strict
   *                 mode will be used.  If this is {@code false}, then a more
   *                 lenient mode will be used.
   */
  public void setStrict(final boolean strict)
  {
    this.strict = strict;
  }



  /**
   * Retrieves a string representation of this JSON-formatted control decode
   * behavior.
   *
   * @return  A string representation of this JSON-formatted control decode
   *          behavior.
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
   * Appends a string representation of this JSON-formatted control decode
   * behavior to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(
         "JSONFormattedControlDecodeBehavior(throwOnUnparsableObject=");
    buffer.append(throwOnUnparsableObject);
    buffer.append(", throwOnInvalidCriticalControl=");
    buffer.append(throwOnInvalidCriticalControl);
    buffer.append(", throwOnInvalidNonCriticalControl=");
    buffer.append(throwOnInvalidNonCriticalControl);
    buffer.append(", allowEmbeddedJSONFormattedControl=");
    buffer.append(allowEmbeddedJSONFormattedControl);
    buffer.append(", strict=");
    buffer.append(strict);
    buffer.append(')');
  }
}
