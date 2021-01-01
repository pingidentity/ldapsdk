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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a Directory Server control that may
 * be used to indicate that the associated operation is used for performing some
 * administrative operation within the server rather than one that was requested
 * by a "normal" client.  The server can use this indication to treat the
 * operation differently (e.g., exclude it from the processing time histogram,
 * or to include additional information about the purpose of the operation in
 * the access log).
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
 * <BR>
 * This request control has an OID of 1.3.6.1.4.1.30221.2.5.11 and a criticality
 * of false.  It may optionally have a value that is simply the bytes that
 * comprise the message to include in the control.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AdministrativeOperationRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.11) for the administrative operation request
   * control.
   */
  @NotNull public static final String ADMINISTRATIVE_OPERATION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.11";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4958642483402677725L;



  // The informational message to include in the control, if defined.
  @Nullable private final String message;



  /**
   * Creates a new administrative operation request control with no message.
   */
  public AdministrativeOperationRequestControl()
  {
    this((String) null);
  }



  /**
   * Creates a new administrative operation request control with the provided
   * informational message.
   *
   * @param  message  A message with additional information about the purpose of
   *                  the associated operation.  It may be {@code null} if no
   *                  additional message should be provided.
   */
  public AdministrativeOperationRequestControl(@Nullable final String message)
  {
    super(ADMINISTRATIVE_OPERATION_REQUEST_OID, false, encodeValue(message));

    this.message = message;
  }



  /**
   * Creates a new administrative operation request control decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an administrative
   *                  operation request control.
   */
  public AdministrativeOperationRequestControl(@NotNull final Control control)
  {
    super(control);

    if (control.hasValue())
    {
      message = control.getValue().stringValue();
    }
    else
    {
      message = null;
    }
  }



  /**
   * Generates an appropriately-encoded value for this control with the provided
   * message.
   *
   * @param  message  A message with additional information about the purpose of
   *                  the associated operation.  It may be {@code null} if no
   *                  additional message should be provided.
   *
   * @return  An appropriately-encoded value for this control, or {@code null}
   *          if no value is needed.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(@Nullable final String message)
  {
    if (message == null)
    {
      return null;
    }
    else
    {
      return new ASN1OctetString(message);
    }
  }



  /**
   * Retrieves the informational message for this control, if defined.
   *
   * @return  The informational message for this control, or {@code null} if
   *          none was provided.
   */
  @Nullable()
  public String getMessage()
  {
    return message;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ADMINISTRATIVE_OPERATION_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AdministrativeOperationRequestControl(");

    if (message != null)
    {
      buffer.append("message='");
      buffer.append(message);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
