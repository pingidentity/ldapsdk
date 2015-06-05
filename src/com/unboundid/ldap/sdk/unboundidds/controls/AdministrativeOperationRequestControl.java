/*
 * Copyright 2009-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides an implementation of a Directory Server control that may
 * be used to indicate that the associated operation is used for performing some
 * administrative operation within the server rather than one that was requested
 * by a "normal" client.  The server can use this indication to treat the
 * operation differently (e.g., exclude it from the processing time histogram,
 * or to include additional information about the purpose of the operation in
 * the access log).
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
  public static final String ADMINISTRATIVE_OPERATION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.11";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4958642483402677725L;



  // The informational message to include in the control, if defined.
  private final String message;



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
  public AdministrativeOperationRequestControl(final String message)
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
  public AdministrativeOperationRequestControl(final Control control)
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
  private static ASN1OctetString encodeValue(final String message)
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
  public String getMessage()
  {
    return message;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ADMINISTRATIVE_OPERATION_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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
