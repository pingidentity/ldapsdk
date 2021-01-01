/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.io.Serializable;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure with information about a one-time
 * password delivery mechanism that is supported by the Directory Server and may
 * or may not be supported for a particular user.
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
public final class SupportedOTPDeliveryMechanismInfo
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6315998976212985213L;



  // Indicates whether the delivery mechanism is supported for the user targeted
  // by the get supported OTP delivery mechanisms extended request.
  @Nullable private final Boolean isSupported;

  // The name of the OTP delivery mechanism.
  @NotNull private final String deliveryMechanism;

  // An optional recipient ID that may be used for the target user in
  // conjunction with the delivery mechanism.
  @Nullable private final String recipientID;



  /**
   * Creates a new supported OTP delivery mechanism info object with the
   * provided information.
   *
   * @param  deliveryMechanism  The name of the one-time password delivery
   *                            mechanism to which this object corresponds.
   * @param  isSupported        Indicates whether the specified delivery
   *                            mechanism is expected to be supported for the
   *                            target user.  This may be {@code true} (to
   *                            indicate that the delivery mechanism is expected
   *                            to be supported for the target user,
   *                            {@code false} if the delivery mechanism is not
   *                            supported for the target user, or {@code null}
   *                            if it cannot be determined whether the delivery
   *                            mechanism is supported for the target user.
   * @param  recipientID        An optional recipient ID that can be used in
   *                            conjunction with the delivery mechanism if it
   *                            is supported for the user (e.g., it may be an
   *                            email address for an email-based delivery
   *                            mechanism or a mobile phone number for an
   *                            SMS-based delivery mechanism).  This may be
   *                            {@code null} if the delivery mechanism is not
   *                            supported or if no recipient ID is applicable.
   */
  public SupportedOTPDeliveryMechanismInfo(
              @NotNull final String deliveryMechanism,
              @Nullable final Boolean isSupported,
              @Nullable final String recipientID)
  {
    Validator.ensureNotNull(deliveryMechanism);

    this.deliveryMechanism = deliveryMechanism;
    this.isSupported       = isSupported;
    this.recipientID       = recipientID;
  }



  /**
   * Retrieves the name of the one-time password delivery mechanism to which
   * this object corresponds.
   *
   * @return  The name of the one-time password delivery mechanism to which this
   *          object corresponds.
   */
  @NotNull()
  public String getDeliveryMechanism()
  {
    return deliveryMechanism;
  }



  /**
   * Retrieves information about whether the one-time password delivery
   * mechanism is supported for the target user.
   *
   * @return  {@code true} if the delivery mechanism is expected to be supported
   *          for the user, {@code false} if the delivery mechanism is not
   *          supported for the user, or {@code null} if it cannot be determined
   *          whether the delivery mechanism is supported for the target user.
   */
  @Nullable()
  public Boolean isSupported()
  {
    return isSupported;
  }



  /**
   * Retrieves the recipient ID, if any, that may be used for the target user
   * in conjunction with the associated delivery mechanism.  If a recipient ID
   * is available, then its format may vary based on the type of delivery
   * mechanism.
   *
   * @return  The recipient ID that may be used for the target user in
   *          conjunction with the associated delivery mechanism, or
   *          {@code null} if there is no recipient ID associated with the
   *          delivery mechanism, or if the delivery mechanism is not expected
   *          to be supported for the target user.
   */
  @Nullable()
  public String getRecipientID()
  {
    return recipientID;
  }



  /**
   * Retrieves a hash code for this supported OTP delivery mechanism info
   * object.
   *
   * @return  A hash code for this supported OTP delivery mechanism info object.
   */
  @Override()
  public int hashCode()
  {
    int hc = deliveryMechanism.hashCode();

    if (isSupported == null)
    {
      hc += 2;
    }
    else if (isSupported)
    {
      hc++;
    }

    if (recipientID != null)
    {
      hc += recipientID.hashCode();
    }

    return hc;
  }



  /**
   * Indicates whether the provided object is considered equal to this supported
   * OTP delivery mechanism info object.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is an equivalent supported OTP
   *          delivery mechanism info object, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == this)
    {
      return true;
    }

    if (! (o instanceof SupportedOTPDeliveryMechanismInfo))
    {
      return false;
    }

    final SupportedOTPDeliveryMechanismInfo i =
         (SupportedOTPDeliveryMechanismInfo) o;
    if (! deliveryMechanism.equals(i.deliveryMechanism))
    {
      return false;
    }

    if (isSupported == null)
    {
      if (i.isSupported != null)
      {
        return false;
      }
    }
    else
    {
      if (! isSupported.equals(i.isSupported))
      {
        return false;
      }
    }

    if (recipientID == null)
    {
      return (i.recipientID == null);
    }
    else
    {
      return recipientID.equals(i.recipientID);
    }
  }



  /**
   * Retrieves a string representation of this supported OTP delivery mechanism
   * info object.
   *
   * @return  A string representation of this supported OTP delivery mechanism
   *          object.
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
   * Appends a string representation of this supported OTP delivery mechanism
   * info object to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SupportedOTPDeliveryMechanismInfo(mechanism='");
    buffer.append(deliveryMechanism);
    buffer.append('\'');

    if (isSupported != null)
    {
      buffer.append(", isSupported=");
      buffer.append(isSupported);
    }

    if (recipientID != null)
    {
      buffer.append(", recipientID='");
      buffer.append(recipientID);
      buffer.append('\'');
    }
    buffer.append(')');
  }
}
