/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.StaticUtils;



/**
 * This class provides an implementation of a {@code SaslClient} for a SASL
 * mechanism that can be used for testing.  This implementation claims to
 * support integrity and confidentiality protection, but in actuality doesn't
 * perform any transformation on the data to be protected.
 */
final class UNBOUNDIDTESTSASLClient
      implements SaslClient
{
  // The password for the user to authenticate.
  private final byte[] password;

  // The quality of protection negotiated during authentication.
  private SASLQualityOfProtection negotiatedQoP;

  // The quality of protection to use for the bind.
  private final SASLQualityOfProtection requestedQoP;

  // The DN for the user to authenticate.
  private final String dn;



  /**
   * Creates a new instance of this SASL client with the provided information.
   *
   * @param  dn        The DN for the user to authenticate.
   * @param  password  The password for the user to authenticate.
   * @param  qop       The quality of protection to use for the bind.
   */
  UNBOUNDIDTESTSASLClient(final String dn, final byte[] password,
                          final SASLQualityOfProtection qop)
  {
    this.dn       = dn;
    this.password = password;
    requestedQoP  = qop;
    negotiatedQoP = null;
  }



  /**
   * Retrieves the name for the SASL mechanism.  In this case, it is
   * "UNBOUNDID-TEST".
   *
   * @return  The name for the SASL mechanism.
   */
  @Override()
  public String getMechanismName()
  {
    return "UNBOUNDID-TEST";
  }



  /**
   * Indicates whether the SASL mechanism has an initial response (in which case
   * the caller should invoke {@link #evaluateChallenge} with an empty array).
   * In this case, it does not have an initial response.
   *
   * @return  {@code true} if this SASL mechanism has an initial response, or
   *          {@code false} if not.  This method always returns {@code false}.
   */
  @Override()
  public boolean hasInitialResponse()
  {
    return false;
  }



  /**
   * Evaluates the challenge encoded in the provided array.
   *
   * @param  challenge  The encoded challenge provided by the server.
   *
   * @return  The data the client should include
   *
   * @throws  SaslException  If a problem is encountered during authentication.
   */
  @Override()
  public byte[] evaluateChallenge(final byte[] challenge)
         throws SaslException
  {
    if ((challenge == null) || (challenge.length == 0))
    {
      // This should be the case for the portion of the request in which we
      // send the authentication data.
      return new ASN1Sequence(
           new ASN1OctetString(dn),
           new ASN1OctetString(password),
           new ASN1OctetString(requestedQoP.toString())).encode();
    }
    else
    {
      // This should be the case for the portion of the request in which we
      // are told what QoP to use.
      negotiatedQoP = SASLQualityOfProtection.forName(
           StaticUtils.toUTF8String(challenge));
      if (negotiatedQoP == null)
      {
        throw new SaslException("Unrecognized negotiated QoP");
      }
      else
      {
        return null;
      }
    }
  }



  /**
   * Indicates whether authentication processing has completed.
   *
   * @return  {@code true} if authentication processing has completed, or
   *          {@code false} if not.
   */
  @Override()
  public boolean isComplete()
  {
    return (negotiatedQoP != null);
  }



  /**
   * Retrieves the value of the specified negotiated property.
   *
   * @param  name  The name of the property to retrieve.
   *
   * @return  The negotiated value for the specified property, or {@code null}
   *          if no value was negotiated.
   */
  @Override()
  public Object getNegotiatedProperty(final String name)
  {
    if (name.equals(Sasl.QOP))
    {
      if (negotiatedQoP == null)
      {
        return null;
      }
      else
      {
        return negotiatedQoP.toString();
      }
    }
    else
    {
      return null;
    }
  }



  /**
   * Wraps data to be sent to the server.
   *
   * @param  outgoing  The array containing the data to be sent.
   * @param  offset    The position in the array at which the data to wrap
   *                   begins.
   * @param  len       The number of bytes in the data to be wrapped.
   *
   * @return  An array containing the wrapped representation of the data.
   */
  @Override()
  public byte[] wrap(final byte[] outgoing, final int offset, final int len)
  {
    final byte[] b = new byte[len];
    System.arraycopy(outgoing, offset, b, 0, len);
    return b;
  }



  /**
   * Unwraps data read from the server.
   *
   * @param  incoming  The array containing the data that was read.
   * @param  offset    The position in the array at which the data to unwrap
   *                   begins.
   * @param  len       The number of bytes in the data to be unwrapped.
   *
   * @return  An array containing the unwrapped representation of the data.
   */
  @Override()
  public byte[] unwrap(final byte[] incoming, final int offset, final int len)
  {
    final byte[] b = new byte[len];
    System.arraycopy(incoming, offset, b, 0, len);
    return b;
  }



  /**
   * Disposes of any sensitive information associated with this SASL mechanism.
   */
  @Override()
  public void dispose()
  {
    // Clear the password.
    if (password != null)
    {
      Arrays.fill(password, (byte) 0x00);
    }
  }
}
