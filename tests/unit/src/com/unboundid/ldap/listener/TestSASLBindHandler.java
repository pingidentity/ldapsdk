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
package com.unboundid.ldap.listener;



import java.util.Arrays;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides an implementation of a SASL bind handler that may be used
 * for testing purposes.
 */
public final class TestSASLBindHandler
       extends InMemorySASLBindHandler
{
  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return "TEST";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public BindResult processSASLBind(final InMemoryRequestHandler handler,
                                    final int messageID, final DN bindDN,
                                    final ASN1OctetString credentials,
                                    final List<Control> controls)
  {
    try
    {
      final String credString = credentials.stringValue();
      final int tabPos = credString.indexOf('\t');
      final DN dn = new DN(credString.substring(0, tabPos));
      final byte[] pw = StaticUtils.getBytes(credString.substring(tabPos+1));

      final byte[] expectedBytes = handler.getAdditionalBindCredentials(dn);
      if ((expectedBytes == null) ||
          (! Arrays.equals(pw, expectedBytes)))
      {
        return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
             "Bad user or wrong pw", null, null, null);
      }
      else
      {
        handler.setAuthenticatedDN(dn);
        return new BindResult(messageID, ResultCode.SUCCESS, null, null, null,
             null);
      }
    }
    catch (final Exception e)
    {
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           StaticUtils.getExceptionMessage(e), null, null, null);
    }
  }
}
