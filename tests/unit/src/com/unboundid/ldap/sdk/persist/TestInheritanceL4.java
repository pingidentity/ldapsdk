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
package com.unboundid.ldap.sdk.persist;



import java.util.concurrent.atomic.AtomicInteger;

import com.unboundid.ldap.sdk.Entry;



/**
 * This class provides an object which may be used to test object inheritance
 * with the persistence framework.  It extends the TestInheritanceL2 class, and
 * may itself be extended.
 */
@LDAPObject(structuralClass="testInheritanceL4",
            requestAllAttributes=false,
            postDecodeMethod="doPostDecode",
            postEncodeMethod="doPostEncode")
public class TestInheritanceL4
       extends TestInheritanceL3
{
  /**
   * A count of the number of times the post-decode method has been invoked.
   */
  private static final AtomicInteger POST_DECODE_INVOKE_COUNT =
       new AtomicInteger(0);



  /**
   * A count of the number of times the post-encode method has been invoked.
   */
  private static final AtomicInteger POST_ENCODE_INVOKE_COUNT =
       new AtomicInteger(0);



  // An optional field.
  @LDAPField(attribute="optionalL4",
             filterUsage=FilterUsage.CONDITIONALLY_ALLOWED)
  private String optionalL4;

  // A required field.
  @LDAPField(attribute="requiredL4",
             requiredForEncode=true,
             requiredForDecode=true,
             filterUsage=FilterUsage.ALWAYS_ALLOWED)
  private String requiredL4;



  /**
   * Creates a new instance of this object with no fields set.
   */
  public TestInheritanceL4()
  {
    optionalL4 = null;
    requiredL4 = null;
  }



  /**
   * Performs any processing that may be necessary after initializing this
   * object from an LDAP entry.
   *
   * @throws  LDAPPersistException  If the generated entry should not be used.
   */
  private void doPostDecode()
          throws LDAPPersistException
  {
    POST_DECODE_INVOKE_COUNT.incrementAndGet();
  }



  /**
   * Performs any processing that may be necessary after encoding this object
   * to an LDAP entry.
   *
   * @param  entry  The entry that has been generated.  It may be altered if
   *                desired.
   *
   * @throws  LDAPPersistException  If there is a problem with the object after
   *                                it has been decoded from an LDAP entry.
   */
  private void doPostEncode(final Entry entry)
          throws LDAPPersistException
  {
    POST_ENCODE_INVOKE_COUNT.incrementAndGet();
  }



  /**
   * Retrieves the value of the optionalL4 field.
   *
   * @return  The value of the optionalL4 field.
   */
  public String getOptionalL4()
  {
    return optionalL4;
  }



  /**
   * Sets the value of the optionalL4 field.
   *
   * @param  optionalL4  The value for the optionalL4 field.
   */
  public void setOptionalL4(final String optionalL4)
  {
    this.optionalL4 = optionalL4;
  }



  /**
   * Retrieves the value of the requiredL4 field.
   *
   * @return  The value of the requiredL4 field.
   */
  public String getRequiredL4()
  {
    return requiredL4;
  }



  /**
   * Sets the value of the requiredL4 field.
   *
   * @param  requiredL4  The value for the requiredL4 field.
   */
  public void setRequiredL4(final String requiredL4)
  {
    this.requiredL4 = requiredL4;
  }



  /**
   * Retrieves the number of times the post-decode method has been invoked
   * for this class.
   *
   * @return  The number of times the post-decode method has been invoked for
   *          this class.
   */
  public static int getL4PostDecodeInvokeCount()
  {
    return POST_DECODE_INVOKE_COUNT.get();
  }



  /**
   * Retrieves the number of times the post-encode method has been invoked
   * for this class.
   *
   * @return  The number of times the post-encode method has been invoked for
   *          this class.
   */
  public static int getL4PostEncodeInvokeCount()
  {
    return POST_ENCODE_INVOKE_COUNT.get();
  }
}
