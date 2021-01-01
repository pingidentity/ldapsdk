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
@LDAPObject(structuralClass="testInheritanceL3",
            defaultParentDN="dc=example,dc=com",
            requestAllAttributes=true,
            postDecodeMethod="doPostDecode",
            postEncodeMethod="doPostEncode")
public class TestInheritanceL3
       extends TestInheritanceL2
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
  @LDAPField(attribute="optionalL3",
             filterUsage=FilterUsage.CONDITIONALLY_ALLOWED)
  private String optionalL3;

  // A required field.
  @LDAPField(attribute="requiredL3",
             requiredForEncode=true,
             requiredForDecode=true,
             inRDN=true,
             filterUsage=FilterUsage.ALWAYS_ALLOWED)
  private String requiredL3;



  /**
   * Creates a new instance of this object with no fields set.
   */
  public TestInheritanceL3()
  {
    optionalL3 = null;
    requiredL3 = null;
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
   * Retrieves the value of the optionalL3 field.
   *
   * @return  The value of the optionalL3 field.
   */
  public String getOptionalL3()
  {
    return optionalL3;
  }



  /**
   * Sets the value of the optionalL3 field.
   *
   * @param  optionalL3  The value for the optionalL3 field.
   */
  public void setOptionalL3(final String optionalL3)
  {
    this.optionalL3 = optionalL3;
  }



  /**
   * Retrieves the value of the requiredL3 field.
   *
   * @return  The value of the requiredL3 field.
   */
  public String getRequiredL3()
  {
    return requiredL3;
  }



  /**
   * Sets the value of the requiredL3 field.
   *
   * @param  requiredL3  The value for the requiredL3 field.
   */
  public void setRequiredL3(final String requiredL3)
  {
    this.requiredL3 = requiredL3;
  }



  /**
   * Retrieves the number of times the post-decode method has been invoked
   * for this class.
   *
   * @return  The number of times the post-decode method has been invoked for
   *          this class.
   */
  public static int getL3PostDecodeInvokeCount()
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
  public static int getL3PostEncodeInvokeCount()
  {
    return POST_ENCODE_INVOKE_COUNT.get();
  }
}
