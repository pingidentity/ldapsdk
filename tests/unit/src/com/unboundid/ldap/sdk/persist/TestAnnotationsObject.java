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
package com.unboundid.ldap.sdk.persist;



import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ReadOnlyEntry;



/**
 * This class provides an object that can be used to test a number of different
 * types of annotations.
 */
@LDAPObject(structuralClass="testAnnotationsStructural",
            auxiliaryClass="testAnnotationsAuxiliary",
            superiorClass="top",
            postDecodeMethod="doPostDecode",
            postEncodeMethod="doPostEncode",
            requestAllAttributes=true)
public class TestAnnotationsObject
{
  @LDAPField()
  private String testDefaults;

  @LDAPField(failOnInvalidValue=false, failOnTooManyValues=false, inAdd=false,
             filterUsage=FilterUsage.ALWAYS_ALLOWED, inModify=false, inRDN=true,
             attribute="foo", defaultEncodeValue="bar",
             defaultDecodeValue="baz", objectClass="testAnnotationsAuxiliary",
             requiredForDecode=true, requiredForEncode=true)
  private String testNonDefaults;

  @LDAPField(defaultEncodeValue={"a", "b"}, defaultDecodeValue={"c", "d"},
       objectClass={"testAnnotationsStructural","testAnnotationsAuxiliary"})
  private String[] testMultiValued;

  @LDAPField(requiredForDecode=true, requiredForEncode=true)
  private String requiredNotInRDN;

  @LDAPField(inAdd=false)
  private String notInAdd;

  private String notAnnotated;

  @LDAPDNField private String dnField;
  @LDAPEntryField private ReadOnlyEntry entryField;



  private String testMethodDefaults;
  private String testMethodNonDefaults;
  private String testRDNMethodValue;
  private String[] testMethodMultiValued;



  /**
   * Creates a new instance of this object.
   */
  public TestAnnotationsObject()
  {
  }



  /**
   * Gets the value of the {@code testDefaults} field.
   *
   * @return  The value of the {@code testDefaults} field.
   */
  public String getTestDefaults()
  {
    return testDefaults;
  }



  /**
   * Sets the value of the {@code testDefaults} field.
   *
   * @param  testDefaults  The value of the {@code testDefaults} field.
   */
  public void setTestDefaults(final String testDefaults)
  {
    this.testDefaults = testDefaults;
  }



  /**
   * Gets the value of the {@code testNonDefaults} field.
   *
   * @return  The value of the {@code testNonDefaults} field.
   */
  public String getTestNonDefaults()
  {
    return testNonDefaults;
  }



  /**
   * Sets the value of the {@code testNonDefaults} field.
   *
   * @param  testNonDefaults  The value of the {@code testNonDefaults} field.
   */
  public void setTestNonDefaults(final String testNonDefaults)
  {
    this.testNonDefaults = testNonDefaults;
  }



  /**
   * Gets the value of the {@code testMultiValued} field.
   *
   * @return  The value of the {@code testMultiValued} field.
   */
  public String[] getTestMultiValued()
  {
    return testMultiValued;
  }



  /**
   * Sets the value of the {@code testMultiValued} field.
   *
   * @param  testMultiValued  The value of the {@code testMultiValued} field.
   */
  public void setTestMultiValued(final String... testMultiValued)
  {
    this.testMultiValued = testMultiValued;
  }



  /**
   * Gets the value of the {@code requiredNotInRDN} field.
   *
   * @return  The value of the {@code requiredNotInRDN} field.
   */
  public String getRequiredNotInRDN()
  {
    return requiredNotInRDN;
  }



  /**
   * Sets the value of the {@code requiredNotInRDN} field.
   *
   * @param  requiredNotInRDN  The value of the {@code requiredNotInRDN} field.
   */
  public void setRequiredNotInRDN(final String requiredNotInRDN)
  {
    this.requiredNotInRDN = requiredNotInRDN;
  }



  /**
   * Gets the value of the {@code testMethodDefaults} field.
   *
   * @return  The value of the {@code testMethodDefaults} field.
   */
  @LDAPGetter()
  public String getTestMethodDefaults()
  {
    return testMethodDefaults;
  }



  /**
   * Sets the value of the {@code testMethodDefaults} field.
   *
   * @param  testMethodDefaults  The value of the {@code testMethodDefaults}
   *                             field.
   */
  @LDAPSetter()
  public void setTestMethodDefaults(final String testMethodDefaults)
  {
    this.testMethodDefaults = testMethodDefaults;
  }



  /**
   * Gets the value of the {@code testMethodNonDefaults} field.
   *
   * @return  The value of the {@code testMethodNonDefaults} field.
   */
  @LDAPGetter(attribute="x", inAdd=false, inModify=false,
       filterUsage=FilterUsage.ALWAYS_ALLOWED, inRDN=false,
       objectClass="testAnnotationsAuxiliary")
  public String getTestMethodNonDefaults()
  {
    return testMethodNonDefaults;
  }



  /**
   * Sets the value of the {@code testMethodDefaults} field.
   *
   * @param  testMethodNonDefaults  The value of the
   *                                {@code testMethodNonDefaults} field.
   */
  @LDAPSetter(attribute="x", failOnInvalidValue=false,
       failOnTooManyValues=false)
  public void setTestMethodNonDefaults(final String testMethodNonDefaults)
  {
    this.testMethodNonDefaults = testMethodNonDefaults;
  }



  /**
   * Gets a value that should be included in an entry's DN.
   *
   * @return  A value that should be included in an entry's DN.
   */
  @LDAPGetter(attribute="y", inAdd=true, inRDN= true,
       filterUsage=FilterUsage.ALWAYS_ALLOWED)
  public String getRDNMethodValue()
  {
    return testRDNMethodValue;
  }



  /**
   * Sets a value that should be included in an entry's DN.
   *
   * @param  testRDNMethodValue  A value that should be included in an entry's
   *                             DN.
   */
  @LDAPSetter(attribute="y")
  public void setRDNMethodValue(final String testRDNMethodValue)
  {
    this.testRDNMethodValue = testRDNMethodValue;
  }



  /**
   * Gets the value of the {@code testMethodMultiValued} field.
   *
   * @return  The value of the {@code testMethodMultiValued} field.
   */
  @LDAPGetter(attribute="testMethodMultiValued")
  public String[] getTestMethodMultiValued()
  {
    return testMethodMultiValued;
  }



  /**
   * Sets the value of the {@code testMethodMultiValued} field.
   *
   * @param  testMethodMultiValued  The value of the
   *                                {@code testMethodMultiValued} field.
   */
  @LDAPSetter(attribute="testMethodMultiValued")
  public void setTestMethodMultiValued(final String[] testMethodMultiValued)
  {
    this.testMethodMultiValued = testMethodMultiValued;
  }



  /**
   * Retrieves the DN of the associated entry, if available.
   *
   * @return  The DN of the associated entry, or {@code null} if it is not
   *          available.
   */
  public String getEntryDN()
  {
    return dnField;
  }



  /**
   * Retrieves the associated entry, if available.
   *
   * @return  The associated entry, or {@code null} if it is not available.
   */
  public ReadOnlyEntry getEntry()
  {
    return entryField;
  }



  /**
   * Performs any post-decode processing for this object.
   */
  private void doPostDecode()
  {
  }



  /**
   * Performs any post-decode processing for the provided entry.
   *
   * @param  entry  The entry that was encoded from this object.
   */
  private void doPostEncode(final Entry entry)
  {
  }
}
