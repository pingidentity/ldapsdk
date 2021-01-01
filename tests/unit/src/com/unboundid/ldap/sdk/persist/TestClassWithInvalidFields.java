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



/**
 * This class provides an object that has fields with various problems.
 */
@LDAPObject(auxiliaryClass="testAuxiliaryClass")
public class TestClassWithInvalidFields
{
  @LDAPField()
  private final String finalField = "final";

  @LDAPField()
  private static String staticField;

  @LDAPField()
  private Object unsupportedObjectType;

  @LDAPField(defaultEncodeValue={"a","b"})
  private String multipleDefaultEncodeValues;

  @LDAPField(defaultDecodeValue={"a","b"})
  private String multipleDefaultDecodeValues;

  @LDAPField()
  private String not_a_valid_ldap_name;

  @LDAPField(objectClass="undefined")
  private String undefinedObjectClass;

  @LDAPField(encoderClass=TestInvalidObjectEncoder.class)
  private String invalidEncoder;



  private static String testStaticMethodField;



  /**
   * Creates a new instance of this class.
   */
  public TestClassWithInvalidFields()
  {
  }



  /**
   * Gets the {@code testStaticMethodField} value.
   *
   * @return  The {@code testStaticMethodField} value.
   */
  @LDAPGetter(attribute="testStaticMethodField", inAdd=false)
  public static String getTestStaticMethodField()
  {
    return testStaticMethodField;
  }



  /**
   * Sets the {@code testStaticMethodField} value.
   *
   * @param  testStaticMethodField  The {@code testStaticMethodField} value.
   */
  @LDAPSetter(attribute="testStaticMethodField")
  public static void setTestStaticMethodField(
                          final String testStaticMethodField)
  {
    TestClassWithInvalidFields.testStaticMethodField = testStaticMethodField;
  }



  /**
   * A method marked with the {@code LDAPGetter} annotation but takes an
   * argument.
   *
   * @param  a  The argument.
   *
   * @return  The provided argument.
   */
  @LDAPGetter(attribute="getterWithArgument")
  public String getGetterWithArgument(final String a)
  {
    return a;
  }



  /**
   * A method marked with the {@code LDAPGetter} annotation but a return
   * type that isn't supported.
   *
   * @return  An object.
   */
  @LDAPGetter(attribute="unsupportedReturnType")
  public Object getUnsupportedReturnType()
  {
    return new Object();
  }



  /**
   * A method marked with the {@code LDAPGetter} annotation but a void
   * return type.
   */
  @LDAPGetter(attribute="unsupportedReturnType")
  public void getVoidReturnType()
  {
  }



  /**
   * A method marked with the {@code LDAPGetter} annotation but including
   * an invalid encoder class.
   *
   * @return  A value.
   */
  @LDAPGetter(attribute="invalidEncoder",
       encoderClass=TestInvalidObjectEncoder.class)
  public String getInvalidEncoder()
  {
    return "foo";
  }



  /**
   * A method marked with the {@code LDAPSetter} annotation but including
   * an invalid encoder class.
   *
   * @param  s  The argument.
   */
  @LDAPSetter(attribute="invalidEncoder",
       encoderClass=TestInvalidObjectEncoder.class)
  public void setInvalidEncoder(final String s)
  {
  }



  /**
   * A method marked with the {@code LDAPGetter} annotation but including
   * an invalid object class.
   *
   * @return  A value.
   */
  @LDAPGetter(attribute="invalidObjectClass", objectClass="invalid")
  public String getInvalidObjectClass()
  {
    return "foo";
  }



  /**
   * A method marked with the {@code LDAPGetter} annotation that will
   * always throw a runtime exception when invoked.
   *
   * @return  A value.
   */
  @LDAPGetter(attribute="runtimeException")
  public String getRuntimeException()
  {
    throw new RuntimeException();
  }



  /**
   * A method marked with the {@code LDAPGetter} annotation that will
   * always throw an LDAP persist exception when invoked.
   *
   * @return  A value.
   *
   * @throws  LDAPPersistException  Always.
   */
  @LDAPGetter(attribute="persistException")
  public String getPersistException()
         throws LDAPPersistException
  {
    throw new LDAPPersistException("foo");
  }



  /**
   * A method marked with the {@code LDAPSetter} annotation which does not
   * take any arguments.
   */
  @LDAPSetter(attribute="noArguments")
  public void setNoArguments()
  {
  }



  /**
   * A method marked with the {@code LDAPSetter} annotation that takes
   * multiple arguments.
   *
   * @param  a1  The first argument.
   * @param  a2  The second argument.
   */
  @LDAPSetter(attribute="multipleArguments")
  public void setMultipleArguments(final String a1, final String a2)
  {
  }



  /**
   * A method marked with the {@code LDAPSetter} annotation that takes an
   * unsupported argument type.
   *
   * @param  o  The argument.
   */
  @LDAPSetter(attribute="unsupportedArgument")
  public void setUnsupportedArgument(final Object o)
  {
  }



  /**
   * A method marked with the {@code LDAPSetter} annotation that always
   * throws a runtime exception.
   *
   * @param  s  The argument.
   */
  @LDAPSetter(attribute="throwsRuntimeException")
  public void setThrowsRuntimeException(final String s)
  {
    throw new RuntimeException();
  }



  /**
   * A method marked with the {@code LDAPSetter} annotation that always
   * throws a runtime exception.
   *
   * @param  s  The argument.
   *
   * @throws  LDAPPersistException  Always.
   */
  @LDAPSetter(attribute="throwsPersistException")
  public void setThrowsPersistException(final String s)
         throws LDAPPersistException
  {
    throw new LDAPPersistException("foo");
  }
}
