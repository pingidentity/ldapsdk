/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
 * This class provides an object with a field and method whose types are not
 * supported by the default object encoder.
 */
@LDAPObject(structuralClass="testClass")
public class TestDefaultEncoderUnsupportedType
{
  @LDAPField() private Object fieldValue;
  @LDAPField() private Object[] fieldArrayValue;
  private Object methodValue;
  private Object[] methodArrayValue;




  /**
   * Creates a new instance of this object.
   */
  public TestDefaultEncoderUnsupportedType()
  {
  }



  /**
   * Gets the field value.
   *
   * @return  The field value.
   */
  public Object getFieldValue()
  {
    return fieldValue;
  }



  /**
   * Sets the field value.
   *
   * @param  fieldValue  The field value.
   */
  public void setFieldValue(final Object fieldValue)
  {
    this.fieldValue = fieldValue;
  }



  /**
   * Gets the field array value.
   *
   * @return  The field array value.
   */
  public Object[] getFieldArrayValue()
  {
    return fieldArrayValue;
  }



  /**
   * Sets the field array value.
   *
   * @param  fieldArrayValue  The field array value.
   */
  public void setFieldArrayValue(final Object[] fieldArrayValue)
  {
    this.fieldArrayValue = fieldArrayValue;
  }



  /**
   * Gets the method value.
   *
   * @return  The method value.
   */
  @LDAPGetter(attribute="methodValue")
  public Object getMethodValue()
  {
    return methodValue;
  }



  /**
   * Sets the method value.
   *
   * @param  methodValue  The method value.
   */
  @LDAPSetter(attribute="methodValue")
  public void setMethodValue(final Object methodValue)
  {
    this.methodValue = methodValue;
  }



  /**
   * Gets the method array value.
   *
   * @return  The method array value.
   */
  @LDAPGetter(attribute="methodArrayValue")
  public Object[] getMethodArrayValue()
  {
    return methodArrayValue;
  }



  /**
   * Sets the method array value.
   *
   * @param  methodArrayValue  The method array value.
   */
  @LDAPSetter(attribute="methodArrayValue")
  public void setMethodArrayValue(final Object[] methodArrayValue)
  {
    this.methodArrayValue = methodArrayValue;
  }
}
