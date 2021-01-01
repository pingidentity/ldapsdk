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
 * This class provides an object with a number of different types of fields that
 * can be set used with the {@code ObjectEncoder.setNull} method.
 */
@LDAPObject()
public class TestNullable
{
  @LDAPField() private boolean booleanF;
  @LDAPField() private byte byteF;
  @LDAPField() private char charF;
  @LDAPField() private double doubleF;
  @LDAPField() private float floatF;
  @LDAPField() private int intF;
  @LDAPField() private long longF;
  @LDAPField() private short shortF;
  @LDAPField() private Object objectF;

  private boolean booleanMF;
  private byte byteMF;
  private char charMF;
  private double doubleMF;
  private float floatMF;
  private int intMF;
  private long longMF;
  private short shortMF;
  private Object objectMF;



  /**
   * Creates a new instance of this object.
   */
  public TestNullable()
  {
  }



  /**
   * Gets the {@code booleanF} field.
   *
   * @return  The {@code booleanF} field.
   */
  public boolean getBooleanF()
  {
    return booleanF;
  }



  /**
   * Sets the {@code booleanF} field.
   *
   * @param  booleanF  The {@code booleanF} field.
   */
  public void setBooleanF(final boolean booleanF)
  {
    this.booleanF = booleanF;
  }



  /**
   * Gets the {@code byteF} field.
   *
   * @return  The {@code byteF} field.
   */
  public byte getByteF()
  {
    return byteF;
  }



  /**
   * Sets the {@code byteF} field.
   *
   * @param  byteF  The {@code byteF} field.
   */
  public void setByteF(final byte byteF)
  {
    this.byteF = byteF;
  }



  /**
   * Gets the {@code charF} field.
   *
   * @return  The {@code charF} field.
   */
  public char getCharF()
  {
    return charF;
  }



  /**
   * Sets the {@code charF} field.
   *
   * @param  charF  The {@code charF} field.
   */
  public void setCharF(final char charF)
  {
    this.charF = charF;
  }



  /**
   * Gets the {@code doubleF} field.
   *
   * @return  The {@code doubleF} field.
   */
  public double getDoubleF()
  {
    return doubleF;
  }



  /**
   * Sets the {@code doubleF} field.
   *
   * @param  doubleF  The {@code doubleF} field.
   */
  public void setDoubleF(final double doubleF)
  {
    this.doubleF = doubleF;
  }



  /**
   * Gets the {@code floatF} field.
   *
   * @return  The {@code floatF} field.
   */
  public float getFloatF()
  {
    return floatF;
  }



  /**
   * Sets the {@code floatF} field.
   *
   * @param  floatF  The {@code floatF} field.
   */
  public void setFloatF(final float floatF)
  {
    this.floatF = floatF;
  }



  /**
   * Gets the {@code intF} field.
   *
   * @return  The {@code intF} field.
   */
  public int getIntF()
  {
    return intF;
  }



  /**
   * Sets the {@code intF} field.
   *
   * @param  intF  The {@code intF} field.
   */
  public void setIntF(final int intF)
  {
    this.intF = intF;
  }



  /**
   * Gets the {@code longF} field.
   *
   * @return  The {@code longF} field.
   */
  public long getLongF()
  {
    return longF;
  }



  /**
   * Sets the {@code longF} field.
   *
   * @param  longF  The {@code longF} field.
   */
  public void setLongF(final long longF)
  {
    this.longF = longF;
  }



  /**
   * Gets the {@code shortF} field.
   *
   * @return  The {@code shortF} field.
   */
  public short getShortF()
  {
    return shortF;
  }



  /**
   * Sets the {@code shortF} field.
   *
   * @param  shortF  The {@code shortF} field.
   */
  public void setShortF(final short shortF)
  {
    this.shortF = shortF;
  }



  /**
   * Gets the {@code objectF} field.
   *
   * @return  The {@code objectF} field.
   */
  public Object getObjectF()
  {
    return objectF;
  }



  /**
   * Sets the {@code objectF} field.
   *
   * @param  objectF  The {@code objectF} field.
   */
  public void setObjectF(final Object objectF)
  {
    this.objectF = objectF;
  }



  /**
   * Gets the {@code booleanMF} field.
   *
   * @return  The {@code booleanMF} field.
   */
  @LDAPGetter(attribute="booleanMF")
  public boolean getBooleanMF()
  {
    return booleanMF;
  }



  /**
   * Sets the {@code booleanMF} field.
   *
   * @param  booleanMF  The {@code booleanMF} field.
   */
  @LDAPSetter(attribute="booleanMF")
  public void setBooleanMF(final boolean booleanMF)
  {
    this.booleanMF = booleanMF;
  }



  /**
   * Gets the {@code byteMF} field.
   *
   * @return  The {@code byteMF} field.
   */
  @LDAPGetter(attribute="byteMF")
  public byte getByteMF()
  {
    return byteMF;
  }



  /**
   * Sets the {@code byteMF} field.
   *
   * @param  byteMF  The {@code byteMF} field.
   */
  @LDAPSetter(attribute="byteMF")
  public void setByteMF(final byte byteMF)
  {
    this.byteMF = byteMF;
  }



  /**
   * Gets the {@code charMF} field.
   *
   * @return  The {@code charMF} field.
   */
  @LDAPGetter(attribute="charMF")
  public char getCharMF()
  {
    return charMF;
  }



  /**
   * Sets the {@code charMF} field.
   *
   * @param  charMF  The {@code charMF} field.
   */
  @LDAPSetter(attribute="charMF")
  public void setCharMF(final char charMF)
  {
    this.charMF = charMF;
  }



  /**
   * Gets the {@code doubleMF} field.
   *
   * @return  The {@code doubleMF} field.
   */
  @LDAPGetter(attribute="doubleMF")
  public double getDoubleMF()
  {
    return doubleMF;
  }



  /**
   * Sets the {@code doubleMF} field.
   *
   * @param  doubleMF  The {@code doubleMF} field.
   */
  @LDAPSetter(attribute="doubleMF")
  public void setDoubleMF(final double doubleMF)
  {
    this.doubleMF = doubleMF;
  }



  /**
   * Gets the {@code floatMF} field.
   *
   * @return  The {@code floatMF} field.
   */
  @LDAPGetter(attribute="floatMF")
  public float getFloatMF()
  {
    return floatMF;
  }



  /**
   * Sets the {@code floatMF} field.
   *
   * @param  floatMF  The {@code floatMF} field.
   */
  @LDAPSetter(attribute="floatMF")
  public void setFloatMF(final float floatMF)
  {
    this.floatMF = floatMF;
  }



  /**
   * Gets the {@code intMF} field.
   *
   * @return  The {@code intMF} field.
   */
  @LDAPGetter(attribute="intMF")
  public int getIntMF()
  {
    return intMF;
  }



  /**
   * Sets the {@code intMF} field.
   *
   * @param  intMF  The {@code intMF} field.
   */
  @LDAPSetter(attribute="intMF")
  public void setIntMF(final int intMF)
  {
    this.intMF = intMF;
  }



  /**
   * Gets the {@code longMF} field.
   *
   * @return  The {@code longMF} field.
   */
  @LDAPGetter(attribute="longMF")
  public long getLongMF()
  {
    return longMF;
  }



  /**
   * Sets the {@code longMF} field.
   *
   * @param  longMF  The {@code longMF} field.
   */
  @LDAPSetter(attribute="longMF")
  public void setLongMF(final long longMF)
  {
    this.longMF = longMF;
  }



  /**
   * Gets the {@code shortMF} field.
   *
   * @return  The {@code shortMF} field.
   */
  @LDAPGetter(attribute="shortMF")
  public short getShortMF()
  {
    return shortMF;
  }



  /**
   * Sets the {@code shortMF} field.
   *
   * @param  shortMF  The {@code shortMF} field.
   */
  @LDAPSetter(attribute="shortMF")
  public void setShortMF(final short shortMF)
  {
    this.shortMF = shortMF;
  }



  /**
   * Gets the {@code objectMF} field.
   *
   * @return  The {@code objectMF} field.
   */
  @LDAPGetter(attribute="objectMF")
  public Object getObjectMF()
  {
    return objectMF;
  }



  /**
   * Sets the {@code objectMF} field.
   *
   * @param  objectMF  The {@code objectMF} field.
   */
  @LDAPSetter(attribute="objectMF")
  public void setObjectMF(final Object objectMF)
  {
    this.objectMF = objectMF;
  }
}
