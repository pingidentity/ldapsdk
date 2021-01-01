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



import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.util.Date;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.RDN;



/**
 * This class provides a valid object that can be used to test the default
 * object encoder.
 */
@LDAPObject(structuralClass="testStructuralClass",
            auxiliaryClass="testAuxiliaryClass")
public class TestDefaultObjectEncoderValidObject
{
  // The RDN field for this class.
  @LDAPField(attribute="cn", inAdd=true, filterUsage=FilterUsage.ALWAYS_ALLOWED,
             inModify=false, inRDN=true, requiredForDecode=true,
             requiredForEncode=true)
  private String rdnField;

  // Simple fields that will be used for testing with the @LDAPField annotation.
  @LDAPField private AtomicInteger atomicIntF;
  @LDAPField private AtomicLong atomicLongF;
  @LDAPField private BigDecimal bigDecimalF;
  @LDAPField private BigInteger bigIntegerF;
  @LDAPField private boolean booleanPF;
  @LDAPField private Boolean booleanOF;
  @LDAPField private byte[] bytePAF;
  @LDAPField private char[] charPAF;
  @LDAPField private Date dateF;
  @LDAPField private DN dnF;
  @LDAPField private double doublePF;
  @LDAPField private Double doubleOF;
  @LDAPField private Filter filterF;
  @LDAPField private FilterUsage filterUsageF;
  @LDAPField private float floatPF;
  @LDAPField private Float floatOF;
  @LDAPField private int intPF;
  @LDAPField private Integer intOF;
  @LDAPField private LDAPURL ldapURLF;
  @LDAPField private long longPF;
  @LDAPField private Long longOF;
  @LDAPField private RDN rdnF;
  @LDAPField private short shortPF;
  @LDAPField private Short shortOF;
  @LDAPField private String stringF;
  @LDAPField private StringBuffer stringBufferF;
  @LDAPField private StringBuilder stringBuilderF;
  @LDAPField private URI uriF;
  @LDAPField private URL urlF;
  @LDAPField private UUID uuidF;

  // Array fields that will be used for testing with the @LDAPField annotation.
  @LDAPField private AtomicInteger[] atomicIntAF;
  @LDAPField private AtomicLong[] atomicLongAF;
  @LDAPField private BigDecimal[] bigDecimalAF;
  @LDAPField private BigInteger[] bigIntegerAF;
  @LDAPField private boolean[] booleanPAF;
  @LDAPField private Boolean[] booleanOAF;
  @LDAPField private byte[][] bytePAAF;
  @LDAPField private char[][] charPAAF;
  @LDAPField private Date[] dateAF;
  @LDAPField private DN[] dnAF;
  @LDAPField private double[] doublePAF;
  @LDAPField private Double[] doubleOAF;
  @LDAPField private Filter[] filterAF;
  @LDAPField private FilterUsage[] filterUsageAF;
  @LDAPField private float[] floatPAF;
  @LDAPField private Float[] floatOAF;
  @LDAPField private int[] intPAF;
  @LDAPField private Integer[] intOAF;
  @LDAPField private LDAPURL[] ldapURLAF;
  @LDAPField private long[] longPAF;
  @LDAPField private Long[] longOAF;
  @LDAPField private RDN[] rdnAF;
  @LDAPField private short[] shortPAF;
  @LDAPField private Short[] shortOAF;
  @LDAPField private String[] stringAF;
  @LDAPField private StringBuffer[] stringBufferAF;
  @LDAPField private StringBuilder[] stringBuilderAF;
  @LDAPField private URI[] uriAF;
  @LDAPField private URL[] urlAF;
  @LDAPField private UUID[] uuidAF;

  // List fields that will be used for testing with the @LDAPField annotation.
  @LDAPField private ArrayList<String> stringArrayListF;
  @LDAPField private CopyOnWriteArrayList<String> stringCopyOnWriteArrayListF;
  @LDAPField private LinkedList<String> stringLinkedListF;
  @LDAPField private List<String> stringListF;

  // Set fields that will be used for testing with the @LDAPField annotation.
  @LDAPField private CopyOnWriteArraySet<String> stringCopyOnWriteArraySetF;
  @LDAPField private HashSet<String> stringHashSetF;
  @LDAPField private LinkedHashSet<String> stringLinkedHashSetF;
  @LDAPField private TreeSet<String> stringTreeSetF;
  @LDAPField private Set<String> stringSetF;

  // Fields pertaining to serializable objects that wouldn't otherwise be
  // supported.
  @LDAPField private GregorianCalendar gregorianCalendarF;
  @LDAPField private GregorianCalendar[] gregorianCalendarAF;
  @LDAPField private ArrayList<GregorianCalendar> gregorianCalendarArrayListF;
  @LDAPField private HashSet<GregorianCalendar> gregorianCalendarHashSetF;

  // Simple fields that will be used for testing with the @LDAPGetter and
  // @LDAPSetter  annotations.
  private AtomicInteger atomicIntM;
  private AtomicLong atomicLongM;
  private BigDecimal bigDecimalM;
  private BigInteger bigIntegerM;
  private boolean booleanPM;
  private Boolean booleanOM;
  private byte[] bytePAM;
  private char[] charPAM;
  private Date dateM;
  private DN dnM;
  private double doublePM;
  private Double doubleOM;
  private Filter filterM;
  private FilterUsage filterUsageM;
  private float floatPM;
  private Float floatOM;
  private int intPM;
  private Integer intOM;
  private LDAPURL ldapURLM;
  private long longPM;
  private Long longOM;
  private RDN rdnM;
  private short shortPM;
  private Short shortOM;
  private String stringM;
  private StringBuffer stringBufferM;
  private StringBuilder stringBuilderM;
  private URI uriM;
  private URL urlM;
  private UUID uuidM;

  // Array fields that will be used for testing with the @LDAPGetter and
  // @LDAPSetter  annotations.
  private AtomicInteger[] atomicIntAM;
  private AtomicLong[] atomicLongAM;
  private BigDecimal[] bigDecimalAM;
  private BigInteger[] bigIntegerAM;
  private boolean[] booleanPAM;
  private Boolean[] booleanOAM;
  private byte[][] bytePAAM;
  private char[][] charPAAM;
  private Date[] dateAM;
  private DN[] dnAM;
  private double[] doublePAM;
  private Double[] doubleOAM;
  private Filter[] filterAM;
  private FilterUsage[] filterUsageAM;
  private float[] floatPAM;
  private Float[] floatOAM;
  private int[] intPAM;
  private Integer[] intOAM;
  private LDAPURL[] ldapURLAM;
  private long[] longPAM;
  private Long[] longOAM;
  private RDN[] rdnAM;
  private short[] shortPAM;
  private Short[] shortOAM;
  private String[] stringAM;
  private StringBuffer[] stringBufferAM;
  private StringBuilder[] stringBuilderAM;
  private URI[] uriAM;
  private URL[] urlAM;
  private UUID[] uuidAM;

  // List fields that will be used for testing with the @LDAPGetter and
  // @LDAPSetter annotations.
  private ArrayList<String> stringArrayListM;
  private CopyOnWriteArrayList<String> stringCopyOnWriteArrayListM;
  private LinkedList<String> stringLinkedListM;
  private List<String> stringListM;

  // Set fields that will be used for testing with the @LDAPGetter and
  // @LDAPSetter annotations.
  private CopyOnWriteArraySet<String> stringCopyOnWriteArraySetM;
  private HashSet<String> stringHashSetM;
  private LinkedHashSet<String> stringLinkedHashSetM;
  private TreeSet<String> stringTreeSetM;
  private Set<String> stringSetM;



  /**
   * Retrieves the value of the rdnField field.
   *
   * @return  The value of the rdnField field.
   */
  public String getRDNField()
  {
    return rdnField;
  }



  /**
   * Sets the value of the rdnField field.
   *
   * @param  rdnField  The value to use for the rdnField field.
   */
  public void setRDNField(final String rdnField)
  {
    this.rdnField = rdnField;
  }



  /**
   * Retrieves the value of the atomicIntF field.
   *
   * @return  The value of the AtomicIntF field.
   */
  public AtomicInteger getAtomicIntF()
  {
    return atomicIntF;
  }



  /**
   * Sets the value of the atomicIntF field.
   *
   * @param  atomicIntF  The value to use for the atomicIntF field.
   */
  public void setAtomicIntF(final AtomicInteger atomicIntF)
  {
    this.atomicIntF = atomicIntF;
  }



  /**
   * Retrieves the value of the atomicIntAF field.
   *
   * @return  The value of the AtomicIntAF field.
   */
  public AtomicInteger[] getAtomicIntAF()
  {
    return atomicIntAF;
  }



  /**
   * Sets the value of the atomicIntAF field.
   *
   * @param  atomicIntAF  The value to use for the atomicIntAF field.
   */
  public void setAtomicIntAF(final AtomicInteger[] atomicIntAF)
  {
    this.atomicIntAF = atomicIntAF;
  }



  /**
   * Retrieves the value of the atomicIntM field.
   *
   * @return  The value of the AtomicIntM field.
   */
  @LDAPGetter(attribute="atomicIntM")
  public AtomicInteger getAtomicIntM()
  {
    return atomicIntM;
  }



  /**
   * Sets the value of the atomicIntM field.
   *
   * @param  atomicIntM  The value to use for the atomicIntM field.
   */
  @LDAPSetter(attribute="atomicIntM")
  public void setAtomicIntM(final AtomicInteger atomicIntM)
  {
    this.atomicIntM = atomicIntM;
  }



  /**
   * Retrieves the value of the atomicIntAM field.
   *
   * @return  The value of the AtomicIntAM field.
   */
  @LDAPGetter(attribute="atomicIntAM")
  public AtomicInteger[] getAtomicIntAM()
  {
    return atomicIntAM;
  }



  /**
   * Sets the value of the atomicIntAM field.
   *
   * @param  atomicIntAM  The value to use for the atomicIntAM field.
   */
  @LDAPSetter(attribute="atomicIntAM")
  public void setAtomicIntAM(final AtomicInteger[] atomicIntAM)
  {
    this.atomicIntAM = atomicIntAM;
  }



  /**
   * Retrieves the value of the atomicLongF field.
   *
   * @return  The value of the AtomicLongF field.
   */
  public AtomicLong getAtomicLongF()
  {
    return atomicLongF;
  }



  /**
   * Sets the value of the atomicLongF field.
   *
   * @param  atomicLongF  The value to use for the atomicLongF field.
   */
  public void setAtomicLongF(final AtomicLong atomicLongF)
  {
    this.atomicLongF = atomicLongF;
  }



  /**
   * Retrieves the value of the atomicLongAF field.
   *
   * @return  The value of the AtomicLongAF field.
   */
  public AtomicLong[] getAtomicLongAF()
  {
    return atomicLongAF;
  }



  /**
   * Sets the value of the atomicLongAF field.
   *
   * @param  atomicLongAF  The value to use for the atomicLongAF field.
   */
  public void setAtomicLongAF(final AtomicLong[] atomicLongAF)
  {
    this.atomicLongAF = atomicLongAF;
  }



  /**
   * Retrieves the value of the atomicLongM field.
   *
   * @return  The value of the AtomicLongM field.
   */
  @LDAPGetter(attribute="atomicLongM")
  public AtomicLong getAtomicLongM()
  {
    return atomicLongM;
  }



  /**
   * Sets the value of the atomicLongM field.
   *
   * @param  atomicLongM  The value to use for the atomicLongM field.
   */
  @LDAPSetter(attribute="atomicLongM")
  public void setAtomicLongM(final AtomicLong atomicLongM)
  {
    this.atomicLongM = atomicLongM;
  }



  /**
   * Retrieves the value of the atomicLongAM field.
   *
   * @return  The value of the AtomicLongAM field.
   */
  @LDAPGetter(attribute="atomicLongAM")
  public AtomicLong[] getAtomicLongAM()
  {
    return atomicLongAM;
  }



  /**
   * Sets the value of the atomicLongAM field.
   *
   * @param  atomicLongAM  The value to use for the atomicLongAM field.
   */
  @LDAPSetter(attribute="atomicLongAM")
  public void setAtomicLongAM(final AtomicLong[] atomicLongAM)
  {
    this.atomicLongAM = atomicLongAM;
  }



  /**
   * Retrieves the value of the bigDecimalF field.
   *
   * @return  The value of the bigDecimalF field.
   */
  public BigDecimal getBigDecimalF()
  {
    return bigDecimalF;
  }



  /**
   * Sets the value of the bigDecimalF field.
   *
   * @param  bigDecimalF  The value to use for the bigDecimalF field.
   */
  public void setBigDecimalF(final BigDecimal bigDecimalF)
  {
    this.bigDecimalF = bigDecimalF;
  }



  /**
   * Retrieves the value of the bigDecimalAF field.
   *
   * @return  The value of the bigDecimalAF field.
   */
  public BigDecimal[] getBigDecimalAF()
  {
    return bigDecimalAF;
  }



  /**
   * Sets the value of the bigDecimalAF field.
   *
   * @param  bigDecimalAF  The value to use for the bigDecimalAF field.
   */
  public void setBigDecimalAF(final BigDecimal[] bigDecimalAF)
  {
    this.bigDecimalAF = bigDecimalAF;
  }



  /**
   * Retrieves the value of the bigDecimalM field.
   *
   * @return  The value of the bigDecimalM field.
   */
  @LDAPGetter(attribute="bigDecimalM")
  public BigDecimal getBigDecimalM()
  {
    return bigDecimalM;
  }



  /**
   * Sets the value of the bigDecimalM field.
   *
   * @param  bigDecimalM  The value to use for the bigDecimalM field.
   */
  @LDAPSetter(attribute="bigDecimalM")
  public void setBigDecimalM(final BigDecimal bigDecimalM)
  {
    this.bigDecimalM = bigDecimalM;
  }



  /**
   * Retrieves the value of the bigDecimalAM field.
   *
   * @return  The value of the bigDecimalAM field.
   */
  @LDAPGetter(attribute="bigDecimalAM")
  public BigDecimal[] getBigDecimalAM()
  {
    return bigDecimalAM;
  }



  /**
   * Sets the value of the bigDecimalAM field.
   *
   * @param  bigDecimalAM  The value to use for the bigDecimalAM field.
   */
  @LDAPSetter(attribute="bigDecimalAM")
  public void setBigDecimalAM(final BigDecimal[] bigDecimalAM)
  {
    this.bigDecimalAM = bigDecimalAM;
  }



  /**
   * Retrieves the value of the bigIntegerF field.
   *
   * @return  The value of the bigIntegerF field.
   */
  public BigInteger getBigIntegerF()
  {
    return bigIntegerF;
  }



  /**
   * Sets the value of the bigIntegerF field.
   *
   * @param  bigIntegerF  The value to use for the bigIntegerF field.
   */
  public void setBigIntegerF(final BigInteger bigIntegerF)
  {
    this.bigIntegerF = bigIntegerF;
  }



  /**
   * Retrieves the value of the bigIntegerAF field.
   *
   * @return  The value of the bigIntegerAF field.
   */
  public BigInteger[] getBigIntegerAF()
  {
    return bigIntegerAF;
  }



  /**
   * Sets the value of the bigIntegerAF field.
   *
   * @param  bigIntegerAF  The value to use for the bigIntegerAF field.
   */
  public void setBigIntegerAF(final BigInteger[] bigIntegerAF)
  {
    this.bigIntegerAF = bigIntegerAF;
  }



  /**
   * Retrieves the value of the bigIntegerM field.
   *
   * @return  The value of the bigIntegerM field.
   */
  @LDAPGetter(attribute="bigIntegerM")
  public BigInteger getBigIntegerM()
  {
    return bigIntegerM;
  }



  /**
   * Sets the value of the bigIntegerM field.
   *
   * @param  bigIntegerM  The value to use for the bigIntegerM field.
   */
  @LDAPSetter(attribute="bigIntegerM")
  public void setBigIntegerM(final BigInteger bigIntegerM)
  {
    this.bigIntegerM = bigIntegerM;
  }



  /**
   * Retrieves the value of the bigIntegerAM field.
   *
   * @return  The value of the bigIntegerAM field.
   */
  @LDAPGetter(attribute="bigIntegerAM")
  public BigInteger[] getBigIntegerAM()
  {
    return bigIntegerAM;
  }



  /**
   * Sets the value of the bigIntegerAM field.
   *
   * @param  bigIntegerAM  The value to use for the bigIntegerAM field.
   */
  @LDAPSetter(attribute="bigIntegerAM")
  public void setBigIntegerAM(final BigInteger[] bigIntegerAM)
  {
    this.bigIntegerAM = bigIntegerAM;
  }



  /**
   * Retrieves the value of the booleanPF field.
   *
   * @return  The value of the booleanPF field.
   */
  public boolean getBooleanPF()
  {
    return booleanPF;
  }



  /**
   * Sets the value of the booleanPF field.
   *
   * @param  booleanPF  The value to use for the booleanPF field.
   */
  public void setBooleanPF(final boolean booleanPF)
  {
    this.booleanPF = booleanPF;
  }



  /**
   * Retrieves the value of the booleanPAF field.
   *
   * @return  The value of the booleanPAF field.
   */
  public boolean[] getBooleanPAF()
  {
    return booleanPAF;
  }



  /**
   * Sets the value of the booleanPAF field.
   *
   * @param  booleanPAF  The value to use for the booleanPAF field.
   */
  public void setBooleanPAF(final boolean[] booleanPAF)
  {
    this.booleanPAF = booleanPAF;
  }



  /**
   * Retrieves the value of the booleanPM field.
   *
   * @return  The value of the booleanPM field.
   */
  @LDAPGetter(attribute="booleanPM")
  public boolean getBooleanPM()
  {
    return booleanPM;
  }



  /**
   * Sets the value of the booleanPM field.
   *
   * @param  booleanPM  The value to use for the booleanOM field.
   */
  @LDAPSetter(attribute="booleanPM")
  public void setBooleanPM(final boolean booleanPM)
  {
    this.booleanPM = booleanPM;
  }



  /**
   * Retrieves the value of the booleanPAM field.
   *
   * @return  The value of the booleanPAM field.
   */
  @LDAPGetter(attribute="booleanPAM")
  public boolean[] getBooleanPAM()
  {
    return booleanPAM;
  }



  /**
   * Sets the value of the booleanPAM field.
   *
   * @param  booleanPAM  The value to use for the booleanPAM field.
   */
  @LDAPSetter(attribute="booleanPAM")
  public void setBooleanPAM(final boolean[] booleanPAM)
  {
    this.booleanPAM = booleanPAM;
  }



  /**
   * Retrieves the value of the booleanOF field.
   *
   * @return  The value of the booleanOF field.
   */
  public Boolean getBooleanOF()
  {
    return booleanOF;
  }



  /**
   * Sets the value of the booleanOF field.
   *
   * @param  booleanOF  The value to use for the booleanOF field.
   */
  public void setBooleanOF(final Boolean booleanOF)
  {
    this.booleanOF = booleanOF;
  }



  /**
   * Retrieves the value of the booleanOAF field.
   *
   * @return  The value of the booleanOAF field.
   */
  public Boolean[] getBooleanOAF()
  {
    return booleanOAF;
  }



  /**
   * Sets the value of the booleanOAF field.
   *
   * @param  booleanOAF  The value to use for the booleanOAF field.
   */
  public void setBooleanOAF(final Boolean[] booleanOAF)
  {
    this.booleanOAF = booleanOAF;
  }



  /**
   * Retrieves the value of the booleanOM field.
   *
   * @return  The value of the booleanOM field.
   */
  @LDAPGetter(attribute="booleanOM")
  public Boolean getBooleanOM()
  {
    return booleanOM;
  }



  /**
   * Sets the value of the booleanOM field.
   *
   * @param  booleanOM  The value to use for the booleanOM field.
   */
  @LDAPSetter(attribute="booleanOM")
  public void setBooleanOM(final Boolean booleanOM)
  {
    this.booleanOM = booleanOM;
  }



  /**
   * Retrieves the value of the booleanOAM field.
   *
   * @return  The value of the booleanOAM field.
   */
  @LDAPGetter(attribute="booleanOAM")
  public Boolean[] getBooleanOAM()
  {
    return booleanOAM;
  }



  /**
   * Sets the value of the booleanOAM field.
   *
   * @param  booleanOAM  The value to use for the booleanOAM field.
   */
  @LDAPSetter(attribute="booleanOAM")
  public void setBooleanOAM(final Boolean[] booleanOAM)
  {
    this.booleanOAM = booleanOAM;
  }



  /**
   * Retrieves the value of the bytePAF field.
   *
   * @return  The value of the bytePAF field.
   */
  public byte[] getBytePAF()
  {
    return bytePAF;
  }



  /**
   * Sets the value of the bytePAF field.
   *
   * @param  bytePAF  The value to use for the bytePAF field.
   */
  public void setBytePAF(final byte[] bytePAF)
  {
    this.bytePAF = bytePAF;
  }



  /**
   * Retrieves the value of the bytePAAF field.
   *
   * @return  The value of the bytePAAF field.
   */
  public byte[][] getBytePAAF()
  {
    return bytePAAF;
  }



  /**
   * Sets the value of the bytePAAF field.
   *
   * @param  bytePAAF  The value to use for the bytePAAF field.
   */
  public void setBytePAAF(final byte[][] bytePAAF)
  {
    this.bytePAAF = bytePAAF;
  }



  /**
   * Retrieves the value of the bytePAM field.
   *
   * @return  The value of the bytePAM field.
   */
  @LDAPGetter(attribute="bytePAM")
  public byte[] getBytePAM()
  {
    return bytePAM;
  }



  /**
   * Sets the value of the bytePAM field.
   *
   * @param  bytePAM  The value to use for the bytePAM field.
   */
  @LDAPSetter(attribute="bytePAM")
  public void setBytePAM(final byte[] bytePAM)
  {
    this.bytePAM = bytePAM;
  }



  /**
   * Retrieves the value of the bytePAAM field.
   *
   * @return  The value of the bytePAAM field.
   */
  @LDAPGetter(attribute="bytePAAM")
  public byte[][] getBytePAAM()
  {
    return bytePAAM;
  }



  /**
   * Sets the value of the bytePAAM field.
   *
   * @param  bytePAAM  The value to use for the bytePAAM field.
   */
  @LDAPSetter(attribute="bytePAAM")
  public void setBytePAAM(final byte[][] bytePAAM)
  {
    this.bytePAAM = bytePAAM;
  }



  /**
   * Retrieves the value of the charPAF field.
   *
   * @return  The value of the charPAF field.
   */
  public char[] getCharPAF()
  {
    return charPAF;
  }



  /**
   * Sets the value of the charPAF field.
   *
   * @param  charPAF  The value to use for the charPAF field.
   */
  public void setCharPAF(final char[] charPAF)
  {
    this.charPAF = charPAF;
  }



  /**
   * Retrieves the value of the charPAAF field.
   *
   * @return  The value of the charPAAF field.
   */
  public char[][] getCharPAAF()
  {
    return charPAAF;
  }



  /**
   * Sets the value of the charPAAF field.
   *
   * @param  charPAAF  The value to use for the charPAAF field.
   */
  public void setCharPAAF(final char[][] charPAAF)
  {
    this.charPAAF = charPAAF;
  }



  /**
   * Retrieves the value of the charPAM field.
   *
   * @return  The value of the charPAM field.
   */
  @LDAPGetter(attribute="charPAM")
  public char[] getCharPAM()
  {
    return charPAM;
  }



  /**
   * Sets the value of the charPAM field.
   *
   * @param  charPAM  The value to use for the charPAM field.
   */
  @LDAPSetter(attribute="charPAM")
  public void setCharPAM(final char[] charPAM)
  {
    this.charPAM = charPAM;
  }



  /**
   * Retrieves the value of the charPAAM field.
   *
   * @return  The value of the charPAAM field.
   */
  @LDAPGetter(attribute="charPAAM")
  public char[][] getCharPAAM()
  {
    return charPAAM;
  }



  /**
   * Sets the value of the charPAAM field.
   *
   * @param  charPAAM  The value to use for the charPAAM field.
   */
  @LDAPSetter(attribute="charPAAM")
  public void setCharPAAM(final char[][] charPAAM)
  {
    this.charPAAM = charPAAM;
  }



  /**
   * Retrieves the value of the dateF field.
   *
   * @return  The value of the dateF field.
   */
  public Date getDateF()
  {
    return dateF;
  }



  /**
   * Sets the value of the dateF field.
   *
   * @param  dateF  The value to use for the dateF field.
   */
  public void setDateF(final Date dateF)
  {
    this.dateF = dateF;
  }



  /**
   * Retrieves the value of the dateAF field.
   *
   * @return  The value of the dateAF field.
   */
  public Date[] getDateAF()
  {
    return dateAF;
  }



  /**
   * Sets the value of the dateAF field.
   *
   * @param  dateAF  The value to use for the dateAF field.
   */
  public void setDateAF(final Date[] dateAF)
  {
    this.dateAF = dateAF;
  }



  /**
   * Retrieves the value of the dateM field.
   *
   * @return  The value of the dateM field.
   */
  @LDAPGetter(attribute="dateM")
  public Date getDateM()
  {
    return dateM;
  }



  /**
   * Sets the value of the dateM field.
   *
   * @param  dateM  The value to use for the dateM field.
   */
  @LDAPSetter(attribute="dateM")
  public void setDateM(final Date dateM)
  {
    this.dateM = dateM;
  }



  /**
   * Retrieves the value of the dateAM field.
   *
   * @return  The value of the dateAM field.
   */
  @LDAPGetter(attribute="dateAM")
  public Date[] getDateAM()
  {
    return dateAM;
  }



  /**
   * Sets the value of the dateAM field.
   *
   * @param  dateAM  The value to use for the dateAM field.
   */
  @LDAPSetter(attribute="dateAM")
  public void setDateAM(final Date[] dateAM)
  {
    this.dateAM = dateAM;
  }



  /**
   * Retrieves the value of the dnF field.
   *
   * @return  The value of the dnF field.
   */
  public DN getDNF()
  {
    return dnF;
  }



  /**
   * Sets the value of the dnF field.
   *
   * @param  dnF  The value to use for the dnF field.
   */
  public void setDNF(final DN dnF)
  {
    this.dnF = dnF;
  }



  /**
   * Retrieves the value of the dnAF field.
   *
   * @return  The value of the dnAF field.
   */
  public DN[] getDNAF()
  {
    return dnAF;
  }



  /**
   * Sets the value of the dnAF field.
   *
   * @param  dnAF  The value to use for the dnAF field.
   */
  public void setDNAF(final DN[] dnAF)
  {
    this.dnAF = dnAF;
  }



  /**
   * Retrieves the value of the dnM field.
   *
   * @return  The value of the dnM field.
   */
  @LDAPGetter(attribute="dnM")
  public DN getDNM()
  {
    return dnM;
  }



  /**
   * Sets the value of the dnM field.
   *
   * @param  dnM  The value to use for the dnM field.
   */
  @LDAPSetter(attribute="dnM")
  public void setDNM(final DN dnM)
  {
    this.dnM = dnM;
  }



  /**
   * Retrieves the value of the dnAM field.
   *
   * @return  The value of the dnAM field.
   */
  @LDAPGetter(attribute="dnAM")
  public DN[] getDNAM()
  {
    return dnAM;
  }



  /**
   * Sets the value of the dnAM field.
   *
   * @param  dnAM  The value to use for the dnAM field.
   */
  @LDAPSetter(attribute="dnAM")
  public void setDNAM(final DN[] dnAM)
  {
    this.dnAM = dnAM;
  }



  /**
   * Retrieves the value of the doublePF field.
   *
   * @return  The value of the doublePF field.
   */
  public double getDoublePF()
  {
    return doublePF;
  }



  /**
   * Sets the value of the doublePF field.
   *
   * @param  doublePF  The value to use for the doublePF field.
   */
  public void setDoublePF(final double doublePF)
  {
    this.doublePF = doublePF;
  }



  /**
   * Retrieves the value of the doublePAF field.
   *
   * @return  The value of the doublePAF field.
   */
  public double[] getDoublePAF()
  {
    return doublePAF;
  }



  /**
   * Sets the value of the doublePAF field.
   *
   * @param  doublePAF  The value to use for the doublePAF field.
   */
  public void setDoublePAF(final double[] doublePAF)
  {
    this.doublePAF = doublePAF;
  }



  /**
   * Retrieves the value of the doublePM field.
   *
   * @return  The value of the doublePM field.
   */
  @LDAPGetter(attribute="doublePM")
  public double getDoublePM()
  {
    return doublePM;
  }



  /**
   * Sets the value of the doublePM field.
   *
   * @param  doublePM  The value to use for the doublePM field.
   */
  @LDAPSetter(attribute="doublePM")
  public void setDoublePM(final double doublePM)
  {
    this.doublePM = doublePM;
  }



  /**
   * Retrieves the value of the doublePAM field.
   *
   * @return  The value of the doublePAM field.
   */
  @LDAPGetter(attribute="doublePAM")
  public double[] getDoublePAM()
  {
    return doublePAM;
  }



  /**
   * Sets the value of the doublePAM field.
   *
   * @param  doublePAM  The value to use for the doublePAM field.
   */
  @LDAPSetter(attribute="doublePAM")
  public void setDoublePAM(final double[] doublePAM)
  {
    this.doublePAM = doublePAM;
  }



  /**
   * Retrieves the value of the doubleOF field.
   *
   * @return  The value of the doubleOF field.
   */
  public Double getDoubleOF()
  {
    return doubleOF;
  }



  /**
   * Sets the value of the doubleOF field.
   *
   * @param  doubleOF  The value to use for the doubleOF field.
   */
  public void setDoubleOF(final Double doubleOF)
  {
    this.doubleOF = doubleOF;
  }



  /**
   * Retrieves the value of the doubleOAF field.
   *
   * @return  The value of the doubleOAF field.
   */
  public Double[] getDoubleOAF()
  {
    return doubleOAF;
  }



  /**
   * Sets the value of the doubleOAF field.
   *
   * @param  doubleOAF  The value to use for the doubleOAF field.
   */
  public void setDoubleOAF(final Double[] doubleOAF)
  {
    this.doubleOAF = doubleOAF;
  }



  /**
   * Retrieves the value of the doubleOM field.
   *
   * @return  The value of the doubleOM field.
   */
  @LDAPGetter(attribute="doubleOM")
  public Double getDoubleOM()
  {
    return doubleOM;
  }



  /**
   * Sets the value of the doubleOM field.
   *
   * @param  doubleOM  The value to use for the doubleOM field.
   */
  @LDAPSetter(attribute="doubleOM")
  public void setDoubleOM(final Double doubleOM)
  {
    this.doubleOM = doubleOM;
  }



  /**
   * Retrieves the value of the doubleOAM field.
   *
   * @return  The value of the doubleOAM field.
   */
  @LDAPGetter(attribute="doubleOAM")
  public Double[] getDoubleOAM()
  {
    return doubleOAM;
  }



  /**
   * Sets the value of the doubleOAM field.
   *
   * @param  doubleOAM  The value to use for the doubleOAM field.
   */
  @LDAPSetter(attribute="doubleOAM")
  public void setDoubleOAM(final Double[] doubleOAM)
  {
    this.doubleOAM = doubleOAM;
  }



  /**
   * Retrieves the value of the filterF field.
   *
   * @return  The value of the filterF field.
   */
  public Filter getFilterF()
  {
    return filterF;
  }



  /**
   * Sets the value of the filterF field.
   *
   * @param  filterF  The value to use for the filterF field.
   */
  public void setFilterF(final Filter filterF)
  {
    this.filterF = filterF;
  }



  /**
   * Retrieves the value of the filterAF field.
   *
   * @return  The value of the filterAF field.
   */
  public Filter[] getFilterAF()
  {
    return filterAF;
  }



  /**
   * Sets the value of the filterAF field.
   *
   * @param  filterAF  The value to use for the filterAF field.
   */
  public void setFilterAF(final Filter[] filterAF)
  {
    this.filterAF = filterAF;
  }



  /**
   * Retrieves the value of the filterM field.
   *
   * @return  The value of the filterM field.
   */
  @LDAPGetter(attribute="filterM")
  public Filter getFilterM()
  {
    return filterM;
  }



  /**
   * Sets the value of the filterM field.
   *
   * @param  filterM  The value to use for the filterM field.
   */
  @LDAPSetter(attribute="filterM")
  public void setFilterM(final Filter filterM)
  {
    this.filterM = filterM;
  }



  /**
   * Retrieves the value of the filterAM field.
   *
   * @return  The value of the filterAM field.
   */
  @LDAPGetter(attribute="filterAM")
  public Filter[] getFilterAM()
  {
    return filterAM;
  }



  /**
   * Sets the value of the filterAM field.
   *
   * @param  filterAM  The value to use for the filterAM field.
   */
  @LDAPSetter(attribute="filterAM")
  public void setFilterAM(final Filter[] filterAM)
  {
    this.filterAM = filterAM;
  }



  /**
   * Retrieves the value of the filterUsageF field.
   *
   * @return  The value of the filterUsageF field.
   */
  public FilterUsage getFilterUsageF()
  {
    return filterUsageF;
  }



  /**
   * Sets the value of the filterUsageF field.
   *
   * @param  filterUsageF  The value to use for the filterUsageF field.
   */
  public void setFilterUsageF(final FilterUsage filterUsageF)
  {
    this.filterUsageF = filterUsageF;
  }



  /**
   * Retrieves the value of the filterUsageAF field.
   *
   * @return  The value of the filterUsageAF field.
   */
  public FilterUsage[] getFilterUsageAF()
  {
    return filterUsageAF;
  }



  /**
   * Sets the value of the filterUsageAF field.
   *
   * @param  filterUsageAF  The value to use for the filterUsageAF field.
   */
  public void setFilterUsageAF(final FilterUsage[] filterUsageAF)
  {
    this.filterUsageAF = filterUsageAF;
  }



  /**
   * Retrieves the value of the filterUsageM field.
   *
   * @return  The value of the filterUsageM field.
   */
  @LDAPGetter(attribute="filterUsageM")
  public FilterUsage getFilterUsageM()
  {
    return filterUsageM;
  }



  /**
   * Sets the value of the filterUsageM field.
   *
   * @param  filterUsageM  The value to use for the filterUsageM field.
   */
  @LDAPSetter(attribute="filterUsageM")
  public void setFilterUsageM(final FilterUsage filterUsageM)
  {
    this.filterUsageM = filterUsageM;
  }



  /**
   * Retrieves the value of the filterUsageAM field.
   *
   * @return  The value of the filterUsageAM field.
   */
  @LDAPGetter(attribute="filterUsageAM")
  public FilterUsage[] getFilterUsageAM()
  {
    return filterUsageAM;
  }



  /**
   * Sets the value of the filterUsageAM field.
   *
   * @param  filterUsageAM  The value to use for the filterUsageAM field.
   */
  @LDAPSetter(attribute="filterUsageAM")
  public void setFilterUsageAM(final FilterUsage[] filterUsageAM)
  {
    this.filterUsageAM = filterUsageAM;
  }



  /**
   * Retrieves the value of the floatPF field.
   *
   * @return  The value of the floatPF field.
   */
  public float getFloatPF()
  {
    return floatPF;
  }



  /**
   * Sets the value of the floatPF field.
   *
   * @param  floatPF  The value to use for the floatPF field.
   */
  public void setFloatPF(final float floatPF)
  {
    this.floatPF = floatPF;
  }



  /**
   * Retrieves the value of the floatPAF field.
   *
   * @return  The value of the floatPAF field.
   */
  public float[] getFloatPAF()
  {
    return floatPAF;
  }



  /**
   * Sets the value of the floatPAF field.
   *
   * @param  floatPAF  The value to use for the floatPAF field.
   */
  public void setFloatPAF(final float[] floatPAF)
  {
    this.floatPAF = floatPAF;
  }



  /**
   * Retrieves the value of the floatPM field.
   *
   * @return  The value of the floatPM field.
   */
  @LDAPGetter(attribute="floatPM")
  public float getFloatPM()
  {
    return floatPM;
  }



  /**
   * Sets the value of the floatPM field.
   *
   * @param  floatPM  The value to use for the floatPM field.
   */
  @LDAPSetter(attribute="floatPM")
  public void setFloatPM(final float floatPM)
  {
    this.floatPM = floatPM;
  }



  /**
   * Retrieves the value of the floatPAM field.
   *
   * @return  The value of the floatPAM field.
   */
  @LDAPGetter(attribute="floatPAM")
  public float[] getFloatPAM()
  {
    return floatPAM;
  }



  /**
   * Sets the value of the floatPAM field.
   *
   * @param  floatPAM  The value to use for the floatPAM field.
   */
  @LDAPSetter(attribute="floatPAM")
  public void setFloatPAM(final float[] floatPAM)
  {
    this.floatPAM = floatPAM;
  }



  /**
   * Retrieves the value of the floatOF field.
   *
   * @return  The value of the floatOF field.
   */
  public Float getFloatOF()
  {
    return floatOF;
  }



  /**
   * Sets the value of the floatOF field.
   *
   * @param  floatOF  The value to use for the floatOF field.
   */
  public void setFloatOF(final Float floatOF)
  {
    this.floatOF = floatOF;
  }



  /**
   * Retrieves the value of the floatOAF field.
   *
   * @return  The value of the floatOAF field.
   */
  public Float[] getFloatOAF()
  {
    return floatOAF;
  }



  /**
   * Sets the value of the floatOAF field.
   *
   * @param  floatOAF  The value to use for the floatOAF field.
   */
  public void setFloatOAF(final Float[] floatOAF)
  {
    this.floatOAF = floatOAF;
  }



  /**
   * Retrieves the value of the floatOM field.
   *
   * @return  The value of the floatOM field.
   */
  @LDAPGetter(attribute="floatOM")
  public Float getFloatOM()
  {
    return floatOM;
  }



  /**
   * Sets the value of the floatOM field.
   *
   * @param  floatOM  The value to use for the floatOM field.
   */
  @LDAPSetter(attribute="floatOM")
  public void setFloatOM(final Float floatOM)
  {
    this.floatOM = floatOM;
  }



  /**
   * Retrieves the value of the floatOAM field.
   *
   * @return  The value of the floatOAM field.
   */
  @LDAPGetter(attribute="floatOAM")
  public Float[] getFloatOAM()
  {
    return floatOAM;
  }



  /**
   * Sets the value of the floatOAM field.
   *
   * @param  floatOAM  The value to use for the floatOAM field.
   */
  @LDAPSetter(attribute="floatOAM")
  public void setFloatOAM(final Float[] floatOAM)
  {
    this.floatOAM = floatOAM;
  }



  /**
   * Retrieves the value of the intPF field.
   *
   * @return  The value of the intPF field.
   */
  public int getIntPF()
  {
    return intPF;
  }



  /**
   * Sets the value of the intPF field.
   *
   * @param  intPF  The value to use for the intPF field.
   */
  public void setIntPF(final int intPF)
  {
    this.intPF = intPF;
  }



  /**
   * Retrieves the value of the intPAF field.
   *
   * @return  The value of the intPAF field.
   */
  public int[] getIntPAF()
  {
    return intPAF;
  }



  /**
   * Sets the value of the intPAF field.
   *
   * @param  intPAF  The value to use for the intPAF field.
   */
  public void setIntPAF(final int[] intPAF)
  {
    this.intPAF = intPAF;
  }



  /**
   * Retrieves the value of the intPM field.
   *
   * @return  The value of the intPM field.
   */
  @LDAPGetter(attribute="intPM")
  public int getIntPM()
  {
    return intPM;
  }



  /**
   * Sets the value of the intPM field.
   *
   * @param  intPM  The value to use for the intPM field.
   */
  @LDAPSetter(attribute="intPM")
  public void setIntPM(final int intPM)
  {
    this.intPM = intPM;
  }



  /**
   * Retrieves the value of the intPAM field.
   *
   * @return  The value of the intPAM field.
   */
  @LDAPGetter(attribute="intPAM")
  public int[] getIntPAM()
  {
    return intPAM;
  }



  /**
   * Sets the value of the intPAM field.
   *
   * @param  intPAM  The value to use for the intPAM field.
   */
  @LDAPSetter(attribute="intPAM")
  public void setIntPAM(final int[] intPAM)
  {
    this.intPAM = intPAM;
  }



  /**
   * Retrieves the value of the intOF field.
   *
   * @return  The value of the intOF field.
   */
  public Integer getIntOF()
  {
    return intOF;
  }



  /**
   * Sets the value of the intOF field.
   *
   * @param  intOF  The value to use for the intOF field.
   */
  public void setIntOF(final Integer intOF)
  {
    this.intOF = intOF;
  }



  /**
   * Retrieves the value of the intOAF field.
   *
   * @return  The value of the intOAF field.
   */
  public Integer[] getIntOAF()
  {
    return intOAF;
  }



  /**
   * Sets the value of the intOAF field.
   *
   * @param  intOAF  The value to use for the intOAF field.
   */
  public void setIntOAF(final Integer[] intOAF)
  {
    this.intOAF = intOAF;
  }



  /**
   * Retrieves the value of the intOM field.
   *
   * @return  The value of the intOM field.
   */
  @LDAPGetter(attribute="intOM")
  public Integer getIntOM()
  {
    return intOM;
  }



  /**
   * Sets the value of the intOM field.
   *
   * @param  intOM  The value to use for the intOM field.
   */
  @LDAPSetter(attribute="intOM")
  public void setIntOM(final Integer intOM)
  {
    this.intOM = intOM;
  }



  /**
   * Retrieves the value of the intOAM field.
   *
   * @return  The value of the intOAM field.
   */
  @LDAPGetter(attribute="intOAM")
  public Integer[] getIntOAM()
  {
    return intOAM;
  }



  /**
   * Sets the value of the intOAM field.
   *
   * @param  intOAM  The value to use for the intOAM field.
   */
  @LDAPSetter(attribute="intOAM")
  public void setIntOAM(final Integer[] intOAM)
  {
    this.intOAM = intOAM;
  }



  /**
   * Retrieves the value of the ldapURLF field.
   *
   * @return  The value of the ldapURLF field.
   */
  public LDAPURL getLDAPURLF()
  {
    return ldapURLF;
  }



  /**
   * Sets the value of the ldapURLF field.
   *
   * @param  ldapURLF  The value to use for the ldapURLF field.
   */
  public void setLDAPURLF(final LDAPURL ldapURLF)
  {
    this.ldapURLF = ldapURLF;
  }



  /**
   * Retrieves the value of the ldapURLAF field.
   *
   * @return  The value of the ldapURLAF field.
   */
  public LDAPURL[] getLDAPURLAF()
  {
    return ldapURLAF;
  }



  /**
   * Sets the value of the ldapURLAF field.
   *
   * @param  ldapURLAF  The value to use for the ldapURLAF field.
   */
  public void setLDAPURLAF(final LDAPURL[] ldapURLAF)
  {
    this.ldapURLAF = ldapURLAF;
  }



  /**
   * Retrieves the value of the ldapURLM field.
   *
   * @return  The value of the ldapURLM field.
   */
  @LDAPGetter(attribute="ldapURLM")
  public LDAPURL getLDAPURLM()
  {
    return ldapURLM;
  }



  /**
   * Sets the value of the ldapURLM field.
   *
   * @param  ldapURLM  The value to use for the ldapURLM field.
   */
  @LDAPSetter(attribute="ldapURLM")
  public void setLDAPURLM(final LDAPURL ldapURLM)
  {
    this.ldapURLM = ldapURLM;
  }



  /**
   * Retrieves the value of the ldapURLAM field.
   *
   * @return  The value of the ldapURLAM field.
   */
  @LDAPGetter(attribute="ldapURLAM")
  public LDAPURL[] getLDAPURLAM()
  {
    return ldapURLAM;
  }



  /**
   * Sets the value of the ldapURLAM field.
   *
   * @param  ldapURLAM  The value to use for the ldapURLAM field.
   */
  @LDAPSetter(attribute="ldapURLAM")
  public void setLDAPURLAM(final LDAPURL[] ldapURLAM)
  {
    this.ldapURLAM = ldapURLAM;
  }



  /**
   * Retrieves the value of the longPF field.
   *
   * @return  The value of the longPF field.
   */
  public long getLongPF()
  {
    return longPF;
  }



  /**
   * Sets the value of the longPF field.
   *
   * @param  longPF  The value to use for the longPF field.
   */
  public void setLongPF(final long longPF)
  {
    this.longPF = longPF;
  }



  /**
   * Retrieves the value of the longPAF field.
   *
   * @return  The value of the longPAF field.
   */
  public long[] getLongPAF()
  {
    return longPAF;
  }



  /**
   * Sets the value of the longPAF field.
   *
   * @param  longPAF  The value to use for the longPAF field.
   */
  public void setLongPAF(final long[] longPAF)
  {
    this.longPAF = longPAF;
  }



  /**
   * Retrieves the value of the longPM field.
   *
   * @return  The value of the longPM field.
   */
  @LDAPGetter(attribute="longPM")
  public long getLongPM()
  {
    return longPM;
  }



  /**
   * Sets the value of the longPM field.
   *
   * @param  longPM  The value to use for the longPM field.
   */
  @LDAPSetter(attribute="longPM")
  public void setLongPM(final long longPM)
  {
    this.longPM = longPM;
  }



  /**
   * Retrieves the value of the longPAM field.
   *
   * @return  The value of the longPAM field.
   */
  @LDAPGetter(attribute="longPAM")
  public long[] getLongPAM()
  {
    return longPAM;
  }



  /**
   * Sets the value of the longPAM field.
   *
   * @param  longPAM  The value to use for the longPAM field.
   */
  @LDAPSetter(attribute="longPAM")
  public void setLongPAM(final long[] longPAM)
  {
    this.longPAM = longPAM;
  }



  /**
   * Retrieves the value of the longOF field.
   *
   * @return  The value of the longOF field.
   */
  public Long getLongOF()
  {
    return longOF;
  }



  /**
   * Sets the value of the longOF field.
   *
   * @param  longOF  The value to use for the longOF field.
   */
  public void setLongOF(final Long longOF)
  {
    this.longOF = longOF;
  }



  /**
   * Retrieves the value of the longOAF field.
   *
   * @return  The value of the longOAF field.
   */
  public Long[] getLongOAF()
  {
    return longOAF;
  }



  /**
   * Sets the value of the longOAF field.
   *
   * @param  longOAF  The value to use for the longOAF field.
   */
  public void setLongOAF(final Long[] longOAF)
  {
    this.longOAF = longOAF;
  }



  /**
   * Retrieves the value of the longOM field.
   *
   * @return  The value of the longOM field.
   */
  @LDAPGetter(attribute="longOM")
  public Long getLongOM()
  {
    return longOM;
  }



  /**
   * Sets the value of the longOM field.
   *
   * @param  longOM  The value to use for the longOM field.
   */
  @LDAPSetter(attribute="longOM")
  public void setLongOM(final Long longOM)
  {
    this.longOM = longOM;
  }



  /**
   * Retrieves the value of the longOAM field.
   *
   * @return  The value of the longOAM field.
   */
  @LDAPGetter(attribute="longOAM")
  public Long[] getLongOAM()
  {
    return longOAM;
  }



  /**
   * Sets the value of the longOAM field.
   *
   * @param  longOAM  The value to use for the longOAM field.
   */
  @LDAPSetter(attribute="longOAM")
  public void setLongOAM(final Long[] longOAM)
  {
    this.longOAM = longOAM;
  }



  /**
   * Retrieves the value of the rdnF field.
   *
   * @return  The value of the rdnF field.
   */
  public RDN getRDNF()
  {
    return rdnF;
  }



  /**
   * Sets the value of the rdnF field.
   *
   * @param  rdnF  The value to use for the rdnF field.
   */
  public void setRDNF(final RDN rdnF)
  {
    this.rdnF = rdnF;
  }



  /**
   * Retrieves the value of the rdnAF field.
   *
   * @return  The value of the rdnAF field.
   */
  public RDN[] getRDNAF()
  {
    return rdnAF;
  }



  /**
   * Sets the value of the rdnAF field.
   *
   * @param  rdnAF  The value to use for the rdnAF field.
   */
  public void setRDNAF(final RDN[] rdnAF)
  {
    this.rdnAF = rdnAF;
  }



  /**
   * Retrieves the value of the rdnM field.
   *
   * @return  The value of the rdnM field.
   */
  @LDAPGetter(attribute="rdnM")
  public RDN getRDNM()
  {
    return rdnM;
  }



  /**
   * Sets the value of the rdnM field.
   *
   * @param  rdnM  The value to use for the rdnM field.
   */
  @LDAPSetter(attribute="rdnM")
  public void setRDNM(final RDN rdnM)
  {
    this.rdnM = rdnM;
  }



  /**
   * Retrieves the value of the rdnAM field.
   *
   * @return  The value of the rdnAM field.
   */
  @LDAPGetter(attribute="rdnAM")
  public RDN[] getRDNAM()
  {
    return rdnAM;
  }



  /**
   * Sets the value of the rdnAM field.
   *
   * @param  rdnAM  The value to use for the rdnAM field.
   */
  @LDAPSetter(attribute="rdnAM")
  public void setRDNAM(final RDN[] rdnAM)
  {
    this.rdnAM = rdnAM;
  }



  /**
   * Retrieves the value of the shortPF field.
   *
   * @return  The value of the shortPF field.
   */
  public short getShortPF()
  {
    return shortPF;
  }



  /**
   * Sets the value of the shortPF field.
   *
   * @param  shortPF  The value to use for the shortPF field.
   */
  public void setShortPF(final short shortPF)
  {
    this.shortPF = shortPF;
  }



  /**
   * Retrieves the value of the shortPAF field.
   *
   * @return  The value of the shortPAF field.
   */
  public short[] getShortPAF()
  {
    return shortPAF;
  }



  /**
   * Sets the value of the shortPAF field.
   *
   * @param  shortPAF  The value to use for the shortPAF field.
   */
  public void setShortPAF(final short[] shortPAF)
  {
    this.shortPAF = shortPAF;
  }



  /**
   * Retrieves the value of the shortPM field.
   *
   * @return  The value of the shortPM field.
   */
  @LDAPGetter(attribute="shortPM")
  public short getShortPM()
  {
    return shortPM;
  }



  /**
   * Sets the value of the shortPM field.
   *
   * @param  shortPM  The value to use for the shortPM field.
   */
  @LDAPSetter(attribute="shortPM")
  public void setShortPM(final short shortPM)
  {
    this.shortPM = shortPM;
  }



  /**
   * Retrieves the value of the shortPAM field.
   *
   * @return  The value of the shortPAM field.
   */
  @LDAPGetter(attribute="shortPAM")
  public short[] getShortPAM()
  {
    return shortPAM;
  }



  /**
   * Sets the value of the shortPAM field.
   *
   * @param  shortPAM  The value to use for the shortPAM field.
   */
  @LDAPSetter(attribute="shortPAM")
  public void setShortPAM(final short[] shortPAM)
  {
    this.shortPAM = shortPAM;
  }



  /**
   * Retrieves the value of the shortOF field.
   *
   * @return  The value of the shortOF field.
   */
  public Short getShortOF()
  {
    return shortOF;
  }



  /**
   * Sets the value of the shortOF field.
   *
   * @param  shortOF  The value to use for the shortOF field.
   */
  public void setShortOF(final Short shortOF)
  {
    this.shortOF = shortOF;
  }



  /**
   * Retrieves the value of the shortOAF field.
   *
   * @return  The value of the shortOAF field.
   */
  public Short[] getShortOAF()
  {
    return shortOAF;
  }



  /**
   * Sets the value of the shortOAF field.
   *
   * @param  shortOAF  The value to use for the shortOAF field.
   */
  public void setShortOAF(final Short[] shortOAF)
  {
    this.shortOAF = shortOAF;
  }



  /**
   * Retrieves the value of the shortOM field.
   *
   * @return  The value of the shortOM field.
   */
  @LDAPGetter(attribute="shortOM")
  public Short getShortOM()
  {
    return shortOM;
  }



  /**
   * Sets the value of the shortOM field.
   *
   * @param  shortOM  The value to use for the shortOM field.
   */
  @LDAPSetter(attribute="shortOM")
  public void setShortOM(final Short shortOM)
  {
    this.shortOM = shortOM;
  }



  /**
   * Retrieves the value of the shortOAM field.
   *
   * @return  The value of the shortOAM field.
   */
  @LDAPGetter(attribute="shortOAM")
  public Short[] getShortOAM()
  {
    return shortOAM;
  }



  /**
   * Sets the value of the shortOAM field.
   *
   * @param  shortOAM  The value to use for the shortOAM field.
   */
  @LDAPSetter(attribute="shortOAM")
  public void setShortOAM(final Short[] shortOAM)
  {
    this.shortOAM = shortOAM;
  }



  /**
   * Retrieves the value of the stringF field.
   *
   * @return  The value of the stringF field.
   */
  public String getStringF()
  {
    return stringF;
  }



  /**
   * Sets the value of the stringF field.
   *
   * @param  stringF  The value to use for the stringF field.
   */
  public void setStringF(final String stringF)
  {
    this.stringF = stringF;
  }



  /**
   * Retrieves the value of the stringAF field.
   *
   * @return  The value of the stringAF field.
   */
  public String[] getStringAF()
  {
    return stringAF;
  }



  /**
   * Sets the value of the stringAF field.
   *
   * @param  stringAF  The value to use for the stringAF field.
   */
  public void setStringAF(final String[] stringAF)
  {
    this.stringAF = stringAF;
  }



  /**
   * Retrieves the value of the stringM field.
   *
   * @return  The value of the stringM field.
   */
  @LDAPGetter(attribute="stringM")
  public String getStringM()
  {
    return stringM;
  }



  /**
   * Sets the value of the stringM field.
   *
   * @param  stringM  The value to use for the stringM field.
   */
  @LDAPSetter(attribute="stringM")
  public void setStringM(final String stringM)
  {
    this.stringM = stringM;
  }



  /**
   * Retrieves the value of the stringAM field.
   *
   * @return  The value of the stringAM field.
   */
  @LDAPGetter(attribute="stringAM")
  public String[] getStringAM()
  {
    return stringAM;
  }



  /**
   * Sets the value of the stringAM field.
   *
   * @param  stringAM  The value to use for the stringAM field.
   */
  @LDAPSetter(attribute="stringAM")
  public void setStringAM(final String[] stringAM)
  {
    this.stringAM = stringAM;
  }



  /**
   * Retrieves the value of the stringBufferF field.
   *
   * @return  The value of the stringBufferF field.
   */
  public StringBuffer getStringBufferF()
  {
    return stringBufferF;
  }



  /**
   * Sets the value of the stringBufferF field.
   *
   * @param  stringBufferF  The value to use for the stringBufferF field.
   */
  public void setStringBufferF(final StringBuffer stringBufferF)
  {
    this.stringBufferF = stringBufferF;
  }



  /**
   * Retrieves the value of the stringBufferAF field.
   *
   * @return  The value of the stringBufferAF field.
   */
  public StringBuffer[] getStringBufferAF()
  {
    return stringBufferAF;
  }



  /**
   * Sets the value of the stringBufferAF field.
   *
   * @param  stringBufferAF  The value to use for the stringBufferAF field.
   */
  public void setStringBufferAF(final StringBuffer[] stringBufferAF)
  {
    this.stringBufferAF = stringBufferAF;
  }



  /**
   * Retrieves the value of the stringBufferM field.
   *
   * @return  The value of the stringBufferM field.
   */
  @LDAPGetter(attribute="stringBufferM")
  public StringBuffer getStringBufferM()
  {
    return stringBufferM;
  }



  /**
   * Sets the value of the stringBufferM field.
   *
   * @param  stringBufferM  The value to use for the stringBufferM field.
   */
  @LDAPSetter(attribute="stringBufferM")
  public void setStringBufferM(final StringBuffer stringBufferM)
  {
    this.stringBufferM = stringBufferM;
  }



  /**
   * Retrieves the value of the stringBufferAM field.
   *
   * @return  The value of the stringBufferAM field.
   */
  @LDAPGetter(attribute="stringBufferAM")
  public StringBuffer[] getStringBufferAM()
  {
    return stringBufferAM;
  }



  /**
   * Sets the value of the stringBufferAM field.
   *
   * @param  stringBufferAM  The value to use for the stringBufferAM field.
   */
  @LDAPSetter(attribute="stringBufferAM")
  public void setStringBufferAM(final StringBuffer[] stringBufferAM)
  {
    this.stringBufferAM = stringBufferAM;
  }



  /**
   * Retrieves the value of the stringBuilderF field.
   *
   * @return  The value of the stringBuilderF field.
   */
  public StringBuilder getStringBuilderF()
  {
    return stringBuilderF;
  }



  /**
   * Sets the value of the stringBuilderF field.
   *
   * @param  stringBuilderF  The value to use for the stringBuilderF field.
   */
  public void setStringBuilderF(final StringBuilder stringBuilderF)
  {
    this.stringBuilderF = stringBuilderF;
  }



  /**
   * Retrieves the value of the stringBuilderAF field.
   *
   * @return  The value of the stringBuilderAF field.
   */
  public StringBuilder[] getStringBuilderAF()
  {
    return stringBuilderAF;
  }



  /**
   * Sets the value of the stringBuilderAF field.
   *
   * @param  stringBuilderAF  The value to use for the stringBuilderAF field.
   */
  public void setStringBuilderAF(final StringBuilder[] stringBuilderAF)
  {
    this.stringBuilderAF = stringBuilderAF;
  }



  /**
   * Retrieves the value of the stringBuilderM field.
   *
   * @return  The value of the stringBuilderM field.
   */
  @LDAPGetter(attribute="stringBuilderM")
  public StringBuilder getStringBuilderM()
  {
    return stringBuilderM;
  }



  /**
   * Sets the value of the stringBuilderM field.
   *
   * @param  stringBuilderM  The value to use for the stringBuilderM field.
   */
  @LDAPSetter(attribute="stringBuilderM")
  public void setStringBuilderM(final StringBuilder stringBuilderM)
  {
    this.stringBuilderM = stringBuilderM;
  }



  /**
   * Retrieves the value of the stringBuilderAM field.
   *
   * @return  The value of the stringBuilderAM field.
   */
  @LDAPGetter(attribute="stringBuilderAM")
  public StringBuilder[] getStringBuilderAM()
  {
    return stringBuilderAM;
  }



  /**
   * Sets the value of the stringBuilderAM field.
   *
   * @param  stringBuilderAM  The value to use for the stringBuilderAM field.
   */
  @LDAPSetter(attribute="stringBuilderAM")
  public void setStringBuilderAM(final StringBuilder[] stringBuilderAM)
  {
    this.stringBuilderAM = stringBuilderAM;
  }



  /**
   * Retrieves the value of the uriF field.
   *
   * @return  The value of the uriF field.
   */
  public URI getURIF()
  {
    return uriF;
  }



  /**
   * Sets the value of the uriF field.
   *
   * @param  uriF  The value to use for the uriF field.
   */
  public void setURIF(final URI uriF)
  {
    this.uriF = uriF;
  }



  /**
   * Retrieves the value of the uriAF field.
   *
   * @return  The value of the uriAF field.
   */
  public URI[] getURIAF()
  {
    return uriAF;
  }



  /**
   * Sets the value of the uriAF field.
   *
   * @param  uriAF  The value to use for the uriAF field.
   */
  public void setURIAF(final URI[] uriAF)
  {
    this.uriAF = uriAF;
  }



  /**
   * Retrieves the value of the uriM field.
   *
   * @return  The value of the uriM field.
   */
  @LDAPGetter(attribute="uriM")
  public URI getURIM()
  {
    return uriM;
  }



  /**
   * Sets the value of the uriM field.
   *
   * @param  uriM  The value to use for the uriM field.
   */
  @LDAPSetter(attribute="uriM")
  public void setURIM(final URI uriM)
  {
    this.uriM = uriM;
  }



  /**
   * Retrieves the value of the uriAM field.
   *
   * @return  The value of the uriAM field.
   */
  @LDAPGetter(attribute="uriAM")
  public URI[] getURIAM()
  {
    return uriAM;
  }



  /**
   * Sets the value of the uriAM field.
   *
   * @param  uriAM  The value to use for the uriAM field.
   */
  @LDAPSetter(attribute="uriAM")
  public void setURIAM(final URI[] uriAM)
  {
    this.uriAM = uriAM;
  }



  /**
   * Retrieves the value of the urlF field.
   *
   * @return  The value of the urlF field.
   */
  public URL getURLF()
  {
    return urlF;
  }



  /**
   * Sets the value of the urlF field.
   *
   * @param  urlF  The value to use for the urlF field.
   */
  public void setURLF(final URL urlF)
  {
    this.urlF = urlF;
  }



  /**
   * Retrieves the value of the urlAF field.
   *
   * @return  The value of the urlAF field.
   */
  public URL[] getURLAF()
  {
    return urlAF;
  }



  /**
   * Sets the value of the urlAF field.
   *
   * @param  urlAF  The value to use for the urlAF field.
   */
  public void setURLAF(final URL[] urlAF)
  {
    this.urlAF = urlAF;
  }



  /**
   * Retrieves the value of the urlM field.
   *
   * @return  The value of the urlM field.
   */
  @LDAPGetter(attribute="urlM")
  public URL getURLM()
  {
    return urlM;
  }



  /**
   * Sets the value of the urlM field.
   *
   * @param  urlM  The value to use for the urlM field.
   */
  @LDAPSetter(attribute="urlM")
  public void setURLM(final URL urlM)
  {
    this.urlM = urlM;
  }



  /**
   * Retrieves the value of the urlAM field.
   *
   * @return  The value of the urlAM field.
   */
  @LDAPGetter(attribute="urlAM")
  public URL[] getURLAM()
  {
    return urlAM;
  }



  /**
   * Sets the value of the urlAM field.
   *
   * @param  urlAM  The value to use for the urlAM field.
   */
  @LDAPSetter(attribute="urlAM")
  public void setURLAM(final URL[] urlAM)
  {
    this.urlAM = urlAM;
  }



  /**
   * Retrieves the value of the uuidF field.
   *
   * @return  The value of the uuidF field.
   */
  public UUID getUUIDF()
  {
    return uuidF;
  }



  /**
   * Sets the value of the uuidF field.
   *
   * @param  uuidF  The value to use for the uuidF field.
   */
  public void setUUIDF(final UUID uuidF)
  {
    this.uuidF = uuidF;
  }



  /**
   * Retrieves the value of the uuidAF field.
   *
   * @return  The value of the uuidAF field.
   */
  public UUID[] getUUIDAF()
  {
    return uuidAF;
  }



  /**
   * Sets the value of the uuidAF field.
   *
   * @param  uuidAF  The value to use for the uuidAF field.
   */
  public void setUUIDAF(final UUID[] uuidAF)
  {
    this.uuidAF = uuidAF;
  }



  /**
   * Retrieves the value of the uuidM field.
   *
   * @return  The value of the uuidM field.
   */
  @LDAPGetter(attribute="uuidM")
  public UUID getUUIDM()
  {
    return uuidM;
  }



  /**
   * Sets the value of the uuidM field.
   *
   * @param  uuidM  The value to use for the uuidM field.
   */
  @LDAPSetter(attribute="uuidM")
  public void setUUIDM(final UUID uuidM)
  {
    this.uuidM = uuidM;
  }



  /**
   * Retrieves the value of the uuidAM field.
   *
   * @return  The value of the uuidAM field.
   */
  @LDAPGetter(attribute="uuidAM")
  public UUID[] getUUIDAM()
  {
    return uuidAM;
  }



  /**
   * Sets the value of the uuidAM field.
   *
   * @param  uuidAM  The value to use for the uuidAM field.
   */
  @LDAPSetter(attribute="uuidAM")
  public void setUUIDAM(final UUID[] uuidAM)
  {
    this.uuidAM = uuidAM;
  }



  /**
   * Gets the value of the stringArrayListF field.
   *
   * @return  The value of the stringArrayListF field.
   */
  public ArrayList<String> getStringArrayListF()
  {
    return stringArrayListF;
  }



  /**
   * Sets the value of the stringArrayListF field.
   *
   * @param  stringArrayListF  The value to use for the stringArrayListF field.
   */
  public void setStringArrayListF(final ArrayList<String> stringArrayListF)
  {
    this.stringArrayListF = stringArrayListF;
  }



  /**
   * Gets the value of the stringCopyOnWriteArrayListF field.
   *
   * @return  The value of the stringCopyOnWriteArrayListF field.
   */
  public CopyOnWriteArrayList<String> getStringCopyOnWriteArrayListF()
  {
    return stringCopyOnWriteArrayListF;
  }



  /**
   * Sets the value of the stringCopyOnWriteArrayListF field.
   *
   * @param  stringCopyOnWriteArrayListF  The value to use for the
   *                                      stringCopyOnWriteArrayListF field.
   */
  public void setStringCopyOnWriteArrayListF(
       final CopyOnWriteArrayList<String> stringCopyOnWriteArrayListF)
  {
    this.stringCopyOnWriteArrayListF = stringCopyOnWriteArrayListF;
  }



  /**
   * Gets the value of the stringLinkedListF field.
   *
   * @return  The value of the stringLinkedListF field.
   */
  public LinkedList<String> getStringLinkedListF()
  {
    return stringLinkedListF;
  }



  /**
   * Sets the value of the stringLinkedListF field.
   *
   * @param  stringLinkedListF  The value to use for the stringLinkedListF
   *                            field.
   */
  public void setStringLinkedListF(final LinkedList<String> stringLinkedListF)
  {
    this.stringLinkedListF = stringLinkedListF;
  }



  /**
   * Gets the value of the stringListF field.
   *
   * @return  The value of the stringListF field.
   */
  public List<String> getStringListF()
  {
    return stringListF;
  }



  /**
   * Sets the value of the stringListF field.
   *
   * @param  stringListF  The value to use for the stringListF field.
   */
  public void setStringListF(final List<String> stringListF)
  {
    this.stringListF = stringListF;
  }



  /**
   * Gets the value of the stringCopyOnWriteArraySetF field.
   *
   * @return  The value of the stringCopyOnWriteArraySetF field.
   */
  public CopyOnWriteArraySet<String> getStringCopyOnWriteArraySetF()
  {
    return stringCopyOnWriteArraySetF;
  }



  /**
   * Sets the value of the stringCopyOnWriteArraySetF field.
   *
   * @param  stringCopyOnWriteArraySetF  The value to use for the
   *                                     stringCopyOnWriteArraySetF field.
   */
  public void setStringCopyOnWriteArraySetF(
       final CopyOnWriteArraySet<String> stringCopyOnWriteArraySetF)
  {
    this.stringCopyOnWriteArraySetF = stringCopyOnWriteArraySetF;
  }



  /**
   * Gets the value of the stringHashSetF field.
   *
   * @return  The value of the stringHashSetF field.
   */
  public HashSet<String> getStringHashSetF()
  {
    return stringHashSetF;
  }



  /**
   * Sets the value of the stringHashSetF field.
   *
   * @param  stringHashSetF  The value to use for the stringHashSetF field.
   */
  public void setStringHashSetF(final HashSet<String> stringHashSetF)
  {
    this.stringHashSetF = stringHashSetF;
  }



  /**
   * Gets the value of the stringLinkedHashSetF field.
   *
   * @return  The value of the stringLinkedHashSetF field.
   */
  public LinkedHashSet<String> getStringLinkedHashSetF()
  {
    return stringLinkedHashSetF;
  }



  /**
   * Sets the value of the stringLinkedHashSetF field.
   *
   * @param  stringLinkedHashSetF  The value to use for the stringLinkedHashSetF
   *                               field.
   */
  public void setStringLinkedHashSetF(
                   final LinkedHashSet<String> stringLinkedHashSetF)
  {
    this.stringLinkedHashSetF = stringLinkedHashSetF;
  }



  /**
   * Gets the value of the stringTreeSetF field.
   *
   * @return  The value of the stringTreeSetF field.
   */
  public TreeSet<String> getStringTreeSetF()
  {
    return stringTreeSetF;
  }



  /**
   * Sets the value of the stringTreeSetF field.
   *
   * @param  stringTreeSetF  The value to use for the stringTreeSetF field.
   */
  public void setStringTreeSetF(final TreeSet<String> stringTreeSetF)
  {
    this.stringTreeSetF = stringTreeSetF;
  }



  /**
   * Gets the value of the stringSetF field.
   *
   * @return  The value of the stringSetF field.
   */
  public Set<String> getStringSetF()
  {
    return stringSetF;
  }



  /**
   * Sets the value of the stringSetF field.
   *
   * @param  stringSetF  The value to use for the stringSetF field.
   */
  public void setStringSetF(final Set<String> stringSetF)
  {
    this.stringSetF = stringSetF;
  }



  /**
   * Gets the value of the stringArrayListM field.
   *
   * @return  The value of the stringArrayListM field.
   */
  @LDAPGetter(attribute="stringArrayListM")
  public ArrayList<String> getStringArrayListM()
  {
    return stringArrayListM;
  }



  /**
   * Sets the value of the stringArrayListM field.
   *
   * @param  stringArrayListM  The value to use for the stringArrayListM field.
   */
  @LDAPSetter(attribute="stringArrayListM")
  public void setStringArrayListM(final ArrayList<String> stringArrayListM)
  {
    this.stringArrayListM = stringArrayListM;
  }



  /**
   * Gets the value of the stringCopyOnWriteArrayListM field.
   *
   * @return  The value of the stringCopyOnWriteArrayListM field.
   */
  @LDAPGetter(attribute="stringCopyOnWriteArrayListM")
  public CopyOnWriteArrayList<String> getStringCopyOnWriteArrayListM()
  {
    return stringCopyOnWriteArrayListM;
  }



  /**
   * Sets the value of the stringCopyOnWriteArrayListM field.
   *
   * @param  stringCopyOnWriteArrayListM  The value to use for the
   *                                      stringCopyOnWriteArrayListM field.
   */
  @LDAPSetter(attribute="stringCopyOnWriteArrayListM")
  public void setStringCopyOnWriteArrayListM(
       final CopyOnWriteArrayList<String> stringCopyOnWriteArrayListM)
  {
    this.stringCopyOnWriteArrayListM = stringCopyOnWriteArrayListM;
  }



  /**
   * Gets the value of the stringLinkedListM field.
   *
   * @return  The value of the stringLinkedListM field.
   */
  @LDAPGetter(attribute="stringLinkedListM")
  public LinkedList<String> getStringLinkedListM()
  {
    return stringLinkedListM;
  }



  /**
   * Sets the value of the stringLinkedListM field.
   *
   * @param  stringLinkedListM  The value to use for the stringLinkedListM
   *                            field.
   */
  @LDAPSetter(attribute="stringLinkedListM")
  public void setStringLinkedListM(final LinkedList<String> stringLinkedListM)
  {
    this.stringLinkedListM = stringLinkedListM;
  }



  /**
   * Gets the value of the stringListM field.
   *
   * @return  The value of the stringListM field.
   */
  @LDAPGetter(attribute="stringListM")
  public List<String> getStringListM()
  {
    return stringListM;
  }



  /**
   * Sets the value of the stringListM field.
   *
   * @param  stringListM  The value to use for the stringListM field.
   */
  @LDAPSetter(attribute="stringListM")
  public void setStringListM(final List<String> stringListM)
  {
    this.stringListM = stringListM;
  }



  /**
   * Gets the value of the stringCopyOnWriteArraySetM field.
   *
   * @return  The value of the stringCopyOnWriteArraySetM field.
   */
  @LDAPGetter(attribute="stringCopyOnWriteArraySetM")
  public CopyOnWriteArraySet<String> getStringCopyOnWriteArraySetM()
  {
    return stringCopyOnWriteArraySetM;
  }



  /**
   * Sets the value of the stringCopyOnWriteArraySetM field.
   *
   * @param  stringCopyOnWriteArraySetM  The value to use for the
   *                                     stringCopyOnWriteArraySetM field.
   */
  @LDAPSetter(attribute="stringCopyOnWriteArraySetM")
  public void setStringCopyOnWriteArraySetM(
       final CopyOnWriteArraySet<String> stringCopyOnWriteArraySetM)
  {
    this.stringCopyOnWriteArraySetM = stringCopyOnWriteArraySetM;
  }



  /**
   * Gets the value of the stringHashSetM field.
   *
   * @return  The value of the stringHashSetM field.
   */
  @LDAPGetter(attribute="stringHashSetM")
  public HashSet<String> getStringHashSetM()
  {
    return stringHashSetM;
  }



  /**
   * Sets the value of the stringHashSetM field.
   *
   * @param  stringHashSetM  The value to use for the stringHashSetM field.
   */
  @LDAPSetter(attribute="stringHashSetM")
  public void setStringHashSetM(final HashSet<String> stringHashSetM)
  {
    this.stringHashSetM = stringHashSetM;
  }



  /**
   * Gets the value of the stringLinkedHashSetM field.
   *
   * @return  The value of the stringLinkedHashSetM field.
   */
  @LDAPGetter(attribute="stringLinkedHashSetM")
  public LinkedHashSet<String> getStringLinkedHashSetM()
  {
    return stringLinkedHashSetM;
  }



  /**
   * Sets the value of the stringLinkedHashSetM field.
   *
   * @param  stringLinkedHashSetM  The value to use for the stringLinkedHashSetM
   *                               field.
   */
  @LDAPSetter(attribute="stringLinkedHashSetM")
  public void setStringLinkedHashSetM(
                   final LinkedHashSet<String> stringLinkedHashSetM)
  {
    this.stringLinkedHashSetM = stringLinkedHashSetM;
  }



  /**
   * Gets the value of the stringTreeSetM field.
   *
   * @return  The value of the stringTreeSetM field.
   */
  @LDAPGetter(attribute="stringTreeSetM")
  public TreeSet<String> getStringTreeSetM()
  {
    return stringTreeSetM;
  }



  /**
   * Sets the value of the stringTreeSetM field.
   *
   * @param  stringTreeSetM  The value to use for the stringTreeSetM field.
   */
  @LDAPSetter(attribute="stringTreeSetM")
  public void setStringTreeSetM(final TreeSet<String> stringTreeSetM)
  {
    this.stringTreeSetM = stringTreeSetM;
  }



  /**
   * Gets the value of the stringSetM field.
   *
   * @return  The value of the stringSetM field.
   */
  @LDAPGetter(attribute="stringSetM")
  public Set<String> getStringSetM()
  {
    return stringSetM;
  }



  /**
   * Sets the value of the stringSetM field.
   *
   * @param  stringSetM  The value to use for the stringSetM field.
   */
  @LDAPSetter(attribute="stringSetM")
  public void setStringSetM(final Set<String> stringSetM)
  {
    this.stringSetM = stringSetM;
  }



  /**
   * Gets the value of the gregorianCalendarF field.
   *
   * @return  The value of the gregorianCalendarF field.
   */
  public GregorianCalendar getGregorianCalendarF()
  {
    return gregorianCalendarF;
  }



  /**
   * Sets the value of the gregorianCalendarF field.
   *
   * @param  gregorianCalendarF  The value of the gregorianCalendarF field.
   */
  public void setGregorianCalendarF(final GregorianCalendar gregorianCalendarF)
  {
    this.gregorianCalendarF = gregorianCalendarF;
  }



  /**
   * Gets the value of the gregorianCalendarF field.
   *
   * @return  The value of the gregorianCalendarF field.
   */
  public GregorianCalendar[] getGregorianCalendarAF()
  {
    return gregorianCalendarAF;
  }



  /**
   * Sets the value of the gregorianCalendarAF field.
   *
   * @param  gregorianCalendarAF  The value of the gregorianCalendarF field.
   */
  public void setGregorianCalendarAF(
                   final GregorianCalendar[] gregorianCalendarAF)
  {
    this.gregorianCalendarAF = gregorianCalendarAF;
  }



  /**
   * Gets the value of the gregorianCalendarArrayListF field.
   *
   * @return  The value of the gregorianCalendarArrayListF field.
   */
  public ArrayList<GregorianCalendar> getGregorianCalendarArrayListF()
  {
    return gregorianCalendarArrayListF;
  }



  /**
   * Sets the value of the gregorianCalendarArrayListF field.
   *
   * @param  gregorianCalendarArrayListF  The value of the gregorianCalendarF
   *                                      field.
   */
  public void setGregorianCalendarArrayListF(
              final ArrayList<GregorianCalendar> gregorianCalendarArrayListF)
  {
    this.gregorianCalendarArrayListF = gregorianCalendarArrayListF;
  }



  /**
   * Gets the value of the gregorianCalendarHashSetF field.
   *
   * @return  The value of the gregorianCalendarHashSetF field.
   */
  public HashSet<GregorianCalendar> getGregorianCalendarHashSetF()
  {
    return gregorianCalendarHashSetF;
  }



  /**
   * Sets the value of the gregorianCalendarHashSetF field.
   *
   * @param  gregorianCalendarHashSetF  The value of the
   *                                    gregorianCalendarHashSetF field.
   */
  public void setGregorianCalendarHashSetF(
              final HashSet<GregorianCalendar> gregorianCalendarHashSetF)
  {
    this.gregorianCalendarHashSetF = gregorianCalendarHashSetF;
  }
}
