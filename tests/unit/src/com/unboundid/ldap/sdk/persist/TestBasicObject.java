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
 * This class provides a basic object that can be used for testing purposes.
 */
@LDAPObject(structuralClass="x", auxiliaryClass={ "y", "z" },
     defaultParentDN="ou=default,dc=example,dc=com",
     postDecodeMethod="doPostDecode", postEncodeMethod="doPostEncode")
public class TestBasicObject
{
  @LDAPField(attribute="a", inRDN=true, filterUsage=FilterUsage.ALWAYS_ALLOWED)
  private String a;

  @LDAPField(filterUsage=FilterUsage.ALWAYS_ALLOWED) private String b;

  @LDAPField(requiredForDecode=true, requiredForEncode=true) private String c;
  @LDAPField(inAdd=false, inModify=false) private String d;
  @LDAPField() private String e;

  @LDAPDNField() private String dn;
  @LDAPEntryField() private ReadOnlyEntry entry;

  private String m;
  private String n;
  private String o;
  private String p;
  private String q;
  private String rs;

  /**
   * Indicates whether to throw an exception in the post-decode method.
   */
  boolean throwExceptionInPostDecode;

  /**
   * Indicates whether to throw an exception in the post-encode method.
   */
  boolean throwExceptionInPostEncode;



  /**
   * Creates a new instance of this object.
   */
  public TestBasicObject()
  {
  }



  /**
   * Retrieves the value of a.
   *
   * @return  The value of a.
   */
  public String getA()
  {
    return a;
  }



  /**
   * Sets the value of a.
   *
   * @param  a  The value of a.
   */
  public void setA(final String a)
  {
    this.a = a;
  }



  /**
   * Retrieves the value of b.
   *
   * @return  The value of b.
   */
  public String getB()
  {
    return b;
  }



  /**
   * Sets the value of b.
   *
   * @param  b  The value of b.
   */
  public void setB(final String b)
  {
    this.b = b;
  }



  /**
   * Retrieves the value of c.
   *
   * @return  The value of c.
   */
  public String getC()
  {
    return c;
  }



  /**
   * Sets the value of c.
   *
   * @param  c  The value of c.
   */
  public void setC(final String c)
  {
    this.c = c;
  }



  /**
   * Retrieves the value of d.
   *
   * @return  The value of d.
   */
  public String getD()
  {
    return d;
  }



  /**
   * Sets the value of d.
   *
   * @param  d  The value of d.
   */
  public void setD(final String d)
  {
    this.d = d;
  }



  /**
   * Retrieves the value of e.
   *
   * @return  The value of e.
   */
  public String getE()
  {
    return e;
  }



  /**
   * Sets the value of e.
   *
   * @param  e  The value of e.
   */
  public void setE(final String e)
  {
    this.e = e;
  }



  /**
   * Retrieves the value of m.
   *
   * @return  The value of m.
   */
  @LDAPGetter(attribute="m", filterUsage=FilterUsage.ALWAYS_ALLOWED)
  public String getM()
  {
    return m;
  }



  /**
   * Sets the value of m.
   *
   * @param  m  The value of m.
   */
  @LDAPSetter(attribute="m")
  public void setM(final String m)
  {
    this.m = m;
  }



  /**
   * Retrieves the value of n.
   *
   * @return  The value of n.
   */
  @LDAPGetter(attribute="n", filterUsage=FilterUsage.ALWAYS_ALLOWED)
  public String getN()
  {
    return n;
  }



  /**
   * Sets the value of n.
   *
   * @param  n  The value of n.
   */
  @LDAPSetter(attribute="n")
  public void setN(final String n)
  {
    this.n = n;
  }



  /**
   * Retrieves the value of o.
   *
   * @return  The value of o.
   */
  @LDAPGetter(attribute="o", inAdd=false, inModify=false)
  public String getO()
  {
    return o;
  }



  /**
   * Sets the value of o.
   *
   * @param  o  The value of o.
   */
  @LDAPSetter(attribute="o")
  public void setO(final String o)
  {
    this.o = o;
  }



  /**
   * Retrieves the value of p.
   *
   * @return  The value of p.
   */
  @LDAPGetter(attribute="p")
  public String getP()
  {
    return p;
  }



  /**
   * Sets the value of p.
   *
   * @param  p  The value of p.
   */
  @LDAPSetter(attribute="p")
  public void setP(final String p)
  {
    this.p = p;
  }



  /**
   * Retrieves the value of q.
   *
   * @return  The value of q.
   */
  @LDAPGetter()
  public String getQ()
  {
    return q;
  }



  /**
   * Sets the value of q.
   *
   * @param  q  The value of q.
   */
  @LDAPSetter()
  public void setQ(final String q)
  {
    this.q = q;
  }



  /**
   * Retrieves the value of rs.
   *
   * @return  The value of rs.
   */
  @LDAPGetter()
  public String getRs()
  {
    return rs;
  }



  /**
   * Sets the value of rs.
   *
   * @param  rs  The value of rs.
   */
  @LDAPSetter()
  public void setRs(final String rs)
  {
    this.rs = rs;
  }



  /**
   * Retrieves the DN of the associated entry, if available.
   *
   * @return  The DN of the associated entry, or {@code null} if it is not
   *          available.
   */
  public String getDN()
  {
    return dn;
  }



  /**
   * Sets the DN of the associated entry.
   *
   * @param  dn  The DN of the associated entry.
   */
  void setDN(final String dn)
  {
    this.dn = dn;
  }



  /**
   * Retrieves a read-only copy of the associated entry, if available.
   *
   * @return  A read-only copy of the associated entry, or {@code null} if it is
   *          not available.
   */
  public ReadOnlyEntry getEntry()
  {
    return entry;
  }



  /**
   * Sets the read-only entry.
   *
   * @param  entry  The read-only entry.
   */
  void setEntry(final ReadOnlyEntry entry)
  {
    this.entry = entry;
  }



  /**
   * Performs any appropriate post-decode processing for this object.
   */
  private void doPostDecode()
  {
    if (throwExceptionInPostDecode)
    {
      throw new RuntimeException();
    }
  }



  /**
   * Performs any appropriate post-encode processing for this object.
   *
   * @param  entry  The entry created from this object.
   */
  private void doPostEncode(final Entry entry)
  {
    if (throwExceptionInPostEncode)
    {
      throw new RuntimeException();
    }

    entry.addAttribute("addedInPostEncode", "foo");
  }
}
