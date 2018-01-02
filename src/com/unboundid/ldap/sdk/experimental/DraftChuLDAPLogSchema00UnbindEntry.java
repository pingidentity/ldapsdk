/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class represents an entry that holds information about an unbind
 * operation processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00UnbindEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1596182705806691625L;



  /**
   * Creates a new instance of this unbind access log entry from the provided
   * entry.
   *
   * @param  entry  The entry used to create this unbind access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         unbind access log entry as per the specification
   *                         contained in draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00UnbindEntry(final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.UNBIND);
  }
}
