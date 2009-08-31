/*
 * Copyright 2007-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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
package com.unboundid.ldif;



import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Validator.*;



/**
 * This class provides a base class for LDIF change records, which can be used
 * to represent add, delete, modify, and modify DN operations in LDIF form.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example iterates through all of the change records contained in
 * an LDIF file and attempts to apply those changes to a directory server:
 * <PRE>
 *   LDIFReader ldifReader = new LDIFReader(pathToLDIFFile);
 *
 *   while (true)
 *   {
 *     LDIFChangeRecord changeRecord;
 *     try
 *     {
 *       changeRecord = ldifReader.readChangeRecord();
 *       if (changeRecord == null)
 *       {
 *         System.err.println("All changes have been processed.");
 *         break;
 *       }
 *     }
 *     catch (LDIFException le)
 *     {
 *       if (le.mayContinueReading())
 *       {
 *         System.err.println("A recoverable occurred while attempting to " +
 *              "read a change record at or near line number " +
 *              le.getLineNumber() + ":  " + le.getMessage());
 *         System.err.println("The change record will be skipped.");
 *         continue;
 *       }
 *       else
 *       {
 *         System.err.println("An unrecoverable occurred while attempting to " +
 *              "read a change record at or near line number " +
 *              le.getLineNumber() + ":  " + le.getMessage());
 *         System.err.println("LDIF processing will be aborted.");
 *         break;
 *       }
 *     }
 *     catch (IOException ioe)
 *     {
 *       System.err.println("An I/O error occurred while attempting to read " +
 *            "from the LDIF file:  " + ioe.getMessage());
 *       System.err.println("LDIF processing will be aborted.");
 *       break;
 *     }
 *
 *     try
 *     {
 *       LDAPResult result = changeRecord.processChange(connection);
 *       System.out.println(changeRecord.getChangeType().getName() +
 *            " successful for entry " + changeRecord.getDN());
 *     }
 *     catch (LDAPException le)
 *     {
 *       System.err.println(changeRecord.getChangeType().getName() +
 *            " failed for entry " + changeRecord.getDN() + " -- " +
 *            le.getMessage());
 *     }
 *   }
 *
 *   ldifReader.close();
 * </PRE>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class LDIFChangeRecord
       implements LDIFRecord
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2394617613961232499L;



  // The parsed DN for this LDIF change record.
  private volatile DN parsedDN;

  // The DN for this LDIF change record.
  private final String dn;



  /**
   * Creates a new LDIF change record with the provided DN.
   *
   * @param  dn  The DN of the LDIF change record to create.  It must not be
   *             {@code null}.
   */
  protected LDIFChangeRecord(final String dn)
  {
    ensureNotNull(dn);

    this.dn = dn;
  }



  /**
   * Retrieves the DN for this LDIF change record.
   *
   * @return  The DN for this LDIF change record.
   */
  public final String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the parsed DN for this LDIF change record.
   *
   * @return  The DN for this LDIF change record.
   *
   * @throws  LDAPException  If a problem occurs while trying to parse the DN.
   */
  public final DN getParsedDN()
         throws LDAPException
  {
    if (parsedDN == null)
    {
      parsedDN = new DN(dn);
    }

    return parsedDN;
  }



  /**
   * Retrieves the type of operation represented by this LDIF change record.
   *
   * @return  The type of operation represented by this LDIF change record.
   */
  public abstract ChangeType getChangeType();



  /**
   * Apply the change represented by this LDIF change record to a directory
   * server using the provided connection.
   *
   * @param  connection  The connection to use to apply the change.
   *
   * @return  An object providing information about the result of the operation.
   *
   * @throws  LDAPException  If an error occurs while processing this change
   *                         in the associated directory server.
   */
  public abstract LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException;



  /**
   * Retrieves an {@code Entry} representation of this change record.  This is
   * intended only for internal use by the LDIF reader when operating
   * asynchronously in the case that it is not possible to know ahead of time
   * whether a user will attempt to read an LDIF record by {@code readEntry} or
   * {@code readChangeRecord}.  In the event that the LDIF file has an entry
   * whose first attribute is "changetype" and the client wants to read it as
   * an entry rather than a change record, then this may be used to generate an
   * entry representing the change record.
   *
   * @return  The entry representation of this change record.
   *
   * @throws  LDIFException  If this change record cannot be represented as a
   *                         valid entry.
   */
  final Entry toEntry()
        throws LDIFException
  {
    return new Entry(toLDIF());
  }



  /**
   * Retrieves a string array whose lines contain an LDIF representation of this
   * change record.
   *
   * @return  A string array whose lines contain an LDIF representation of this
   *          change record.
   */
  public final String[] toLDIF()
  {
    return toLDIF(0);
  }



  /**
   * Retrieves a string array whose lines contain an LDIF representation of this
   * change record.
   *
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   *
   * @return  A string array whose lines contain an LDIF representation of this
   *          change record.
   */
  public abstract String[] toLDIF(final int wrapColumn);



  /**
   * Appends an LDIF string representation of this change record to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append an LDIF representation of
   *                 this change record.
   */
  public final void toLDIF(final ByteStringBuffer buffer)
  {
    toLDIF(buffer, 0);
  }



  /**
   * Appends an LDIF string representation of this change record to the provided
   * buffer.
   *
   * @param  buffer      The buffer to which to append an LDIF representation of
   *                     this change record.
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   */
  public abstract void toLDIF(final ByteStringBuffer buffer,
                              final int wrapColumn);



  /**
   * Retrieves an LDIF string representation of this change record.
   *
   * @return  An LDIF string representation of this change record.
   */
  public final String toLDIFString()
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, 0);
    return buffer.toString();
  }



  /**
   * Retrieves an LDIF string representation of this change record.
   *
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   *
   * @return  An LDIF string representation of this change record.
   */
  public final String toLDIFString(final int wrapColumn)
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, wrapColumn);
    return buffer.toString();
  }



  /**
   * Appends an LDIF string representation of this change record to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append an LDIF representation of
   *                 this change record.
   */
  public final void toLDIFString(final StringBuilder buffer)
  {
    toLDIFString(buffer, 0);
  }



  /**
   * Appends an LDIF string representation of this change record to the provided
   * buffer.
   *
   * @param  buffer      The buffer to which to append an LDIF representation of
   *                     this change record.
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   */
  public abstract void toLDIFString(final StringBuilder buffer,
                                    final int wrapColumn);



  /**
   * Retrieves a hash code for this change record.
   *
   * @return  A hash code for this change record.
   */
  @Override()
  public abstract int hashCode();



  /**
   * Indicates whether the provided object is equal to this LDIF change record.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this LDIF change
   *          record, or {@code false} if not.
   */
  @Override()
  public abstract boolean equals(final Object o);



  /**
   * Retrieves a single-line string representation of this change record.
   *
   * @return  A single-line string representation of this change record.
   */
  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of this change record to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be written.
   */
  public abstract void toString(final StringBuilder buffer);
}
