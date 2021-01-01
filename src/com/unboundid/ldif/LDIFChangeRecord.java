/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a base class for LDIF change records, which can be used
 * to represent add, delete, modify, and modify DN operations in LDIF form.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example iterates through all of the change records contained in
 * an LDIF file and attempts to apply those changes to a directory server:
 * <PRE>
 * LDIFReader ldifReader = new LDIFReader(pathToLDIFFile);
 *
 * int changesRead = 0;
 * int changesProcessed = 0;
 * int errorsEncountered = 0;
 * while (true)
 * {
 *   LDIFChangeRecord changeRecord;
 *   try
 *   {
 *     changeRecord = ldifReader.readChangeRecord();
 *     if (changeRecord == null)
 *     {
 *       // All changes have been processed.
 *       break;
 *     }
 *
 *     changesRead++;
 *   }
 *   catch (LDIFException le)
 *   {
 *     errorsEncountered++;
 *     if (le.mayContinueReading())
 *     {
 *       // A recoverable error occurred while attempting to read a change
 *       // record, at or near line number le.getLineNumber()
 *       // The change record will be skipped, but we'll try to keep reading
 *       // from the LDIF file.
 *       continue;
 *     }
 *     else
 *     {
 *       // An unrecoverable error occurred while attempting to read a change
 *       // record, at or near line number le.getLineNumber()
 *       // No further LDIF processing will be performed.
 *       break;
 *     }
 *   }
 *   catch (IOException ioe)
 *   {
 *     // An I/O error occurred while attempting to read from the LDIF file.
 *     // No further LDIF processing will be performed.
 *     errorsEncountered++;
 *     break;
 *   }
 *
 *   // Try to process the change in a directory server.
 *   LDAPResult operationResult;
 *   try
 *   {
 *     operationResult = changeRecord.processChange(connection);
 *     // If we got here, then the change should have been processed
 *     // successfully.
 *     changesProcessed++;
 *   }
 *   catch (LDAPException le)
 *   {
 *     // If we got here, then the change attempt failed.
 *     operationResult = le.toLDAPResult();
 *     errorsEncountered++;
 *   }
 * }
 *
 * ldifReader.close();
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
  private static final long serialVersionUID = 6917212392170911115L;



  // The set of controls for the LDIF change record.
  @NotNull private final List<Control> controls;

  // The parsed DN for this LDIF change record.
  @Nullable private volatile DN parsedDN;

  // The DN for this LDIF change record.
  @NotNull private final String dn;



  /**
   * Creates a new LDIF change record with the provided DN.
   *
   * @param  dn        The DN of the LDIF change record to create.  It must not
   *                   be {@code null}.
   * @param  controls  The set of controls for the change record to create.  It
   *                   may be {@code null} or empty if no controls are needed.
   */
  protected LDIFChangeRecord(@NotNull final String dn,
                             @Nullable final List<Control> controls)
  {
    Validator.ensureNotNull(dn);

    this.dn = dn;
    parsedDN = null;

    if (controls == null)
    {
      this.controls = Collections.emptyList();
    }
    else
    {
      this.controls = Collections.unmodifiableList(controls);
    }
  }



  /**
   * Retrieves the DN for this LDIF change record.
   *
   * @return  The DN for this LDIF change record.
   */
  @Override()
  @NotNull()
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
  @Override()
  @NotNull()
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
  @NotNull()
  public abstract ChangeType getChangeType();



  /**
   * Retrieves the set of controls for this LDIF change record.
   *
   * @return  The set of controls for this LDIF change record, or an empty array
   *          if there are no controls.
   */
  @NotNull()
  public List<Control> getControls()
  {
    return controls;
  }



  /**
   * Creates a duplicate of this LDIF change record with the provided set of
   * controls.
   *
   * @param  controls  The set of controls to include in the duplicate change
   *                   record.  It may be {@code null} or empty if no controls
   *                   should be included.
   *
   * @return  A duplicate of this LDIF change record with the provided set of
   *          controls.
   */
  @NotNull()
  public abstract LDIFChangeRecord duplicate(@Nullable Control... controls);



  /**
   * Apply the change represented by this LDIF change record to a directory
   * server using the provided connection.  Any controls included in the
   * change record will be included in the request.
   *
   * @param  connection  The connection to use to apply the change.
   *
   * @return  An object providing information about the result of the operation.
   *
   * @throws  LDAPException  If an error occurs while processing this change
   *                         in the associated directory server.
   */
  @NotNull()
  public final LDAPResult processChange(@NotNull final LDAPInterface connection)
         throws LDAPException
  {
    return processChange(connection, true);
  }



  /**
   * Apply the change represented by this LDIF change record to a directory
   * server using the provided connection, optionally including any change
   * record controls in the request.
   *
   * @param  connection       The connection to use to apply the change.
   * @param  includeControls  Indicates whether to include any controls in the
   *                          request.
   *
   * @return  An object providing information about the result of the operation.
   *
   * @throws  LDAPException  If an error occurs while processing this change
   *                         in the associated directory server.
   */
  @NotNull()
  public abstract LDAPResult processChange(@NotNull LDAPInterface connection,
                                           boolean includeControls)
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
  @NotNull()
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
  @Override()
  @NotNull()
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
  @Override()
  @NotNull()
  public abstract String[] toLDIF(int wrapColumn);



  /**
   * Encodes the provided name and value and adds the result to the provided
   * list of lines.  This will handle the case in which the encoded name and
   * value includes comments about the base64-decoded representation of the
   * provided value.
   *
   * @param  name   The attribute name to be encoded.
   * @param  value  The attribute value to be encoded.
   * @param  lines  The list of lines to be updated.
   */
  static void encodeNameAndValue(@NotNull final String name,
                                 @NotNull final ASN1OctetString value,
                                 @NotNull final List<String> lines)
  {
    final String line = LDIFWriter.encodeNameAndValue(name, value);
    if (LDIFWriter.commentAboutBase64EncodedValues() &&
        line.startsWith(name + "::"))
    {
      final StringTokenizer tokenizer = new StringTokenizer(line, "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        lines.add(tokenizer.nextToken());
      }
    }
    else
    {
      lines.add(line);
    }
  }



  /**
   * Appends an LDIF string representation of this change record to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append an LDIF representation of
   *                 this change record.
   */
  @Override()
  public final void toLDIF(@NotNull final ByteStringBuffer buffer)
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
  @Override()
  public abstract void toLDIF(@NotNull ByteStringBuffer buffer, int wrapColumn);



  /**
   * Retrieves an LDIF string representation of this change record.
   *
   * @return  An LDIF string representation of this change record.
   */
  @Override()
  @NotNull()
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
  @Override()
  @NotNull()
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
  @Override()
  public final void toLDIFString(@NotNull final StringBuilder buffer)
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
  @Override()
  public abstract void toLDIFString(@NotNull StringBuilder buffer,
                                    int wrapColumn);



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
  public abstract boolean equals(@Nullable Object o);



  /**
   * Encodes a string representation of the provided control for use in the
   * LDIF representation of the change record.
   *
   * @param  c  The control to be encoded.
   *
   * @return  The string representation of the control.
   */
  @NotNull()
  static ASN1OctetString encodeControlString(@NotNull final Control c)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(c.getOID());

    if (c.isCritical())
    {
      buffer.append(" true");
    }
    else
    {
      buffer.append(" false");
    }

    final ASN1OctetString value = c.getValue();
    if (value != null)
    {
      LDIFWriter.encodeValue(value, buffer);
    }

    return buffer.toByteString().toASN1OctetString();
  }



  /**
   * Retrieves a single-line string representation of this change record.
   *
   * @return  A single-line string representation of this change record.
   */
  @Override()
  @NotNull()
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
  @Override()
  public abstract void toString(@NotNull StringBuilder buffer);
}
