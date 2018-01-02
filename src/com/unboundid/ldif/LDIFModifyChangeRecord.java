/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class defines an LDIF modify change record, which can be used to
 * represent an LDAP modify request.  See the documentation for the
 * {@link LDIFChangeRecord} class for an example demonstrating the process for
 * interacting with LDIF change records.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFModifyChangeRecord
       extends LDIFChangeRecord
{
  /**
   * The name of the system property that will be used to indicate whether
   * to always include a trailing dash after the last change in the LDIF
   * representation of a modify change record.  By default, the dash will always
   * be included.
   */
  public static final  String PROPERTY_ALWAYS_INCLUDE_TRAILING_DASH =
       "com.unboundid.ldif.modify.alwaysIncludeTrailingDash";



  /**
   * Indicates whether to always include a trailing dash after the last change
   * in the LDIF representation.
   */
  private static boolean alwaysIncludeTrailingDash = true;



  static
  {
    final String propValue =
         System.getProperty(PROPERTY_ALWAYS_INCLUDE_TRAILING_DASH);
    if ((propValue != null) && (propValue.equalsIgnoreCase("false")))
    {
      alwaysIncludeTrailingDash = false;
    }
  }



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7558098319600288036L;



  // The set of modifications for this modify change record.
  private final Modification[] modifications;



  /**
   * Creates a new LDIF modify change record with the provided DN and set of
   * modifications.
   *
   * @param  dn             The DN for this LDIF add change record.  It must not
   *                        be {@code null}.
   * @param  modifications  The set of modifications for this LDIF modify change
   *                        record.  It must not be {@code null} or empty.
   */
  public LDIFModifyChangeRecord(final String dn,
                                final Modification... modifications)
  {
    this(dn, modifications, null);
  }



  /**
   * Creates a new LDIF modify change record with the provided DN and set of
   * modifications.
   *
   * @param  dn             The DN for this LDIF add change record.  It must not
   *                        be {@code null}.
   * @param  modifications  The set of modifications for this LDIF modify change
   *                        record.  It must not be {@code null} or empty.
   * @param  controls       The set of controls for this LDIF modify change
   *                        record.  It may be {@code null} or empty if there
   *                        are no controls.
   */
  public LDIFModifyChangeRecord(final String dn,
                                final Modification[] modifications,
                                final List<Control> controls)
  {
    super(dn, controls);

    ensureNotNull(modifications);
    ensureTrue(modifications.length > 0,
         "LDIFModifyChangeRecord.modifications must not be empty.");

    this.modifications = modifications;
  }



  /**
   * Creates a new LDIF modify change record with the provided DN and set of
   * modifications.
   *
   * @param  dn             The DN for this LDIF add change record.  It must not
   *                        be {@code null}.
   * @param  modifications  The set of modifications for this LDIF modify change
   *                        record.  It must not be {@code null} or empty.
   */
  public LDIFModifyChangeRecord(final String dn,
                                final List<Modification> modifications)
  {
    this(dn, modifications, null);
  }



  /**
   * Creates a new LDIF modify change record with the provided DN and set of
   * modifications.
   *
   * @param  dn             The DN for this LDIF add change record.  It must not
   *                        be {@code null}.
   * @param  modifications  The set of modifications for this LDIF modify change
   *                        record.  It must not be {@code null} or empty.
   * @param  controls       The set of controls for this LDIF modify change
   *                        record.  It may be {@code null} or empty if there
   *                        are no controls.
   */
  public LDIFModifyChangeRecord(final String dn,
                                final List<Modification> modifications,
                                final List<Control> controls)
  {
    super(dn, controls);

    ensureNotNull(modifications);
    ensureFalse(modifications.isEmpty(),
         "LDIFModifyChangeRecord.modifications must not be empty.");

    this.modifications = new Modification[modifications.size()];
    modifications.toArray(this.modifications);
  }



  /**
   * Creates a new LDIF modify change record from the provided modify request.
   *
   * @param  modifyRequest  The modify request to use to create this LDIF modify
   *                        change record.  It must not be {@code null}.
   */
  public LDIFModifyChangeRecord(final ModifyRequest modifyRequest)
  {
    super(modifyRequest.getDN(), modifyRequest.getControlList());

    final List<Modification> mods = modifyRequest.getModifications();
    modifications = new Modification[mods.size()];

    final Iterator<Modification> iterator = mods.iterator();
    for (int i=0; i < modifications.length; i++)
    {
      modifications[i] = iterator.next();
    }
  }



  /**
   * Indicates whether the LDIF representation of a modify change record should
   * always include a trailing dash after the last (or only) change.
   *
   * @return  {@code true} if the LDIF representation of a modify change record
   *          should always include a trailing dash after the last (or only)
   *          change, or {@code false} if not.
   */
  public static boolean alwaysIncludeTrailingDash()
  {
    return alwaysIncludeTrailingDash;
  }



  /**
   * Specifies whether the LDIF representation of a modify change record should
   * always include a trailing dash after the last (or only) change.
   *
   * @param  alwaysIncludeTrailingDash  Indicates whether the LDIF
   *                                    representation of a modify change record
   *                                    should always include a trailing dash
   *                                    after the last (or only) change.
   */
  public static void setAlwaysIncludeTrailingDash(
                          final boolean alwaysIncludeTrailingDash)
  {
    LDIFModifyChangeRecord.alwaysIncludeTrailingDash =
         alwaysIncludeTrailingDash;
  }



  /**
   * Retrieves the set of modifications for this modify change record.
   *
   * @return  The set of modifications for this modify change record.
   */
  public Modification[] getModifications()
  {
    return modifications;
  }



  /**
   * Creates a modify request from this LDIF modify change record.  Any change
   * record controls will be included in the request
   *
   * @return  The modify request created from this LDIF modify change record.
   */
  public ModifyRequest toModifyRequest()
  {
    return toModifyRequest(true);
  }



  /**
   * Creates a modify request from this LDIF modify change record, optionally
   * including any change record controls in the request.
   *
   * @param  includeControls  Indicates whether to include any controls in the
   *                          request.
   *
   * @return  The modify request created from this LDIF modify change record.
   */
  public ModifyRequest toModifyRequest(final boolean includeControls)
  {
    final ModifyRequest modifyRequest =
         new ModifyRequest(getDN(), modifications);
    if (includeControls)
    {
      modifyRequest.setControls(getControls());
    }

    return modifyRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.MODIFY;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult processChange(final LDAPInterface connection,
                                  final boolean includeControls)
         throws LDAPException
  {
    return connection.modify(toModifyRequest(includeControls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<String>(modifications.length*4);
    encodeNameAndValue("dn", new ASN1OctetString(getDN()), ldifLines);

    for (final Control c : getControls())
    {
      encodeNameAndValue("control", encodeControlString(c), ldifLines);
    }

    ldifLines.add("changetype: modify");

    for (int i=0; i < modifications.length; i++)
    {
      final String attrName = modifications[i].getAttributeName();

      switch (modifications[i].getModificationType().intValue())
      {
        case 0:
          ldifLines.add("add: " + attrName);
          break;
        case 1:
          ldifLines.add("delete: " + attrName);
          break;
        case 2:
          ldifLines.add("replace: " + attrName);
          break;
        case 3:
          ldifLines.add("increment: " + attrName);
          break;
        default:
          // This should never happen.
          continue;
      }

      for (final ASN1OctetString value : modifications[i].getRawValues())
      {
        encodeNameAndValue(attrName, value, ldifLines);
      }

      if (alwaysIncludeTrailingDash || (i < (modifications.length - 1)))
      {
        ldifLines.add("-");
      }
    }

    if (wrapColumn > 2)
    {
      ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);
    }

    final String[] ldifArray = new String[ldifLines.size()];
    ldifLines.toArray(ldifArray);
    return ldifArray;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIF(final ByteStringBuffer buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
         wrapColumn);
    buffer.append(EOL_BYTES);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(EOL_BYTES);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("modify"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);

    for (int i=0; i < modifications.length; i++)
    {
      final String attrName = modifications[i].getAttributeName();

      switch (modifications[i].getModificationType().intValue())
      {
        case 0:
          LDIFWriter.encodeNameAndValue("add", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        case 1:
          LDIFWriter.encodeNameAndValue("delete", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        case 2:
          LDIFWriter.encodeNameAndValue("replace",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        case 3:
          LDIFWriter.encodeNameAndValue("increment",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL_BYTES);
          break;
        default:
          // This should never happen.
          continue;
      }

      for (final ASN1OctetString value : modifications[i].getRawValues())
      {
        LDIFWriter.encodeNameAndValue(attrName, value, buffer, wrapColumn);
        buffer.append(EOL_BYTES);
      }

      if (alwaysIncludeTrailingDash || (i < (modifications.length - 1)))
      {
        buffer.append('-');
        buffer.append(EOL_BYTES);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIFString(final StringBuilder buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
         wrapColumn);
    buffer.append(EOL);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(EOL);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("modify"),
                                  buffer, wrapColumn);
    buffer.append(EOL);

    for (int i=0; i < modifications.length; i++)
    {
      final String attrName = modifications[i].getAttributeName();

      switch (modifications[i].getModificationType().intValue())
      {
        case 0:
          LDIFWriter.encodeNameAndValue("add", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL);
          break;
        case 1:
          LDIFWriter.encodeNameAndValue("delete", new ASN1OctetString(attrName),
                                        buffer, wrapColumn);
          buffer.append(EOL);
          break;
        case 2:
          LDIFWriter.encodeNameAndValue("replace",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL);
          break;
        case 3:
          LDIFWriter.encodeNameAndValue("increment",
                                        new ASN1OctetString(attrName), buffer,
                                        wrapColumn);
          buffer.append(EOL);
          break;
        default:
          // This should never happen.
          continue;
      }

      for (final ASN1OctetString value : modifications[i].getRawValues())
      {
        LDIFWriter.encodeNameAndValue(attrName, value, buffer, wrapColumn);
        buffer.append(EOL);
      }

      if (alwaysIncludeTrailingDash || (i < (modifications.length - 1)))
      {
        buffer.append('-');
        buffer.append(EOL);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    int hashCode;
    try
    {
      hashCode = getParsedDN().hashCode();
    }
    catch (final Exception e)
    {
      debugException(e);
      hashCode = toLowerCase(getDN()).hashCode();
    }

    for (final Modification m : modifications)
    {
      hashCode += m.hashCode();
    }

    return hashCode;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof LDIFModifyChangeRecord))
    {
      return false;
    }

    final LDIFModifyChangeRecord r = (LDIFModifyChangeRecord) o;

    final HashSet<Control> c1 = new HashSet<Control>(getControls());
    final HashSet<Control> c2 = new HashSet<Control>(r.getControls());
    if (! c1.equals(c2))
    {
      return false;
    }

    try
    {
      if (! getParsedDN().equals(r.getParsedDN()))
      {
        return false;
      }
    }
    catch (final Exception e)
    {
      debugException(e);
      if (! toLowerCase(getDN()).equals(toLowerCase(r.getDN())))
      {
        return false;
      }
    }

    if (modifications.length != r.modifications.length)
    {
      return false;
    }

    for (int i=0; i < modifications.length; i++)
    {
      if (! modifications[i].equals(r.modifications[i]))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDIFModifyChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append("', mods={");

    for (int i=0; i < modifications.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      modifications[i].toString(buffer);
    }
    buffer.append('}');

    final List<Control> controls = getControls();
    if (! controls.isEmpty())
    {
      buffer.append(", controls={");

      final Iterator<Control> iterator = controls.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
