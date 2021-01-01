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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for holding information about an LDAP
 * distinguished name (DN).  A DN consists of a comma-delimited list of zero or
 * more RDN components.  See
 * <A HREF="http://www.ietf.org/rfc/rfc4514.txt">RFC 4514</A> for more
 * information about representing DNs and RDNs as strings.
 * <BR><BR>
 * Examples of valid DNs (excluding the quotation marks, which are provided for
 * clarity) include:
 * <UL>
 *   <LI>"" -- This is the zero-length DN (also called the null DN), which may
 *       be used to refer to the directory server root DSE.</LI>
 *   <LI>"{@code o=example.com}".  This is a DN with a single, single-valued
 *       RDN.  The RDN attribute is "{@code o}" and the RDN value is
 *       "{@code example.com}".</LI>
 *   <LI>"{@code givenName=John+sn=Doe,ou=People,dc=example,dc=com}".  This is a
 *       DN with four different RDNs ("{@code givenName=John+sn=Doe"},
 *       "{@code ou=People}", "{@code dc=example}", and "{@code dc=com}".  The
 *       first RDN is multivalued with attribute-value pairs of
 *       "{@code givenName=John}" and "{@code sn=Doe}".</LI>
 * </UL>
 * Note that there is some inherent ambiguity in the string representations of
 * distinguished names.  In particular, there may be differences in spacing
 * (particularly around commas and equal signs, as well as plus signs in
 * multivalued RDNs), and also differences in capitalization in attribute names
 * and/or values.  For example, the strings
 * "{@code uid=john.doe,ou=people,dc=example,dc=com}" and
 * "{@code UID = JOHN.DOE , OU = PEOPLE , DC = EXAMPLE , DC = COM}" actually
 * refer to the same distinguished name.  To deal with these differences, the
 * normalized representation may be used.  The normalized representation is a
 * standardized way of representing a DN, and it is obtained by eliminating any
 * unnecessary spaces and converting all non-case-sensitive characters to
 * lowercase.  The normalized representation of a DN may be obtained using the
 * {@link DN#toNormalizedString} method, and two DNs may be compared to
 * determine if they are equal using the standard {@link DN#equals} method.
 * <BR><BR>
 * Distinguished names are hierarchical.  The rightmost RDN refers to the root
 * of the directory information tree (DIT), and each successive RDN to the left
 * indicates the addition of another level of hierarchy.  For example, in the
 * DN "{@code uid=john.doe,ou=People,o=example.com}", the entry
 * "{@code o=example.com}" is at the root of the DIT, the entry
 * "{@code ou=People,o=example.com}" is an immediate descendant of the
 * "{@code o=example.com}" entry, and the
 * "{@code uid=john.doe,ou=People,o=example.com}" entry is an immediate
 * descendant of the "{@code ou=People,o=example.com}" entry.  Similarly, the
 * entry "{@code uid=jane.doe,ou=People,o=example.com}" would be considered a
 * peer of the "{@code uid=john.doe,ou=People,o=example.com}" entry because they
 * have the same parent.
 * <BR><BR>
 * Note that in some cases, the root of the DIT may actually contain a DN with
 * multiple RDNs.  For example, in the DN
 * "{@code uid=john.doe,ou=People,dc=example,dc=com}", the directory server may
 * or may not actually have a "{@code dc=com}" entry.  In many such cases, the
 * base entry may actually be just "{@code dc=example,dc=com}".  The DNs of the
 * entries that are at the base of the directory information tree are called
 * "naming contexts" or "suffixes" and they are generally available in the
 * {@code namingContexts} attribute of the root DSE.  See the {@link RootDSE}
 * class for more information about interacting with the server root DSE.
 * <BR><BR>
 * This class provides methods for making determinations based on the
 * hierarchical relationships of DNs.  For example, the
 * {@link DN#isAncestorOf} and {@link DN#isDescendantOf} methods may be used to
 * determine whether two DNs have a hierarchical relationship.  In addition,
 * this class implements the {@link Comparable} and {@link Comparator}
 * interfaces so that it may be used to easily sort DNs (ancestors will always
 * be sorted before descendants, and peers will always be sorted
 * lexicographically based on their normalized representations).
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DN
       implements Comparable<DN>, Comparator<DN>, Serializable
{
  /**
   * The RDN array that will be used for the null DN.
   */
  @NotNull private static final RDN[] NO_RDNS = new RDN[0];



  /**
   * A pre-allocated DN object equivalent to the null DN.
   */
  @NotNull public static final DN NULL_DN = new DN();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5272968942085729346L;



  // The set of RDN components that make up this DN.
  @NotNull private final RDN[] rdns;

  // The schema to use to generate the normalized string representation of this
  // DN, if any.
  @Nullable private final Schema schema;

  // The string representation of this DN.
  @NotNull private final String dnString;

  // The normalized string representation of this DN.
  @Nullable private volatile String normalizedString;



  /**
   * Creates a new DN with the provided set of RDNs.
   *
   * @param  rdns  The RDN components for this DN.  It must not be {@code null}.
   */
  public DN(@NotNull final RDN... rdns)
  {
    Validator.ensureNotNull(rdns);

    this.rdns = rdns;
    if (rdns.length == 0)
    {
      dnString         = "";
      normalizedString = "";
      schema           = null;
    }
    else
    {
      Schema s = null;
      final StringBuilder buffer = new StringBuilder();
      for (final RDN rdn : rdns)
      {
        if (buffer.length() > 0)
        {
          buffer.append(',');
        }
        rdn.toString(buffer, false);

        if (s == null)
        {
          s = rdn.getSchema();
        }
      }

      dnString = buffer.toString();
      schema   = s;
    }
  }



  /**
   * Creates a new DN with the provided set of RDNs.
   *
   * @param  rdns  The RDN components for this DN.  It must not be {@code null}.
   */
  public DN(@NotNull final List<RDN> rdns)
  {
    Validator.ensureNotNull(rdns);

    if (rdns.isEmpty())
    {
      this.rdns        = NO_RDNS;
      dnString         = "";
      normalizedString = "";
      schema           = null;
    }
    else
    {
      this.rdns = rdns.toArray(new RDN[rdns.size()]);

      Schema s = null;
      final StringBuilder buffer = new StringBuilder();
      for (final RDN rdn : this.rdns)
      {
        if (buffer.length() > 0)
        {
          buffer.append(',');
        }
        rdn.toString(buffer, false);

        if (s == null)
        {
          s = rdn.getSchema();
        }
      }

      dnString = buffer.toString();
      schema   = s;
    }
  }



  /**
   * Creates a new DN below the provided parent DN with the given RDN.
   *
   * @param  rdn       The RDN for the new DN.  It must not be {@code null}.
   * @param  parentDN  The parent DN for the new DN to create.  It must not be
   *                   {@code null}.
   */
  public DN(@NotNull final RDN rdn, @NotNull final DN parentDN)
  {
    Validator.ensureNotNull(rdn, parentDN);

    rdns = new RDN[parentDN.rdns.length + 1];
    rdns[0] = rdn;
    System.arraycopy(parentDN.rdns, 0, rdns, 1, parentDN.rdns.length);

    Schema s = null;
    final StringBuilder buffer = new StringBuilder();
    for (final RDN r : rdns)
    {
      if (buffer.length() > 0)
      {
        buffer.append(',');
      }
      r.toString(buffer, false);

      if (s == null)
      {
        s = r.getSchema();
      }
    }

    dnString = buffer.toString();
    schema   = s;
  }



  /**
   * Creates a new DN from the provided string representation.
   *
   * @param  dnString  The string representation to use to create this DN.  It
   *                   must not be {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   */
  public DN(@NotNull final String dnString)
         throws LDAPException
  {
    this(dnString, null, false);
  }



  /**
   * Creates a new DN from the provided string representation.
   *
   * @param  dnString  The string representation to use to create this DN.  It
   *                   must not be {@code null}.
   * @param  schema    The schema to use to generate the normalized string
   *                   representation of this DN.  It may be {@code null} if no
   *                   schema is available.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   */
  public DN(@NotNull final String dnString, @Nullable final Schema schema)
         throws LDAPException
  {
    this(dnString, schema, false);
  }



  /**
   * Creates a new DN from the provided string representation.
   *
   * @param  dnString            The string representation to use to create this
   *                             DN.  It must not be {@code null}.
   * @param  schema              The schema to use to generate the normalized
   *                             string representation of this DN.  It may be
   *                             {@code null} if no schema is available.
   * @param  strictNameChecking  Indicates whether to verify that all attribute
   *                             type names are valid as per RFC 4514.  If this
   *                             is {@code false}, then some technically invalid
   *                             characters may be accepted in attribute type
   *                             names.  If this is {@code true}, then names
   *                             must be strictly compliant.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   */
  public DN(@NotNull final String dnString, @Nullable final Schema schema,
            final boolean strictNameChecking)
         throws LDAPException
  {
    Validator.ensureNotNull(dnString);

    this.dnString = dnString;
    this.schema   = schema;

    final ArrayList<RDN> rdnList = new ArrayList<>(5);

    final int length = dnString.length();
    if (length == 0)
    {
      rdns             = NO_RDNS;
      normalizedString = "";
      return;
    }

    int pos = 0;
    boolean expectMore = false;
rdnLoop:
    while (pos < length)
    {
      // Skip over any spaces before the attribute name.
      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if (pos >= length)
      {
        // This is only acceptable if we haven't read anything yet.
        if (rdnList.isEmpty())
        {
          break;
        }
        else
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_DN_ENDS_WITH_COMMA.get(dnString));
        }
      }

      // Read the attribute name, until we find a space or equal sign.
      int rdnEndPos;
      int attrStartPos = pos;
      final int rdnStartPos = pos;
      while (pos < length)
      {
        final char c = dnString.charAt(pos);
        if ((c == ' ') || (c == '='))
        {
          break;
        }
        else if ((c == ',') || (c == ';'))
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_DN_UNEXPECTED_COMMA.get(dnString, pos));
        }

        pos++;
      }

      String attrName = dnString.substring(attrStartPos, pos);
      if (attrName.isEmpty())
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_DN_NO_ATTR_IN_RDN.get(dnString));
      }

      if (strictNameChecking)
      {
        if (! (Attribute.nameIsValid(attrName) ||
             StaticUtils.isNumericOID(attrName)))
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_DN_INVALID_ATTR_NAME.get(dnString, attrName));
        }
      }


      // Skip over any spaces before the equal sign.
      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if ((pos >= length) || (dnString.charAt(pos) != '='))
      {
        // We didn't find an equal sign.
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_DN_NO_EQUAL_SIGN.get(dnString, attrName));
      }

      // Skip over the equal sign, and then any spaces leading up to the
      // attribute value.
      pos++;
      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }


      // Read the value for this RDN component.
      ASN1OctetString value;
      if (pos >= length)
      {
        value = new ASN1OctetString();
        rdnEndPos = pos;
      }
      else if (dnString.charAt(pos) == '#')
      {
        // It is a hex-encoded value, so we'll read until we find the end of the
        // string or the first non-hex character, which must be a space, a
        // comma, or a plus sign.  Then, parse the bytes of the hex-encoded
        // value as a BER element, and take the value of that element.
        final byte[] valueArray = RDN.readHexString(dnString, ++pos);

        try
        {
          value = ASN1OctetString.decodeAsOctetString(valueArray);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_HEX_STRING_NOT_BER_ENCODED.get(dnString, attrName), e);
        }

        pos += (valueArray.length * 2);
        rdnEndPos = pos;
      }
      else
      {
        // It is a string value, which potentially includes escaped characters.
        final StringBuilder buffer = new StringBuilder();
        pos = RDN.readValueString(dnString, pos, buffer);
        value = new ASN1OctetString(buffer.toString());
        rdnEndPos = pos;
      }


      // Skip over any spaces until we find a comma, a plus sign, or the end of
      // the value.
      while ((pos < length) && (dnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if (pos >= length)
      {
        // It's a single-valued RDN, and we're at the end of the DN.
        rdnList.add(new RDN(attrName, value, schema,
             getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
        expectMore = false;
        break;
      }

      switch (dnString.charAt(pos))
      {
        case '+':
          // It is a multivalued RDN, so we're not done reading either the DN
          // or the RDN.
          pos++;
          break;

        case ',':
        case ';':
          // We hit the end of the single-valued RDN, but there's still more of
          // the DN to be read.
          rdnList.add(new RDN(attrName, value, schema,
               getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
          pos++;
          expectMore = true;
          continue rdnLoop;

        default:
          // It's an illegal character.  This should never happen.
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_DN_UNEXPECTED_CHAR.get(dnString, dnString.charAt(pos), pos));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_DN_ENDS_WITH_PLUS.get(dnString));
      }


      // If we've gotten here, then we're dealing with a multivalued RDN.
      // Create lists to hold the names and values, and then loop until we hit
      // the end of the RDN.
      final ArrayList<String> nameList = new ArrayList<>(5);
      final ArrayList<ASN1OctetString> valueList = new ArrayList<>(5);
      nameList.add(attrName);
      valueList.add(value);

      while (pos < length)
      {
        // Skip over any spaces before the attribute name.
        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }

        if (pos >= length)
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_DN_ENDS_WITH_PLUS.get(dnString));
        }

        // Read the attribute name, until we find a space or equal sign.
        attrStartPos = pos;
        while (pos < length)
        {
          final char c = dnString.charAt(pos);
          if ((c == ' ') || (c == '='))
          {
            break;
          }
          else if ((c == ',') || (c == ';'))
          {
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                 ERR_DN_UNEXPECTED_COMMA.get(dnString, pos));
          }

          pos++;
        }

        attrName = dnString.substring(attrStartPos, pos);
        if (attrName.isEmpty())
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_DN_NO_ATTR_IN_RDN.get(dnString));
        }

        if (strictNameChecking)
        {
          if (! (Attribute.nameIsValid(attrName) ||
               StaticUtils.isNumericOID(attrName)))
          {
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                 ERR_DN_INVALID_ATTR_NAME.get(dnString, attrName));
          }
        }


        // Skip over any spaces before the equal sign.
        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }

        if ((pos >= length) || (dnString.charAt(pos) != '='))
        {
          // We didn't find an equal sign.
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_DN_NO_EQUAL_SIGN.get(dnString, attrName));
        }

        // Skip over the equal sign, and then any spaces leading up to the
        // attribute value.
        pos++;
        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }


        // Read the value for this RDN component.
        if (pos >= length)
        {
          value = new ASN1OctetString();
          rdnEndPos = pos;
        }
        else if (dnString.charAt(pos) == '#')
        {
          // It is a hex-encoded value, so we'll read until we find the end of
          // the string or the first non-hex character, which must be a space, a
          // comma, or a plus sign.  Then, parse the bytes of the hex-encoded
          // value as a BER element, and take the value of that element.
          final byte[] valueArray = RDN.readHexString(dnString, ++pos);

          try
          {
            value = ASN1OctetString.decodeAsOctetString(valueArray);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                 ERR_RDN_HEX_STRING_NOT_BER_ENCODED.get(dnString, attrName), e);
          }

          pos += (valueArray.length * 2);
          rdnEndPos = pos;
        }
        else
        {
          // It is a string value, which potentially includes escaped
          // characters.
          final StringBuilder buffer = new StringBuilder();
          pos = RDN.readValueString(dnString, pos, buffer);
          value = new ASN1OctetString(buffer.toString());
          rdnEndPos = pos;
        }


        // Skip over any spaces until we find a comma, a plus sign, or the end
        // of the value.
        while ((pos < length) && (dnString.charAt(pos) == ' '))
        {
          pos++;
        }

        nameList.add(attrName);
        valueList.add(value);

        if (pos >= length)
        {
          // We've hit the end of the RDN and the end of the DN.
          final String[] names = nameList.toArray(new String[nameList.size()]);
          final ASN1OctetString[] values =
               valueList.toArray(new ASN1OctetString[valueList.size()]);
          rdnList.add(new RDN(names, values, schema,
               getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
          expectMore = false;
          break rdnLoop;
        }

        switch (dnString.charAt(pos))
        {
          case '+':
            // There are still more RDN components to be read, so we're not done
            // yet.
            pos++;

            if (pos >= length)
            {
              throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                   ERR_DN_ENDS_WITH_PLUS.get(dnString));
            }
            break;

          case ',':
          case ';':
            // We've hit the end of the RDN, but there is still more of the DN
            // to be read.
            final String[] names =
                 nameList.toArray(new String[nameList.size()]);
            final ASN1OctetString[] values =
                 valueList.toArray(new ASN1OctetString[valueList.size()]);
            rdnList.add(new RDN(names, values, schema,
                 getTrimmedRDN(dnString, rdnStartPos,rdnEndPos)));
            pos++;
            expectMore = true;
            continue rdnLoop;

          default:
            // It's an illegal character.  This should never happen.
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                 ERR_DN_UNEXPECTED_CHAR.get(dnString, dnString.charAt(pos),
                      pos));
        }
      }
    }

    // If we are expecting more information to be provided, then it means that
    // the string ended with a comma or semicolon.
    if (expectMore)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_DN_ENDS_WITH_COMMA.get(dnString));
    }

    // At this point, we should have all of the RDNs to use to create this DN.
    rdns = new RDN[rdnList.size()];
    rdnList.toArray(rdns);
  }



  /**
   * Retrieves a trimmed version of the string representation of the RDN in the
   * specified portion of the provided DN string.  Only non-escaped trailing
   * spaces will be removed.
   *
   * @param  dnString  The string representation of the DN from which to extract
   *                   the string representation of the RDN.
   * @param  start     The position of the first character in the RDN.
   * @param  end       The position marking the end of the RDN.
   *
   * @return  A properly-trimmed string representation of the RDN.
   */
  @NotNull()
  private static String getTrimmedRDN(@NotNull final String dnString,
                                      final int start, final int end)
  {
    final String rdnString = dnString.substring(start, end);
    if (! rdnString.endsWith(" "))
    {
      return rdnString;
    }

    final StringBuilder buffer = new StringBuilder(rdnString);
    while ((buffer.charAt(buffer.length() - 1) == ' ') &&
           (buffer.charAt(buffer.length() - 2) != '\\'))
    {
      buffer.setLength(buffer.length() - 1);
    }

    return buffer.toString();
  }



  /**
   * Indicates whether the provided string represents a valid DN.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string represents a valid DN, or
   *          {@code false} if not.
   */
  public static boolean isValidDN(@NotNull final String s)
  {
    return isValidDN(s, false);
  }



  /**
   * Indicates whether the provided string represents a valid DN.
   *
   * @param  s                   The string for which to make the determination.
   *                             It must not be {@code null}.
   * @param  strictNameChecking  Indicates whether to verify that all attribute
   *                             type names are valid as per RFC 4514.  If this
   *                             is {@code false}, then some technically invalid
   *                             characters may be accepted in attribute type
   *                             names.  If this is {@code true}, then names
   *                             must be strictly compliant.
   *
   * @return  {@code true} if the provided string represents a valid DN, or
   *          {@code false} if not.
   */
  public static boolean isValidDN(@NotNull final String s,
                                  final boolean strictNameChecking)
  {
    try
    {
      new DN(s, null, strictNameChecking);
      return true;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return false;
    }
  }



  /**
   * Retrieves the leftmost (i.e., furthest from the naming context) RDN
   * component for this DN.
   *
   * @return  The leftmost RDN component for this DN, or {@code null} if this DN
   *          does not have any RDNs (i.e., it is the null DN).
   */
  @Nullable()
  public RDN getRDN()
  {
    if (rdns.length == 0)
    {
      return null;
    }
    else
    {
      return rdns[0];
    }
  }



  /**
   * Retrieves the string representation of the leftmost (i.e., furthest from
   * the naming context) RDN component for this DN.
   *
   * @return  The string representation of the leftmost RDN component for this
   *          DN, or {@code null} if this DN does not have any RDNs (i.e., it is
   *          the null DN).
   */
  @Nullable()
  public String getRDNString()
  {
    if (rdns.length == 0)
    {
      return null;
    }
    else
    {
      return rdns[0].toString();
    }
  }



  /**
   * Retrieves the string representation of the leftmost (i.e., furthest from
   * the naming context) RDN component for the DN with the provided string
   * representation.
   *
   * @param  s  The string representation of the DN to process.  It must not be
   *            {@code null}.
   *
   * @return  The string representation of the leftmost RDN component for this
   *          DN, or {@code null} if this DN does not have any RDNs (i.e., it is
   *          the null DN).
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  @Nullable()
  public static String getRDNString(@NotNull final String s)
         throws LDAPException
  {
    return new DN(s).getRDNString();
  }



  /**
   * Retrieves the set of RDNs that comprise this DN.
   *
   * @return  The set of RDNs that comprise this DN.
   */
  @NotNull()
  public RDN[] getRDNs()
  {
    return rdns;
  }



  /**
   * Retrieves the set of RDNs that comprise the DN with the provided string
   * representation.
   *
   * @param  s  The string representation of the DN for which to retrieve the
   *            RDNs.  It must not be {@code null}.
   *
   * @return  The set of RDNs that comprise the DN with the provided string
   *          representation.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  @NotNull()
  public static RDN[] getRDNs(@NotNull final String s)
         throws LDAPException
  {
    return new DN(s).getRDNs();
  }



  /**
   * Retrieves the set of string representations of the RDNs that comprise this
   * DN.
   *
   * @return  The set of string representations of the RDNs that comprise this
   *          DN.
   */
  @NotNull()
  public String[] getRDNStrings()
  {
    final String[] rdnStrings = new String[rdns.length];
    for (int i=0; i < rdns.length; i++)
    {
      rdnStrings[i] = rdns[i].toString();
    }
    return rdnStrings;
  }



  /**
   * Retrieves the set of string representations of the RDNs that comprise this
   * DN.
   *
   * @param  s  The string representation of the DN for which to retrieve the
   *            RDN strings.  It must not be {@code null}.
   *
   * @return  The set of string representations of the RDNs that comprise this
   *          DN.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  @NotNull()
  public static String[] getRDNStrings(@NotNull final String s)
         throws LDAPException
  {
    return new DN(s).getRDNStrings();
  }



  /**
   * Indicates whether this DN represents the null DN, which does not have any
   * RDN components.
   *
   * @return  {@code true} if this DN represents the null DN, or {@code false}
   *          if not.
   */
  public boolean isNullDN()
  {
    return (rdns.length == 0);
  }



  /**
   * Retrieves the DN that is the parent for this DN.  Note that neither the
   * null DN nor DNs consisting of a single RDN component will be considered to
   * have parent DNs.
   *
   * @return  The DN that is the parent for this DN, or {@code null} if there
   *          is no parent.
   */
  @Nullable()
  public DN getParent()
  {
    switch (rdns.length)
    {
      case 0:
      case 1:
        return null;

      case 2:
        return new DN(rdns[1]);

      case 3:
        return new DN(rdns[1], rdns[2]);

      case 4:
        return new DN(rdns[1], rdns[2], rdns[3]);

      case 5:
        return new DN(rdns[1], rdns[2], rdns[3], rdns[4]);

      default:
        final RDN[] parentRDNs = new RDN[rdns.length - 1];
        System.arraycopy(rdns, 1, parentRDNs, 0, parentRDNs.length);
        return new DN(parentRDNs);
    }
  }



  /**
   * Retrieves the DN that is the parent for the DN with the provided string
   * representation.  Note that neither the null DN nor DNs consisting of a
   * single RDN component will be considered to have parent DNs.
   *
   * @param  s  The string representation of the DN for which to retrieve the
   *            parent.  It must not be {@code null}.
   *
   * @return  The DN that is the parent for this DN, or {@code null} if there
   *          is no parent.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  @Nullable()
  public static DN getParent(@NotNull final String s)
         throws LDAPException
  {
    return new DN(s).getParent();
  }



  /**
   * Retrieves the string representation of the DN that is the parent for this
   * DN.  Note that neither the null DN nor DNs consisting of a single RDN
   * component will be considered to have parent DNs.
   *
   * @return  The DN that is the parent for this DN, or {@code null} if there
   *          is no parent.
   */
  @Nullable()
  public String getParentString()
  {
    final DN parentDN = getParent();
    if (parentDN == null)
    {
      return null;
    }
    else
    {
      return parentDN.toString();
    }
  }



  /**
   * Retrieves the string representation of the DN that is the parent for the
   * DN with the provided string representation.  Note that neither the null DN
   * nor DNs consisting of a single RDN component will be considered to have
   * parent DNs.
   *
   * @param  s  The string representation of the DN for which to retrieve the
   *            parent.  It must not be {@code null}.
   *
   * @return  The DN that is the parent for this DN, or {@code null} if there
   *          is no parent.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  @Nullable()
  public static String getParentString(@NotNull final String s)
         throws LDAPException
  {
    return new DN(s).getParentString();
  }



  /**
   * Indicates whether this DN is an ancestor of the provided DN.  It will be
   * considered an ancestor of the provided DN if the array of RDN components
   * for the provided DN ends with the elements that comprise the array of RDN
   * components for this DN (i.e., if the provided DN is subordinate to, or
   * optionally equal to, this DN).  The null DN will be considered an ancestor
   * for all other DNs (with the exception of the null DN if {@code allowEquals}
   * is {@code false}).
   *
   * @param  dn           The DN for which to make the determination.
   * @param  allowEquals  Indicates whether a DN should be considered an
   *                      ancestor of itself.
   *
   * @return  {@code true} if this DN may be considered an ancestor of the
   *          provided DN, or {@code false} if not.
   */
  public boolean isAncestorOf(@NotNull final DN dn, final boolean allowEquals)
  {
    int thisPos = rdns.length - 1;
    int thatPos = dn.rdns.length - 1;

    if (thisPos < 0)
    {
      // This DN must be the null DN, which is an ancestor for all other DNs
      // (and equal to the null DN, which we may still classify as being an
      // ancestor).
      return (allowEquals || (thatPos >= 0));
    }

    if ((thisPos > thatPos) || ((thisPos == thatPos) && (! allowEquals)))
    {
      // This DN has more RDN components than the provided DN, so it can't
      // possibly be an ancestor, or has the same number of components and equal
      // DNs shouldn't be considered ancestors.
      return false;
    }

    while (thisPos >= 0)
    {
      if (! rdns[thisPos--].equals(dn.rdns[thatPos--]))
      {
        return false;
      }
    }

    // If we've gotten here, then we can consider this DN to be an ancestor of
    // the provided DN.
    return true;
  }



  /**
   * Indicates whether this DN is an ancestor of the DN with the provided string
   * representation.  It will be considered an ancestor of the provided DN if
   * the array of RDN components for the provided DN ends with the elements that
   * comprise the array of RDN components for this DN (i.e., if the provided DN
   * is subordinate to, or optionally equal to, this DN).  The null DN will be
   * considered an ancestor for all other DNs (with the exception of the null DN
   * if {@code allowEquals} is {@code false}).
   *
   * @param  s            The string representation of the DN for which to make
   *                      the determination.
   * @param  allowEquals  Indicates whether a DN should be considered an
   *                      ancestor of itself.
   *
   * @return  {@code true} if this DN may be considered an ancestor of the
   *          provided DN, or {@code false} if not.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  public boolean isAncestorOf(@NotNull final String s,
                              final boolean allowEquals)
         throws LDAPException
  {
    return isAncestorOf(new DN(s), allowEquals);
  }



  /**
   * Indicates whether the DN represented by the first string is an ancestor of
   * the DN represented by the second string.  The first DN will be considered
   * an ancestor of the second DN if the array of RDN components for the first
   * DN ends with the elements that comprise the array of RDN components for the
   * second DN (i.e., if the first DN is subordinate to, or optionally equal to,
   * the second DN).  The null DN will be considered an ancestor for all other
   * DNs (with the exception of the null DN if {@code allowEquals} is
   * {@code false}).
   *
   * @param  s1           The string representation of the first DN for which to
   *                      make the determination.
   * @param  s2           The string representation of the second DN for which
   *                      to make the determination.
   * @param  allowEquals  Indicates whether a DN should be considered an
   *                      ancestor of itself.
   *
   * @return  {@code true} if the first DN may be considered an ancestor of the
   *          second DN, or {@code false} if not.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as a DN.
   */
  public static boolean isAncestorOf(@NotNull final String s1,
                                     @NotNull final String s2,
                                     final boolean allowEquals)
         throws LDAPException
  {
    return new DN(s1).isAncestorOf(new DN(s2), allowEquals);
  }



  /**
   * Indicates whether this DN is a descendant of the provided DN.  It will be
   * considered a descendant of the provided DN if the array of RDN components
   * for this DN ends with the elements that comprise the RDN components for the
   * provided DN (i.e., if this DN is subordinate to, or optionally equal to,
   * the provided DN).  The null DN will not be considered a descendant for any
   * other DNs (with the exception of the null DN if {@code allowEquals} is
   * {@code true}).
   *
   * @param  dn           The DN for which to make the determination.
   * @param  allowEquals  Indicates whether a DN should be considered a
   *                      descendant of itself.
   *
   * @return  {@code true} if this DN may be considered a descendant of the
   *          provided DN, or {@code false} if not.
   */
  public boolean isDescendantOf(@NotNull final DN dn, final boolean allowEquals)
  {
    int thisPos = rdns.length - 1;
    int thatPos = dn.rdns.length - 1;

    if (thatPos < 0)
    {
      // The provided DN must be the null DN, which will be considered an
      // ancestor for all other DNs (and equal to the null DN), making this DN
      // considered a descendant for that DN.
      return (allowEquals || (thisPos >= 0));
    }

    if ((thisPos < thatPos) || ((thisPos == thatPos) && (! allowEquals)))
    {
      // This DN has fewer DN components than the provided DN, so it can't
      // possibly be a descendant, or it has the same number of components and
      // equal DNs shouldn't be considered descendants.
      return false;
    }

    while (thatPos >= 0)
    {
      if (! rdns[thisPos--].equals(dn.rdns[thatPos--]))
      {
        return false;
      }
    }

    // If we've gotten here, then we can consider this DN to be a descendant of
    // the provided DN.
    return true;
  }



  /**
   * Indicates whether this DN is a descendant of the DN with the provided
   * string representation.  It will be considered a descendant of the provided
   * DN if the array of RDN components for this DN ends with the elements that
   * comprise the RDN components for the provided DN (i.e., if this DN is
   * subordinate to, or optionally equal to, the provided DN).  The null DN will
   * not be considered a descendant for any other DNs (with the exception of the
   * null DN if {@code allowEquals} is {@code true}).
   *
   * @param  s            The string representation of the DN for which to make
   *                      the determination.
   * @param  allowEquals  Indicates whether a DN should be considered a
   *                      descendant of itself.
   *
   * @return  {@code true} if this DN may be considered a descendant of the
   *          provided DN, or {@code false} if not.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  public boolean isDescendantOf(@NotNull final String s,
                                final boolean allowEquals)
         throws LDAPException
  {
    return isDescendantOf(new DN(s), allowEquals);
  }



  /**
   * Indicates whether the DN represented by the first string is a descendant of
   * the DN represented by the second string.  The first DN will be considered a
   * descendant of the second DN if the array of RDN components for the first DN
   * ends with the elements that comprise the RDN components for the second DN
   * (i.e., if the first DN is subordinate to, or optionally equal to, the
   * second DN).  The null DN will not be considered a descendant for any other
   * DNs (with the exception of the null DN if {@code allowEquals} is
   * {@code true}).
   *
   * @param  s1           The string representation of the first DN for which to
   *                      make the determination.
   * @param  s2           The string representation of the second DN for which
   *                      to make the determination.
   * @param  allowEquals  Indicates whether a DN should be considered an
   *                      ancestor of itself.
   *
   * @return  {@code true} if this DN may be considered a descendant of the
   *          provided DN, or {@code false} if not.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as a DN.
   */
  public static boolean isDescendantOf(@NotNull final String s1,
                                       @NotNull final String s2,
                                       final boolean allowEquals)
         throws LDAPException
  {
    return new DN(s1).isDescendantOf(new DN(s2), allowEquals);
  }



  /**
   * Indicates whether this DN falls within the range of the provided search
   * base DN and scope.
   *
   * @param  baseDN  The base DN for which to make the determination.  It must
   *                 not be {@code null}.
   * @param  scope   The scope for which to make the determination.  It must not
   *                 be {@code null}.
   *
   * @return  {@code true} if this DN is within the range of the provided base
   *          and scope, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while making the determination.
   */
  public boolean matchesBaseAndScope(@NotNull final String baseDN,
                                     @NotNull final SearchScope scope)
         throws LDAPException
  {
    return matchesBaseAndScope(new DN(baseDN), scope);
  }



  /**
   * Indicates whether this DN falls within the range of the provided search
   * base DN and scope.
   *
   * @param  baseDN  The base DN for which to make the determination.  It must
   *                 not be {@code null}.
   * @param  scope   The scope for which to make the determination.  It must not
   *                 be {@code null}.
   *
   * @return  {@code true} if this DN is within the range of the provided base
   *          and scope, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while making the determination.
   */
  public boolean matchesBaseAndScope(@NotNull final DN baseDN,
                                     @NotNull final SearchScope scope)
         throws LDAPException
  {
    Validator.ensureNotNull(baseDN, scope);

    switch (scope.intValue())
    {
      case SearchScope.BASE_INT_VALUE:
        return equals(baseDN);

      case SearchScope.ONE_INT_VALUE:
        return baseDN.equals(getParent());

      case SearchScope.SUB_INT_VALUE:
        return isDescendantOf(baseDN, true);

      case SearchScope.SUBORDINATE_SUBTREE_INT_VALUE:
        return isDescendantOf(baseDN, false);

      default:
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_DN_MATCHES_UNSUPPORTED_SCOPE.get(dnString,
                  String.valueOf(scope)));
    }
  }



  /**
   * Generates a hash code for this DN.
   *
   * @return  The generated hash code for this DN.
   */
  @Override() public int hashCode()
  {
    return toNormalizedString().hashCode();
  }



  /**
   * Indicates whether the provided object is equal to this DN.  In order for
   * the provided object to be considered equal, it must be a non-null DN with
   * the same set of RDN components.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          DN, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (this == o)
    {
      return true;
    }

    if (! (o instanceof DN))
    {
      return false;
    }

    final DN dn = (DN) o;
    return (toNormalizedString().equals(dn.toNormalizedString()));
  }



  /**
   * Indicates whether the DN with the provided string representation is equal
   * to this DN.
   *
   * @param  s  The string representation of the DN to compare with this DN.
   *
   * @return  {@code true} if the DN with the provided string representation is
   *          equal to this DN, or {@code false} if not.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  public boolean equals(@Nullable final String s)
         throws LDAPException
  {
    if (s == null)
    {
      return false;
    }

    return equals(new DN(s));
  }



  /**
   * Indicates whether the two provided strings represent the same DN.
   *
   * @param  s1  The string representation of the first DN for which to make the
   *             determination.  It must not be {@code null}.
   * @param  s2  The string representation of the second DN for which to make
   *             the determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the provided strings represent the same DN, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as a DN.
   */
  public static boolean equals(@NotNull final String s1,
                               @NotNull final String s2)
         throws LDAPException
  {
    return new DN(s1).equals(new DN(s2));
  }



  /**
   * Indicates whether the two provided strings represent the same DN.
   *
   * @param  s1      The string representation of the first DN for which to make
   *                 the determination.  It must not be {@code null}.
   * @param  s2      The string representation of the second DN for which to
   *                 make the determination.  It must not be {@code null}.
   * @param  schema  The schema to use while making the determination.  It may
   *                 be {@code null} if no schema is available.
   *
   * @return  {@code true} if the provided strings represent the same DN, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as a DN.
   */
  public static boolean equals(@NotNull final String s1,
                               @NotNull final String s2,
                               @Nullable final Schema schema)
         throws LDAPException
  {
    return new DN(s1, schema).equals(new DN(s2, schema));
  }



  /**
   * Retrieves a string representation of this DN.
   *
   * @return  A string representation of this DN.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return dnString;
  }



  /**
   * Retrieves a string representation of this DN with minimal encoding for
   * special characters.  Only those characters specified in RFC 4514 section
   * 2.4 will be escaped.  No escaping will be used for non-ASCII characters or
   * non-printable ASCII characters.
   *
   * @return  A string representation of this DN with minimal encoding for
   *          special characters.
   */
  @NotNull()
  public String toMinimallyEncodedString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer, true);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this DN to the provided buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this DN.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    toString(buffer, false);
  }



  /**
   * Appends a string representation of this DN to the provided buffer.
   *
   * @param  buffer            The buffer to which the string representation is
   *                           to be appended.
   * @param  minimizeEncoding  Indicates whether to restrict the encoding of
   *                           special characters to the bare minimum required
   *                           by LDAP (as per RFC 4514 section 2.4).  If this
   *                           is {@code true}, then only leading and trailing
   *                           spaces, double quotes, plus signs, commas,
   *                           semicolons, greater-than, less-than, and
   *                           backslash characters will be encoded.
   */
  public void toString(@NotNull final StringBuilder buffer,
                       final boolean minimizeEncoding)
  {
    for (int i=0; i < rdns.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      rdns[i].toString(buffer, minimizeEncoding);
    }
  }



  /**
   * Retrieves a normalized string representation of this DN.
   *
   * @return  A normalized string representation of this DN.
   */
  @NotNull()
  public String toNormalizedString()
  {
    if (normalizedString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toNormalizedString(buffer);
      normalizedString = buffer.toString();
    }

    return normalizedString;
  }



  /**
   * Appends a normalized string representation of this DN to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append the normalized string
   *                 representation of this DN.
   */
  public void toNormalizedString(@NotNull final StringBuilder buffer)
  {
    for (int i=0; i < rdns.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      buffer.append(rdns[i].toNormalizedString());
    }
  }



  /**
   * Retrieves a normalized representation of the DN with the provided string
   * representation.
   *
   * @param  s  The string representation of the DN to normalize.  It must not
   *            be {@code null}.
   *
   * @return  The normalized representation of the DN with the provided string
   *          representation.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  @NotNull()
  public static String normalize(@NotNull final String s)
         throws LDAPException
  {
    return normalize(s, null);
  }



  /**
   * Retrieves a normalized representation of the DN with the provided string
   * representation.
   *
   * @param  s       The string representation of the DN to normalize.  It must
   *                 not be {@code null}.
   * @param  schema  The schema to use to generate the normalized string
   *                 representation of the DN.  It may be {@code null} if no
   *                 schema is available.
   *
   * @return  The normalized representation of the DN with the provided string
   *          representation.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a DN.
   */
  @NotNull()
  public static String normalize(@NotNull final String s,
                                 @Nullable final Schema schema)
         throws LDAPException
  {
    return new DN(s, schema).toNormalizedString();
  }



  /**
   * Compares the provided DN to this DN to determine their relative order in
   * a sorted list.
   *
   * @param  dn  The DN to compare against this DN.  It must not be
   *             {@code null}.
   *
   * @return  A negative integer if this DN should come before the provided DN
   *          in a sorted list, a positive integer if this DN should come after
   *          the provided DN in a sorted list, or zero if the provided DN can
   *          be considered equal to this DN.
   */
  @Override()
  public int compareTo(@NotNull final DN dn)
  {
    return compare(this, dn);
  }



  /**
   * Compares the provided DN values to determine their relative order in a
   * sorted list.
   *
   * @param  dn1  The first DN to be compared.  It must not be {@code null}.
   * @param  dn2  The second DN to be compared.  It must not be {@code null}.
   *
   * @return  A negative integer if the first DN should come before the second
   *          DN in a sorted list, a positive integer if the first DN should
   *          come after the second DN in a sorted list, or zero if the two DN
   *          values can be considered equal.
   */
  @Override()
  public int compare(@NotNull final DN dn1, @NotNull final DN dn2)
  {
    Validator.ensureNotNull(dn1, dn2);

    // We want the comparison to be in reverse order, so that DNs will be sorted
    // hierarchically.
    int pos1 = dn1.rdns.length - 1;
    int pos2 = dn2.rdns.length - 1;
    if (pos1 < 0)
    {
      if (pos2 < 0)
      {
        // Both DNs are the null DN, so they are equal.
        return 0;
      }
      else
      {
        // The first DN is the null DN and the second isn't, so the first DN
        // comes first.
        return -1;
      }
    }
    else if (pos2 < 0)
    {
      // The second DN is the null DN, which always comes first.
      return 1;
    }


    while ((pos1 >= 0) && (pos2 >= 0))
    {
      final int compValue = dn1.rdns[pos1].compareTo(dn2.rdns[pos2]);
      if (compValue != 0)
      {
        return compValue;
      }

      pos1--;
      pos2--;
    }


    // If we've gotten here, then one of the DNs is equal to or a descendant of
    // the other.
    if (pos1 < 0)
    {
      if (pos2 < 0)
      {
        // They're both the same length, so they should be considered equal.
        return 0;
      }
      else
      {
        // The first is shorter than the second, so it should come first.
        return -1;
      }
    }
    else
    {
      // The second RDN is shorter than the first, so it should come first.
      return 1;
    }
  }



  /**
   * Compares the DNs with the provided string representations to determine
   * their relative order in a sorted list.
   *
   * @param  s1  The string representation for the first DN to be compared.  It
   *             must not be {@code null}.
   * @param  s2  The string representation for the second DN to be compared.  It
   *             must not be {@code null}.
   *
   * @return  A negative integer if the first DN should come before the second
   *          DN in a sorted list, a positive integer if the first DN should
   *          come after the second DN in a sorted list, or zero if the two DN
   *          values can be considered equal.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as a DN.
   */
  public static int compare(@NotNull final String s1, @NotNull final String s2)
         throws LDAPException
  {
    return compare(s1, s2, null);
  }



  /**
   * Compares the DNs with the provided string representations to determine
   * their relative order in a sorted list.
   *
   * @param  s1      The string representation for the first DN to be compared.
   *                 It must not be {@code null}.
   * @param  s2      The string representation for the second DN to be compared.
   *                 It must not be {@code null}.
   * @param  schema  The schema to use to generate the normalized string
   *                 representations of the DNs.  It may be {@code null} if no
   *                 schema is available.
   *
   * @return  A negative integer if the first DN should come before the second
   *          DN in a sorted list, a positive integer if the first DN should
   *          come after the second DN in a sorted list, or zero if the two DN
   *          values can be considered equal.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as a DN.
   */
  public static int compare(@NotNull final String s1,
                            @NotNull final String s2,
                            @Nullable final Schema schema)
         throws LDAPException
  {
    return new DN(s1, schema).compareTo(new DN(s2, schema));
  }
}
