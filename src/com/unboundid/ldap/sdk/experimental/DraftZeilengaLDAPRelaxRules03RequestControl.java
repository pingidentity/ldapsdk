/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class provides an implementation of the LDAP relax rules request control
 * as defined in draft-zeilenga-ldap-relax-03.  This control may be included in
 * LDAP update (including add, delete, modify, and modify DN) requests to
 * indicate that the server should relax its enforcement of certain constraints
 * for that update operation.  Such constraints that may be relaxed include:
 * <UL>
 *   <LI>
 *     The restriction that prevents changing an entry's structural object
 *     class.
 *   </LI>
 *   <LI>
 *     The restriction that prevents clients from altering the values of
 *     attributes defined with the NO-USER-MODIFICATION constraint.
 *   </LI>
 *   <LI>
 *     The restriction that prevents using attributes defined with the
 *     OBSOLETE constraint.
 *   </LI>
 *   <LI>
 *     The restriction that prevents including an auxiliary object class in an
 *     entry when that class is prohibited by a DIT content rule.
 *   </LI>
 *   <LI>
 *     The restriction that prevents including an attribute in an entry when
 *     that attribute is prohibited by a DIT content rule.
 *   </LI>
 *   <LI>
 *     The restriction that prevents adding a subordinate entry whose structural
 *     class does not satisfy the DIT structure rule that governs the parent
 *     entry.
 *   </LI>
 *   <LI>
 *     The restriction that prevents adding an entry with RDN attributes that do
 *     not satisfy the governing name form.
 *   </LI>
 *   <LI>
 *     The restriction that prevents altering entries that currently do not
 *     conform to the server schema in some way in a manner that does not fix
 *     the relevant schema conformance issues.
 *   </LI>
 * </UL>
 * <BR><BR>
 * Note that at the time this control was written, the latest version of the
 * specification may be found in draft-zeilenga-ldap-relax-03.  This version of
 * the document does not explicitly specify the OID that should be used for the
 * control.  Until such time as this OID is officially defined, this
 * implementation uses the OID temporarily assigned for its use by the OpenLDAP
 * Foundation, which is used by at least the OpenLDAP and ForgeRock servers.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftZeilengaLDAPRelaxRules03RequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.4203.666.5.12) for the LDAP relax rules request
   * control.
   */
  @NotNull
  public static final String RELAX_RULES_REQUEST_OID =
       "1.3.6.1.4.1.4203.666.5.12";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -945892512562705359L;



  /**
   * Creates a new relax rules request control.  It will be marked critical, as
   * required by the control specification.
   */
  public DraftZeilengaLDAPRelaxRules03RequestControl()
  {
    super(RELAX_RULES_REQUEST_OID, true, null);
  }



  /**
   * Creates a new relax rules request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a relax rules request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         relax rules request control.
   */
  public DraftZeilengaLDAPRelaxRules03RequestControl(
              @NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_RELAX_RULES_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_RELAX_RULES_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RelaxRulesRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
