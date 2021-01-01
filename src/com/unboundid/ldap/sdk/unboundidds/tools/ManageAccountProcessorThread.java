/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedRequest;
import com.unboundid.util.NotNull;



/**
 * This class provides a thread that may be used to parallelize the process of
 * invoking password policy state operations.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
final class ManageAccountProcessorThread
       extends Thread
{
  // The manage-account processor that will actually do the majority of the
  // work.
  @NotNull private final ManageAccountProcessor processor;



  /**
   * Creates a new manage-account processor thread with the provided
   * information.
   *
   * @param  threadNumber  The thread number for this thread.  This will only be
   *                       used for informational purposes in the thread name.
   * @param  processor     The manage-account processor that will actually do
   *                       the majority of the work.  It must not be
   *                       {@code null}.
   */
  ManageAccountProcessorThread(final int threadNumber,
                               @NotNull final ManageAccountProcessor processor)
  {
    setName("manage-account Processor Thread " + threadNumber);

    this.processor = processor;
  }



  /**
   * Performs the processing for this thread.
   */
  @Override()
  public void run()
  {
    while (true)
    {
      final PasswordPolicyStateExtendedRequest request =
           processor.getRequest();
      if (request == null)
      {
        return;
      }
      else
      {
        processor.process(request);
      }
    }
  }
}
