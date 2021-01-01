/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ReadOnlyEntry;



/**
 * This class provides a simple implementation of a move subtree listener that
 * can be used for testing purposes.
 */
public final class TestMoveSubtreeListener
       implements MoveSubtreeListener
{
  private boolean preAddCalled;
  private boolean postAddCalled;
  private boolean preDeleteCalled;
  private boolean postDeleteCalled;



  /**
   * Creates a new instance of this listener.
   */
  public TestMoveSubtreeListener()
  {
    preAddCalled     = false;
    postAddCalled    = false;
    preDeleteCalled  = false;
    postDeleteCalled = false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ReadOnlyEntry doPreAddProcessing(final ReadOnlyEntry entry)
  {
    preAddCalled = true;
    return entry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doPostAddProcessing(final ReadOnlyEntry entry)
  {
    postAddCalled = true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doPreDeleteProcessing(final DN entryDN)
  {
    preDeleteCalled = true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doPostDeleteProcessing(final DN entryDN)
  {
    postDeleteCalled = true;
  }



  /**
   * Indicates whether the pre-add method was called.
   *
   * @return  Whether the pre-add method was called.
   */
  public boolean preAddCalled()
  {
    return preAddCalled;
  }



  /**
   * Indicates whether the post-add method was called.
   *
   * @return  Whether the post-add method was called.
   */
  public boolean postAddCalled()
  {
    return postAddCalled;
  }



  /**
   * Indicates whether the pre-delete method was called.
   *
   * @return  Whether the pre-delete method was called.
   */
  public boolean preDeleteCalled()
  {
    return preDeleteCalled;
  }



  /**
   * Indicates whether the post-delete method was called.
   *
   * @return  Whether the post-delete method was called.
   */
  public boolean postDeleteCalled()
  {
    return postDeleteCalled;
  }
}
