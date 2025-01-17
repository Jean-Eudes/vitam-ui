/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2019-2020)
 * and the signatories of the "VITAM - Accord du Contributeur" agreement.
 *
 * contact@programmevitam.fr
 *
 * This software is a computer program whose purpose is to implement
 * implement a digital archiving front-office system for the secure and
 * efficient high volumetry VITAM solution.
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 */
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';
import { EMPTY } from 'rxjs';
import { tap } from 'rxjs/operators';
import { User } from 'ui-frontend-common';
import {
  BaseUserInfoApiService, SearchService
} from 'ui-frontend-common';

import { UserInfo } from 'ui-frontend-common';
import { VitamUISnackBar, VitamUISnackBarComponent } from '../shared/vitamui-snack-bar';

@Injectable({ providedIn: 'root' })
export class UserInfoService extends SearchService<UserInfo> {

  userInfoUpdated = new Subject<UserInfo>();

  constructor(
    private userInfoServiceApi: BaseUserInfoApiService,
    private snackBar: VitamUISnackBar,

    http: HttpClient
  ) {
    super(http, { getAllPaginated: () => EMPTY }, '');
  }

  create(userInfo: UserInfo) : Observable<UserInfo>{
    return this.userInfoServiceApi.create(userInfo);
  }


  get(id: string): Observable<UserInfo> {
    return this.userInfoServiceApi.getOne(id);
  }

  getMyUserInfo(): Observable<UserInfo> {
    return this.userInfoServiceApi.getMyUserInfo();
  }

  patch(partialUser: { id: string, [key: string]: any }, user: User): Observable<UserInfo> {
    return this.userInfoServiceApi.patch(partialUser).pipe(
      tap((response) => this.userInfoUpdated.next(response)),
      tap(
        () => {
          this.snackBar.openFromComponent(VitamUISnackBarComponent, {
            panelClass: 'vitamui-snack-bar',
            duration: 10000,
            data: { type: 'userUpdate', firstname: user.firstname, lastname: user.lastname },
          });
        },
        (error) => {
          this.snackBar.open(error.error.message, null, {
            panelClass: 'vitamui-snack-bar',
            duration: 10000
          });
        }
      )
    );
  }


}
