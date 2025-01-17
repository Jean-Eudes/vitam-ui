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
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Event } from 'projects/vitamui-library/src/public-api';
import { tap } from 'rxjs/operators';
import { SearchService } from 'ui-frontend-common';
import { OperationApiService } from '../core/api/operation-api.service';
import { VitamUISnackBar, VitamUISnackBarComponent } from '../shared/vitamui-snack-bar';

@Injectable({
  providedIn: 'root',
})
export class ProbativeValueService extends SearchService<Event> {
  constructor(private operationApiService: OperationApiService, private snackBar: VitamUISnackBar, http: HttpClient) {
    super(http, operationApiService, 'ALL');
  }

  create(probativeValueRequest: any, headers: HttpHeaders) {
    for (const header in this.headers) {
      if (this.headers.hasOwnProperty(header)) {
        headers.set(header, this.headers.get(header));
      }
    }

    return this.operationApiService.runProbativeValue(probativeValueRequest, headers).pipe(
      tap(
        () => {
          this.snackBar.openFromComponent(VitamUISnackBarComponent, {
            panelClass: 'vitamui-snack-bar',
            data: { type: 'probativeValueRun' },
            duration: 10000,
          });
        },
        (error: any) => {
          console.log('error: ', error);
          if (!error || !error.error) {
            return;
          }
          this.snackBar.open(error.error.message, null, {
            panelClass: 'vitamui-snack-bar',
            duration: 10000,
          });
        }
      )
    );
  }

  export(id: string, accessContractId: string) {
    this.operationApiService.downloadProbativeValue(id, new HttpHeaders({ 'X-Access-Contract-Id': accessContractId })).subscribe((blob) => {
      const element = document.createElement('a');
      element.href = window.URL.createObjectURL(blob);
      element.download = id + '.zip';
      element.style.visibility = 'hidden';
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
    });
  }
}
