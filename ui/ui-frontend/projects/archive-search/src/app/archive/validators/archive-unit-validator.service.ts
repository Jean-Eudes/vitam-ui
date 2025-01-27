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

import { Injectable } from '@angular/core';
import { AbstractControl, AsyncValidatorFn } from '@angular/forms';
import { cloneDeep } from 'lodash';
import { of, timer } from 'rxjs';
import { map, switchMap, take } from 'rxjs/operators';
import { ArchiveSharedDataService } from '../../core/archive-shared-data.service';
import { ArchiveService } from '../archive.service';
import { SearchCriteriaDto } from '../models/search.criteria';

@Injectable()
export class ArchiveUnitValidatorService {
  constructor(private archiveService: ArchiveService, private archiveSharedDataService: ArchiveSharedDataService) {}
  debounceTime = 400;

  alreadyExistParents(codeToIgnore?: string, archiveUnitAllunitup?: string[]): AsyncValidatorFn {
    return (control: AbstractControl) => {
      return timer(this.debounceTime).pipe(
        switchMap(() =>
          control.value !== codeToIgnore ? of(this.isAlreadyExistingParentValue(control.value, archiveUnitAllunitup)) : of(false)
        ),
        take(1),
        map((exists: boolean) => (exists ? { alreadyExistParents: true } : null))
      );
    };
  }

  isAlreadyExistingParentValue(parentId: string, archiveUnitAllunitup: string[]): boolean {
    return true ? archiveUnitAllunitup.filter((p) => p === parentId).length > 0 : false;
  }

  existArchiveUnit(criteriaDto: SearchCriteriaDto, accessContract: string): AsyncValidatorFn {
    return this.unitExists('targetGuid', criteriaDto, accessContract);
  }

  private unitExists(existTag: string, criteriaDto: SearchCriteriaDto, accessContract: string) {
    return (control: AbstractControl) => {
      const auditExists: any = {};
      auditExists[existTag] = true;
      const criteria = cloneDeep(criteriaDto);
      criteria.pageNumber = 0;
      criteria.criteriaList.forEach((criteriaElement) =>
        criteriaElement.values.forEach((v) => {
          v.id = control.value;
          v.value = control.value;
        })
      );
      const result = timer(this.debounceTime).pipe(
        switchMap(() =>
          control.value !== null
            ? this.archiveService
                .searchArchiveUnitsByCriteria(criteria, accessContract)
                .toPromise()
                .then((data) => {
                  if (data.totalResults === 1) {
                    this.archiveSharedDataService.emitArchiveUnitTitle(ArchiveService.fetchAuTitle(data.results[0]));
                    return false;
                  } else {
                    this.archiveSharedDataService.emitArchiveUnitTitle(null);
                    return true;
                  }
                })
            : of(false)
        ),
        take(1),
        map((exists: boolean) => (exists ? auditExists : null))
      );

      return result;
    };
  }
}
