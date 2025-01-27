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
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { merge } from 'rxjs';
import { debounceTime, filter, map } from 'rxjs/operators';
import { CriteriaDataType, CriteriaOperator, diff } from 'ui-frontend-common';
import { ArchiveSharedDataService } from '../../../core/archive-shared-data.service';
import { ArchiveSearchConstsEnum } from '../../models/archive-search-consts-enum';
import { CriteriaValue, SearchCriteriaTypeEnum } from '../../models/search.criteria';

const TITLE_OR_DESCRIPTION = 'TITLE_OR_DESCRIPTION';

@Component({
  selector: 'app-title-and-description-criteria-search',
  templateUrl: './title-and-description-criteria-search.component.html',
})
export class TitleAndDescriptionCriteriaSearchComponent implements OnInit {
  quickSearchCriteriaForm: FormGroup;

  previousTitleDescriptionCriteriaValue: {
    archiveCriteria: '';
  };
  emptyTitleDescriptionCriteriaForm = {
    archiveCriteria: '',
  };

  constructor(private formBuilder: FormBuilder, private archiveExchangeDataService: ArchiveSharedDataService, public dialog: MatDialog) {
    this.previousTitleDescriptionCriteriaValue = {
      archiveCriteria: '',
    };

    this.quickSearchCriteriaForm = this.formBuilder.group({
      archiveCriteria: ['', []],
    });
    merge(this.quickSearchCriteriaForm.statusChanges, this.quickSearchCriteriaForm.valueChanges)
      .pipe(
        debounceTime(ArchiveSearchConstsEnum.UPDATE_DEBOUNCE_TIME),
        filter(() => this.quickSearchCriteriaForm.valid),
        map(() => this.quickSearchCriteriaForm.value),
        map(() => diff(this.quickSearchCriteriaForm.value, this.previousTitleDescriptionCriteriaValue)),
        filter((formData) => this.isEmpty(formData))
      )
      .subscribe(() => {
        this.resetSimpleCriteriaForm();
      });
  }

  isEmpty(formData: any): boolean {
    if (formData) {
      if (formData.archiveCriteria) {
        this.addCriteria(
          TITLE_OR_DESCRIPTION,
          { value: formData.archiveCriteria.trim(), id: formData.archiveCriteria.trim() },
          formData.archiveCriteria.trim(),
          true,
          CriteriaOperator.EQ,
          false
        );
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  private resetSimpleCriteriaForm() {
    this.quickSearchCriteriaForm.reset(this.emptyTitleDescriptionCriteriaForm);
  }

  ngOnInit() {}

  addCriteria(keyElt: string, valueElt: CriteriaValue, labelElt: string, translated: boolean, operator: string, valueTranslated: boolean) {
    if (keyElt && valueElt) {
      this.archiveExchangeDataService.addSimpleSearchCriteriaSubject({
        keyElt,
        valueElt,
        labelElt,
        keyTranslated: translated,
        operator,
        category: SearchCriteriaTypeEnum.FIELDS,
        valueTranslated,
        dataType: CriteriaDataType.STRING,
      });
    }
  }

  get archiveCriteria() {
    return this.quickSearchCriteriaForm.controls.archiveCriteria;
  }
}
