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
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { TranslateService } from '@ngx-translate/core';
import { merge } from 'rxjs';
import { debounceTime, filter, map } from 'rxjs/operators';
import { ActionOnCriteria, CriteriaDataType, CriteriaOperator, diff } from 'ui-frontend-common';
import { ArchiveSharedDataService } from '../../../core/archive-shared-data.service';
import { ManagementRulesSharedDataService } from '../../../core/management-rules-shared-data.service';
import { ArchiveService } from '../../archive.service';
import { ArchiveSearchConstsEnum } from '../../models/archive-search-consts-enum';
import { CriteriaValue, SearchCriteriaEltDto, SearchCriteriaTypeEnum } from '../../models/search.criteria';

const FINAL_ACTION_TYPE = 'FINAL_ACTION_TYPE';
const ARCHIVE_UNIT_FILING_UNIT = 'ARCHIVE_UNIT_FILING_UNIT';
const ARCHIVE_UNIT_HOLDING_UNIT = 'ARCHIVE_UNIT_HOLDING_UNIT';
const ARCHIVE_UNIT_WITH_OBJECTS = 'ARCHIVE_UNIT_WITH_OBJECTS';
const ARCHIVE_UNIT_WITHOUT_OBJECTS = 'ARCHIVE_UNIT_WITHOUT_OBJECTS';
const ALL_ARCHIVE_UNIT_TYPES = 'ALL_ARCHIVE_UNIT_TYPES';

@Component({
  selector: 'app-simple-criteria-search',
  templateUrl: './simple-criteria-search.component.html',
  styleUrls: ['./simple-criteria-search.component.css'],
})
export class SimpleCriteriaSearchComponent implements OnInit {
  simpleCriteriaForm: FormGroup;
  otherCriteriaValueEnabled = false;
  otherCriteriaValueType = 'DATE';
  selectedValueOntolonogy: any;
  ontologies: any;
  criteriaSearchListToSave: SearchCriteriaEltDto[] = [];

  previousSimpleCriteriaValue: {
    title: '';
    identifier: '';
    description: '';
    guidopi: '';
    guid: '';
    beginDt: '';
    endDt: '';
    serviceProdLabel: '';
    serviceProdCode: '';
    otherCriteria: '';
    otherCriteriaValue: '';
  };
  emptySimpleCriteriaForm = {
    title: '',
    identifier: '',
    description: '',
    guidopi: '',
    guid: '',
    beginDt: '',
    endDt: '',
    serviceProdLabel: '',
    serviceProdCode: '',
    otherCriteria: '',
    otherCriteriaValue: '',
  };
  archiveUnitTypesCriteria: Map<any, boolean> = new Map<any, boolean>([
    [ARCHIVE_UNIT_FILING_UNIT, false],
    [ARCHIVE_UNIT_HOLDING_UNIT, false],
    [ARCHIVE_UNIT_WITH_OBJECTS, true],
    [ARCHIVE_UNIT_WITHOUT_OBJECTS, true],
  ]);

  constructor(
    private formBuilder: FormBuilder,
    private archiveService: ArchiveService,
    private archiveExchangeDataService: ArchiveSharedDataService,
    public dialog: MatDialog,
    private managementRulesSharedDataService: ManagementRulesSharedDataService,
    private translateService: TranslateService
  ) {
    this.archiveService.getOntologiesFromJson().subscribe((data: any) => {
      this.ontologies = data;
      this.ontologies.sort((a: any, b: any) => {
        const shortNameA = a.Label;
        const shortNameB = b.Label;
        return shortNameA < shortNameB ? -1 : shortNameA > shortNameB ? 1 : 0;
      });
    });

    this.previousSimpleCriteriaValue = {
      title: '',
      identifier: '',
      description: '',
      guidopi: '',
      guid: '',
      beginDt: '',
      endDt: '',
      serviceProdLabel: '',
      serviceProdCode: '',
      otherCriteria: '',
      otherCriteriaValue: '',
    };

    this.simpleCriteriaForm = this.formBuilder.group({
      title: ['', []],
      description: ['', []],
      guidopi: ['', []],
      guid: ['', [Validators.pattern('^[a-z0-9_, ]+')]],
      beginDt: ['', []],
      endDt: ['', []],
      serviceProdLabel: ['', []],
      serviceProdCode: ['', []],
      otherCriteria: ['', []],
      otherCriteriaValue: ['', []],
    });
    merge(this.simpleCriteriaForm.statusChanges, this.simpleCriteriaForm.valueChanges)
      .pipe(
        debounceTime(ArchiveSearchConstsEnum.UPDATE_DEBOUNCE_TIME),
        filter(() => this.simpleCriteriaForm.valid),
        map(() => this.simpleCriteriaForm.value),
        map(() => diff(this.simpleCriteriaForm.value, this.previousSimpleCriteriaValue)),
        filter((formData) => this.isEmpty(formData))
      )
      .subscribe(() => {
        this.resetSimpleCriteriaForm();
      });

    this.archiveExchangeDataService.receiveRemoveFromChildSearchCriteriaSubject().subscribe((criteria) => {
      if (criteria) {
        if (criteria.action === ActionOnCriteria.ADD) {
          this.archiveUnitTypesCriteria.set(criteria.valueElt.id, true);
        } else if (criteria.action === ActionOnCriteria.REMOVE) {
          this.archiveUnitTypesCriteria.set(criteria.valueElt.id, false);
        }
      }
    });
  }

  isEmpty(formData: any): boolean {
    if (formData) {
      if (formData.title) {
        this.addCriteria(
          'TITLE',
          { value: formData.title.trim(), id: formData.title.trim() },
          formData.title.trim(),
          true,
          CriteriaOperator.EQ,
          false,
          CriteriaDataType.STRING
        );
        return true;
      } else if (formData.description) {
        this.addCriteria(
          'DESCRIPTION',
          { value: formData.description.trim(), id: formData.description.trim() },
          formData.description.trim(),
          true,
          CriteriaOperator.EQ,
          false,
          CriteriaDataType.STRING
        );
        return true;
      } else if (formData.beginDt) {
        this.addCriteria(
          'START_DATE',
          { value: this.simpleCriteriaForm.value.beginDt, id: this.simpleCriteriaForm.value.beginDt },
          this.simpleCriteriaForm.value.beginDt,
          true,
          CriteriaOperator.GTE,
          false,
          CriteriaDataType.DATE
        );
        return true;
      } else if (formData.endDt) {
        this.addCriteria(
          'END_DATE',
          { value: this.simpleCriteriaForm.value.endDt, id: this.simpleCriteriaForm.value.endDt },
          this.simpleCriteriaForm.value.endDt,
          true,
          CriteriaOperator.LTE,
          false,
          CriteriaDataType.DATE
        );
        return true;
      } else if (formData.serviceProdCode) {
        this.addCriteria(
          'SP_CODE',
          { value: formData.serviceProdCode.trim(), id: formData.serviceProdCode.trim() },
          formData.serviceProdCode.trim(),
          true,
          CriteriaOperator.EQ,
          false,
          CriteriaDataType.STRING
        );
        return true;
      } else if (formData.serviceProdLabel) {
        this.addCriteria(
          'SP_LABEL',
          { value: formData.serviceProdLabel.trim(), id: formData.serviceProdLabel.trim() },
          formData.serviceProdLabel.trim(),
          true,
          CriteriaOperator.EQ,
          false,
          CriteriaDataType.STRING
        );
        return true;
      } else if (formData.guid) {
        const splittedGuids = formData.guid.split(',');
        splittedGuids.forEach((guidElt: string) => {
          if (guidElt && guidElt.trim() !== '') {
            this.addCriteria(
              'GUID',
              { value: guidElt.trim(), id: guidElt.trim() },
              guidElt.trim(),
              true,
              CriteriaOperator.EQ,
              false,
              CriteriaDataType.STRING
            );
          }
        });
        return true;
      } else if (formData.guidopi) {
        this.addCriteria(
          'GUID_OPI',
          { value: formData.guidopi, id: formData.guidopi },
          formData.guidopi,
          true,
          'IN',
          false,
          CriteriaDataType.STRING
        );
        return true;
      } else if (formData.otherCriteriaValue) {
        const ontologyElt = this.ontologies.find((ontoElt: any) => ontoElt.Value === formData.otherCriteria);
        if (this.otherCriteriaValueType === CriteriaDataType.DATE) {
          this.addCriteria(
            ontologyElt.Value,
            { value: this.simpleCriteriaForm.value.otherCriteriaValue, id: this.simpleCriteriaForm.value.otherCriteriaValue },
            this.simpleCriteriaForm.value.otherCriteriaValue,
            false,
            CriteriaOperator.EQ,
            false,
            CriteriaDataType.DATE
          );
        } else {
          this.addCriteria(
            ontologyElt.Value,
            { value: formData.otherCriteriaValue.trim(), id: formData.otherCriteriaValue.trim() },
            formData.otherCriteriaValue.trim(),
            false,
            CriteriaOperator.EQ,
            false,
            CriteriaDataType.STRING
          );
        }
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  private resetSimpleCriteriaForm() {
    this.simpleCriteriaForm.reset(this.emptySimpleCriteriaForm);
  }

  isValueTranslated(criteria: string) {
    return criteria === FINAL_ACTION_TYPE || criteria === ALL_ARCHIVE_UNIT_TYPES;
  }
  ngOnInit() {
    this.managementRulesSharedDataService.getCriteriaSearchListToSave().subscribe((data) => {
      this.criteriaSearchListToSave = data;
    });

    this.criteriaSearchListToSave.forEach((criteriaSearch) => {
      if (criteriaSearch.criteria === ALL_ARCHIVE_UNIT_TYPES) {
        criteriaSearch.values.forEach((unitType) => {
          this.archiveUnitTypesCriteria.set(unitType.id, true);
        });
      }
      criteriaSearch.values.forEach((value) => {
        this.addCriteria(
          criteriaSearch.criteria,
          value,
          value.id,
          true,
          criteriaSearch.operator,
          this.isValueTranslated(criteriaSearch.criteria),
          criteriaSearch.dataType,
          criteriaSearch.category as SearchCriteriaTypeEnum
        );
      });
    });
    if (this.criteriaSearchListToSave.length === 0) {
      this.addCriteria(
        ALL_ARCHIVE_UNIT_TYPES,
        { value: ARCHIVE_UNIT_WITH_OBJECTS, id: ARCHIVE_UNIT_WITH_OBJECTS },
        this.translateService.instant('ARCHIVE_SEARCH.SEARCH_CRITERIA_FILTER.FIELDS.UNIT_TYPE.ARCHIVE_UNIT_WITH_OBJECTS'),
        true,
        CriteriaOperator.EQ,
        false,
        CriteriaDataType.STRING,
        SearchCriteriaTypeEnum.FIELDS
      );

      this.addCriteria(
        ALL_ARCHIVE_UNIT_TYPES,
        { value: ARCHIVE_UNIT_WITHOUT_OBJECTS, id: ARCHIVE_UNIT_WITHOUT_OBJECTS },
        this.translateService.instant('ARCHIVE_SEARCH.SEARCH_CRITERIA_FILTER.FIELDS.UNIT_TYPE.ARCHIVE_UNIT_WITHOUT_OBJECTS'),
        true,
        CriteriaOperator.EQ,
        false,
        CriteriaDataType.STRING,
        SearchCriteriaTypeEnum.FIELDS
      );
    }
  }

  onSelectOtherCriteria() {
    this.simpleCriteriaForm.get('otherCriteria').valueChanges.subscribe((selectedcriteria) => {
      if (selectedcriteria === '') {
        this.otherCriteriaValueEnabled = false;
        this.selectedValueOntolonogy = null;
      } else {
        this.simpleCriteriaForm.controls.otherCriteriaValue.setValue('');
        this.otherCriteriaValueEnabled = true;
        const selectedValueOntolonogyValue = this.simpleCriteriaForm.get('otherCriteria').value;
        const selectedValueOntolonogyElt = this.ontologies.find((ontoElt: any) => ontoElt.Value === selectedValueOntolonogyValue);
        if (selectedValueOntolonogyElt) {
          this.selectedValueOntolonogy = selectedValueOntolonogyElt.Label;
          this.otherCriteriaValueType = selectedValueOntolonogyElt.Type;
        }
      }
    });
  }

  addCriteria(
    keyElt: string,
    valueElt: CriteriaValue,
    labelElt: string,
    keyTranslated: boolean,
    operator: string,
    valueTranslated: boolean,
    dataType: string,
    category?: SearchCriteriaTypeEnum
  ) {
    if (keyElt && valueElt) {
      this.archiveExchangeDataService.addSimpleSearchCriteriaSubject({
        keyElt,
        valueElt,
        labelElt,
        keyTranslated,
        operator,
        category: category ? category : SearchCriteriaTypeEnum.FIELDS,
        valueTranslated,
        dataType,
      });
    }
  }

  addArchiveUnitTypeCriteria(unitType: string, event: any) {
    const action = event.target.checked;
    this.archiveUnitTypesCriteria.set(unitType, action);
    switch (unitType) {
      case ARCHIVE_UNIT_FILING_UNIT:
        if (action) {
          this.addCriteria(
            ALL_ARCHIVE_UNIT_TYPES,
            { value: ARCHIVE_UNIT_FILING_UNIT, id: ARCHIVE_UNIT_FILING_UNIT },
            this.translateService.instant('ARCHIVE_SEARCH.SEARCH_CRITERIA_FILTER.FIELDS.UNIT_TYPE.ARCHIVE_UNIT_PLAN'),
            true,
            CriteriaOperator.EQ,
            false,
            CriteriaDataType.STRING,
            SearchCriteriaTypeEnum.FIELDS
          );
        } else {
          this.emitRemoveCriteriaEvent(ALL_ARCHIVE_UNIT_TYPES, { value: ARCHIVE_UNIT_FILING_UNIT, id: ARCHIVE_UNIT_FILING_UNIT });
        }
        break;
      case ARCHIVE_UNIT_HOLDING_UNIT:
        if (action) {
          this.addCriteria(
            ALL_ARCHIVE_UNIT_TYPES,
            { value: ARCHIVE_UNIT_HOLDING_UNIT, id: ARCHIVE_UNIT_HOLDING_UNIT },
            this.translateService.instant('ARCHIVE_SEARCH.SEARCH_CRITERIA_FILTER.FIELDS.UNIT_TYPE.ARCHIVE_UNIT_HOLDING'),
            true,
            CriteriaOperator.EQ,
            false,
            CriteriaDataType.STRING,
            SearchCriteriaTypeEnum.FIELDS
          );
        } else {
          this.emitRemoveCriteriaEvent(ALL_ARCHIVE_UNIT_TYPES, { value: ARCHIVE_UNIT_HOLDING_UNIT, id: ARCHIVE_UNIT_HOLDING_UNIT });
        }
        break;
      case ARCHIVE_UNIT_WITH_OBJECTS:
        if (action) {
          this.addCriteria(
            ALL_ARCHIVE_UNIT_TYPES,
            { value: ARCHIVE_UNIT_WITH_OBJECTS, id: ARCHIVE_UNIT_WITH_OBJECTS },
            this.translateService.instant('ARCHIVE_SEARCH.SEARCH_CRITERIA_FILTER.FIELDS.UNIT_TYPE.ARCHIVE_UNIT_WITH_OBJECTS'),
            true,
            CriteriaOperator.EQ,
            false,
            CriteriaDataType.STRING,
            SearchCriteriaTypeEnum.FIELDS
          );
        } else {
          this.emitRemoveCriteriaEvent(ALL_ARCHIVE_UNIT_TYPES, { value: ARCHIVE_UNIT_WITH_OBJECTS, id: ARCHIVE_UNIT_WITH_OBJECTS });
        }
        break;
      case ARCHIVE_UNIT_WITHOUT_OBJECTS:
        if (action) {
          this.addCriteria(
            ALL_ARCHIVE_UNIT_TYPES,
            { value: ARCHIVE_UNIT_WITHOUT_OBJECTS, id: ARCHIVE_UNIT_WITHOUT_OBJECTS },
            this.translateService.instant('ARCHIVE_SEARCH.SEARCH_CRITERIA_FILTER.FIELDS.UNIT_TYPE.ARCHIVE_UNIT_WITHOUT_OBJECTS'),
            true,
            CriteriaOperator.EQ,
            false,
            CriteriaDataType.STRING,
            SearchCriteriaTypeEnum.FIELDS
          );
        } else {
          this.emitRemoveCriteriaEvent(ALL_ARCHIVE_UNIT_TYPES, { value: ARCHIVE_UNIT_WITHOUT_OBJECTS, id: ARCHIVE_UNIT_WITHOUT_OBJECTS });
        }
        break;
      default:
        break;
    }
  }

  emitRemoveCriteriaEvent(keyElt: string, valueElt?: CriteriaValue) {
    this.archiveExchangeDataService.sendRemoveFromChildSearchCriteriaAction({ keyElt, valueElt, action: ActionOnCriteria.REMOVE });
  }

  get guid() {
    return this.simpleCriteriaForm.controls.guid;
  }
  get archiveCriteria() {
    return this.simpleCriteriaForm.controls.archiveCriteria;
  }
  get title() {
    return this.simpleCriteriaForm.controls.title;
  }
  get description() {
    return this.simpleCriteriaForm.controls.description;
  }
  get guidopi() {
    return this.simpleCriteriaForm.controls.guidopi;
  }
  get beginDt() {
    return this.simpleCriteriaForm.controls.beginDt;
  }
  get endDt() {
    return this.simpleCriteriaForm.controls.endDt;
  }
  get serviceProdLabel() {
    return this.simpleCriteriaForm.controls.serviceProdLabel;
  }

  get serviceProdCode() {
    return this.simpleCriteriaForm.controls.serviceProdCode;
  }

  get otherCriteria() {
    return this.simpleCriteriaForm.controls.otherCriteria;
  }
  get otherCriteriaValue() {
    return this.simpleCriteriaForm.controls.otherCriteriaValue;
  }
}
