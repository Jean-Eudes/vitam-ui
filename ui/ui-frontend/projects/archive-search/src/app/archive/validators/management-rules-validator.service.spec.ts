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

import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { ManagementRulesSharedDataService } from '../../core/management-rules-shared-data.service';
import { ManagementRules, RuleAction, RuleCategoryAction } from '../models/ruleAction.interface';
import { ManagementRulesValidatorService } from './management-rules-validator.service';

const rules: RuleAction[] = [
  {
    rule: 'ruleId1',
    name: 'ruleName_1',
  },
  {
    rule: 'ruleId3',
    name: 'ruleName_3',
  },
  {
    rule: 'ruleId2',
    name: 'ruleName_2',
  },
];

const ruleCategoryAction: RuleCategoryAction = {
  finalAction: 'keep',
  preventInheritance: false,
  rules,
};
const managementRules: ManagementRules[] = [
  {
    category: 'category',
    ruleCategoryAction,
    actionType: 'actionType',
  },
];

describe('ManagementRulesValidatorService', () => {
  let service: ManagementRulesValidatorService;
  const managementRulesSharedDataServiceMock = {
    getCriteriaSearchDSLQuery: () => of({}),
    getManagementRules: () => of(managementRules),
    getAccessContract: () => of('AccessContract'),
    getselectedItems: () => of(35),
    getCriteriaSearchListToSave: () => of({}),
    getRuleActions: () => of({}),
  };

  const managementRulesValidatorServiceMock = {
    filterRuleActions: () => of(Boolean),
    uniqueRuleId: () => of({}),
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: ManagementRulesSharedDataService, useValue: managementRulesSharedDataServiceMock },
        { provide: ManagementRulesValidatorService, useValue: managementRulesValidatorServiceMock },
      ],
    });
    service = TestBed.inject(ManagementRulesValidatorService);
  });

  it('should the service be created', () => {
    expect(service).toBeTruthy();
  });

  it(' uniqueRuleId should return false when ruleId does not exists in the list', () => {
    // When
    service.ruleCategorySelected = 'category';
    // Then
    expect(of(service.uniqueRuleId('ruleId150'))._isScalar).toBeFalsy();
  });

  it('filterRuleActions should return true when ruleId exists in the list', () => {
    // When
    service.ruleCategorySelected = 'category';
    // Then
    expect(service.filterRuleActions('ruleId1')).toBeTruthy();
  });

  it('filterRuleActions should return false when ruleId does not exists in the list', () => {
    // When
    service.ruleCategorySelected = 'category';
    // Then
    expect(of(service.filterRuleActions('ruleId150'))._isScalar).toBeFalsy();
  });

  it(' uniqueRuleId should return true when ruleId exists in the list', () => {
    // When
    service.ruleCategorySelected = 'category';
    // Then
    expect(service.uniqueRuleId('ruleId1')).toBeTruthy();
  });
});
