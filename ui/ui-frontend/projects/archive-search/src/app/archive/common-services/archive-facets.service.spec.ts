/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2019-2022)
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
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { inject, TestBed } from '@angular/core/testing';
import { ResultFacet, ResultFacetList, SearchCriteriaTypeEnum } from '../models/search.criteria';
import { ArchiveFacetsService } from './archive-facets.service';

describe('CustomerService', () => {
  let archiveFacetsService: ArchiveFacetsService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [ArchiveFacetsService],
    });

    archiveFacetsService = TestBed.inject(ArchiveFacetsService);
  });

  it('should be created', inject([ArchiveFacetsService], (service: ArchiveFacetsService) => {
    expect(service).toBeTruthy();
  }));

  it('should call extractNodesFacetsResults', () => {
    let resultFacets = archiveFacetsService.extractNodesFacetsResults(facetResultsInput);
    expect(resultFacets).toEqual(expectedResultNodesFacets);
  });

  it('should call extractRulesFacetsResultsByCategory', () => {
    let resultFacets = archiveFacetsService.extractRulesFacetsResultsByCategory(facetResultsInput, SearchCriteriaTypeEnum.APPRAISAL_RULE);
    expect(resultFacets.expiredRulesListFacets).toEqual(expectedResultExpiredFacets);
    expect(resultFacets.finalActionsFacets).toEqual(expectedResultFinalActionsFacets);
    expect(resultFacets.noRulesFacets).toEqual(expectedResultCountWithoutRulesFacets);
    expect(resultFacets.waitingToRecalculateRulesListFacets).toEqual(expectedResultComputeRulesFacets);
  });
});
const expectedResultNodesFacets: ResultFacet[] = [{ node: 'node1', count: 10 }];
const expectedResultExpiredFacets: ResultFacet[] = [{ node: 'facet2', count: 120 }];
const expectedResultFinalActionsFacets: ResultFacet[] = [{ node: 'facet-final', count: 18 }];
const expectedResultCountWithoutRulesFacets: ResultFacet[] = [{ node: 'facet-count', count: 11 }];
const expectedResultComputeRulesFacets: ResultFacet[] = [{ node: 'facet-Computed', count: 121 }];

const facetNodeResultsInput: ResultFacetList = {
  name: 'COUNT_BY_NODE',
  buckets: [
    {
      value: 'node1',
      count: 10,
    },
  ],
};

const facetComutedRulesInput: ResultFacetList = {
  name: 'FINAL_ACTION_COMPUTED_APPRAISAL_RULE',
  buckets: [
    {
      value: 'facet-final',
      count: 18,
    },
  ],
};
const facetExpiredComutedRulesInput: ResultFacetList = {
  name: 'EXPIRED_RULES_COMPUTED_APPRAISAL_RULE',
  buckets: [
    {
      value: 'facet2',
      count: 120,
    },
  ],
};
const facetCountRulesInput: ResultFacetList = {
  name: 'COUNT_WITHOUT_RULES_APPRAISAL_RULE',
  buckets: [
    {
      value: 'facet-count',
      count: 11,
    },
  ],
};
const facetComputeRulesInput: ResultFacetList = {
  name: 'COMPUTE_RULES_AU_NUMBER',
  buckets: [
    {
      value: 'facet-Computed',
      count: 121,
    },
  ],
};
const facetResultsInput: ResultFacetList[] = [
  facetNodeResultsInput,
  facetComutedRulesInput,
  facetExpiredComutedRulesInput,
  facetCountRulesInput,
  facetComputeRulesInput,
];

describe('ArchiveFacetsService', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [],
    })
  );

  it('should be created', () => {
    const service: ArchiveFacetsService = TestBed.inject(ArchiveFacetsService);
    expect(service).toBeTruthy();
  });
});
