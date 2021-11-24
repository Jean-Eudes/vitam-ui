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
import { TranslateService } from '@ngx-translate/core';
import {BehaviorSubject, EMPTY, Observable, of, Subject} from 'rxjs';
import {catchError, exhaustMap, map, withLatestFrom} from 'rxjs/operators';
import {
  AccessionRegisterDetail,
  AccessionRegisterStats,
  AccessionRegisterStatus,
  BytesPipe,
  Colors,
  ExternalParameters,
  ExternalParametersService,
  SearchService,
} from 'ui-frontend-common';
import { FacetDetails } from 'ui-frontend-common/app/modules/models/operation/facet-details.interface';
import { AccessionRegisterDetailApiService } from '../core/api/accession-register-detail-api.service';

@Injectable({
  providedIn: 'root',
})
export class AccessionRegistersService extends SearchService<AccessionRegisterDetail> {
  pageEvent = new Subject<string>();
  tenantEvent = new Subject<string>();
  customerEvent = new Subject<string>();
  updated = new Subject<AccessionRegisterDetail>();

  private searchTextChange$ = new BehaviorSubject<string>('');
  private statusFilterChange$ = new BehaviorSubject<{ [key: string]: any[] }>(null);
  private dateIntervalChange$ = new BehaviorSubject<{ endDateMin: string; endDateMax: string }>(null);

  private openAdvancedSearchPanel: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);
  private advancedSearchData$ = new BehaviorSubject<any>(null);
  private globalSearchButtonEvent$ = new BehaviorSubject<boolean>(true);
  private advancedFormHaveChanged$ = new BehaviorSubject<boolean>(false);
  private globalResetEvent$ = new BehaviorSubject<boolean>(false);

  constructor(
    private accessionRegisterApiService: AccessionRegisterDetailApiService,
    http: HttpClient,
    private translateService: TranslateService,
    private externalParameterService: ExternalParametersService,
    private bytesPipe: BytesPipe
  ) {
    super(http, accessionRegisterApiService, 'ALL');
  }

  getAccessionRegisterStatus(locale: string) {
    const prefix = 'ACCESSION_REGISTER.STATUS.';
    return this.translateService.getStreamOnTranslationChange(prefix + AccessionRegisterStatus.STORED_AND_COMPLETED).pipe(
      withLatestFrom(
        this.translateService.getStreamOnTranslationChange(prefix + AccessionRegisterStatus.STORED_AND_UPDATED),
        this.translateService.getStreamOnTranslationChange(prefix + AccessionRegisterStatus.UNSTORED)
      ),
      map(([storedAndCompleted, storedAndUpdated, unstored]) => {
        const data = [
          { value: AccessionRegisterStatus.STORED_AND_COMPLETED, label: storedAndCompleted },
          { value: AccessionRegisterStatus.STORED_AND_UPDATED, label: storedAndUpdated },
          { value: AccessionRegisterStatus.UNSTORED, label: unstored },
        ];
        return data.sort(this.sortByLabel(locale));
      }),
      catchError((error) => {
        return of(error);
      })
    );
  }

  private sortByLabel(locale: string): (a: { label: string }, b: { label: string }) => number {
    return (a: { label: string }, b: { label: string }) => a.label.localeCompare(b.label, locale);
  }

  fetchUserAccessContract(): Observable<string> {
    return this.externalParameterService
      .getUserExternalParameters()
      .pipe(map((parameters) => parameters.get(ExternalParameters.PARAM_ACCESS_CONTRACT)));
  }

  getFacetDetailsStats(): Observable<FacetDetails[]> {
    return this.globalSearchButtonEvent$.pipe(
      withLatestFrom(this.searchTextChange$, this.statusFilterChange$, this.dateIntervalChange$, this.advancedSearchData$),
      exhaustMap((changes: any) => {
        const globalSearch = changes[0];
        if (globalSearch) {
          const search = {
            searchText: changes[1],
            statusFilter: changes[2],
            dateInterval: changes[3],
            advancedSearch: changes[4],
          };

          return this.fetchUserAccessContract().pipe(
            exhaustMap((accessContract) => {
              let headers = new HttpHeaders().append('Content-Type', 'application/json');
              headers = headers.append('X-Access-Contract-Id', accessContract);
              return this.accessionRegisterApiService
                .getAccessionRegisterDetailStats(headers, search)
                .pipe(map((accessionRegisterStats) => this.fetchFacetDetails(accessionRegisterStats)));
            })
          );
        }
        return EMPTY;
      })
    );
  }

  private fetchFacetDetails(accessionRegisterStats: AccessionRegisterStats): FacetDetails[] {
    const stateFacetDetails: FacetDetails[] = [];

    stateFacetDetails.push({
      title: this.translateService.instant('ACCESSION_REGISTER.FACETS.TOTAL_OPERATION_ENTRIES'),
      totalResults: this.data?.length,
      clickable: false,
      color: Colors.BLACK,
      backgroundColor: Colors.DISABLED,
    });
    stateFacetDetails.push({
      title: this.translateService.instant('ACCESSION_REGISTER.FACETS.TOTAL_UNITS'),
      totalResults: accessionRegisterStats.totalUnits,
      clickable: false,
      color: Colors.BLACK,
      backgroundColor: Colors.DISABLED,
    });
    stateFacetDetails.push({
      title: this.translateService.instant('ACCESSION_REGISTER.FACETS.TOTAL_OBJECTS_GROUP'),
      totalResults: accessionRegisterStats.totalObjectsGroups,
      clickable: false,
      color: Colors.BLACK,
      backgroundColor: Colors.DISABLED,
    });
    stateFacetDetails.push({
      title: this.translateService.instant('ACCESSION_REGISTER.FACETS.TOTAL_OBJECTS'),
      totalResults: accessionRegisterStats.totalObjects,
      clickable: false,
      color: Colors.BLACK,
      backgroundColor: Colors.DISABLED,
    });
    stateFacetDetails.push({
      title: this.translateService.instant('ACCESSION_REGISTER.FACETS.TOTAL_SIZE'),
      totalResults: this.bytesPipe.transform(accessionRegisterStats.objectSizes),
      clickable: false,
      color: Colors.BLACK,
      backgroundColor: Colors.DISABLED,
    });

    return stateFacetDetails;
  }

  notifyFilterChange(value: { [key: string]: any[] }) {
    this.statusFilterChange$.next(value);
    this.globalSearchButtonEvent$.next(true);
  }

  notifySearchChange(value: string) {
    this.searchTextChange$.next(value);
  }

  notifyDateIntervalChange(value: { endDateMin: string; endDateMax: string }) {
    this.dateIntervalChange$.next(value);
    this.globalSearchButtonEvent$.next(true);
  }

  getDateIntervalChanges(): BehaviorSubject<{ endDateMin: string; endDateMax: string }> {
    return this.dateIntervalChange$;
  }

  toggleOpenAdvancedSearchPanel() {
    this.openAdvancedSearchPanel.next(!this.openAdvancedSearchPanel.getValue());
  }

  isOpenAdvancedSearchPanel(): Observable<boolean> {
    return this.openAdvancedSearchPanel.asObservable();
  }

  getAcquisitionInformations() {
    return [
      'Versement',
      'Protocole',
      'Achat',
      'Copie',
      'Dation',
      'Dépôt',
      'Dévolution',
      'Don',
      'Legs',
      'Réintégration',
      'Autres',
      'Non renseigné',
    ];
  }

  setAdvancedSearchData(value: any) {
    this.advancedSearchData$.next(value);
  }

  getAdvancedSearchData(): BehaviorSubject<any> {
    return this.advancedSearchData$;
  }

  setGlobalSearchButtonEvent(value: any) {
    this.globalSearchButtonEvent$.next(value);
  }

  getGlobalSearchButtonEvent(): Observable<any> {
    return this.globalSearchButtonEvent$.asObservable();
  }

  setAdvancedFormHaveChanged(value: boolean) {
    this.advancedFormHaveChanged$.next(value);
  }

  isAdvancedFormChanged(): Observable<boolean> {
    return this.advancedFormHaveChanged$.asObservable();
  }

  setGlobalResetEvent(value: boolean) {
    this.globalResetEvent$.next(value);
    this.globalSearchButtonEvent$.next(true);
  }

  isGlobalResetEvent(): Observable<boolean> {
    return this.globalResetEvent$.asObservable();
  }

  notifyOrderChange() {
    this.globalSearchButtonEvent$.next(true);
  }
}