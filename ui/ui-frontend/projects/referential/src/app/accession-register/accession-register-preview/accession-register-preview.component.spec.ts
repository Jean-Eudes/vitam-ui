/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2022)
 *
 * contact.vitam@culture.gouv.fr
 *
 * This software is a computer program whose purpose is to implement a digital archiving back-office system managing
 * high volumetry securely and efficiently.
 *
 * This software is governed by the CeCILL 2.1 license under French law and abiding by the rules of distribution of free
 * software. You can use, modify and/ or redistribute the software under the terms of the CeCILL 2.1 license as
 * circulated by CEA, CNRS and INRIA at the following URL "https://cecill.info".
 *
 * As a counterpart to the access to the source code and rights to copy, modify and redistribute granted by the license,
 * users are provided only with a limited warranty and the software's author, the holder of the economic rights, and the
 * successive licensors have only limited liability.
 *
 * In this respect, the user's attention is drawn to the risks associated with loading, using, modifying and/or
 * developing or reproducing the software by the user in light of its specific status of free software, that may mean
 * that it is complicated to manipulate, and that also therefore means that it is reserved for developers and
 * experienced professionals having in-depth computer knowledge. Users are therefore encouraged to load and test the
 * software's suitability as regards their requirements in conditions enabling the security of their systems and/or data
 * to be ensured and, more generally, to use and operate it in the same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had knowledge of the CeCILL 2.1 license and that you
 * accept its terms.
 */
import {NO_ERRORS_SCHEMA, Pipe, PipeTransform} from '@angular/core';
import {ComponentFixture, TestBed, waitForAsync} from '@angular/core/testing';
import {MatIconModule} from '@angular/material/icon';
import {MatMenuModule} from '@angular/material/menu';
import {MatProgressSpinnerModule} from '@angular/material/progress-spinner';
import {MatSidenavModule} from '@angular/material/sidenav';
import {MatTreeModule} from '@angular/material/tree';
import {BrowserAnimationsModule} from '@angular/platform-browser/animations';
import {ActivatedRoute} from '@angular/router';
import {RouterTestingModule} from '@angular/router/testing';
import {TranslateModule} from '@ngx-translate/core';
import {of} from 'rxjs';
import {
  AccessionRegisterDetail,
  BASE_URL,
  ENVIRONMENT,
  InjectorModule,
  LoggerModule,
  StartupService,
  WINDOW_LOCATION
} from 'ui-frontend-common';
import {environment} from '../../../environments/environment.prod';
import {AccessionRegisterPreviewComponent} from './accession-register-preview.component';
import {AccessionRegistersService} from "../accession-register.service";

describe('AccessionRegisterPreviewComponent', () => {
  let component: AccessionRegisterPreviewComponent;
  let fixture: ComponentFixture<AccessionRegisterPreviewComponent>;

  @Pipe({name: 'truncate'})
  class MockTruncatePipe implements PipeTransform {
    transform(value: number): number {
      return value;
    }
  }

  beforeEach(
    waitForAsync(() => {
      const activatedRouteMock = {
        params: of({tenantIdentifier: 1}),
        data: of({appId: 'ARCHIVE_SEARCH_MANAGEMENT_APP'}),
      };

      const AccessionRegistersServiceMock = {
        getBaseUrl: () => '/fake-api',
        buildAccessionRegisterAccessionRegisterDetailPath: () => of({resumePath: '', fullPath: ''}),
        receiveDownloadProgressSubject: () => of(true),
      };

      TestBed.configureTestingModule({
        imports: [
          MatMenuModule,
          MatTreeModule,
          MatProgressSpinnerModule,
          MatSidenavModule,
          InjectorModule,
          LoggerModule.forRoot(),
          RouterTestingModule,
          MatIconModule,
          BrowserAnimationsModule,
          TranslateModule.forRoot(),
        ],
        declarations: [AccessionRegisterPreviewComponent, MockTruncatePipe],
        providers: [
          {provide: AccessionRegistersService, useValue: AccessionRegistersServiceMock},
          {provide: BASE_URL, useValue: '/fake-api'},
          {provide: ActivatedRoute, useValue: activatedRouteMock},
          {provide: ENVIRONMENT, useValue: environment},
          {provide: WINDOW_LOCATION, useValue: window.location},
          {
            provide: StartupService, useValue: {
              getPortalUrl: () => '', setTenantIdentifier: () => {
              }
            }
          },
        ],
        schemas: [NO_ERRORS_SCHEMA],
      }).compileComponents();
    })
  );

  beforeEach(() => {
    fixture = TestBed.createComponent(AccessionRegisterPreviewComponent);
    component = fixture.componentInstance;
    const accessionRegisterDetail: AccessionRegisterDetail = {
      acquisitionInformation: "",
      archivalAgreement: "",
      comment: ["Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
        "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
        "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
      ],
      endDate: "",
      events: [],
      id: "",
      lastUpdate: "",
      obIdIn: "",
      objectSize: undefined,
      opc: "",
      operationType: "",
      operationsIds: [],
      opi: "",
      originatingAgency: "",
      originatingAgencyLabel: "",
      startDate: "",
      status: undefined,
      submissionAgency: "",
      submissionAgencyLabel: "",
      tenant: 0,
      totalObjects: undefined,
      totalObjectsGroups: undefined,
      totalUnits: undefined,
      version: 0
    };
    component.accessionRegisterDetail = accessionRegisterDetail;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
