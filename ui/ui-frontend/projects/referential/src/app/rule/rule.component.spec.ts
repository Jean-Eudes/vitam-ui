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
import {ComponentFixture, TestBed, waitForAsync} from '@angular/core/testing';

import {HttpClientTestingModule} from '@angular/common/http/testing';
import { Component, Input } from '@angular/core';
import {ReactiveFormsModule} from '@angular/forms';
// tslint:disable-next-line: max-line-length
import {NoopAnimationsModule} from '@angular/platform-browser/animations';
import {ActivatedRoute} from '@angular/router';
import {RouterTestingModule} from '@angular/router/testing';
import {EMPTY, of} from 'rxjs';
// tslint:disable-next-line: max-line-length
import {ApplicationService, AuthService, BASE_URL, ENVIRONMENT, GlobalEventService, HistoryModule, InjectorModule, LoggerModule, SearchBarModule, VitamUISnackBar} from 'ui-frontend-common';

import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import {Rule} from '../../../../vitamui-library/src/lib/models/rule';
import {environment} from '../../environments/environment';
import {RuleComponent} from './rule.component';

import { MatOptionModule } from '@angular/material/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatTabsModule } from '@angular/material/tabs';
import {VitamUICommonTestModule} from 'ui-frontend-common/testing';

@Component({selector: 'app-rule-preview', template: ''})
// tslint:disable-next-line:component-class-suffix
class RulePreviewStub {
  @Input()
  rule: Rule;
}

@Component({selector: 'app-rule-list', template: ''})
// tslint:disable-next-line:component-class-suffix
class RuleListStub {
  @Input()
  search: string;

  @Input()
  filters: string;
}

describe('RuleComponent', () => {
  let component: RuleComponent;
  let fixture: ComponentFixture<RuleComponent>;

  beforeEach(waitForAsync(() => {
    const matDialogRefSpy = jasmine.createSpyObj('MatDialogRef', ['close']);
    const snackBarSpy = jasmine.createSpyObj('VitamUISnackBar', ['open', 'openFromComponent']);

    const authServiceMock = {
      user: {
        proofTenantIdentifier: '1',
        profileGroup: {
          profiles: [{applicationName: 'USERS_APP'}]
        }
      }
    };

    const activatedRouteMock = {
      params: of({tenantIdentifier: 1}),
      data: of({appId: 'RULE_APP'}),
      paramMap: EMPTY
    };

    TestBed.configureTestingModule({
      imports: [
        NoopAnimationsModule,
        HttpClientTestingModule,
        RouterTestingModule,
        VitamUICommonTestModule,
        ReactiveFormsModule,
        MatFormFieldModule,
        MatMenuModule,
        MatSidenavModule,
        MatProgressSpinnerModule,
        MatTabsModule,
        MatOptionModule,
        MatSelectModule,
        MatSidenavModule,
        MatDialogModule,
        SearchBarModule,
        HistoryModule,
        InjectorModule,
        LoggerModule.forRoot()
      ],
      declarations: [
        RuleComponent,
        RuleListStub,
        RulePreviewStub
      ],
      providers: [
        GlobalEventService,
        {provide: ActivatedRoute, useValue: activatedRouteMock},
        {provide: MatDialogRef, useValue: matDialogRefSpy},
        {provide: VitamUISnackBar, useValue: snackBarSpy},
        {provide: AuthService, useValue: authServiceMock},
        {provide: ApplicationService, useValue: { applications: [] } },
        {provide: ENVIRONMENT, useValue: environment},
        {provide: BASE_URL, useValue: '/fake-api'}
      ]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(RuleComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
