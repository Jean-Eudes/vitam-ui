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
import { ApplicationService, BreadCrumbData, GlobalEventService, Profile, SidenavPage } from 'ui-frontend-common';

import { Component, OnInit, ViewChild } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { ActivatedRoute } from '@angular/router';

import { ProfileCreateComponent } from './profile-create/profile-create.component';
import { ProfileListComponent } from './profile-list/profile-list.component';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.scss']
})
export class ProfileComponent extends SidenavPage<Profile> implements OnInit {

  public breadCrumbData: BreadCrumbData[];
  public search: string;

  @ViewChild(ProfileListComponent, { static: true }) profileListComponent: ProfileListComponent;

  constructor(public dialog: MatDialog, private route: ActivatedRoute, public globalEventService: GlobalEventService,
              private applicationService: ApplicationService) {
    super(route, globalEventService);
  }

  ngOnInit() {
    const appId = this.route.snapshot.data.appId;
    this.breadCrumbData = [
      {
        label: 'Portail'
      },
      {
        label: this.applicationService.getAppById(appId).name,
        identifier: appId
      }
    ];
  }

  openProfilAdminCreateDialog() {
    const dialogRef = this.dialog.open(ProfileCreateComponent, { panelClass: 'vitamui-modal', disableClose: true });
    dialogRef.afterClosed().subscribe((result) => {
        if (result) { this.refreshList(); }
    });
  }

  onSearchSubmit(search: string) {
    this.search = search;
  }

  private refreshList() {
    if (!this.profileListComponent) { return; }

    this.profileListComponent.search();
  }

}
