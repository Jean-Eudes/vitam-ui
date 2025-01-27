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

import { Component, EventEmitter, Input, OnChanges, OnInit, Output, SimpleChanges } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { TranslateService } from '@ngx-translate/core';
import { Unit } from '../models/unit.interface';

@Component({
  selector: 'app-archive-preview',
  templateUrl: './archive-preview.component.html',
  styleUrls: ['./archive-preview.component.scss'],
})
export class ArchivePreviewComponent implements OnInit, OnChanges {
  @Input()
  archiveUnit: Unit;
  @Input()
  accessContract: string;
  @Output()
  backToNormalLateralPanel: EventEmitter<any> = new EventEmitter();
  @Output()
  previewClose: EventEmitter<any> = new EventEmitter();
  @Output()
  showExtendedLateralPanel: EventEmitter<any> = new EventEmitter();
  @Input()
  isPopup: boolean;
  isPanelextended = false;
  selectedIndex = 0;

  tenantIdentifier: number;

  updateStarted = false;
  @Input()
  hasAccessContractManagementPermissions: boolean;
  @Input()
  hasUpdateDescriptiveUnitMetadataRole: boolean;
  hasAccessContractManagementPermissionsMessage = '';
  constructor(private route: ActivatedRoute, private translateService: TranslateService) {
    this.route.params.subscribe((params) => {
      this.tenantIdentifier = +params.tenantIdentifier;
    });
  }

  ngOnInit() {
    this.hasAccessContractManagementPermissionsMessage = this.translateService.instant('UNIT_UPDATE.NO_PERMISSION');
  }

  emitClose() {
    this.isPanelextended = false;
    this.previewClose.emit();
    this.backToNormalLateralPanel.emit();
    this.selectedIndex = 0;
  }
  showNormalPanel() {
    this.selectedIndex--;
    this.isPanelextended = false;
    this.backToNormalLateralPanel.emit();
    this.updateStarted = false;
  }

  showExtendedPanel() {
    this.isPanelextended = true;
    this.showExtendedLateralPanel.emit();
    this.selectedIndex = 1;
  }

  updateMetadataDesc() {
    this.isPanelextended = true;
    this.showExtendedLateralPanel.emit();
    this.updateStarted = true;
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes.archiveUnit) {
      this.showNormalPanel();
    }
  }
}
