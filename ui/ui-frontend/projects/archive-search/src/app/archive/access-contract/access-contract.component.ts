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
import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { Option } from 'ui-frontend-common';
import { ArchiveSharedDataServiceService } from '../../core/archive-shared-data-service.service';
import { ArchiveService } from '../archive.service';

@Component({
  selector: 'app-access-contract',
  templateUrl: './access-contract.component.html',
  styleUrls: ['./access-contract.component.scss'],
})
export class AccessContractComponent implements OnInit {
  tenantIdentifier: string;
  accessContracts: Option[] = [];
  form: FormGroup;
  accessContractIdSelected: string;

  @Output() selectedAccessContract = new EventEmitter<string>();

  constructor(
    private archiveService: ArchiveService,
    private route: ActivatedRoute,
    private archiveSharedDataServiceService: ArchiveSharedDataServiceService,
    private formBuilder: FormBuilder
  ) {
    this.route.params.subscribe((params) => {
      this.tenantIdentifier = params.tenantIdentifier;
    });

    this.archiveService.getAllAccessContracts(this.tenantIdentifier).subscribe((accessContracts) => {
      this.accessContracts = accessContracts.map((accessContract) => ({
        key: accessContract.identifier,
        label: accessContract.name,
      }));
    });

    this.form = this.formBuilder.group({
      id: null,
      accessContract: [null, Validators.required],
      dsl: [null, Validators.required],
      response: null,
    });
  }

  ngOnInit() {}

  initContractSelected(event: any) {
    this.accessContractIdSelected = event.value;
    this.selectedAccessContract.emit(event.value);
    this.archiveSharedDataServiceService.emitToggle(true);
  }
}
