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
import { Subscription } from 'rxjs';
import { ConfirmDialogService, Customer, Owner, Tenant } from 'ui-frontend-common';

import { Component, Inject, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';

import { OwnerService } from '../owner.service';
import { TenantFormValidators } from '../tenant-create/tenant-form.validators';
import { TenantService } from '../tenant.service';

@Component({
  selector: 'app-owner-create',
  templateUrl: './owner-create.component.html',
  styleUrls: ['./owner-create.component.scss']
})
export class OwnerCreateComponent implements OnInit, OnDestroy {

  public ownerForm: FormGroup;
  public tenantForm: FormGroup;
  public stepIndex = 0;

  private keyPressSubscription: Subscription;

  constructor(
    public dialogRef: MatDialogRef<OwnerCreateComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { customer: Customer },
    private formBuilder: FormBuilder,
    private ownerService: OwnerService,
    private tenantService: TenantService,
    private tenantFormValidators: TenantFormValidators,
    private confirmDialogService: ConfirmDialogService
  ) { }

  ngOnInit() {
    this.ownerForm = this.formBuilder.group({
      owner: [null, Validators.required]
    });
    this.tenantForm = this.formBuilder.group({
      name: [
        null,
        [Validators.required],
        this.tenantFormValidators.uniqueName(),
      ],
      ownerId: [null],
      customerId: [this.data.customer.id],
      enabled: [true, Validators.required]
    });
    this.keyPressSubscription = this.confirmDialogService.listenToEscapeKeyPress(this.dialogRef).subscribe(() => this.onCancel());
  }

  ngOnDestroy() {
    this.keyPressSubscription.unsubscribe();
  }

  onCancel() {
    if (this.ownerForm.dirty || this.tenantForm.dirty) {
      this.confirmDialogService.confirmBeforeClosing(this.dialogRef);
    } else {
      this.dialogRef.close();
    }
  }

  onOwnerSubmit() {
    if (this.ownerForm.pending || this.ownerForm.invalid) { return; }
    this.ownerService.create(this.ownerForm.value.owner).subscribe(
      (newOwner: Owner) => this.dialogRef.close({ owner: newOwner }),
      (error) => {
        // TODO
        console.error(error);
      });
  }

  onTenantSubmit() {
    if (this.ownerForm.pending || this.ownerForm.invalid || this.tenantForm.pending || this.tenantForm.invalid) { return; }
    this.ownerService.create(this.ownerForm.value.owner).subscribe(
      (newOwner) => {
        this.tenantForm.get('ownerId').setValue(newOwner.id);
        this.tenantService.create(this.tenantForm.value, newOwner.name).subscribe(
          (newTenant: Tenant) => {
            this.dialogRef.close({ owner: newOwner, tenant: newTenant });
          },
          (error) => {
            console.error(error);
            this.dialogRef.close();
          }
        );
      },
      (error) => {
        // TODO
        console.error(error);
      });
  }

}
