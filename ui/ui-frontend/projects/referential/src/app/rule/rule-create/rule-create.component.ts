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
import { Component, Inject, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { Subscription } from 'rxjs';
import { ConfirmDialogService, Rule, RuleService } from 'ui-frontend-common';
import { RULE_MEASUREMENTS, RULE_TYPES } from '../rules.constants';
import { RuleCreateValidators } from './rule-create.validators';

const PROGRESS_BAR_MULTIPLICATOR = 100;

@Component({
  selector: 'app-rule-create',
  templateUrl: './rule-create.component.html',
  styleUrls: ['./rule-create.component.scss'],
})
export class RuleCreateComponent implements OnInit, OnDestroy {
  form: FormGroup;
  stepIndex = 0;
  hasCustomGraphicIdentity = false;
  hasError = true;
  message: string;

  // stepCount is the total number of steps and is used to calculate the advancement of the progress bar.
  // We could get the number of steps using ViewChildren(StepComponent) but this triggers a
  // "Expression has changed after it was checked" error so we instead manually define the value.
  // Make sure to update this value whenever you add or remove a step from the  template.
  private stepCount = 1;
  private keyPressSubscription: Subscription;

  ruleTypes = RULE_TYPES;
  ruleMeasurements = RULE_MEASUREMENTS;
  isDisabledButton = false;

  @ViewChild('fileSearch', { static: false }) fileSearch: any;
  tenantIdentifier: number;

  constructor(
    public dialogRef: MatDialogRef<RuleCreateComponent>,
    @Inject(MAT_DIALOG_DATA) public data: any,
    private formBuilder: FormBuilder,
    private confirmDialogService: ConfirmDialogService,
    private ruleService: RuleService,
    private ruleCreateValidator: RuleCreateValidators
  ) {}

  ngOnInit() {
    this.form = this.formBuilder.group({
      ruleId: [null, [Validators.required, this.ruleCreateValidator.ruleIdPattern()], this.ruleCreateValidator.uniqueRuleId()],
      ruleType: [null, Validators.required],
      ruleValue: [null, Validators.required],
      ruleDescription: [null, Validators.required],
      ruleDuration: [null, Validators.required],
      ruleMeasurement: [null, Validators.required],
    });

    this.keyPressSubscription = this.confirmDialogService.listenToEscapeKeyPress(this.dialogRef).subscribe(() => this.onCancel());
  }

  ngOnDestroy() {
    this.keyPressSubscription.unsubscribe();
  }

  onCancel() {
    if (this.form.dirty) {
      this.confirmDialogService.confirmBeforeClosing(this.dialogRef);
    } else {
      this.dialogRef.close();
    }
  }

  onSubmit() {
    if (this.form.invalid) {
      this.isDisabledButton = true;
      return;
    }

    const format: Rule = this.form.value;
    this.isDisabledButton = true;

    this.ruleService.create(format).subscribe(
      () => {
        this.isDisabledButton = false;

        this.dialogRef.close({ success: true });
      },
      (error: any) => {
        this.dialogRef.close({ success: false });
        console.error(error);
      }
    );
  }

  get stepProgress() {
    return ((this.stepIndex + 1) / this.stepCount) * PROGRESS_BAR_MULTIPLICATOR;
  }
}
