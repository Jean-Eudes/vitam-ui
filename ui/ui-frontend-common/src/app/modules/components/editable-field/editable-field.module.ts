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
import { OverlayModule } from '@angular/cdk/overlay';
import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule} from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { TranslateModule } from '@ngx-translate/core';
import { ConfirmDialogModule } from '../confirm-dialog/confirm-dialog.module';
import { EditableDurationInputComponent } from './editable-duration-input/editable-duration-input.component';
import { HumanizedDurationPipe } from './editable-duration-input/humanized-duration.pipe';
import { EditableEmailInputComponent } from './editable-email-input/editable-email-input.component';
import { EditableFieldComponent } from './editable-field.component';
import { EditableFileComponent } from './editable-file/editable-file.component';
import { EditableInputComponent } from './editable-input/editable-input.component';
import { EditableLevelInputComponent } from './editable-level-input/editable-level-input.component';
import { SubLevelPipe } from './editable-level-input/sub-level.pipe';
import { EditableOptionComponent } from './editable-select/editable-option.component';
import { EditableSelectComponent } from './editable-select/editable-select.component';
import { EditableTextareaComponent } from './editable-textarea/editable-textarea.component';
import { EditableButtonToggleComponent } from './editable-toggle-group/editable-button-toggle.component';
import { EditableToggleGroupComponent } from './editable-toggle-group/editable-toggle-group.component';
import { EmailsInputModule } from './emails-input/emails-input.module';
import { LevelInputModule } from './level-input/level-input.module';
import { MultipleEmailInputComponent } from './multiple-email-input/multiple-email-input.component';


@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    OverlayModule,
    MatSelectModule,
    MatProgressSpinnerModule,
    MatButtonToggleModule,
    MatDialogModule,
    ConfirmDialogModule,
    EmailsInputModule,
    LevelInputModule,
    MatInputModule,
    MatFormFieldModule,
    TranslateModule
  ],
  declarations: [
    EditableFieldComponent,
    EditableButtonToggleComponent,
    EditableDurationInputComponent,
    EditableEmailInputComponent,
    EditableFileComponent,
    EditableInputComponent,
    EditableLevelInputComponent,
    EditableOptionComponent,
    EditableSelectComponent,
    EditableTextareaComponent,
    EditableToggleGroupComponent,
    HumanizedDurationPipe,
    MultipleEmailInputComponent,
    SubLevelPipe,
  ],
  exports: [
    EditableFieldComponent,
    EditableInputComponent,
    EditableOptionComponent,
    EditableSelectComponent,
    EditableTextareaComponent,
    EditableToggleGroupComponent,
    EditableButtonToggleComponent,
    EditableFileComponent,
    EditableEmailInputComponent,
    EditableLevelInputComponent,
    MultipleEmailInputComponent,
    EditableDurationInputComponent,
    HumanizedDurationPipe,
    SubLevelPipe,
    LevelInputModule,
    EmailsInputModule
  ]
})
export class EditableFieldModule { }
