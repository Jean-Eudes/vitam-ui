import { Component, forwardRef, ElementRef, OnInit, EventEmitter, Input, Output } from '@angular/core';
import { NG_VALUE_ACCESSOR } from '@angular/forms';
import { EditableFieldComponent } from 'ui-frontend-common';

export const EDITABLE_DOMAIN_INPUT_VALUE_ACCESSOR: any = {
  provide: NG_VALUE_ACCESSOR,
  useExisting: forwardRef(() => EditableCustomParamsComponent),
  multi: true,
};

@Component({
  selector: 'editable-custom-params',
  templateUrl: './editable-custom-params.component.html',
  providers: [EDITABLE_DOMAIN_INPUT_VALUE_ACCESSOR],
})
export class EditableCustomParamsComponent extends EditableFieldComponent implements OnInit {
  array: any[] = [];

  selected: string;
  private domainInputClicked = false;
  get canConfirm(): boolean {
    return this.editMode && !this.control.pending && this.control.valid && this.control.dirty;
  }
  @Input()
  set defaultDomain(defaultDomain: string) {
    this._defaultDomain = defaultDomain;
    this.selected = defaultDomain;
  }
  get defaultDomain(): string {
    return this._defaultDomain;
  }
  private _defaultDomain: string;

  @Output() defaultDomainChange = new EventEmitter<string>();
  @Input() placeholder: string;
  constructor(elementRef: ElementRef) {
    super(elementRef);
  }
  ngOnInit(): void {}

  getList(obj: any) {
    let map = new Map<string, string>();
    if (!!obj) {
      Object.entries(obj).forEach((array: [string, string]) => {
        map.set(array[0], array[1]);
      });
    }
    return map;
  }

  cancel() {
    super.cancel();
    this.selected = this.defaultDomain;
  }

  onClick(target: HTMLElement) {
    if (!this.editMode) {
      return;
    }
    if (this.domainInputClicked) {
      this.domainInputClicked = false;

      return;
    }
    const overlayRef = this.cdkConnectedOverlay.overlayRef;
    if (this.isInside(target, this.elementRef.nativeElement) || this.isInside(target, overlayRef.hostElement)) {
      return;
    }
    this.cancel();
  }

  onDomainInputClick() {
    this.domainInputClicked = true;
  }

  enterEditMode() {
    super.enterEditMode();
  }
}
