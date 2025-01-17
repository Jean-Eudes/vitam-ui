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
import { coerceBooleanProperty } from '@angular/cdk/coercion';
import {
  ConnectedPosition,
  Overlay,
  OverlayPositionBuilder,
  OverlayRef,
} from '@angular/cdk/overlay';
import { ComponentPortal } from '@angular/cdk/portal';
import {
  ComponentRef,
  Directive,
  ElementRef,
  HostListener,
  Input,
  OnDestroy,
  OnInit,
} from '@angular/core';
import { CommonTooltipComponent } from './common-tooltip.component';
import { TooltipType } from './TooltipType.enum';

@Directive({
  selector: '[vitamuiCommonToolTip]',
})
export class CommonTooltipDirective implements OnInit, OnDestroy {
  @Input('vitamuiCommonToolTip') text = '';
  @Input() type = 'BOTTOM';
  @Input() outline = false;

 /** Disables the display of the tooltip. */
  @Input('vitamuiCommonToolTipDisabled')
  get disabled(): boolean { return this._disabled; }
  set disabled(value) {
    this._disabled = coerceBooleanProperty(value);

    // If tooltip is disabled, hide immediately.
    if (this._disabled && this.overlayRef) {
      this.hide();
    }
  }
  // tslint:disable-next-line:variable-name
  private _disabled = false;

  private overlayRef: OverlayRef;

  constructor(
    private overlay: Overlay,
    private overlayPositionBuilder: OverlayPositionBuilder,
    private elementRef: ElementRef
  ) {}

  ngOnInit(): void {
    const position = this.buildPosition(this.type);
    const positionStrategy = this.overlayPositionBuilder
      .flexibleConnectedTo(this.elementRef)
      .withPositions([position]);

    this.overlayRef = this.overlay.create({ positionStrategy });
  }

  ngOnDestroy() {
    this.overlayRef.detach();
  }

  @HostListener('mouseenter')
  show() {
    if (this.disabled) {
      return;
    }
    const tooltipPortal = new ComponentPortal(CommonTooltipComponent);
    const tooltipRef: ComponentRef<CommonTooltipComponent> = this.overlayRef.attach(
      tooltipPortal
    );
    tooltipRef.instance.text = this.text;
    tooltipRef.instance.className = this.type;
    tooltipRef.instance.outline = this.outline;
  }

  @HostListener('mouseout')
  hide() {
     this.overlayRef.detach();
  }

  private buildPosition(type: string): ConnectedPosition {
    switch (type) {
      case TooltipType.TOP: {
        return {
          originX: 'start',
          originY: 'top',
          overlayX: 'start',
          overlayY: 'bottom',
        };
      }
      case TooltipType.BOTTOM:
        return {
          originX: 'start',
          originY: 'bottom',
          overlayX: 'start',
          overlayY: 'top',
        };
      case TooltipType.LEFT:
        return {
          originX: 'start',
          originY: 'center',
          overlayX: 'end',
          overlayY: 'center',
        };

      case TooltipType.RIGHT:
        return {
          originX: 'end',
          originY: 'center',
          overlayX: 'start',
          overlayY: 'center',
        };
    }
  }
}
