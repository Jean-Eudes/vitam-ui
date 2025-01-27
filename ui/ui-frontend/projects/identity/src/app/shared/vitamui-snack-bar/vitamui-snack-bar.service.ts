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

import { LiveAnnouncer } from '@angular/cdk/a11y';
import { BreakpointObserver, Breakpoints } from '@angular/cdk/layout';
import { Overlay, OverlayConfig, OverlayRef } from '@angular/cdk/overlay';
import { ComponentPortal, ComponentType, TemplatePortal } from '@angular/cdk/portal';
import {
  ComponentRef,
  EmbeddedViewRef,
  Inject,
  Injectable,
  InjectionToken,
  Injector,
  Optional,
  SkipSelf,
  TemplateRef
} from '@angular/core';
import { MatSnackBarConfig, MatSnackBarContainer, MatSnackBarRef, MAT_SNACK_BAR_DATA, SimpleSnackBar } from '@angular/material/snack-bar';
import { take, takeUntil } from 'rxjs/operators';

export const MAT_SNACK_BAR_DEFAULT_OPTIONS =
  new InjectionToken<MatSnackBarConfig>('mat-snack-bar-default-options', {
    providedIn: 'root',
    factory: MAT_SNACK_BAR_DEFAULT_OPTIONS_FACTORY,
  });

export function MAT_SNACK_BAR_DEFAULT_OPTIONS_FACTORY(): MatSnackBarConfig {
  return new MatSnackBarConfig();
}

@Injectable({
  providedIn: 'root'
})
export class VitamUISnackBar {

  /**
   * Reference to the current snack bar in the view *at this level* (in the Angular injector tree).
   * If there is a parent snack-bar service, all operations should delegate to that parent
   * via `_openedSnackBarRef`.
   */

  private _snackBarRefAtThisLevel: MatSnackBarRef<any> | null = null;

  get _openedSnackBarRef(): MatSnackBarRef<any> | null {
    const parent = this._parentSnackBar;

    return parent ? parent._openedSnackBarRef : this._snackBarRefAtThisLevel;
  }

  set _openedSnackBarRef(value: MatSnackBarRef<any> | null) {
    if (this._parentSnackBar) {
      this._parentSnackBar._openedSnackBarRef = value;
    } else {
      this._snackBarRefAtThisLevel = value;
    }
  }

  constructor(
    private _overlay: Overlay,
    private _live: LiveAnnouncer,
    private _injector: Injector,
    private _breakpointObserver: BreakpointObserver,
    @Optional() @SkipSelf() private _parentSnackBar: VitamUISnackBar,
    @Inject(MAT_SNACK_BAR_DEFAULT_OPTIONS) private _defaultConfig: MatSnackBarConfig) { }

  /**
   * Creates and dispatches a snack bar with a custom component for the content, removing any
   * currently opened snack bars.
   *
   * @param component Component to be instantiated.
   * @param config Extra configuration for the snack bar.
   */
  openFromComponent<T>(component: ComponentType<T>, config?: MatSnackBarConfig):
    MatSnackBarRef<T> {
    return this._attach(component, config) as MatSnackBarRef<T>;
  }

  /**
   * Creates and dispatches a snack bar with a custom template for the content, removing any
   * currently opened snack bars.
   *
   * @param template Template to be instantiated.
   * @param config Extra configuration for the snack bar.
   */
  openFromTemplate(template: TemplateRef<any>, config?: MatSnackBarConfig):
    MatSnackBarRef<EmbeddedViewRef<any>> {
    return this._attach(template, config);
  }

  /**
   * Opens a snackbar with a message and an optional action.
   * @param message The message to show in the snackbar.
   * @param action The label for the snackbar action.
   * @param config Additional configuration options for the snackbar.
   */
  open(message: string, action: string = '', config?: MatSnackBarConfig):
    MatSnackBarRef<SimpleSnackBar> {
    const mergedConfig = { ...this._defaultConfig, ...config };

    mergedConfig.data = { message, action };
    mergedConfig.announcementMessage = message;

    return this.openFromComponent(SimpleSnackBar, mergedConfig);
  }

  /**
   * Dismisses the currently-visible snack bar.
   */
  dismiss(): void {
    if (this._openedSnackBarRef) {
      this._openedSnackBarRef.dismiss();
    }
  }

  /**
   * Attaches the snack bar container component to the overlay.
   */
  private _attachSnackBarContainer(overlayRef: OverlayRef,
                                   config: MatSnackBarConfig): MatSnackBarContainer {

    const userInjector = config && config.viewContainerRef && config.viewContainerRef.injector;
    const injector = Injector.create({
      parent: userInjector || this._injector,
      providers: [{provide: MatSnackBarConfig, useValue: config}]
    });

    const containerPortal =
      new ComponentPortal(MatSnackBarContainer, config.viewContainerRef, injector);
    const containerRef: ComponentRef<MatSnackBarContainer> = overlayRef.attach(containerPortal);
    containerRef.instance.snackBarConfig = config;

    return containerRef.instance;
  }

  /**
   * Places a new component or a template as the content of the snack bar container.
   */
  private _attach<T>(content: ComponentType<T> | TemplateRef<T>, userConfig?: MatSnackBarConfig):
    MatSnackBarRef<T | EmbeddedViewRef<any>> {

    const config = { ...new MatSnackBarConfig(), ...this._defaultConfig, ...userConfig };
    const overlayRef = this._createOverlay(config);
    const container = this._attachSnackBarContainer(overlayRef, config);
    const snackBarRef = new MatSnackBarRef<T | EmbeddedViewRef<any>>(container, overlayRef);

    if (content instanceof TemplateRef) {
      const portal = new TemplatePortal(content, null, {
        $implicit: config.data,
        snackBarRef
      } as any);

      snackBarRef.instance = container.attachTemplatePortal(portal);
    } else {
      const injector = this._createInjector(config, snackBarRef);
      const portal = new ComponentPortal(content, undefined, injector);
      const contentRef = container.attachComponentPortal<T>(portal);

      snackBarRef.instance = contentRef.instance;
    }

    this._breakpointObserver.observe(Breakpoints.Handset).pipe(
      takeUntil(overlayRef.detachments().pipe(take(1)))
    ).subscribe((state) => {
      if (state.matches) {
        overlayRef.overlayElement.classList.add('mat-snack-bar-handset');
      } else {
        overlayRef.overlayElement.classList.remove('mat-snack-bar-handset');
      }
    });

    this._animateSnackBar(snackBarRef, config);
    this._openedSnackBarRef = snackBarRef;

    return this._openedSnackBarRef;
  }

  private _animateSnackBar(snackBarRef: MatSnackBarRef<any>, config: MatSnackBarConfig) {
    snackBarRef.afterDismissed().subscribe(() => {
      if (this._openedSnackBarRef === snackBarRef) {
        this._openedSnackBarRef = null;
      }
    });

    if (this._openedSnackBarRef) {
      this._openedSnackBarRef.afterDismissed().subscribe(() => {
        snackBarRef.containerInstance.enter();
      });
      this._openedSnackBarRef.dismiss();
    } else {
      snackBarRef.containerInstance.enter();
    }

    if (config.duration && config.duration > 0) {
      snackBarRef.afterOpened().subscribe(() => snackBarRef._dismissAfter(config.duration));
    }

    if (config.announcementMessage) {
      this._live.announce(config.announcementMessage, config.politeness);
    }
  }

  /**
   * Creates a new overlay and places it in the correct location.
   * @param config The user-specified snack bar config.
   */
  private _createOverlay(config: MatSnackBarConfig): OverlayRef {
    const overlayConfig = new OverlayConfig();
    overlayConfig.direction = config.direction;

    const positionStrategy = this._overlay.position().global();
    const isRtl = config.direction === 'rtl';
    const isLeft = (
      config.horizontalPosition === 'left' ||
      (config.horizontalPosition === 'start' && !isRtl) ||
      (config.horizontalPosition === 'end' && isRtl));
    const isRight = !isLeft && config.horizontalPosition !== 'center';
    if (isLeft) {
      positionStrategy.left('0');
    } else if (isRight) {
      positionStrategy.right('0');
    } else {
      positionStrategy.centerHorizontally();
    }
    if (config.verticalPosition === 'top') {
      positionStrategy.top('0');
    } else {
      positionStrategy.bottom('0');
    }

    overlayConfig.width = '100%';

    overlayConfig.positionStrategy = positionStrategy;

    return this._overlay.create(overlayConfig);
  }

  /**
   * Creates an injector to be used inside of a snack bar component.
   * @param config Config that was used to create the snack bar.
   * @param snackBarRef Reference to the snack bar.
   */
  private _createInjector<T>(
    config: MatSnackBarConfig,
    snackBarRef: MatSnackBarRef<T>): Injector {

    const userInjector = config && config.viewContainerRef && config.viewContainerRef.injector;

    return Injector.create({
      parent: userInjector || this._injector,
      providers: [
        {provide: MatSnackBarRef, useValue: snackBarRef},
        {provide: MAT_SNACK_BAR_DATA, useValue: config.data}
      ]
    });
  }
}
