import { Component, Input, OnDestroy, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { Subject } from 'rxjs';
import { AuthService, Customer, StartupService } from 'ui-frontend-common';
import { UserInfoService } from './../../../user/user-info.service';
import { HomepageMessageUpdateComponent } from './homepage-message-update/homepage-message-update.component';

@Component({
  selector: 'app-homepage-message-tab',
  templateUrl: './homepage-message-tab.component.html',
  styleUrls: ['./homepage-message-tab.component.scss']
})
export class HomepageMessageTabComponent implements OnInit, OnDestroy {

  @Input()
  set customer(customer: Customer) {
    this._customer = customer;
    this.resetTab(this.customer);
  }
  get customer(): Customer { return this._customer; }
  // tslint:disable-next-line:variable-name
  private _customer: Customer;

  @Input()
  set readOnly(readOnly: boolean) {
    this._readonly = readOnly;
  }
  get readonly(): boolean { return this._readonly; }

  // tslint:disable-next-line:variable-name
  private _readonly: boolean;
  private destroy = new Subject();

  public portalTitle: string;
  public portalMessage: string;

  public portalTitles: {
    [key: string]: string;
  };
  public portalMessages: {
    [key: string]: string;
  };

  public language : string;

  constructor(private dialog: MatDialog, private startupService: StartupService, private authService: AuthService,
    private userInfoService: UserInfoService) {
  }

  ngOnDestroy(): void {
    this.destroy.next();
  }

  ngOnInit() {
    const userInfosId = this.authService.user.userInfoId;
    this.userInfoService.get(userInfosId).subscribe((userInfo) => {
        this.language = userInfo.language;
    });
  }

  private resetTab(customer: Customer): void {
    const title = this.startupService.getDefaultPortalTitle();
    const message = this.startupService.getDefaultPortalMessage();

    if (customer) {
      if (customer.language) {
        this.language = customer.language;
      }
      if (customer.portalMessages) {
        this.portalMessages = customer.portalMessages;
      }
      if (customer.portalTitles) {
        this.portalTitles = this.customer.portalTitles;
      }
    }

    this.portalTitle = (this.portalTitles && this.portalTitles[this.language]) ? (this.portalTitles[this.language]) : title;
    this.portalMessage = (this.portalMessages && this.portalMessages[this.language]) ? this.portalMessages[this.language] : message;
  }

  openUpdateHomepageMessage() {
    const dialogRef = this.dialog.open(HomepageMessageUpdateComponent, {
      panelClass: 'vitamui-modal',
      disableClose: true,
      data: { customer: this.customer }
    });
    dialogRef.afterClosed().subscribe();
  }
}
